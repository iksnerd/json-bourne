// Package bgp is a core.BGPSource over a public BGP data API shaped like RIPEstat
// (GET <base>/data/<endpoint>/data.json?resource=<AS or address>).
//
// What it will and will not do:
//
//   - Passive towards the target. It asks the data service about an AS number or an
//     address. It never contacts the address: the dialer refuses any connection whose
//     resolved address is the target, whether it comes from the base URL or a redirect,
//     and a redirect to a bare IP address is refused outright.
//   - Third party. The AS number or address in the question leaves the machine to the
//     service named by the base URL. The caller must have the operator's consent to that.
//   - Failure is not silence. A timeout, a network error, a 429, any non-200, a body that
//     is too large or does not parse, a response whose status is not "ok" and a cancelled
//     context each return an error that is not core.ErrNotFound. Only an answer that says
//     "nothing announced" is core.ErrNotFound. A 429 is core.ErrRateLimited.
//   - Bounded. One timeout per request, at most MaxBody bytes read, at most MaxPrefixes
//     prefixes kept (more sets Truncated), at most three redirects, never https to http.
//   - Service text is untrusted. Holder names are length-capped.
//
// A route's origin AS says who announces the range. For a CDN, transit or hosting
// address that is the provider, and says nothing about who runs the site or the visitor.
package bgp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	// DefaultBaseURL is RIPEstat's public data API.
	DefaultBaseURL = "https://stat.ripe.net"
	// DefaultTimeout bounds one request, redirects included.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxBody bounds the bytes read from one response.
	DefaultMaxBody int64 = 4 << 20
	// DefaultMaxPrefixes bounds the prefixes kept for one AS.
	DefaultMaxPrefixes = 500

	maxRedirects = 3
	maxField     = 255
	maxHolders   = 20
	userAgent    = "json-bourne-estate"
)

var _ core.BGPSource = (*Client)(nil)

// Client asks one BGP data service.
type Client struct {
	BaseURL     string
	Timeout     time.Duration     // per request; <= 0 means DefaultTimeout
	MaxBody     int64             // <= 0 means DefaultMaxBody
	MaxPrefixes int               // <= 0 means DefaultMaxPrefixes
	Transport   http.RoundTripper // tests only; nil builds a transport that refuses the target
}

// New validates base (http or https, a host, no credentials, query or fragment).
func New(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("BGP data URL %q must be an http or https URL with a host", base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(base, "#") {
		return nil, fmt.Errorf("BGP data URL %q must not carry credentials, a query or a fragment", base)
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), Timeout: DefaultTimeout, MaxBody: DefaultMaxBody, MaxPrefixes: DefaultMaxPrefixes}, nil
}

func refuse(target netip.Addr) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err == nil && target.IsValid() && ap.Addr().Unmap() == target.Unmap() {
			return errors.New("refused: the lookup would connect to the address under investigation")
		}
		return nil
	}
}

func (c *Client) httpClient(target netip.Addr, timeout time.Duration) *http.Client {
	rt := c.Transport
	if rt == nil {
		d := &net.Dialer{Timeout: timeout, Control: refuse(target)}
		rt = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           d.DialContext,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		}
	}
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			switch {
			case len(via) > maxRedirects:
				return errors.New("too many redirects")
			case req.URL.Scheme != "http" && req.URL.Scheme != "https":
				return errors.New("redirect to a non-http URL")
			case via[0].URL.Scheme == "https" && req.URL.Scheme != "https":
				return errors.New("redirect from https to http")
			}
			if _, err := netip.ParseAddr(strings.Trim(req.URL.Hostname(), "[]")); err == nil {
				return errors.New("redirect to a bare IP address")
			}
			return nil
		},
	}
}

// get fetches one endpoint and returns the "data" object. target is the address under
// investigation, or the zero Addr for an AS question.
func (c *Client) get(ctx context.Context, endpoint, resource string, target netip.Addr) (query string, data json.RawMessage, err error) {
	query = c.BaseURL + "/data/" + endpoint + "/data.json?resource=" + url.QueryEscape(resource)
	method := "GET " + query
	fail := func(format string, a ...any) (string, json.RawMessage, error) {
		return method, nil, fmt.Errorf("%w: %s", core.ErrLookupFailed, fmt.Sprintf(format, a...))
	}
	timeout, max := c.Timeout, c.MaxBody
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if max <= 0 {
		max = DefaultMaxBody
	}
	if u, perr := url.Parse(c.BaseURL); perr != nil {
		return fail("bad base URL")
	} else if a, perr := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); perr == nil && target.IsValid() && a.Unmap() == target.Unmap() {
		return fail("the data service URL is the address under investigation; not sent")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, query, nil)
	if err != nil {
		return fail("build request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.httpClient(target, timeout).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fail("%v", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return method, nil, fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)
	case resp.StatusCode != http.StatusOK:
		// The body of anything but a 200 is not read or quoted.
		return fail("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return fail("read body: %v", err)
	}
	if int64(len(body)) > max {
		return fail("response larger than %d bytes", max)
	}
	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fail("response is not the expected JSON object")
	}
	if env.Status != "ok" || len(env.Data) == 0 || string(env.Data) == "null" {
		return fail("response status is not ok or has no data")
	}
	return method, env.Data, nil
}

// LookupASN implements core.BGPSource: the prefixes an AS announces, and its holder.
func (c *Client) LookupASN(ctx context.Context, asn uint32) (core.BGPAnnouncement, error) {
	res := "AS" + strconv.FormatUint(uint64(asn), 10)
	out := core.BGPAnnouncement{}
	q1, raw, err := c.get(ctx, "announced-prefixes", res, netip.Addr{})
	out.Query = q1
	if err != nil {
		return out, err
	}
	var p struct {
		Prefixes *[]struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.Prefixes == nil {
		return out, fmt.Errorf("%w: announced-prefixes response has no prefix list", core.ErrLookupFailed)
	}
	maxP := c.MaxPrefixes
	if maxP <= 0 {
		maxP = DefaultMaxPrefixes
	}
	for _, e := range *p.Prefixes {
		pf, err := netip.ParsePrefix(e.Prefix)
		if err != nil {
			return out, fmt.Errorf("%w: a prefix in the response does not parse", core.ErrLookupFailed)
		}
		if len(out.Prefixes) == maxP {
			out.Truncated = true
			break
		}
		out.Prefixes = append(out.Prefixes, pf.Masked())
	}
	if len(*p.Prefixes) == 0 {
		return out, fmt.Errorf("%w: the service lists no announced prefix for %s", core.ErrNotFound, res)
	}
	q2, raw, err := c.get(ctx, "as-overview", res, netip.Addr{})
	out.Query += "; GET " + strings.TrimPrefix(q2, "GET ")
	if err != nil {
		out.Prefixes, out.Truncated = nil, false
		return out, err
	}
	var o struct {
		Holder string `json:"holder"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		out.Prefixes, out.Truncated = nil, false
		return out, fmt.Errorf("%w: as-overview response does not parse", core.ErrLookupFailed)
	}
	out.Holder = core.BGPHolder{ASN: asn, Holder: clip(o.Holder)}
	return out, nil
}

// LookupIP implements core.BGPSource: the route that covers an address and its origin.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (core.BGPOrigin, error) {
	ip = ip.Unmap()
	q, raw, err := c.get(ctx, "prefix-overview", ip.String(), ip)
	out := core.BGPOrigin{Query: q}
	if err != nil {
		return out, err
	}
	var d struct {
		Resource  string `json:"resource"`
		Announced *bool  `json:"announced"`
		ASNs      []struct {
			ASN    uint32 `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.Announced == nil {
		return out, fmt.Errorf("%w: prefix-overview response is not the expected shape", core.ErrLookupFailed)
	}
	if !*d.Announced || len(d.ASNs) == 0 {
		return out, fmt.Errorf("%w: no announced route covers %s", core.ErrNotFound, ip)
	}
	pf, err := netip.ParsePrefix(d.Resource)
	if err != nil || !pf.Contains(ip) {
		return out, fmt.Errorf("%w: the announced prefix does not parse or does not cover the address", core.ErrLookupFailed)
	}
	out.Prefix = pf.Masked()
	for i, a := range d.ASNs {
		if i == maxHolders {
			break
		}
		if a.ASN == 0 {
			return core.BGPOrigin{Query: q}, fmt.Errorf("%w: an origin AS number is missing", core.ErrLookupFailed)
		}
		out.Origin = append(out.Origin, core.BGPHolder{ASN: a.ASN, Holder: clip(a.Holder)})
	}
	return out, nil
}

func clip(s string) string {
	if len(s) <= maxField {
		return s
	}
	s = s[:maxField]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
