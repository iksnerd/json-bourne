// Package rdap is a core.RDAPRegistry over an RDAP service (rdap.org-style bootstrap
// or a registry's own base URL): GET <base>/ip/<address>.
//
// What it will and will not do:
//
//   - Passive. It asks the registry about an address. It never contacts the address:
//     the dialer refuses any connection whose resolved address is the target, whether it
//     comes from the base URL, a redirect or a name that resolves to it, and a redirect
//     to a bare IP address is refused outright.
//   - Failure is not silence. A timeout, a network error, a 429, any other non-200
//     except 404, a body that is too large or does not parse, a record that is not an
//     "ip network" and a cancelled context each return an error that is not
//     core.ErrNotFound. Only a real 404 is core.ErrNotFound. A 429 is core.ErrRateLimited.
//   - Bounded. One timeout per lookup, at most MaxBody bytes read, at most three
//     redirects, never from https to http.
//   - Registry text is untrusted. Fields are length-capped and entities are limited.
//
// A registration describes who holds the address range. For a CDN or proxy edge address
// that is the CDN, and says nothing about the visitor behind it.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/guardedhttp"
)

const (
	// DefaultBaseURL is the public rdap.org bootstrap, which redirects to the registry
	// that holds the address.
	DefaultBaseURL = "https://rdap.org"
	// DefaultTimeout bounds one lookup, redirects included.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxBody bounds the bytes read from one response.
	DefaultMaxBody int64 = 1 << 20

	maxEntities = 20
	maxField    = 255
	userAgent   = "json-bourne-estate"
)

var _ core.RDAPRegistry = (*Client)(nil)

// Client asks one RDAP service.
type Client struct {
	BaseURL   string
	Timeout   time.Duration     // per lookup; <= 0 means DefaultTimeout
	MaxBody   int64             // <= 0 means DefaultMaxBody
	Transport http.RoundTripper // tests only; nil builds a transport that refuses the target
}

// New validates base (http or https, a host, no credentials, query or fragment).
func New(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("RDAP base URL %q must be an http or https URL with a host", base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(base, "#") {
		return nil, fmt.Errorf("RDAP base URL %q must not carry credentials, a query or a fragment", base)
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), Timeout: DefaultTimeout, MaxBody: DefaultMaxBody}, nil
}

func (c *Client) httpClient(target netip.Addr, timeout time.Duration) *http.Client {
	return guardedhttp.New(c.Transport, timeout, guardedhttp.RefuseAddr(target))
}

// LookupIP implements core.RDAPRegistry.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (core.RDAPNetwork, error) {
	out := core.RDAPNetwork{Query: "GET " + c.BaseURL + "/ip/" + ip.String()}
	fail := func(format string, a ...any) (core.RDAPNetwork, error) {
		return out, fmt.Errorf("%w: %s", core.ErrLookupFailed, fmt.Sprintf(format, a...))
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	max := c.MaxBody
	if max <= 0 {
		max = DefaultMaxBody
	}
	if u, err := url.Parse(c.BaseURL); err != nil {
		return fail("bad base URL")
	} else if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && a.Unmap() == ip.Unmap() {
		return fail("the registry URL is the address under investigation; not sent")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/ip/"+ip.String(), nil)
	if err != nil {
		return fail("build request")
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.httpClient(ip, timeout).Do(req)
	if err != nil {
		return fail("%v", unwrapURL(err))
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return out, fmt.Errorf("%w: HTTP 404", core.ErrNotFound)
	case resp.StatusCode == http.StatusTooManyRequests:
		return out, fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)
	case resp.StatusCode != http.StatusOK:
		// The body of anything but a 200 is not read or quoted: an error page can
		// reflect request headers.
		return fail("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return fail("read body: %v", err)
	}
	if int64(len(body)) > max {
		return fail("response larger than %d bytes", max)
	}
	var d struct {
		ObjectClassName string `json:"objectClassName"`
		Handle          string `json:"handle"`
		StartAddress    string `json:"startAddress"`
		EndAddress      string `json:"endAddress"`
		Name            string `json:"name"`
		Country         string `json:"country"`
		ParentHandle    string `json:"parentHandle"`
		Entities        []struct {
			Handle     string   `json:"handle"`
			Roles      []string `json:"roles"`
			VCardArray []any    `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return fail("response is not the expected JSON object")
	}
	if d.ObjectClassName != "ip network" {
		return fail("response is not an ip network record")
	}
	if d.Handle == "" && d.StartAddress == "" {
		// A 200 that names neither the network nor its range is not an answer.
		return fail("record has neither handle nor range")
	}
	out.Handle, out.Name, out.Country = clip(d.Handle), clip(d.Name), clip(d.Country)
	out.Start, out.End, out.ParentHandle = clip(d.StartAddress), clip(d.EndAddress), clip(d.ParentHandle)
	for i, e := range d.Entities {
		if i == maxEntities {
			break
		}
		roles := make([]string, 0, len(e.Roles))
		for _, r := range e.Roles {
			roles = append(roles, clip(r))
		}
		out.Entities = append(out.Entities, core.RDAPEntity{Handle: clip(e.Handle), Name: clip(vcardName(e.VCardArray)), Roles: roles})
	}
	return out, nil
}

// clip shortens s to maxField bytes without cutting a UTF-8 sequence.
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

// vcardName finds the "fn" property of a jCard: ["vcard", [["fn", {}, "text", "Name"], ...]].
func vcardName(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		pa, _ := p.([]any)
		if len(pa) >= 4 && pa[0] == "fn" {
			if s, ok := pa[3].(string); ok {
				return s
			}
		}
	}
	return ""
}

// unwrapURL drops the *url.Error wrapper so the message does not repeat the URL.
func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
