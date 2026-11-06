// Package crtsh is a core.CTSource over a crt.sh-style certificate transparency search
// (GET <base>/?q=%.<domain>&output=json).
//
// What it will and will not do:
//
//   - Passive towards the target. It asks the search service which certificates name a
//     domain. It never contacts the domain or any host under it: the dialer refuses a
//     connection to a name inside the domain (checked before DNS, so it holds for the
//     base URL and for every redirect), and a redirect to a bare IP address is refused.
//     A different name that resolves to the domain's servers cannot be detected here.
//   - Third party. The domain name leaves the machine to the service named by the base
//     URL. The caller must have the operator's consent to that.
//   - Failure is not silence. A timeout, a network error, a 429, any non-200, a body that
//     is too large or does not parse and a cancelled context each return an error that is
//     not core.ErrNotFound. Only an empty certificate list is core.ErrNotFound.
//     A 429 is core.ErrRateLimited.
//   - Bounded. One timeout, at most MaxBody bytes read, at most three redirects, never
//     https to http, at most MaxNames distinct names kept. More sets Truncated: the
//     names kept are real, the rest are unknown.
//   - Candidates, not hosts. A name on a certificate may be long dead, internal-only,
//     shared by a CDN or never served. Wildcard names are counted and dropped, and names
//     on the same certificates but outside the domain are counted and dropped.
//   - Service text is untrusted. Names must be plausible DNS names to be kept.
package crtsh

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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	// DefaultBaseURL is the public crt.sh search.
	DefaultBaseURL = "https://crt.sh"
	// DefaultTimeout bounds one search, redirects included. crt.sh is slow on big domains.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxBody bounds the bytes read from one response.
	DefaultMaxBody int64 = 16 << 20
	// DefaultMaxNames bounds the distinct names kept.
	DefaultMaxNames = 500

	maxRedirects = 3
	userAgent    = "json-bourne-estate"
)

var nameRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$`)

var _ core.CTSource = (*Client)(nil)

// Client asks one certificate transparency search service.
type Client struct {
	BaseURL   string
	Timeout   time.Duration     // <= 0 means DefaultTimeout
	MaxBody   int64             // <= 0 means DefaultMaxBody
	MaxNames  int               // <= 0 means DefaultMaxNames
	Transport http.RoundTripper // tests only; nil builds a transport that refuses the target
}

// New validates base (http or https, a host, no credentials, query or fragment).
func New(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("crt.sh URL %q must be an http or https URL with a host", base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(base, "#") {
		return nil, fmt.Errorf("crt.sh URL %q must not carry credentials, a query or a fragment", base)
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), Timeout: DefaultTimeout, MaxBody: DefaultMaxBody, MaxNames: DefaultMaxNames}, nil
}

// inDomain reports whether host is the domain or a name under it.
func inDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func (c *Client) httpClient(domain string, timeout time.Duration) *http.Client {
	rt := c.Transport
	if rt == nil {
		d := &net.Dialer{Timeout: timeout}
		rt = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}
				if inDomain(host, domain) {
					return nil, errors.New("refused: the search would connect to the domain under investigation")
				}
				return d.DialContext(ctx, network, addr)
			},
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
			case inDomain(req.URL.Hostname(), domain):
				return errors.New("redirect to the domain under investigation")
			}
			if _, err := netip.ParseAddr(strings.Trim(req.URL.Hostname(), "[]")); err == nil {
				return errors.New("redirect to a bare IP address")
			}
			return nil
		},
	}
}

// LookupSubdomains implements core.CTSource. domain must be a lower-case DNS name; the
// caller validates it.
func (c *Client) LookupSubdomains(ctx context.Context, domain string) (core.CTAnswer, error) {
	q := url.Values{"q": {"%." + domain}, "output": {"json"}}.Encode()
	full := c.BaseURL + "/?" + q
	out := core.CTAnswer{Query: "GET " + full}
	fail := func(format string, a ...any) (core.CTAnswer, error) {
		return out, fmt.Errorf("%w: %s", core.ErrLookupFailed, fmt.Sprintf(format, a...))
	}
	timeout, max, maxNames := c.Timeout, c.MaxBody, c.MaxNames
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if max <= 0 {
		max = DefaultMaxBody
	}
	if maxNames <= 0 {
		maxNames = DefaultMaxNames
	}
	if u, err := url.Parse(c.BaseURL); err != nil {
		return fail("bad base URL")
	} else if inDomain(u.Hostname(), domain) {
		return fail("the search URL is inside the domain under investigation; not sent")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return fail("build request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.httpClient(domain, timeout).Do(req)
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
		return out, fmt.Errorf("%w: HTTP 429", core.ErrRateLimited)
	case resp.StatusCode != http.StatusOK:
		return fail("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return fail("read body: %v", err)
	}
	if int64(len(body)) > max {
		return fail("response larger than %d bytes", max)
	}
	var certs []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		return fail("response is not the expected JSON array")
	}
	if len(certs) == 0 {
		return out, fmt.Errorf("%w: the service has no certificate for %s", core.ErrNotFound, domain)
	}
	seen, skipped := map[string]bool{}, map[string]bool{}
	for _, c := range certs {
		for _, raw := range append(strings.Split(c.NameValue, "\n"), c.CommonName) {
			n := strings.ToLower(strings.TrimSpace(raw))
			n = strings.TrimSuffix(n, ".")
			switch {
			case n == "":
				continue
			case skipped[n]:
				continue
			case strings.Contains(n, "*"):
				skipped[n] = true
				if inDomain(strings.TrimPrefix(n, "*."), domain) {
					out.Wildcards++
				} else {
					out.OutOfScope++
				}
				continue
			case !nameRE.MatchString(n) || !inDomain(n, domain):
				skipped[n] = true
				out.OutOfScope++
				continue
			case n == domain || seen[n]:
				continue
			}
			if len(seen) == maxNames {
				out.Truncated = true
				continue
			}
			seen[n] = true
			out.Names = append(out.Names, n)
		}
	}
	sort.Strings(out.Names)
	return out, nil
}
