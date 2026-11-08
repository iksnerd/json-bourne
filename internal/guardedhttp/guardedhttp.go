// Package guardedhttp builds the *http.Client of the passive-only collectors (rdap, bgp,
// crtsh). Each of them asks a public registry or data service about an address or a
// domain and must never contact that address or domain itself. The client here owns what
// they share: no keep-alive, every stage bounded by one timeout, and the redirect rules.
// The part that differs is the Guard each collector passes in.
//
// Standard library only.
package guardedhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// MaxRedirects is how many redirects a request may follow.
const MaxRedirects = 3

// Guard is what a collector refuses to contact. Every field is optional.
type Guard struct {
	// Control runs for every connection the dialer makes, on the resolved address
	// ("ip:port"), after DNS. A non-nil error aborts the connection.
	Control func(network, address string, c syscall.RawConn) error
	// Dial runs before each connection with the host as written in the URL, before DNS.
	// A non-nil error aborts the connection.
	Dial func(host string) error
	// Redirect runs for the host of every redirect target. A non-nil error refuses the
	// redirect.
	Redirect func(host string) error
}

// RefuseAddr is the Guard of a collector that asks about one IP address: it refuses any
// connection whose resolved address is target. A zero target refuses nothing.
func RefuseAddr(target netip.Addr) Guard {
	return Guard{Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err == nil && target.IsValid() && ap.Addr().Unmap() == target.Unmap() {
			return errors.New("refused: the lookup would connect to the address under investigation")
		}
		return nil
	}}
}

// New returns a client with one overall timeout. A nil rt builds the guarded transport;
// a non-nil rt (tests) is used as given, but the redirect rules still apply.
func New(rt http.RoundTripper, timeout time.Duration, g Guard) *http.Client {
	if rt == nil {
		d := &net.Dialer{Timeout: timeout, Control: g.Control}
		rt = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if g.Dial != nil {
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						host = addr
					}
					if err := g.Dial(host); err != nil {
						return nil, err
					}
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
			case len(via) > MaxRedirects:
				return errors.New("too many redirects")
			case req.URL.Scheme != "http" && req.URL.Scheme != "https":
				return errors.New("redirect to a non-http URL")
			case via[0].URL.Scheme == "https" && req.URL.Scheme != "https":
				return errors.New("redirect from https to http")
			}
			if g.Redirect != nil {
				if err := g.Redirect(req.URL.Hostname()); err != nil {
					return err
				}
			}
			if _, err := netip.ParseAddr(strings.Trim(req.URL.Hostname(), "[]")); err == nil {
				return errors.New("redirect to a bare IP address")
			}
			return nil
		},
	}
}
