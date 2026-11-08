package guardedhttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// redirector answers every request with a redirect to loc, or 200 when loc is empty.
func redirector(loc string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loc == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, loc, http.StatusFound)
	})
}

// loopRT answers every request with a redirect to another named host, with no network.
type loopRT struct{ n *int }

func (l loopRT) RoundTrip(r *http.Request) (*http.Response, error) {
	*l.n++
	return &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": {"http://a.example/next"}},
		Body:       http.NoBody,
		Request:    r,
	}, nil
}

func get(t *testing.T, c *http.Client, url string) error {
	t.Helper()
	resp, err := c.Get(url)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestRedirectRefusals(t *testing.T) {
	plain := httptest.NewServer(redirector("ftp://example.org/x"))
	defer plain.Close()
	toIP := httptest.NewServer(redirector("http://203.0.113.9/x"))
	defer toIP.Close()
	toIPv6 := httptest.NewServer(redirector("http://[2001:db8::1]/x"))
	defer toIPv6.Close()
	tls := httptest.NewTLSServer(redirector("http://example.org/x"))
	defer tls.Close()

	cases := []struct {
		name string
		rt   http.RoundTripper
		url  string
		want string
	}{
		{"too many redirects", loopRT{new(int)}, "http://a.example/start", "too many redirects"},
		{"non-http scheme", nil, plain.URL, "redirect to a non-http URL"},
		{"https to http", tls.Client().Transport, tls.URL, "redirect from https to http"},
		{"bare IPv4", nil, toIP.URL, "redirect to a bare IP address"},
		{"bare IPv6", nil, toIPv6.URL, "redirect to a bare IP address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := get(t, New(tc.rt, time.Second, Guard{}), tc.url)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestRedirectLimitIsExact(t *testing.T) {
	n := 0
	err := get(t, New(loopRT{&n}, time.Second, Guard{}), "http://a.example/start")
	if err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("err = %v, want too many redirects", err)
	}
	if want := MaxRedirects + 1; n != want {
		t.Fatalf("made %d requests, want %d (the first and %d redirects)", n, want, MaxRedirects)
	}
}

func TestRedirectGuardIsApplied(t *testing.T) {
	srv := httptest.NewServer(redirector("http://blocked.example/x"))
	defer srv.Close()
	g := Guard{Redirect: func(host string) error {
		if host == "blocked.example" {
			return errors.New("redirect to the blocked name")
		}
		return nil
	}}
	err := get(t, New(nil, time.Second, g), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "redirect to the blocked name") {
		t.Fatalf("err = %v, want the Redirect guard's error", err)
	}
}

func TestPlainRequestSucceeds(t *testing.T) {
	srv := httptest.NewServer(redirector(""))
	defer srv.Close()
	if err := get(t, New(nil, time.Second, Guard{}), srv.URL); err != nil {
		t.Fatalf("unguarded request failed: %v", err)
	}
}

func TestDialGuardIsApplied(t *testing.T) {
	srv := httptest.NewServer(redirector(""))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	var seen string
	g := Guard{Dial: func(h string) error {
		seen = h
		return errors.New("refused: by the dial guard")
	}}
	err := get(t, New(nil, time.Second, g), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "refused: by the dial guard") {
		t.Fatalf("err = %v, want the Dial guard's error", err)
	}
	if want := strings.Split(host, ":")[0]; seen != want {
		t.Fatalf("Dial saw host %q, want %q (host only, no port)", seen, want)
	}
}

func TestRefuseAddrRefusesTheTargetOnly(t *testing.T) {
	srv := httptest.NewServer(redirector(""))
	defer srv.Close()
	// The server listens on 127.0.0.1: refusing it must fail, refusing another must not.
	err := get(t, New(nil, time.Second, RefuseAddr(netip.MustParseAddr("127.0.0.1"))), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "refused: the lookup would connect to the address under investigation") {
		t.Fatalf("err = %v, want the refusal", err)
	}
	if err := get(t, New(nil, time.Second, RefuseAddr(netip.MustParseAddr("203.0.113.1"))), srv.URL); err != nil {
		t.Fatalf("a different target must not be refused: %v", err)
	}
	if err := get(t, New(nil, time.Second, RefuseAddr(netip.Addr{})), srv.URL); err != nil {
		t.Fatalf("a zero target must refuse nothing: %v", err)
	}
	// An IPv4-mapped form of the target is still the target.
	err = get(t, New(nil, time.Second, RefuseAddr(netip.MustParseAddr("::ffff:127.0.0.1"))), srv.URL)
	if err == nil {
		t.Fatal("a mapped form of the target must be refused")
	}
}
