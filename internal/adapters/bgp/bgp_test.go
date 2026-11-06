package bgp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	prefixesBody = `{"status":"ok","data":{"resource":"64500","prefixes":[{"prefix":"192.0.2.0/24"},{"prefix":"198.51.100.0/24"}]}}`
	overviewBody = `{"status":"ok","data":{"resource":"64500","holder":"EXAMPLE-AS Example Network Operator","announced":true}}`
	ipBody       = `{"status":"ok","data":{"resource":"192.0.2.0/24","announced":true,"asns":[{"asn":64500,"holder":"EXAMPLE-AS"}]}}`
)

var target = netip.MustParseAddr("192.0.2.10")

func serve(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); h(w, r) }))
	t.Cleanup(s.Close)
	return s, &n
}

func newClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 2 * time.Second
	return c
}

func ripe(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/data/announced-prefixes/data.json":
		_, _ = w.Write([]byte(prefixesBody))
	case "/data/as-overview/data.json":
		_, _ = w.Write([]byte(overviewBody))
	case "/data/prefix-overview/data.json":
		_, _ = w.Write([]byte(ipBody))
	default:
		http.NotFound(w, r)
	}
}

func TestLookupASNParsesPrefixesAndHolder(t *testing.T) {
	var paths, resources []string
	s, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		paths, resources = append(paths, r.URL.Path), append(resources, r.URL.Query().Get("resource"))
		ripe(w, r)
	})
	a, err := newClient(t, s.URL).LookupASN(context.Background(), 64500)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Prefixes) != 2 || a.Prefixes[0].String() != "192.0.2.0/24" || a.Holder.ASN != 64500 || !strings.HasPrefix(a.Holder.Holder, "EXAMPLE-AS") || a.Truncated {
		t.Errorf("%+v", a)
	}
	if len(paths) != 2 || resources[0] != "AS64500" {
		t.Errorf("requests %v %v", paths, resources)
	}
	if !strings.Contains(a.Query, "announced-prefixes") || !strings.Contains(a.Query, "as-overview") {
		t.Errorf("query must name every request made: %q", a.Query)
	}
}

func TestLookupIPParsesTheOrigin(t *testing.T) {
	s, _ := serve(t, ripe)
	o, err := newClient(t, s.URL).LookupIP(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if o.Prefix.String() != "192.0.2.0/24" || len(o.Origin) != 1 || o.Origin[0].ASN != 64500 {
		t.Errorf("%+v", o)
	}
}

func TestPrefixCapIsReportedNotSilent(t *testing.T) {
	s, _ := serve(t, ripe)
	c := newClient(t, s.URL)
	c.MaxPrefixes = 1
	a, err := c.LookupASN(context.Background(), 64500)
	if err != nil || len(a.Prefixes) != 1 || !a.Truncated {
		t.Fatalf("%+v %v: a cut list must say so", a, err)
	}
}

func TestNotFoundIsAnAnswer(t *testing.T) {
	s, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/data/prefix-overview/data.json" {
			_, _ = w.Write([]byte(`{"status":"ok","data":{"resource":"192.0.2.0/24","announced":false,"asns":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"resource":"64500","prefixes":[]}}`))
	})
	c := newClient(t, s.URL)
	o, err := c.LookupIP(context.Background(), target)
	if !errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrLookupFailed) || o.Query == "" {
		t.Fatalf("not announced must be ErrNotFound with its query: %v %q", err, o.Query)
	}
	a, err := c.LookupASN(context.Background(), 64500)
	if !errors.Is(err, core.ErrNotFound) || a.Query == "" {
		t.Fatalf("no prefixes must be ErrNotFound: %v", err)
	}
}

func TestFailuresAreNotAnswers(t *testing.T) {
	cases := map[string]struct {
		h    http.HandlerFunc
		want error
	}{
		"429":                         {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, core.ErrRateLimited},
		"404 is not a not-found here": {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, core.ErrLookupFailed},
		"500":                         {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, core.ErrLookupFailed},
		"204":                         {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }, core.ErrLookupFailed},
		"garbage":                     {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, core.ErrLookupFailed},
		"status error": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"error","data":{"prefixes":[]}}`))
		}, core.ErrLookupFailed},
		"no data": {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) }, core.ErrLookupFailed},
		"no prefix list": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"ok","data":{"resource":"64500"}}`))
		}, core.ErrLookupFailed},
		"bad prefix": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"ok","data":{"prefixes":[{"prefix":"not-a-prefix"}]}}`))
		}, core.ErrLookupFailed},
		"error status with an ok-looking body": {func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(502)
			_, _ = w.Write([]byte(prefixesBody))
		}, core.ErrLookupFailed},
		"oversized": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"ok","data":{"prefixes":[],"x":"` + strings.Repeat("a", 5000) + `"}}`))
		}, core.ErrLookupFailed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := serve(t, c.h)
			cl := newClient(t, s.URL)
			cl.MaxBody = 2048
			for _, call := range []func() error{
				func() error { _, err := cl.LookupASN(context.Background(), 64500); return err },
				func() error { _, err := cl.LookupIP(context.Background(), target); return err },
			} {
				err := call()
				if !errors.Is(err, c.want) || errors.Is(err, core.ErrNotFound) {
					t.Fatalf("want %v and never a not-found, got %v", c.want, err)
				}
			}
		})
	}
}

// If the second request of an AS lookup fails, nothing from the first is returned.
func TestASNLookupIsAllOrNothing(t *testing.T) {
	s, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/data/as-overview/data.json" {
			w.WriteHeader(503)
			return
		}
		ripe(w, r)
	})
	a, err := newClient(t, s.URL).LookupASN(context.Background(), 64500)
	if !errors.Is(err, core.ErrLookupFailed) || len(a.Prefixes) != 0 {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestTimeoutIsBoundedAndAFailure(t *testing.T) {
	release := make(chan struct{})
	s, _ := serve(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	c := newClient(t, s.URL)
	c.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := c.LookupASN(context.Background(), 64500); !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("not bounded: %v", time.Since(start))
	}
}

// The address asked about is never connected to. The data service sits at the same
// loopback address as the "target": the dialer must refuse, and the server must see
// nothing.
func TestLookupIPNeverConnectsToTheTarget(t *testing.T) {
	s, hits := serve(t, ripe)
	loop := netip.MustParseAddr("127.0.0.1")
	named := strings.Replace(s.URL, "127.0.0.1", "localhost", 1) // a name that resolves to the target
	for _, base := range []string{named, s.URL} {
		if _, err := newClient(t, base).LookupIP(context.Background(), loop); !errors.Is(err, core.ErrLookupFailed) {
			t.Fatalf("%s: the service at the target must not be asked: %v", base, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("the server at the target address received %d request(s)", hits.Load())
	}
	if _, err := newClient(t, s.URL).LookupIP(context.Background(), target); err != nil {
		t.Fatalf("control lookup failed: %v", err)
	}
}

func TestRedirectToABareAddressIsRefused(t *testing.T) {
	var hit atomic.Int64
	victim := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Add(1) }))
	defer victim.Close()
	toIP, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+r.URL.Path, http.StatusFound)
	})
	if _, err := newClient(t, toIP.URL).LookupASN(context.Background(), 64500); !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("%v", err)
	}
	if hit.Load() != 0 {
		t.Error("the redirect target was contacted")
	}
}

func TestNewValidatesTheBaseURL(t *testing.T) {
	for _, bad := range []string{"", "stat.example.com", "ftp://stat.example.com", "https://u:p@stat.example.com", "https://stat.example.com/?q=1", "https://", "https://stat.example.com#x"} {
		if _, err := New(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
