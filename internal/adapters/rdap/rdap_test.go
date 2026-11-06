package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const goodBody = `{
  "objectClassName": "ip network",
  "handle": "NET-192-0-2-0-1",
  "startAddress": "192.0.2.0",
  "endAddress": "192.0.2.255",
  "ipVersion": "v4",
  "name": "EXAMPLE-NET",
  "type": "ALLOCATION",
  "country": "ZZ",
  "parentHandle": "NET-192-0-0-0-0",
  "entities": [
    {"handle": "ORG-EX1", "roles": ["registrant"],
     "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Network Operator"]]]},
    {"handle": "ABUSE-EX", "roles": ["abuse"]}
  ]
}`

var target = netip.MustParseAddr("192.0.2.10")

func newClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 2 * time.Second
	return c
}

func serve(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); h(w, r) }))
	t.Cleanup(s.Close)
	return s, &n
}

func TestLookupIPParsesTheRecord(t *testing.T) {
	var gotPath, gotAccept, gotAuth string
	s, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAccept, gotAuth = r.URL.Path, r.Header.Get("Accept"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(goodBody))
	})
	n, err := newClient(t, s.URL).LookupIP(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/ip/192.0.2.10" || !strings.Contains(gotAccept, "application/rdap+json") || gotAuth != "" {
		t.Errorf("request: path %q accept %q auth %q", gotPath, gotAccept, gotAuth)
	}
	if n.Query != "GET "+s.URL+"/ip/192.0.2.10" {
		t.Errorf("query %q", n.Query)
	}
	if n.Handle != "NET-192-0-2-0-1" || n.Name != "EXAMPLE-NET" || n.Start != "192.0.2.0" || n.End != "192.0.2.255" || n.Country != "ZZ" {
		t.Errorf("%+v", n)
	}
	if len(n.Entities) != 2 || n.Entities[0].Name != "Example Network Operator" || n.Entities[0].Roles[0] != "registrant" {
		t.Errorf("entities %+v", n.Entities)
	}
}

func TestLookupIPNotFoundIsAnAnswerWithItsQuery(t *testing.T) {
	s, _ := serve(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	n, err := newClient(t, s.URL).LookupIP(context.Background(), target)
	if !errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("404 must be ErrNotFound only: %v", err)
	}
	if n.Query == "" {
		t.Error("query must be set on a not-found answer")
	}
}

func TestLookupIPFailuresAreNotAnswers(t *testing.T) {
	cases := map[string]struct {
		h    http.HandlerFunc
		want error
	}{
		"429":               {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, core.ErrRateLimited},
		"500":               {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, core.ErrLookupFailed},
		"503":               {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, core.ErrLookupFailed},
		"403":               {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }, core.ErrLookupFailed},
		"204 empty success": {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }, core.ErrLookupFailed},
		"garbage":           {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>login</html>")) }, core.ErrLookupFailed},
		"wrong object class": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"objectClassName":"domain","handle":"X"}`))
		}, core.ErrLookupFailed},
		"no handle and no range": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"objectClassName":"ip network"}`))
		}, core.ErrLookupFailed},
		"oversized": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"H","name":"` + strings.Repeat("a", 5000) + `"}`))
		}, core.ErrLookupFailed},
		"error status with a json body that looks fine": {func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(502)
			_, _ = w.Write([]byte(goodBody))
		}, core.ErrLookupFailed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := serve(t, c.h)
			cl := newClient(t, s.URL)
			cl.MaxBody = 2048
			_, err := cl.LookupIP(context.Background(), target)
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
			if errors.Is(err, core.ErrNotFound) {
				t.Fatalf("a failure must never look like a not-found: %v", err)
			}
		})
	}
}

func TestLookupIPTimeoutIsBoundedAndAFailure(t *testing.T) {
	release := make(chan struct{})
	s, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	cl := newClient(t, s.URL)
	cl.Timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := cl.LookupIP(context.Background(), target)
	if !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("not bounded: %v", time.Since(start))
	}
}

func TestLookupIPFollowsARedirectToANamedHostOnly(t *testing.T) {
	final, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(goodBody)) })
	named := strings.Replace(final.URL, "127.0.0.1", "localhost", 1)
	redir, _ := serve(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, named+r.URL.Path, http.StatusFound) })
	n, err := newClient(t, redir.URL).LookupIP(context.Background(), target)
	if err != nil {
		t.Fatalf("redirect to a registry host should work (rdap.org does this): %v", err)
	}
	if n.Handle == "" {
		t.Error("empty record")
	}

	// A redirect to a bare address is refused, whatever address it is.
	var hit atomic.Int64
	victim := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Add(1) }))
	defer victim.Close()
	toIP, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+r.URL.Path, http.StatusFound)
	})
	if _, err := newClient(t, toIP.URL).LookupIP(context.Background(), target); !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("redirect to an address must fail: %v", err)
	}
	if hit.Load() != 0 {
		t.Error("the redirect target was contacted")
	}

	// A redirect loop ends.
	var loop *httptest.Server
	loop, _ = serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(loop.URL, "127.0.0.1", "localhost", 1)+r.URL.Path, http.StatusFound)
	})
	if _, err := newClient(t, loop.URL).LookupIP(context.Background(), target); !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("a redirect loop must fail: %v", err)
	}
}

// The target of the lookup is never connected to. Here the registry sits at the same
// loopback address as the "target", which is the only way to show on one machine that
// the dialer itself refuses the target: the connection is blocked and the server never
// sees a request.
func TestLookupIPNeverConnectsToTheTarget(t *testing.T) {
	s, hits := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(goodBody)) })
	loop := netip.MustParseAddr("127.0.0.1")

	named := strings.Replace(s.URL, "127.0.0.1", "localhost", 1) // a name that resolves to the target
	_, err := newClient(t, named).LookupIP(context.Background(), loop)
	if !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("a registry name that resolves to the target must not be dialled: %v", err)
	}
	_, err = newClient(t, s.URL).LookupIP(context.Background(), loop) // literal
	if !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("a registry URL that is the target must be refused: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the server at the target address received %d request(s)", hits.Load())
	}
	// Control: the same server answers when the target is some other address.
	if _, err := newClient(t, s.URL).LookupIP(context.Background(), target); err != nil {
		t.Fatalf("control lookup failed: %v", err)
	}
}

func TestEveryRequestGoesToTheRegistryHost(t *testing.T) {
	s, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(goodBody)) })
	rec := &recorder{next: http.DefaultTransport}
	cl := newClient(t, s.URL)
	cl.Transport = rec
	if _, err := cl.LookupIP(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(rec.hosts) != 1 || rec.hosts[0] != strings.TrimPrefix(s.URL, "http://") {
		t.Errorf("hosts contacted: %v", rec.hosts)
	}
	for _, h := range rec.hosts {
		if strings.Contains(h, target.String()) {
			t.Errorf("the target is a host in a request: %s", h)
		}
	}
}

type recorder struct {
	next  http.RoundTripper
	hosts []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.hosts = append(r.hosts, req.URL.Host)
	return r.next.RoundTrip(req)
}

func TestNewValidatesTheBaseURL(t *testing.T) {
	for _, bad := range []string{"", "rdap.example.com", "ftp://rdap.example.com", "https://user:pw@rdap.example.com", "https://rdap.example.com/?q=1", "https://", "https://rdap.example.com#x"} {
		if _, err := New(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{"https://rdap.org", "https://rdap.example.com/", "http://127.0.0.1:8080"} {
		if _, err := New(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}

func TestHostileFieldsAreBounded(t *testing.T) {
	body := fmt.Sprintf(`{"objectClassName":"ip network","handle":"H","name":%q,"startAddress":"192.0.2.0","endAddress":"192.0.2.255"}`, strings.Repeat("n", 3000))
	s, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
	n, err := newClient(t, s.URL).LookupIP(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Name) > 255 {
		t.Errorf("name is %d bytes", len(n.Name))
	}
}
