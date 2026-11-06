package crtsh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const goodBody = `[
 {"common_name":"www.example.com","name_value":"www.example.com\nmail.example.com"},
 {"common_name":"*.example.com","name_value":"*.example.com\nexample.com"},
 {"common_name":"api.example.com","name_value":"api.example.com\nother.example.net\nWWW.example.com"},
 {"common_name":"api.example.com","name_value":"api.example.com"}
]`

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

func TestLookupSubdomainsKeepsOnlyCandidatesInsideTheDomain(t *testing.T) {
	var q, out string
	s, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		q, out = r.URL.Query().Get("q"), r.URL.Query().Get("output")
		_, _ = w.Write([]byte(goodBody))
	})
	a, err := newClient(t, s.URL).LookupSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if q != "%.example.com" || out != "json" {
		t.Errorf("request q=%q output=%q", q, out)
	}
	if got := strings.Join(a.Names, ","); got != "api.example.com,mail.example.com,www.example.com" {
		t.Errorf("names %q: distinct, sorted, lower case, no wildcard, no apex, nothing outside the domain", got)
	}
	if a.Wildcards != 1 || a.OutOfScope != 1 || a.Truncated {
		t.Errorf("wildcards %d out of scope %d truncated %v", a.Wildcards, a.OutOfScope, a.Truncated)
	}
	if !strings.HasPrefix(a.Query, "GET "+s.URL) {
		t.Errorf("query %q", a.Query)
	}
}

func TestNameCapIsReportedNotSilent(t *testing.T) {
	s, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(goodBody)) })
	c := newClient(t, s.URL)
	c.MaxNames = 2
	a, err := c.LookupSubdomains(context.Background(), "example.com")
	if err != nil || len(a.Names) != 2 || !a.Truncated {
		t.Fatalf("%+v %v: more names than the cap must say so", a, err)
	}
}

func TestEmptyListIsNotFoundAndFailuresAreNot(t *testing.T) {
	s, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	a, err := newClient(t, s.URL).LookupSubdomains(context.Background(), "example.com")
	if !errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrLookupFailed) || a.Query == "" {
		t.Fatalf("[] must be ErrNotFound with its query: %v", err)
	}
	cases := map[string]struct {
		h    http.HandlerFunc
		want error
	}{
		"429":              {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, core.ErrRateLimited},
		"404":              {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, core.ErrLookupFailed},
		"500":              {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, core.ErrLookupFailed},
		"502 body":         {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(502); _, _ = w.Write([]byte(goodBody)) }, core.ErrLookupFailed},
		"204":              {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }, core.ErrLookupFailed},
		"html page":        {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>busy</html>")) }, core.ErrLookupFailed},
		"object not array": {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"error":"x"}`)) }, core.ErrLookupFailed},
		"oversized": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"name_value":"` + strings.Repeat("a", 5000) + `"}]`))
		}, core.ErrLookupFailed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := serve(t, c.h)
			cl := newClient(t, s.URL)
			cl.MaxBody = 2048
			_, err := cl.LookupSubdomains(context.Background(), "example.com")
			if !errors.Is(err, c.want) || errors.Is(err, core.ErrNotFound) {
				t.Fatalf("want %v and never a not-found, got %v", c.want, err)
			}
		})
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
	if _, err := c.LookupSubdomains(context.Background(), "example.com"); !errors.Is(err, core.ErrLookupFailed) || errors.Is(err, core.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("not bounded: %v", time.Since(start))
	}
}

// The domain under investigation is never connected to. Here the search service is
// reached through a name inside the "target" domain (localhost), the only way on one
// machine to show that the dialer itself refuses it: the server never sees a request.
func TestNeverConnectsToTheTargetDomain(t *testing.T) {
	s, hits := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(goodBody)) })
	named := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
	_, err := newClient(t, named).LookupSubdomains(context.Background(), "localhost")
	if !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("a search URL inside the target domain must be refused: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the server inside the target domain received %d request(s)", hits.Load())
	}
	// A redirect into the target domain is refused at the redirect and at the dialer.
	redir, _ := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(s.URL, "127.0.0.1", "localhost", 1)+"/", http.StatusFound)
	})
	if _, err := newClient(t, redir.URL).LookupSubdomains(context.Background(), "localhost"); !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("redirect into the target domain: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the redirect target received %d request(s)", hits.Load())
	}
	// Control: the same server answers for some other domain.
	if _, err := newClient(t, s.URL).LookupSubdomains(context.Background(), "example.com"); err != nil {
		t.Fatalf("control lookup failed: %v", err)
	}
}

func TestRedirectToABareAddressIsRefused(t *testing.T) {
	var hit atomic.Int64
	victim := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Add(1) }))
	defer victim.Close()
	toIP, _ := serve(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, victim.URL, http.StatusFound) })
	if _, err := newClient(t, toIP.URL).LookupSubdomains(context.Background(), "example.com"); !errors.Is(err, core.ErrLookupFailed) {
		t.Fatalf("%v", err)
	}
	if hit.Load() != 0 {
		t.Error("the redirect target was contacted")
	}
}

func TestHostileNamesAreDropped(t *testing.T) {
	body := fmt.Sprintf(`[{"name_value":"ok.example.com\nbad name.example.com\n%s.example.com\nx.example.com.evil.net"}]`, strings.Repeat("a", 300))
	s, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
	a, err := newClient(t, s.URL).LookupSubdomains(context.Background(), "example.com")
	if err != nil || len(a.Names) != 1 || a.Names[0] != "ok.example.com" {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestNewValidatesTheBaseURL(t *testing.T) {
	for _, bad := range []string{"", "crt.example.com", "ftp://crt.example.com", "https://u:p@crt.example.com", "https://crt.example.com/?q=1", "https://"} {
		if _, err := New(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The three guards (URL check, redirect check, dialer) overlap on purpose. Each is
// exercised alone here, so removing one cannot hide behind another.
func TestEachGuardRefusesTheTargetDomainOnItsOwn(t *testing.T) {
	s, hits := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(goodBody)) })
	named := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
	hc := newClient(t, s.URL).httpClient("localhost", time.Second)

	if resp, err := hc.Get(named); err == nil {
		resp.Body.Close()
		t.Error("the dialer let a connection into the target domain through")
	}
	if hits.Load() != 0 {
		t.Fatalf("the dialer let %d request(s) reach the target", hits.Load())
	}
	req, _ := http.NewRequest(http.MethodGet, named, nil)
	first, _ := http.NewRequest(http.MethodGet, "http://ct.example.com/", nil)
	if err := hc.CheckRedirect(req, []*http.Request{first}); err == nil {
		t.Error("the redirect check let a redirect into the target domain through")
	}
	// The URL check, with no dialer in the way: a transport that must never be used.
	var sent atomic.Int64
	c := newClient(t, named)
	c.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { sent.Add(1); return nil, errors.New("must not be sent") })
	if _, err := c.LookupSubdomains(context.Background(), "localhost"); !errors.Is(err, core.ErrLookupFailed) || sent.Load() != 0 {
		t.Errorf("the URL check let a request into the target domain through: %v, %d sent", err, sent.Load())
	}
	other, _ := http.NewRequest(http.MethodGet, "http://other.example.net/", nil)
	if err := hc.CheckRedirect(other, []*http.Request{first}); err != nil {
		t.Errorf("a redirect elsewhere must pass: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
