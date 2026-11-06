package sansisc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

type fake struct {
	mu    sync.Mutex
	paths []string
	raw   []string
	heads []http.Header
	h     func(w http.ResponseWriter, ip string)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.raw = append(f.raw, r.URL.RawQuery)
	f.heads = append(f.heads, r.Header.Clone())
	f.mu.Unlock()
	f.h(w, strings.TrimPrefix(r.URL.Path, "/api/ip/"))
}

func newFeed(t *testing.T, h func(w http.ResponseWriter, ip string), mod func(*Feed)) (*Feed, *fake) {
	t.Helper()
	f := &fake{h: h}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	feed := &Feed{BaseURL: srv.URL, MaxLookups: 10, Timeout: 2 * time.Second, MaxBody: 4096,
		Now:   func() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	if mod != nil {
		mod(feed)
	}
	return feed, f
}

func body(s string) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, _ string) { fmt.Fprint(w, s) }
}

const reported = `{"ip":{"number":"192.0.2.1","count":12,"attacks":3,"maxdate":"2026-11-03","mindate":"2026-10-01","updated":"2026-11-04 01:02:03","comment":null,"as":64496,"asname":"EXAMPLE-AS","ascountry":"ZZ","network":"192.0.2.0/24","threatfeeds":{"blocklistde":{"lastseen":"2026-11-03","firstseen":"2026-10-01"}}}}`
const unreported = `{"ip":{"number":"192.0.2.2","count":null,"attacks":null,"maxdate":null,"mindate":null,"updated":null,"comment":null}}`

func TestReportedUnreportedAndFailureAreThreeDifferentAnswers(t *testing.T) {
	feed, _ := newFeed(t, func(w http.ResponseWriter, ip string) {
		switch ip {
		case "192.0.2.1":
			fmt.Fprint(w, reported)
		case "192.0.2.2":
			fmt.Fprint(w, unreported)
		case "192.0.2.4":
			w.WriteHeader(404)
		default:
			w.WriteHeader(500)
		}
	}, nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"})
	if len(rs) != 3 {
		t.Fatalf("want 3 answers, got %+v", rs)
	}
	if rs[0].Verdict != "count=12;attacks=3;mindate=2026-10-01;maxdate=2026-11-03;feeds=blocklistde" {
		t.Fatalf("verdict %q", rs[0].Verdict)
	}
	if rs[1].Verdict != core.VerdictNotFound || rs[2].Verdict != core.VerdictNotFound || rs[2].Indicator != "192.0.2.4" {
		t.Fatalf("no reports / 404 must be not_found: %+v", rs)
	}
	if rs[0].Source != "sans-isc" || !rs[0].Observed.Equal(time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("source/time: %+v", rs[0])
	}
	les := core.LookupErrors(err)
	if len(les) != 1 || les[0].Indicator != "192.0.2.3" || !errors.Is(les[0], core.ErrFeedFailed) {
		t.Fatalf("500 must be a lookup error: %v", err)
	}
}

func TestStringNumbersAreAccepted(t *testing.T) {
	feed, _ := newFeed(t, body(`{"ip":{"number":"192.0.2.1","count":"12","attacks":"3","maxdate":"2026-11-03","mindate":"2026-10-01"}}`), nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if err != nil || len(rs) != 1 || !strings.HasPrefix(rs[0].Verdict, "count=12;attacks=3;") {
		t.Fatalf("%v %v", rs, err)
	}
}

func TestNon200IsNeverAnAnswer(t *testing.T) {
	for _, code := range []int{201, 203, 400, 401, 403, 500, 502, 503} {
		feed, _ := newFeed(t, func(w http.ResponseWriter, _ string) { w.WriteHeader(code); fmt.Fprint(w, reported) }, nil)
		rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
		if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
			t.Fatalf("status %d: rs=%v err=%v", code, rs, err)
		}
	}
}

func TestRateLimitStopsTheRunAndMarksTheRestUnasked(t *testing.T) {
	feed, f := newFeed(t, func(w http.ResponseWriter, _ string) { w.WriteHeader(429) }, nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	les := core.LookupErrors(err)
	if len(rs) != 0 || len(les) != 3 || !errors.Is(les[0], core.ErrRateLimited) || !errors.Is(les[2], core.ErrRateLimited) {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
	if len(f.paths) != 1 {
		t.Fatalf("after a 429 the feed must not be asked again, got %d requests", len(f.paths))
	}
}

func TestMalformedBodyIsAFailureNotNotFound(t *testing.T) {
	for _, b := range []string{"", "<html>", `{"ip":`, `[]`, `{}`, `{"ip":null}`, `{"ip":{}}`,
		`{"ip":{"number":"198.51.100.9","count":3,"attacks":1}}`, // answers for a different address
		`{"ip":{"number":"192.0.2.1","count":{"x":1},"attacks":1}}`} {
		feed, _ := newFeed(t, body(b), nil)
		rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
		if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
			t.Fatalf("body %q: rs=%v err=%v", b, rs, err)
		}
	}
}

func TestTimeoutIsAFailure(t *testing.T) {
	feed, _ := newFeed(t, func(http.ResponseWriter, string) { time.Sleep(300 * time.Millisecond) },
		func(f *Feed) { f.Timeout = 50 * time.Millisecond })
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}

func TestResponseSizeIsCapped(t *testing.T) {
	feed, _ := newFeed(t, body(`{"ip":{"number":"192.0.2.1","count":1,"attacks":1,"comment":"`+strings.Repeat("x", 10000)+`"}}`),
		func(f *Feed) { f.MaxBody = 512 })
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("oversized must fail, not truncate into an answer: rs=%v err=%v", rs, err)
	}
}

func TestLookupBudgetIsEnforcedAndReported(t *testing.T) {
	feed, f := newFeed(t, func(w http.ResponseWriter, ip string) {
		fmt.Fprintf(w, `{"ip":{"number":%q,"count":1,"attacks":1}}`, ip)
	}, func(f *Feed) { f.MaxLookups = 2 })
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"})
	les := core.LookupErrors(err)
	if len(rs) != 2 || len(f.paths) != 2 || len(les) != 2 || !errors.Is(les[0], core.ErrBudgetExceeded) {
		t.Fatalf("rs=%d requests=%d err=%v", len(rs), len(f.paths), err)
	}
}

func TestRequestsAreSpacedAndOnlyGoToTheFeedAPI(t *testing.T) {
	var slept []time.Duration
	feed, f := newFeed(t, func(w http.ResponseWriter, ip string) {
		fmt.Fprintf(w, `{"ip":{"number":%q,"count":null,"attacks":null}}`, ip)
	}, func(f *Feed) {
		f.MinInterval = 750 * time.Millisecond
		f.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	})
	ips := []string{"192.0.2.1", "198.51.100.7", "2001:db8::9"}
	if _, err := feed.Lookup(context.Background(), ips); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 2 || slept[0] != 750*time.Millisecond {
		t.Fatalf("want a pause between requests only, got %v", slept)
	}
	for i, p := range f.paths {
		if p != "/api/ip/"+ips[i] || f.raw[i] != "json" {
			t.Fatalf("unexpected request %q?%q", p, f.raw[i])
		}
	}
	for _, h := range f.heads {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" || h.Get("Key") != "" {
			t.Fatalf("a keyless feed must send no credential header: %v", h)
		}
	}
}

func TestBadIndicatorsNeverReachTheWire(t *testing.T) {
	feed, f := newFeed(t, body(`{}`), nil)
	rs, err := feed.Lookup(context.Background(), []string{"../../etc/passwd", "example.com", "192.0.2.1/../x", "", "198.51.100.1?x=y", "fe80::1%eth0"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 6 || len(f.paths) != 0 {
		t.Fatalf("rs=%v err=%v requests=%v", rs, err, f.paths)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect target was contacted")
	}))
	defer other.Close()
	feed, _ := newFeed(t, func(w http.ResponseWriter, _ string) {
		w.Header().Set("Location", other.URL+"/x")
		w.WriteHeader(302)
	}, nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}

func TestOddValuesFromTheFeedAreSanitisedAndAHostileBodyIsNotQuoted(t *testing.T) {
	feed, _ := newFeed(t, body(`{"ip":{"number":"192.0.2.1","count":1,"attacks":1,"mindate":"a;b\nc=d","maxdate":"`+strings.Repeat("9", 200)+`","threatfeeds":{"x y;z":{}}}}`), nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	v := rs[0].Verdict
	if strings.ContainsAny(v, "\n ") || strings.Count(v, ";") != 4 || len(v) > 250 {
		t.Fatalf("verdict not sanitised: %q", v)
	}
	feed, _ = newFeed(t, func(w http.ResponseWriter, _ string) { w.WriteHeader(500); fmt.Fprint(w, "SENTINEL-BODY-TEXT") }, nil)
	_, err = feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if err == nil || strings.Contains(err.Error(), "SENTINEL-BODY-TEXT") {
		t.Fatalf("a non-200 body must not be quoted: %v", err)
	}
}

func TestCanceledContextIsAFailureForTheRest(t *testing.T) {
	feed, _ := newFeed(t, body(unreported), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rs, err := feed.Lookup(ctx, []string{"192.0.2.1", "192.0.2.2"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 2 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}
