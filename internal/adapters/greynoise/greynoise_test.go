package greynoise

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

const sentinel = "SENTINEL-KEY-0123456789abcdef"

type fake struct {
	mu    sync.Mutex
	paths []string
	keys  []string
	h     func(w http.ResponseWriter, ip string)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.keys = append(f.keys, r.Header.Get("key"))
	f.mu.Unlock()
	f.h(w, strings.TrimPrefix(r.URL.Path, "/v3/community/"))
}

func newFeed(t *testing.T, h func(w http.ResponseWriter, ip string), mod func(*Feed)) (*Feed, *fake) {
	t.Helper()
	f := &fake{h: h}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	feed := &Feed{BaseURL: srv.URL, Key: sentinel, MaxLookups: 10,
		Timeout: 2 * time.Second, MaxBody: 4096,
		Now:   func() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	if mod != nil {
		mod(feed)
	}
	return feed, f
}

func ok(body string) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, _ string) { fmt.Fprint(w, body) }
}

func TestLookupAnswersAndNotFoundAreDistinctFromFailure(t *testing.T) {
	feed, _ := newFeed(t, func(w http.ResponseWriter, ip string) {
		switch ip {
		case "192.0.2.1":
			fmt.Fprint(w, `{"ip":"192.0.2.1","noise":true,"riot":false,"classification":"malicious","last_seen":"2026-11-03"}`)
		case "192.0.2.2":
			w.WriteHeader(404)
			fmt.Fprint(w, `{"ip":"192.0.2.2","message":"IP not observed scanning the internet or contained in RIOT data set."}`)
		default:
			w.WriteHeader(500)
		}
	}, nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	if len(rs) != 2 {
		t.Fatalf("want 2 answers, got %+v", rs)
	}
	if rs[0].Verdict != "classification=malicious;noise=true;riot=false;last_seen=2026-11-03" {
		t.Fatalf("verdict %q", rs[0].Verdict)
	}
	if rs[1].Verdict != core.VerdictNotFound || rs[1].Indicator != "192.0.2.2" {
		t.Fatalf("404 must be a not_found answer: %+v", rs[1])
	}
	if rs[0].Source != "greynoise:community" || !rs[0].Observed.Equal(time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("source/time: %+v", rs[0])
	}
	les := core.LookupErrors(err)
	if len(les) != 1 || les[0].Indicator != "192.0.2.3" || !errors.Is(les[0], core.ErrFeedFailed) {
		t.Fatalf("500 must be a lookup error for that indicator: %v", err)
	}
}

func TestNon200IsNeverAnAnswer(t *testing.T) {
	for _, code := range []int{400, 401, 403, 500, 502, 503} {
		feed, _ := newFeed(t, func(w http.ResponseWriter, _ string) { w.WriteHeader(code) }, nil)
		rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
		if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
			t.Fatalf("status %d: rs=%v err=%v", code, rs, err)
		}
	}
}

func TestRateLimitStopsTheRunAndMarksTheRestUnasked(t *testing.T) {
	feed, f := newFeed(t, func(w http.ResponseWriter, _ string) { w.WriteHeader(429) }, nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	if len(rs) != 0 {
		t.Fatalf("429 must not produce an answer: %v", rs)
	}
	les := core.LookupErrors(err)
	if len(les) != 3 {
		t.Fatalf("every indicator must be reported: %v", err)
	}
	if !errors.Is(les[0], core.ErrRateLimited) || !errors.Is(les[2], core.ErrRateLimited) {
		t.Fatalf("want rate limited: %v", err)
	}
	if len(f.paths) != 1 {
		t.Fatalf("after a 429 the feed must not be asked again, got %d requests", len(f.paths))
	}
}

func TestMalformedBodyIsAFailureNotUnknown(t *testing.T) {
	for _, body := range []string{"", "<html>", `{"noise":`, `[]`} {
		feed, _ := newFeed(t, ok(body), nil)
		rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
		if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
			t.Fatalf("body %q: rs=%v err=%v", body, rs, err)
		}
	}
}

func TestTimeoutIsAFailure(t *testing.T) {
	feed, _ := newFeed(t, func(w http.ResponseWriter, _ string) { time.Sleep(300 * time.Millisecond) },
		func(f *Feed) { f.Timeout = 50 * time.Millisecond })
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}

func TestResponseSizeIsCapped(t *testing.T) {
	feed, _ := newFeed(t, ok(`{"noise":true,"classification":"malicious","pad":"`+strings.Repeat("x", 10000)+`"}`),
		func(f *Feed) { f.MaxBody = 512 })
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("an oversized body must fail, not be truncated into an answer: rs=%v err=%v", rs, err)
	}
}

func TestLookupBudgetIsEnforcedAndReported(t *testing.T) {
	feed, f := newFeed(t, ok(`{"noise":false,"classification":"unknown"}`), func(f *Feed) { f.MaxLookups = 2 })
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"})
	if len(rs) != 2 || len(f.paths) != 2 {
		t.Fatalf("answers %d, requests %d", len(rs), len(f.paths))
	}
	les := core.LookupErrors(err)
	if len(les) != 2 || !errors.Is(les[0], core.ErrBudgetExceeded) || les[0].Indicator != "192.0.2.3" {
		t.Fatalf("the unasked indicators must be reported: %v", err)
	}
}

func TestRequestsAreSpacedAndOnlyGoToTheFeedAPI(t *testing.T) {
	var slept []time.Duration
	feed, f := newFeed(t, ok(`{"noise":false,"classification":"unknown"}`), func(f *Feed) {
		f.MinInterval = 750 * time.Millisecond
		f.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	})
	if _, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "198.51.100.7", "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 2 || slept[0] != 750*time.Millisecond {
		t.Fatalf("want a pause between requests only, got %v", slept)
	}
	for i, p := range f.paths {
		if p != "/v3/community/"+[]string{"192.0.2.1", "198.51.100.7", "203.0.113.9"}[i] {
			t.Fatalf("unexpected request path %q", p)
		}
	}
}

func TestBadIndicatorsNeverReachTheWire(t *testing.T) {
	feed, f := newFeed(t, ok(`{}`), nil)
	rs, err := feed.Lookup(context.Background(), []string{"../../etc/passwd", "example.com", "192.0.2.1/../x", "", "198.51.100.1?x=y"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 5 || len(f.paths) != 0 {
		t.Fatalf("rs=%v err=%v requests=%v", rs, err, f.paths)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect target was contacted (key=%q)", r.Header.Get("key"))
	}))
	defer other.Close()
	feed, _ := newFeed(t, func(w http.ResponseWriter, _ string) {
		w.Header().Set("Location", other.URL+"/steal")
		w.WriteHeader(302)
	}, nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}

func TestKeyIsSentInHeaderAndNeverLeaks(t *testing.T) {
	// A hostile or buggy feed reflects the key in a body field, an error body and a
	// header. Nothing may carry it out of this package.
	feed, f := newFeed(t, func(w http.ResponseWriter, ip string) {
		switch ip {
		case "192.0.2.1":
			fmt.Fprintf(w, `{"noise":true,"classification":"%s","last_seen":"%s"}`, sentinel, sentinel)
		case "192.0.2.2":
			w.WriteHeader(500)
			fmt.Fprint(w, "internal error for key "+sentinel)
		default:
			w.Header().Set("X-Echo", sentinel)
			fmt.Fprint(w, "not json "+sentinel)
		}
	}, nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	var all strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&all, "%+v|", r)
	}
	fmt.Fprint(&all, err, "|", feed.String(), "|", fmt.Sprintf("%v %+v %#v", feed, feed, feed))
	if strings.Contains(all.String(), sentinel) {
		t.Fatalf("key leaked: %s", all.String())
	}
	for _, k := range f.keys {
		if k != sentinel {
			t.Fatalf("key header = %q, want the configured key", k)
		}
	}
}

func TestKeylessSendsNoKeyHeader(t *testing.T) {
	feed, f := newFeed(t, ok(`{"noise":false,"classification":"unknown"}`), func(f *Feed) { f.Key = "" })
	if _, err := feed.Lookup(context.Background(), []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if f.keys[0] != "" {
		t.Fatalf("key header %q", f.keys[0])
	}
}

func TestCanceledContextIsAFailureForTheRest(t *testing.T) {
	feed, _ := newFeed(t, ok(`{"noise":false,"classification":"unknown"}`), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rs, err := feed.Lookup(ctx, []string{"192.0.2.1", "192.0.2.2"})
	if len(rs) != 0 || len(core.LookupErrors(err)) != 2 {
		t.Fatalf("rs=%v err=%v", rs, err)
	}
}

func TestOddValuesFromTheFeedAreSanitised(t *testing.T) {
	feed, _ := newFeed(t, ok(`{"noise":true,"classification":"mal;icious\nx=y","last_seen":"`+strings.Repeat("9", 200)+`"}`), nil)
	rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
	if err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	v := rs[0].Verdict
	if strings.ContainsAny(v, "\n") || strings.Count(v, ";") != 3 || len(v) > 200 {
		t.Fatalf("verdict not sanitised: %q", v)
	}
}

func TestNon200WithAnAnswerShapedBodyIsStillAFailure(t *testing.T) {
	for _, code := range []int{201, 203, 400, 401, 403, 418, 503} {
		feed, _ := newFeed(t, func(w http.ResponseWriter, _ string) {
			w.WriteHeader(code)
			fmt.Fprint(w, `{"noise":false,"classification":"benign","message":"quota"}`)
		}, nil)
		rs, err := feed.Lookup(context.Background(), []string{"192.0.2.1"})
		if len(rs) != 0 || len(core.LookupErrors(err)) != 1 {
			t.Fatalf("status %d produced an answer: rs=%v err=%v", code, rs, err)
		}
	}
}
