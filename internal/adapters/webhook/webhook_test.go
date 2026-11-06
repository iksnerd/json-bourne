package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// token is the secret part of every test URL. Nothing this package returns may hold it.
const token = "T0K3N-sentinel-9f8e7d6c5b4a"

// bidi is a right-to-left override: it can reorder what a reader sees.
var bidi = string(rune(0x202e))

const tokenPath = "/services/" + token

// fake is a webhook receiver. By default it replies 200 "ok". It records requests.
type fake struct {
	srv  *httptest.Server
	mu   sync.Mutex
	got  []string // request bodies
	uris []string
	h    http.HandlerFunc // overrides the default reply
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got = append(f.got, string(b))
		f.uris = append(f.uris, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Content-Type"))
		h := f.h
		f.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) url() Secret { return Secret(f.srv.URL + tokenPath) }
func (f *fake) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}
func (f *fake) texts(t *testing.T) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, b := range f.got {
		var m map[string]string
		if err := json.Unmarshal([]byte(b), &m); err != nil || len(m) != 1 {
			t.Fatalf("body %q is not a one-key JSON object: %v", b, err)
		}
		out = append(out, m["text"])
	}
	return out
}

func newSink(t *testing.T, cfg Config) *Sink {
	t.Helper()
	cfg.AllowInsecureLoopback = true
	if cfg.MinInterval == 0 {
		cfg.MinInterval = -1
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func finding(tag, sev, text, run string) core.Alert {
	return core.Alert{Kind: core.AlertFinding, Tag: tag, Severity: sev, Detector: "authspike", Text: text, Run: run, At: "2026-11-05T12:00:00Z"}
}

func noToken(t *testing.T, what string, v any) {
	t.Helper()
	s := fmt.Sprintf("%v|%+v|%#v|%s", v, v, v, v)
	if strings.Contains(s, token) || strings.Contains(s, "services") {
		t.Errorf("%s leaks the webhook URL: %s", what, s)
	}
}

func TestDeliverPostsOneSmallJSONBody(t *testing.T) {
	f := newFake(t)
	s := newSink(t, Config{URL: f.url()})
	if err := s.Deliver(context.Background(), finding("spray:192.0.2.7", "high", "192.0.2.7 failed 80%", "watch-1")); err != nil {
		t.Fatal(err)
	}
	if got := f.uris; len(got) != 1 || got[0] != "POST "+tokenPath+" application/json" {
		t.Fatalf("request = %q", got)
	}
	want := "[high] spray:192.0.2.7: 192.0.2.7 failed 80% (run watch-1)"
	if got := f.texts(t); len(got) != 1 || got[0] != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}

func TestBelowMinSeverityIsNotSentAndNotAnError(t *testing.T) {
	f := newFake(t)
	s := newSink(t, Config{URL: f.url(), MinSeverity: core.SevHigh})
	for _, sev := range []string{"info", "check", "activity"} {
		if err := s.Deliver(context.Background(), finding("t", sev, "x", "r")); err != nil {
			t.Fatal(err)
		}
	}
	if f.n() != 0 {
		t.Errorf("%d requests for alerts below the threshold", f.n())
	}
	for _, sev := range []string{"high", "critical"} {
		if err := s.Deliver(context.Background(), finding("t", sev, "x", "r")); err != nil {
			t.Fatal(err)
		}
	}
	if f.n() != 2 {
		t.Errorf("%d requests, want 2", f.n())
	}
}

// The URL is a secret. A fake that reflects the path and the URL in its body, and a
// transport failure whose *url.Error would quote the URL, must neither reach an error.
func TestURLNeverAppearsInAnyError(t *testing.T) {
	cases := map[string]func(f *fake){
		"500 echoing the path": func(f *fake) {
			f.h = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprintf(w, "bad request to %s %s host %s", r.URL.Path, r.URL.String(), r.Host)
			}
		},
		"200 echoing the path": func(f *fake) {
			f.h = func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.URL.Path+strings.Repeat("x", 100)) }
		},
		"redirect to the path elsewhere": func(f *fake) {
			f.h = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://198.51.100.9"+r.URL.Path)
				w.WriteHeader(302)
			}
		},
		"connection dropped": func(f *fake) {
			f.h = func(w http.ResponseWriter, r *http.Request) {
				c, _, _ := w.(http.Hijacker).Hijack()
				c.Close()
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			setup(f)
			s := newSink(t, Config{URL: f.url(), MaxResponse: 16})
			err := s.Deliver(context.Background(), finding("t", "high", "x", "r"))
			if err == nil {
				t.Fatal("a failed delivery returned nil")
			}
			noToken(t, "error", err.Error())
			noToken(t, "sink", s)
		})
	}
	t.Run("connection refused", func(t *testing.T) {
		f := newFake(t)
		u := f.url()
		f.srv.Close()
		s := newSink(t, Config{URL: u})
		err := s.Deliver(context.Background(), finding("t", "high", "x", "r"))
		if err == nil {
			t.Fatal("refused connection reported as delivered")
		}
		noToken(t, "error", err.Error())
		// What the standard library would have said, to prove the test can see the leak.
		_, raw := http.Post(string(u), "application/json", nil)
		if raw == nil || !strings.Contains(raw.Error(), token) {
			t.Fatalf("control failed: the net/http error does not hold the URL: %v", raw)
		}
	})
}

func TestSecretNeverFormats(t *testing.T) {
	u := Secret("https://hooks.example.test" + tokenPath)
	noToken(t, "Secret", u)
	noToken(t, "Config", Config{URL: u})
	noToken(t, "*Config", &Config{URL: u})
	b, _ := json.Marshal(Config{URL: u})
	noToken(t, "json", string(b))
	s, err := New(Config{URL: u})
	if err != nil {
		t.Fatal(err)
	}
	noToken(t, "Sink", s)
}

func TestInvalidURLErrorsDoNotQuoteIt(t *testing.T) {
	for _, raw := range []string{
		"http://hooks.example.test" + tokenPath,         // http, not loopback
		"http://127.0.0.1:1" + tokenPath,                // http loopback without the flag
		"ftp://hooks.example.test" + tokenPath,          // scheme
		"https://user:" + token + "@hooks.example.test", // user info
		"https://hooks.example.test/" + token + "#" + token,
		"https://%zz" + token,
		"/" + token,
		token,
	} {
		_, err := New(Config{URL: Secret(raw)})
		if err == nil {
			t.Errorf("accepted %q", raw[:10])
			continue
		}
		noToken(t, "error", err.Error())
	}
	if _, err := New(Config{URL: Secret("https://hooks.example.test" + tokenPath)}); err != nil {
		t.Errorf("https refused: %v", err)
	}
	if _, err := New(Config{URL: Secret("http://127.0.0.1:1" + tokenPath), AllowInsecureLoopback: true}); err != nil {
		t.Errorf("flagged loopback http refused: %v", err)
	}
	if _, err := New(Config{URL: Secret("http://198.51.100.7" + tokenPath), AllowInsecureLoopback: true}); err == nil {
		t.Error("the loopback flag let plain http reach a non-loopback host")
	}
}

func TestHTTPSWorks(t *testing.T) {
	f := &fake{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.got = append(f.got, r.URL.Path)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	s, err := New(Config{URL: Secret(srv.URL + tokenPath), MinInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	s.transport = srv.Client().Transport
	if err := s.Deliver(context.Background(), finding("t", "high", "x", "r")); err != nil || len(f.got) != 1 {
		t.Fatalf("err=%v got=%v", err, f.got)
	}
}

// A redirect carries the token path to another host. It is neither followed nor ok.
func TestRedirectIsNotFollowed(t *testing.T) {
	other := newFake(t)
	f := newFake(t)
	for _, code := range []int{301, 302, 303, 307, 308} {
		f.h = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.srv.URL+r.URL.Path, code)
		}
		s := newSink(t, Config{URL: f.url()})
		err := s.Deliver(context.Background(), finding("t", "high", "x", "r"))
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(code)) {
			t.Errorf("HTTP %d: err = %v", code, err)
		}
	}
	if other.n() != 0 {
		t.Errorf("a redirect target received %d request(s): %v", other.n(), other.uris)
	}
}

func TestNon2xxTimeoutAndOversizedResponseAreErrors(t *testing.T) {
	for _, code := range []int{400, 401, 404, 429, 500, 503} {
		f := newFake(t)
		f.h = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
		err := newSink(t, Config{URL: f.url()}).Deliver(context.Background(), finding("t", "high", "x", "r"))
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(code)) {
			t.Errorf("HTTP %d: err = %v", code, err)
		}
	}
	t.Run("oversized", func(t *testing.T) {
		f := newFake(t)
		f.h = func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, strings.Repeat("x", 5000)) }
		err := newSink(t, Config{URL: f.url(), MaxResponse: 1024}).Deliver(context.Background(), finding("t", "high", "x", "r"))
		if err == nil || !strings.Contains(err.Error(), "larger than 1024") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("exactly at the cap is fine", func(t *testing.T) {
		f := newFake(t)
		f.h = func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, strings.Repeat("x", 1024)) }
		if err := newSink(t, Config{URL: f.url(), MaxResponse: 1024}).Deliver(context.Background(), finding("t", "high", "x", "r")); err != nil {
			t.Error(err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := newFake(t)
		release := make(chan struct{})
		f.h = func(http.ResponseWriter, *http.Request) { <-release }
		defer close(release)
		start := time.Now()
		err := newSink(t, Config{URL: f.url(), Timeout: 100 * time.Millisecond}).Deliver(context.Background(), finding("t", "high", "x", "r"))
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Errorf("err = %v", err)
		}
		if time.Since(start) > 3*time.Second {
			t.Error("the timeout did not bound the request")
		}
		noToken(t, "error", err)
	})
}

func TestCapSendsASummaryAndSaysHowMany(t *testing.T) {
	f := newFake(t)
	s := newSink(t, Config{URL: f.url(), MaxPerCycle: 3, MinSeverity: core.SevHigh})
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		if err := s.Deliver(ctx, finding(fmt.Sprintf("t%d", i), "high", "storm", "watch-1")); err != nil {
			t.Fatal(err)
		}
	}
	if f.n() != 3 {
		t.Fatalf("%d requests before the cycle ended, want the cap of 3", f.n())
	}
	hb := core.Alert{Kind: core.AlertCycle, Severity: "info", Tag: "watch-cycle", Run: "watch-1", Text: "CYCLE FINDINGS"}
	if err := s.Deliver(ctx, hb); err != nil { // the heartbeat is below min severity, but it ends the cycle
		t.Fatal(err)
	}
	got := f.texts(t)
	if len(got) != 4 || got[3] != "5 further alerts not sent to webhook, see watch.log (run watch-1)" {
		t.Fatalf("texts = %q", got)
	}
	// A new cycle starts from zero and does not repeat the summary.
	if err := s.Deliver(ctx, finding("n", "high", "again", "watch-2")); err != nil || f.n() != 5 {
		t.Fatalf("err=%v requests=%d", err, f.n())
	}
	if err := s.Deliver(ctx, core.Alert{Kind: core.AlertCycle, Severity: "info", Run: "watch-2"}); err != nil || f.n() != 5 {
		t.Fatalf("err=%v requests=%d", err, f.n())
	}
}

// A cycle that never reaches its heartbeat still says what it held back.
func TestSummaryIsSentWhenTheRunChanges(t *testing.T) {
	f := newFake(t)
	s := newSink(t, Config{URL: f.url(), MaxPerCycle: 1})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		s.Deliver(ctx, finding("t", "high", "x", "watch-1"))
	}
	if err := s.Deliver(ctx, finding("t", "high", "x", "watch-2")); err != nil {
		t.Fatal(err)
	}
	got := f.texts(t)
	if len(got) != 3 || !strings.HasPrefix(got[1], "2 further alerts not sent to webhook, see watch.log") {
		t.Fatalf("texts = %q", got)
	}
}

func TestOneFailureStopsTheRestOfTheCycleButNotTheNext(t *testing.T) {
	f := newFake(t)
	var fail atomic.Bool
	fail.Store(true)
	f.h = func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, "ok")
	}
	s := newSink(t, Config{URL: f.url()})
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := s.Deliver(ctx, finding("t", "high", "x", "watch-1")); err == nil {
			t.Fatalf("alert %d reported delivered while the webhook is down", i)
		}
	}
	if f.n() != 1 {
		t.Errorf("%d requests to a failing webhook in one cycle, want 1", f.n())
	}
	fail.Store(false)
	if err := s.Deliver(ctx, finding("t", "high", "x", "watch-2")); err != nil {
		t.Errorf("the next cycle did not try again: %v", err)
	}
}

func TestRateLimitWaitsBetweenRequests(t *testing.T) {
	f := newFake(t)
	var slept []time.Duration
	s := newSink(t, Config{URL: f.url(), MinInterval: time.Hour, MaxPerCycle: 5,
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }})
	for i := 0; i < 3; i++ {
		if err := s.Deliver(context.Background(), finding("t", "high", "x", "r")); err != nil {
			t.Fatal(err)
		}
	}
	if len(slept) != 2 || slept[0] <= 0 || slept[0] > time.Hour {
		t.Errorf("sleeps = %v, want two waits of up to an hour", slept)
	}
}

func TestACancelledContextIsAnError(t *testing.T) {
	f := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newSink(t, Config{URL: f.url()}).Deliver(ctx, finding("t", "high", "x", "r")); err == nil {
		t.Error("cancelled delivery reported as sent")
	}
}

func TestMessageEscapesCapsAndLeaksNoPayload(t *testing.T) {
	a := finding("t\nag", "high", "ok\n2026-11-05T12:00:01Z ALERT forged\r\x1b[2J"+bidi+"<!channel> <https://evil.example|click> &amp; \\ end", "r\x00un")
	m := Message(a)
	for _, bad := range []string{"\n", "\r", "\x1b", "\x00", bidi, "<!channel>", "<https"} {
		if strings.Contains(m, bad) {
			t.Errorf("message holds %q: %q", bad, m)
		}
	}
	for _, want := range []string{`t\nag`, `\n2026`, `&lt;!channel&gt;`, `\u202e`, `\\ end`, `r\u0000un`} {
		if !strings.Contains(m, want) {
			t.Errorf("message lacks %q: %q", want, m)
		}
	}

	long := Message(finding("t", "high", strings.Repeat("é", 5000), "r"))
	if n := len([]rune(long)); n > maxTextRunes+200 || !strings.Contains(long, "[truncated]") {
		t.Errorf("long text not capped: %d runes", n)
	}
	longTag := Message(finding(strings.Repeat("g", 5000), "high", "x", strings.Repeat("r", 5000)))
	if len(longTag) > 600 {
		t.Errorf("tag and run not capped: %d bytes", len(longTag))
	}
}

// Only a finding's own summary leaves the machine. The text of every other kind of
// alert is made of error messages from other components (hostnames, paths).
func TestOnlyFindingsCarryTheirText(t *testing.T) {
	for _, kind := range []string{core.AlertIncomplete, core.AlertError, core.AlertCycle, core.AlertRecovered, "something-new"} {
		a := core.Alert{Kind: kind, Tag: "watch-x", Severity: "high", Run: "r", Text: "dial tcp kibana.internal.example:443: connect: refused; token=" + token}
		m := Message(a)
		if strings.Contains(m, "kibana") || strings.Contains(m, token) || !strings.Contains(m, "watch.log") {
			t.Errorf("%s: %q", kind, m)
		}
	}
}

func TestConcurrentDeliveryIsSafe(t *testing.T) {
	f := newFake(t)
	s := newSink(t, Config{URL: f.url(), MaxPerCycle: 100})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Deliver(context.Background(), finding("t", "high", "x", "r")) }()
	}
	wg.Wait()
}
