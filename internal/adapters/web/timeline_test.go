package web

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// fakeHistory is a WatchHistoryReader over canned data.
type fakeHistory struct {
	names   []string
	h       map[string]core.WatchHistory
	errs    map[string]error
	listErr error
	reads   []string
}

func (f *fakeHistory) Watchers(context.Context) ([]string, error) { return f.names, f.listErr }
func (f *fakeHistory) Read(_ context.Context, name string, _ time.Time) (core.WatchHistory, error) {
	f.reads = append(f.reads, name)
	if err := f.errs[name]; err != nil {
		return core.WatchHistory{}, err
	}
	h, ok := f.h[name]
	if !ok {
		return core.WatchHistory{}, fmt.Errorf("%w: no log", core.ErrAbsent)
	}
	return h, nil
}

func tlCycle(ago time.Duration, verdict string) core.WatchCycleLine {
	at := now.Add(-ago)
	return core.WatchCycleLine{At: at, Run: "watch-a-" + at.Format("20060102T150405Z"), Verdict: verdict}
}

// tlHistory is two watchers: "a" with a gap and an open span, and the unnamed one.
func tlHistory() *fakeHistory {
	a := core.WatchHistory{
		GapFactor: 3, Every: 5 * time.Minute, Keep: 48 * time.Hour,
		Cycles: []core.WatchCycleLine{tlCycle(3*time.Hour, "QUIET"), tlCycle(110*time.Minute, "FINDINGS"), tlCycle(100*time.Minute, "INCOMPLETE"), tlCycle(time.Hour, "FAILED")},
	}
	a.Cycles[2].GapReported = true
	a.Cycles[2].GapFrom, a.Cycles[2].GapTo = now.Add(-5*time.Hour), now.Add(-4*time.Hour)
	a.Gaps = []core.WatchNoCycle{{From: now.Add(-3 * time.Hour), To: now.Add(-110 * time.Minute)}, {From: now.Add(-time.Hour)}}
	a.Last = &core.WatchCycleSummary{Run: a.Cycles[3].Run, Verdict: "FAILED", Ended: a.Cycles[3].At.Add(7 * time.Second)}
	u := core.WatchHistory{GapFactor: 3, Cycles: []core.WatchCycleLine{tlCycle(30*time.Minute, "QUIET")}}
	return &fakeHistory{names: []string{"", "a"}, h: map[string]core.WatchHistory{"a": a, "": u}}
}

func tlStore() *fake {
	f := hostileFake()
	f.page = core.FindingsPage{Rows: []core.TimelineFinding{
		{Created: now.Add(-2 * time.Hour), StoredFinding: core.StoredFinding{Run: "watch-a-20261105T100000Z", Finding: core.Finding{Detector: "authspike", Tag: "spray:192.0.2.7", Severity: core.SevHigh, Summary: "s"}}},
		{Created: now.Add(-90 * time.Minute), StoredFinding: core.StoredFinding{Run: "hunt-2", Finding: core.Finding{Detector: "newkey", Tag: "k", Severity: core.SevCheck, Summary: "s"}}},
	}}
	return f
}

func tlServer(f *fake, h *fakeHistory) (Deps, func(string) (int, string)) {
	d := newDeps(f)
	d.History = nil
	if h != nil {
		d.History = h
	}
	srv := New(d, Options{Loopback: true})
	return d, func(target string) (int, string) {
		req := httptest.NewRequest("GET", target, nil)
		req.Host = "127.0.0.1:8090"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
}

func TestTimelineShowsFindingsCyclesAndMarkersNewestFirst(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	code, body := get("/timeline")
	if code != 200 {
		t.Fatalf("code %d\n%s", code, body)
	}
	for _, want := range []string{"<h1>Timeline</h1>", "finding", "CYCLE QUIET", "CYCLE FINDINGS", "CYCLE INCOMPLETE (not a quiet result)", "CYCLE FAILED (not a quiet result)",
		"gap reported: events 2026-11-05T07:00:00Z to 2026-11-05T08:00:00Z were never examined",
		"duration 7s", "duration not recorded", "no cycle recorded", "(unnamed)", "(hunt)",
		"No cycle line in watch.a.log from 2026-11-05T09:00:00Z to 2026-11-05T10:10:00Z (1h10m0s). This watcher&#39;s interval is 5m0s, so this is more than 3 intervals.",
		"since 2026-11-05T11:00:00Z (1h0m0s until 2026-11-05T12:00:00Z)",
		"interval unknown (no readable watch-status record): no gap is judged for this watcher",
		"older than 48h0m0s", `href="/run?id=watch-a-20261105T100000Z"`, `<svg `, `aria-hidden="true"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Newest first: the open marker (11:00) precedes the 10:00 FAILED... by time.
	i, j := strings.Index(body, "since 2026-11-05T11:00:00Z"), strings.Index(body, "CYCLE FINDINGS")
	if i < 0 || j < 0 || i > j {
		t.Errorf("rows are not newest first")
	}
	// Duration only for the newest cycle: exactly one "7s".
	if n := strings.Count(body, "duration 7s"); n != 1 {
		t.Errorf("duration shown %d times", n)
	}
}

func TestTimelineMarkerWordingStatesAbsenceOnly(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, body := get("/timeline")
	for _, m := range regexp.MustCompile(`No cycle line in [^<]*`).FindAllString(body, -1) {
		low := strings.ToLower(m)
		for _, bad := range []string{"down", "dead", "healthy", " ok", "crash", "stopped", "alive"} {
			if strings.Contains(low, bad) {
				t.Errorf("marker %q contains %q", m, bad)
			}
		}
		if !strings.Contains(m, "The log shows no cycle in this span. The cause is not known: the watcher may not have run, or its log may not have been written.") {
			t.Errorf("marker lacks the fixed sentence: %q", m)
		}
	}
}

func TestTimelineUnknownIntervalDrawsNoMarker(t *testing.T) {
	h := tlHistory()
	a := h.h["a"]
	a.Every, a.Gaps = 0, nil // what the reader returns without a status record
	h.h["a"] = a
	_, get := tlServer(tlStore(), h)
	_, body := get("/timeline")
	if strings.Contains(body, "No cycle line in") || strings.Contains(body, "<td>no cycle recorded</td>") {
		t.Error("a marker was drawn without a known interval")
	}
	if !strings.Contains(body, "watcher a: interval unknown (no readable watch-status record): no gap is judged for this watcher.") {
		t.Error("the page does not say the interval is unknown")
	}
}

func TestTimelineHostileStringsAreEscapedInEveryContext(t *testing.T) {
	f := tlStore()
	f.page.Rows[0].Detector, f.page.Rows[0].Tag, f.page.Rows[0].Summary = hostileUA, hostilePath, hostileSum
	f.page.Rows[0].Run = hostilePath
	h := tlHistory()
	a := h.h["a"]
	a.Cycles[0].Verdict, a.Cycles[0].Run = hostileSum, hostileUA
	a.Cycles[2].GapReported = true
	h.h["a"] = a
	h.names = append(h.names, hostilePath)
	h.h[hostilePath] = core.WatchHistory{Cycles: []core.WatchCycleLine{tlCycle(time.Hour, "QUIET")}}
	_, get := tlServer(f, h)
	for _, target := range []string{"/timeline", "/timeline?w=7d&sev=high&watcher=a"} {
		code, body := get(target)
		if code != 200 {
			t.Fatalf("%s = %d", target, code)
		}
		body = ownScript.ReplaceAllString(body, "")
		for _, bad := range rawAttack {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains raw %q", target, bad)
			}
		}
	}
	_, body := get("/timeline")
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the payload did not reach the page, so the test proves nothing")
	}
	if !strings.Contains(body, `href="/run?id=%2Fx%22onmouseover%3D`) {
		t.Error("the run link must percent-encode the stored id")
	}
}

func TestTimelineIsDeterministicWhateverTheInputOrder(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, a := get("/timeline")
	_, b := get("/timeline")
	if a != b {
		t.Fatal("two loads of unchanged data differ")
	}
	f := tlStore()
	f.page.Rows = []core.TimelineFinding{f.page.Rows[1], f.page.Rows[0]}
	h := tlHistory()
	hc := h.h["a"]
	hc.Cycles = []core.WatchCycleLine{hc.Cycles[3], hc.Cycles[1], hc.Cycles[0], hc.Cycles[2]}
	hc.Gaps = []core.WatchNoCycle{hc.Gaps[1], hc.Gaps[0]}
	h.h["a"] = hc
	// The reader orders cycles itself, so reverse what it would return: the page must not depend on it for rows.
	_, c := tlServer(f, h)
	_, shuffled := c("/timeline")
	rowsOf := func(s string) string { return s[strings.Index(s, "<h2>Record</h2>"):] }
	if rowsOf(a) != rowsOf(shuffled) {
		t.Error("shuffled input changed the table")
	}
}

func TestTimelineBoundsAndTheIncompleteNotice(t *testing.T) {
	f := tlStore()
	f.page.More = true
	h := tlHistory()
	a := h.h["a"]
	a.Cut = true
	h.h["a"] = a
	_, get := tlServer(f, h)
	_, body := get("/timeline")
	for _, want := range []string{
		"INCOMPLETE: the newest 500 findings of this window are shown; older ones in the window are not.",
		"INCOMPLETE: watch.a.log read from 2026-11-05T09:00:00Z only; earlier cycles are not shown.",
		"<caption>INCOMPLETE:"} {
		if !strings.Contains(body, want) {
			t.Errorf("lacks %q", want)
		}
	}
	// Window clamp: an unknown or too large value means the default.
	for _, w := range []string{"30d", "99999h", "", "x"} {
		_, b := get("/timeline?w=" + w)
		if !strings.Contains(b, "Window 2026-11-04T12:00:00Z to 2026-11-05T12:00:00Z") {
			t.Errorf("w=%q did not fall back to 24h", w)
		}
	}
	_, b := get("/timeline?w=7d")
	if !strings.Contains(b, "Window 2026-10-29T12:00:00Z to 2026-11-05T12:00:00Z") {
		t.Error("7d window")
	}
	// A cycle cap says so.
	big := tlHistory()
	ba := big.h["a"]
	ba.Cycles = nil
	for i := 0; i < timelineCycleRows+5; i++ {
		ba.Cycles = append(ba.Cycles, tlCycle(time.Duration(i+1)*time.Second, "QUIET"))
	}
	big.h["a"] = ba
	_, g2 := tlServer(tlStore(), big)
	_, body = g2("/timeline")
	if !strings.Contains(body, "INCOMPLETE: the newest 500 cycles of a in this window are shown") {
		t.Error("no cycle cut notice")
	}
	if n := strings.Count(body, "<td>cycle</td>"); n != timelineCycleRows+1 { // +1: the unnamed watcher's cycle
		t.Errorf("cycle rows = %d", n)
	}
}

func TestTimelineStoreFailureLeavesTheCyclesAndNamesTheCause(t *testing.T) {
	f := tlStore()
	f.failWith = errors.New("database is locked")
	_, get := tlServer(f, tlHistory())
	_, body := get("/timeline")
	if !strings.Contains(body, "could not read the store: ") || !strings.Contains(body, "CYCLE QUIET") {
		t.Errorf("store failure must be said and the cycles still shown:\n%s", body)
	}
	if strings.Contains(body, "no findings in this window") {
		t.Error("a failed read rendered as an empty result")
	}
	// A store that never answers is cut by the budget.
	old := timelineBudget
	timelineBudget = 20 * time.Millisecond
	defer func() { timelineBudget = old }()
	f = tlStore()
	f.betweenBlock = true
	_, get = tlServer(f, tlHistory())
	_, body = get("/timeline")
	if !strings.Contains(body, "could not read the store: ") || !strings.Contains(body, "CYCLE FAILED") {
		t.Error("the 3 s limit must show the store note and still render the cycles")
	}
	// The four distinct empty texts.
	f = tlStore()
	f.page = core.FindingsPage{}
	_, get = tlServer(f, tlHistory())
	if _, body = get("/timeline"); !strings.Contains(body, "no findings in this window") {
		t.Error("empty window text")
	}
	d := newDeps(tlStore())
	d.Open = func(context.Context) (core.DashboardStore, error) {
		return nil, fmt.Errorf("%w: no evidence database", core.ErrAbsent)
	}
	d.History = tlHistory()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/timeline", nil)
	req.Host = "127.0.0.1:8090"
	New(d, Options{Loopback: true}).ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "store not available") {
		t.Error("absent store text")
	}
}

func TestTimelineWithoutHistoryOrWatchersSaysSo(t *testing.T) {
	_, get := tlServer(tlStore(), nil)
	_, body := get("/timeline")
	if !strings.Contains(body, "watch history is not available") || !strings.Contains(body, "finding") {
		t.Errorf("no history:\n%s", body)
	}
	_, get = tlServer(tlStore(), &fakeHistory{})
	if _, body = get("/timeline"); !strings.Contains(body, "no watch log or status record was found") {
		t.Error("no watchers")
	}
	_, get = tlServer(tlStore(), &fakeHistory{names: []string{"a"}})
	if _, body = get("/timeline"); !strings.Contains(body, "there is no watch.a.log in the evidence directory") {
		t.Error("absent log")
	}
}

func TestTimelineFiltersAreRepeatableAndIgnoreUnknownValues(t *testing.T) {
	h := tlHistory()
	f := tlStore()
	var q core.FindingsQuery
	f.betweenFn = func(x core.FindingsQuery) { q = x }
	_, get := tlServer(f, h)
	get("/timeline?watcher=a&watcher=_&watcher=nope&sev=high&sev=critical&sev=bogus")
	if fmt.Sprint(q.RunPrefixes) != "[watch-a- watch-]" && fmt.Sprint(q.RunPrefixes) != "[watch- watch-a-]" {
		t.Errorf("prefixes = %v", q.RunPrefixes)
	}
	if fmt.Sprint(q.Severities) != fmt.Sprint([]core.Severity{core.SevHigh, core.SevCritical}) {
		t.Errorf("severities = %v", q.Severities)
	}
	if q.Limit != timelineFindingsLimit {
		t.Errorf("limit = %d", q.Limit)
	}
	// _ alone selects the unnamed watcher only; an unknown name alone selects all.
	h.reads = nil
	get("/timeline?watcher=_")
	if fmt.Sprint(h.reads) != "[]" || len(q.RunPrefixes) != 1 || q.RunPrefixes[0] != "watch-" {
		t.Errorf("_ selected reads %q prefixes %v", h.reads, q.RunPrefixes)
	}
	h.reads = nil
	get("/timeline?watcher=nope")
	if len(h.reads) != 2 || len(q.RunPrefixes) != 0 {
		t.Errorf("unknown watcher: reads %v prefixes %v", h.reads, q.RunPrefixes)
	}
}

func TestTimelineDrawsAtMostSixteenWatchersAndNamesTheRest(t *testing.T) {
	h := &fakeHistory{h: map[string]core.WatchHistory{}}
	for i := 0; i < 20; i++ {
		n := fmt.Sprintf("w%02d", i)
		h.names = append(h.names, n)
		h.h[n] = core.WatchHistory{GapFactor: 3, Cycles: []core.WatchCycleLine{tlCycle(time.Hour, "QUIET")}}
	}
	_, get := tlServer(tlStore(), h)
	_, body := get("/timeline")
	if !strings.Contains(body, "INCOMPLETE: 4 more watcher(s) found and not drawn: w16, w17, w18, w19.") || len(h.reads) != 16 {
		t.Errorf("reads %d\n%s", len(h.reads), body)
	}
}

func TestTimelineHasNoVerdictColourAndNoScript(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, body := get("/timeline")
	for _, bad := range []string{"badge", "alert-destructive", "bad", "warn", "destructive", "warning", "success", "style=", "<script src=\"/static/d3", "estate.js"} {
		if strings.Contains(body[strings.Index(body, "<main>"):], bad) {
			t.Errorf("page markup contains %q", bad)
		}
	}
	// Only the shared htmx file is loaded.
	if n := strings.Count(body, "<script"); n != 1 {
		t.Errorf("%d script tags", n)
	}
}

func TestTimelineHXRequestGetsTheFragmentOnly(t *testing.T) {
	d, _ := tlServer(tlStore(), tlHistory())
	req := httptest.NewRequest("GET", "/timeline?w=6h", nil)
	req.Host = "127.0.0.1:8090"
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	New(d, Options{Loopback: true}).ServeHTTP(rec, req)
	b := rec.Body.String()
	if strings.Contains(b, "<html") || strings.Contains(b, "<nav") || !strings.Contains(b, "Window 2026-11-05T06:00:00Z") {
		t.Errorf("fragment:\n%s", b)
	}
	if rec.Header().Get("Vary") != "HX-Request" {
		t.Error("no Vary")
	}
}

func TestTimelineIsOnTheNavigationAndGetOnly(t *testing.T) {
	_, get := tlServer(tlStore(), tlHistory())
	_, body := get("/timeline")
	if !strings.Contains(body, `<a class="tab" href="/timeline" aria-current="page">Timeline</a>`) {
		t.Error("no nav entry")
	}
	_, other := get("/findings")
	if !strings.Contains(other, `href="/timeline"`) {
		t.Error("nav entry missing on other pages")
	}
	req := httptest.NewRequest("POST", "/timeline", nil)
	req.Host = "127.0.0.1:8090"
	rec := httptest.NewRecorder()
	New(newDeps(tlStore()), Options{Loopback: true}).ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Errorf("POST = %d", rec.Code)
	}
}
