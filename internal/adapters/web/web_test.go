package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const (
	hostilePath = `/x"onmouseover="alert(1)<script>alert(1)</script>?q=1`
	hostileUA   = `Mozilla/5.0 "onmouseover="alert(2)<script>alert(2)</script>`
	hostileSum  = `<script>alert(3)</script> 192.0.2.7 "onmouseover="alert(3)`
)

// fake is a DashboardStore over canned data. It records the limits it was asked for.
type fake struct {
	runs      []core.RunGroup
	summary   core.EventSummary
	events    []core.StoredEvent
	findings  []core.StoredFinding
	rep       []core.Reputation
	failWith  error // every call fails
	limits    map[string]int
	closed    int
	summaryFn func(core.DashboardFields)

	// The estate overlays. overlayCalls counts the questions asked of the store for them.
	overlayCalls int
	repErr       error
	repFilter    core.ReputationFilter
	seenAt       time.Time
	seenOK       bool
	seenErr      error
	seenBlock    bool // wait for the caller's context, as a slow query does
	seenField    string
	seenValue    string
	seenSince    time.Time
}

func (f *fake) note(k string, n int) {
	if f.limits == nil {
		f.limits = map[string]int{}
	}
	f.limits[k] = n
}
func (f *fake) Stats(context.Context) (core.StoreStats, error) {
	return core.StoreStats{SchemaVersion: 1, Runs: 2, Events: 9, Findings: 3, FirstSeen: now, LastSeen: now}, f.failWith
}
func (f *fake) Runs(_ context.Context, n int) ([]core.RunGroup, error) {
	f.note("runs", n)
	return f.runs, f.failWith
}
func (f *fake) Run(_ context.Context, g string) (core.RunGroup, error) {
	if f.failWith != nil {
		return core.RunGroup{}, f.failWith
	}
	for _, r := range f.runs {
		if r.ID == g {
			return r, nil
		}
	}
	return core.RunGroup{}, fmt.Errorf("%w: run", core.ErrNotFound)
}
func (f *fake) EventSummary(_ context.Context, _ string, fl core.DashboardFields, n int) (core.EventSummary, error) {
	f.note("top", n)
	if f.summaryFn != nil {
		f.summaryFn(fl)
	}
	return f.summary, f.failWith
}
func (f *fake) RecentEvents(_ context.Context, _ string, n int) ([]core.StoredEvent, error) {
	f.note("events", n)
	return f.events, f.failWith
}
func (f *fake) RunFindings(_ context.Context, _ string, n int) ([]core.StoredFinding, error) {
	f.note("runfindings", n)
	return f.findings, f.failWith
}
func (f *fake) LatestFindings(_ context.Context, n int) ([]core.StoredFinding, error) {
	f.note("findings", n)
	return f.findings, f.failWith
}
func (f *fake) LatestReputation(_ context.Context, n int) ([]core.Reputation, error) {
	f.note("rep", n)
	return f.rep, f.failWith
}
func (f *fake) Close() error { f.closed++; return nil }

type fakeLog struct {
	lines []string
	err   error
}

func (l fakeLog) Tail(context.Context, int) ([]string, error) { return l.lines, l.err }

type fakeState struct {
	st  core.WatchState
	err error
}

func (s fakeState) Peek(context.Context) (core.WatchState, error) { return s.st, s.err }

type fakeEstate struct {
	g   []core.EstateGraph
	err error
}

func (e fakeEstate) Estates(context.Context) ([]core.EstateGraph, error) { return e.g, e.err }

func hostileFake() *fake {
	return &fake{
		runs: []core.RunGroup{
			{ID: "watch-1", Created: now, EventRuns: 2, Events: 5, Findings: 1},
			{ID: "hunt-2", Created: now.Add(-time.Hour), Events: 0, Findings: 0},
		},
		summary: core.EventSummary{Rows: 5,
			BySource: []core.Count{{Label: "kibana:a", N: 5}}, ByKind: []core.Count{{Label: "request", N: 5}},
			ByStatus: []core.Count{{Label: "401", N: 5}},
			TopPaths: []core.Count{{Label: hostilePath, N: 3}, {Label: "(no path)", N: 2}},
			TopKeys:  []core.Count{{Label: "192.0.2.7", N: 5}}},
		events: []core.StoredEvent{{Run: "watch-1/kibana:a", Event: core.Event{Time: now, Source: "kibana:a", Kind: "request",
			Fields: map[string]any{"path": hostilePath, "user_agent": hostileUA, "status": float64(401)}}}},
		findings: []core.StoredFinding{{Run: "watch-1", Finding: core.Finding{Detector: "authspike", Tag: "spray:192.0.2.7",
			Severity: core.SevHigh, Summary: hostileSum}}},
		rep: []core.Reputation{{Indicator: "192.0.2.7", Verdict: hostileUA, Observed: now, Source: "greynoise"}},
	}
}

func hostileEstate() core.EstateGraph {
	return core.EstateGraph{ID: "e1", Caveat: "ownership, not operators",
		Nodes: []core.EstateNode{
			{ID: "ip:192.0.2.10", Kind: "ip", Label: hostileSum, Source: "rdns", Method: `PTR "onmouseover="x`, Observed: "2026-11-06T10:00:00Z",
				Facts: []core.EstateFact{
					{Key: "port.open", Value: "443", Source: "scan-cache", Method: "import of a synthetic export", Observed: "2026-11-06T10:00:00Z"},
					{Key: "tech", Value: hostilePath, Source: "scan-cache", Method: hostileUA, Observed: "2026-11-06T10:00:00Z"}}},
			{ID: "host:edge.example.com", Kind: "host", Label: "edge.example.com", Source: "rdns", Method: "PTR q", Observed: "2026-11-06T10:00:00Z"},
			{ID: "service:dns-provider", Kind: "service", Label: "Example DNS Provider", Source: "dns", Method: "NS lookup", Observed: "2026-11-06T10:00:00Z"}},
		Assessments: []core.EstateAssessment{{ID: "a1", Subject: "ip:192.0.2.10", Label: "suspicious", By: hostileSum, Decided: "2026-11-06T12:00:00Z",
			Basis: []string{"ip:192.0.2.10#port.open", hostilePath}, Note: hostileUA}},
		Edges:    []core.EstateEdge{{From: "ip:192.0.2.10", To: "host:edge.example.com", Relation: "ptr", Source: "rdns", Method: "PTR q", Observed: "2026-11-06T10:00:00Z", Confidence: "stated"}},
		Absences: []core.EstateAbsence{{Subject: "ip:192.0.2.10", Source: "rdap", Method: "GET q", Observed: "2026-11-06T10:00:00Z", Answer: "not_found"}},
	}
}

func newDeps(f *fake) Deps {
	return Deps{
		Open:   func(context.Context) (core.DashboardStore, error) { return f, nil },
		Log:    fakeLog{lines: []string{now.Format(time.RFC3339) + " CYCLE watch-1 CYCLE INCOMPLETE: 1 component(s) did not finish", "line " + hostileSum}},
		State:  fakeState{st: core.WatchState{Seen: map[string]core.SeenTag{"spray:192.0.2.7": {At: now, Severity: core.SevHigh}}, Health: map[string]core.HealthSeen{"kibana:a": {At: now}, hostileSum: {At: now}}}},
		Estate: fakeEstate{g: []core.EstateGraph{hostileEstate()}},
		Fields: core.DashboardFields{Path: "path", Status: "status", Key: "client_ip"},
		Now:    func() time.Time { return now },
	}
}

func get(t *testing.T, h http.Handler, target string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	req.Host = "127.0.0.1:8090"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, rec.Header(), string(b)
}

var allPages = []string{
	"/", "/run?id=watch-1", "/run?id=hunt-2", "/findings", "/reputation", "/watch",
	"/estate", "/estate/node?g=e1&id=ip:192.0.2.10", "/estate/edge?g=e1&i=0",
}

func TestEveryPageSetsSecurityHeadersAndNoCORS(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	for _, p := range append(allPages, "/static/tailwind.css", "/estate/graph.json?g=e1", "/no-such-page") {
		_, hd, _ := get(t, h, p)
		csp := hd.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "style-src 'self'", "img-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", p, csp, want)
			}
		}
		// Script is allowed from this origin only: no inline, no eval, no remote origin,
		// no data: URL, no wildcard.
		for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http", "data:", "*", "blob:", "strict-dynamic"} {
			if strings.Contains(csp, bad) {
				t.Errorf("%s: CSP %q must not contain %q", p, csp, bad)
			}
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", p)
		}
		for k := range hd {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s: sets %s: no CORS", p, k)
			}
		}
	}
}

func TestOnlyReadMethods(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		req := httptest.NewRequest(m, "/", strings.NewReader("sql=DROP TABLE events"))
		req.Host = "127.0.0.1:8090"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", m, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s answered with CORS", m)
		}
	}
}

func TestForeignHostHeaderRefusedOnLoopbackOnly(t *testing.T) {
	d := newDeps(hostileFake())
	for _, host := range []string{"evil.example.com", "evil.example.com:8090", "192.0.2.1:8090"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		New(d, Options{Loopback: true}).ServeHTTP(rec, req)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q = %d, want 421 (DNS rebinding)", host, rec.Code)
		}
	}
	for _, host := range []string{"127.0.0.1:8090", "localhost:8090", "[::1]:8090", "localhost"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		New(d, Options{Loopback: true}).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Host %q = %d, want 200", host, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "dash.example.com"
	rec := httptest.NewRecorder()
	New(d, Options{Loopback: false}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("remote mode must not filter Host, got %d", rec.Code)
	}
}

var rawAttack = []string{"<script", `"onmouseover=`, `'onmouseover=`, "<img", "javascript:"}

func TestHostileStoredTextIsEscapedOnEveryPage(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	sawEscaped := 0
	for _, p := range allPages {
		code, _, body := get(t, h, p)
		if code != 200 {
			t.Fatalf("%s = %d: %s", p, code, body)
		}
		body = ownScript.ReplaceAllString(body, "") // the vendored scripts the page loads are the only ones
		for _, bad := range rawAttack {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains raw %q:\n%s", p, bad, body)
			}
		}
		if strings.Contains(body, "&lt;script&gt;") {
			sawEscaped++
		}
	}
	if sawEscaped < 5 {
		t.Errorf("only %d pages showed the hostile text escaped: the payload is not reaching the templates, so the test proves nothing", sawEscaped)
	}
}

// ownScript matches exactly the script tags a page may carry: a vendored file of this
// dashboard, loaded from this origin, deferred, with no inline body.
var ownScript = regexp.MustCompile(`<script src="/static/(htmx\.min|d3\.min|estate|estate-search|sheet)\.js" defer></script>`)

func TestPagesCarryOnlyTheVendoredScriptsAndNoInlineCode(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	ref := regexp.MustCompile(`(?i)(src|href|action)\s*=\s*"(https?:)?//`)
	handler := regexp.MustCompile(`(?i)\son[a-z]+\s*=`) // onclick= and friends
	for _, p := range allPages {
		_, _, body := get(t, h, p)
		rest := ownScript.ReplaceAllString(body, "")
		if strings.Contains(strings.ToLower(rest), "<script") {
			t.Errorf("%s has a script that is not one of the vendored files, or has an inline body", p)
		}
		if strings.Contains(body, "@import") || ref.MatchString(body) {
			t.Errorf("%s has an external reference", p)
		}
		if handler.MatchString(rest) || strings.Contains(strings.ToLower(rest), " style=") || strings.Contains(strings.ToLower(rest), "javascript:") {
			t.Errorf("%s has an inline event handler, an inline style or a javascript: URL", p)
		}
		if !strings.Contains(body, `<script src="/static/htmx.min.js" defer></script>`) {
			t.Errorf("%s does not load htmx", p)
		}
		wantD3 := strings.HasPrefix(p, "/estate") && !strings.Contains(p, "/node") && !strings.Contains(p, "/edge")
		if got := strings.Contains(body, "/static/d3.min.js"); got != wantD3 {
			t.Errorf("%s loads d3 = %v, want %v: only the estate page draws a graph", p, got, wantD3)
		}
		// sheet.js comes with the sheet and before the script that fills it.
		if got := strings.Contains(body, "/static/sheet.js"); got != wantD3 {
			t.Errorf("%s loads sheet.js = %v, want %v", p, got, wantD3)
		}
	}
}

func TestLongStoredStringsAreCapped(t *testing.T) {
	f := hostileFake()
	f.findings[0].Summary = strings.Repeat("A", 50_000)
	f.events[0].Fields["user_agent"] = strings.Repeat("B", 50_000)
	h := New(newDeps(f), Options{Loopback: true})
	for _, p := range []string{"/findings", "/run?id=watch-1"} {
		_, _, body := get(t, h, p)
		if len(body) > 40_000 {
			t.Errorf("%s: %d bytes from two 50k strings: not capped", p, len(body))
		}
		if strings.Contains(body, strings.Repeat("A", 1000)) || strings.Contains(body, strings.Repeat("B", 1000)) {
			t.Errorf("%s: shows an uncapped string", p)
		}
	}
}

func TestOverviewFlagsIncompleteRunsAndSaysWhy(t *testing.T) {
	_, _, body := get(t, New(newDeps(hostileFake()), Options{Loopback: true}), "/")
	if !strings.Contains(body, "INCOMPLETE") || !strings.Contains(body, "no events stored") {
		t.Errorf("hunt-2 holds no events and must be flagged INCOMPLETE with the reason:\n%s", body)
	}
	_, _, run := get(t, New(newDeps(hostileFake()), Options{Loopback: true}), "/run?id=hunt-2")
	if !strings.Contains(run, "INCOMPLETE") || !strings.Contains(run, "not a clean result") {
		t.Errorf("run page must say an empty run is not a clean result:\n%s", run)
	}
}

func TestEmptyAndFailedPanelsSayWhy(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Deps, *fake)
		page   string
		want   []string
		not    []string
	}{
		{"no runs", func(d *Deps, f *fake) { f.runs = nil }, "/", []string{"no runs yet"}, nil},
		{"no findings", func(d *Deps, f *fake) { f.findings = nil }, "/findings", []string{"no findings stored"}, nil},
		{"no reputation", func(d *Deps, f *fake) { f.rep = nil }, "/reputation", []string{"no reputation snapshots", "context, not attribution"}, nil},
		{"db absent", func(d *Deps, f *fake) {
			d.Open = func(context.Context) (core.DashboardStore, error) {
				return nil, fmt.Errorf("%w: no evidence database at x yet", core.ErrAbsent)
			}
		}, "/", []string{"no evidence database"}, []string{"alert-destructive"}},
		{"query fails", func(d *Deps, f *fake) { f.failWith = errors.New("boom: io") }, "/", []string{`alert-destructive`, "boom: io"}, []string{"no runs yet"}},
		{"query fails findings", func(d *Deps, f *fake) { f.failWith = errors.New("boom: io") }, "/findings", []string{`alert-destructive`}, []string{"no findings stored"}},
		{"open fails", func(d *Deps, f *fake) {
			d.Open = func(context.Context) (core.DashboardStore, error) { return nil, errors.New("database is locked") }
		}, "/reputation", []string{`alert-destructive`, "database is locked"}, []string{"no reputation snapshots"}},
		{"estate nil", func(d *Deps, f *fake) { d.Estate = nil }, "/estate", []string{"estate is not available", "--case"}, nil},
		{"estate dir absent", func(d *Deps, f *fake) {
			d.Estate = fakeEstate{err: fmt.Errorf("%w: estate dir absent: x", core.ErrAbsent)}
		}, "/estate", []string{"estate dir absent"}, []string{`alert-destructive`}},
		{"estate broken", func(d *Deps, f *fake) { d.Estate = fakeEstate{err: errors.New("estate file bad.yaml: unknown key")} }, "/estate", []string{`alert-destructive`, "unknown key"}, nil},
		{"log absent", func(d *Deps, f *fake) {
			d.Log = fakeLog{err: fmt.Errorf("%w: no alert log", core.ErrAbsent)}
			d.State = fakeState{err: fmt.Errorf("%w: no watch state", core.ErrAbsent)}
		}, "/watch", []string{"no alert log", "no watch has run"}, nil},
		{"state corrupt", func(d *Deps, f *fake) { d.State = fakeState{err: fmt.Errorf("%w: bad", core.ErrStateCorrupt)} }, "/watch", []string{`alert-destructive`, "corrupt"}, nil},
		{"log empty", func(d *Deps, f *fake) { d.Log = fakeLog{} }, "/watch", []string{"watch.log is empty"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := hostileFake()
			d := newDeps(f)
			c.mutate(&d, f)
			code, _, body := get(t, New(d, Options{Loopback: true}), c.page)
			if code != 200 {
				t.Fatalf("status %d", code)
			}
			for _, w := range c.want {
				if !strings.Contains(body, w) {
					t.Errorf("lacks %q:\n%s", w, body)
				}
			}
			for _, n := range c.not {
				if strings.Contains(body, n) {
					t.Errorf("must not contain %q:\n%s", n, body)
				}
			}
		})
	}
}

func TestRunPageShowsSummaryFindingsAndSampleAndPassesConfiguredFields(t *testing.T) {
	f := hostileFake()
	var got core.DashboardFields
	f.summaryFn = func(fl core.DashboardFields) { got = fl }
	_, _, body := get(t, New(newDeps(f), Options{Loopback: true}), "/run?id=watch-1")
	for _, w := range []string{"kibana:a", "401", "(no path)", "192.0.2.7", "spray:192.0.2.7", "authspike", "high", "stored rows"} {
		if !strings.Contains(body, w) {
			t.Errorf("run page lacks %q", w)
		}
	}
	if got != (core.DashboardFields{Path: "path", Status: "status", Key: "client_ip"}) {
		t.Errorf("fields = %+v", got)
	}
	if f.closed == 0 {
		t.Error("the store handle was not closed after the request: a watch could not write")
	}
}

func TestUnknownRunIs404AndStoreErrorsAreNot(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	for _, p := range []string{"/run?id=nope", "/run", "/run?id=" + strings.Repeat("x", 500), "/estate/node?g=e1&id=nope", "/estate/edge?g=e1&i=99", "/estate/edge?g=e1&i=-1", "/estate/edge?g=e1&i=abc", "/nope"} {
		if code, _, _ := get(t, h, p); code != 404 {
			t.Errorf("%s = %d, want 404", p, code)
		}
	}
	f := hostileFake()
	f.failWith = errors.New("disk on fire")
	code, _, body := get(t, New(newDeps(f), Options{Loopback: true}), "/run?id=watch-1")
	if code != 200 || !strings.Contains(body, "disk on fire") || !strings.Contains(body, `alert-destructive`) {
		t.Errorf("a failing store must show a banner, got %d:\n%s", code, body)
	}
}

func TestEveryQueryIsBounded(t *testing.T) {
	f := hostileFake()
	h := New(newDeps(f), Options{Loopback: true})
	for _, p := range []string{"/", "/run?id=watch-1", "/findings", "/reputation"} {
		get(t, h, p)
	}
	for k, n := range f.limits {
		if n <= 0 || n > 500 {
			t.Errorf("limit for %s = %d: every query needs a row limit of at most 500", k, n)
		}
	}
	for _, k := range []string{"runs", "top", "events", "runfindings", "findings", "rep"} {
		if _, ok := f.limits[k]; !ok {
			t.Errorf("%s was never queried", k)
		}
	}
	if f.limits["events"] > 100 {
		t.Errorf("raw events panel shows up to %d rows: keep it small", f.limits["events"])
	}
}

func TestRowsRenderedNeverExceedTheCap(t *testing.T) {
	f := hostileFake()
	f.findings = nil
	for i := 0; i < 3000; i++ {
		f.findings = append(f.findings, core.StoredFinding{Run: "watch-1", Finding: core.Finding{Detector: "d", Tag: fmt.Sprint("t", i), Summary: "s"}})
	}
	_, _, body := get(t, New(newDeps(f), Options{Loopback: true}), "/findings")
	if n := strings.Count(body, "<tr>"); n > 600 {
		t.Errorf("%d rows rendered from a store that returned 3000", n)
	}
	if !strings.Contains(body, "showing the first") {
		t.Error("a truncated table must say it is truncated")
	}
}

func TestReputationPageLabelsContextNotAttribution(t *testing.T) {
	_, _, body := get(t, New(newDeps(hostileFake()), Options{Loopback: true}), "/reputation")
	if !strings.Contains(body, "context, not attribution") || !strings.Contains(body, "192.0.2.7") {
		t.Errorf("reputation page:\n%s", body)
	}
}

func TestWatchPageShowsTailHealthAndStateAndDoesNotCallAnIncompleteCycleQuiet(t *testing.T) {
	_, _, body := get(t, New(newDeps(hostileFake()), Options{Loopback: true}), "/watch")
	for _, w := range []string{"CYCLE INCOMPLETE", "not healthy", "kibana:a", "spray", "open outage"} {
		if !strings.Contains(body, w) {
			t.Errorf("watch page lacks %q:\n%s", w, body)
		}
	}
	d := newDeps(hostileFake())
	d.Log = fakeLog{lines: []string{now.Add(-time.Minute).Format(time.RFC3339) + " CYCLE watch-3 CYCLE QUIET: every source and detector completed"}}
	d.State = fakeState{st: core.WatchState{Seen: map[string]core.SeenTag{}}}
	_, _, ok := get(t, New(d, Options{Loopback: true}), "/watch")
	if !strings.Contains(ok, "CYCLE QUIET") || strings.Contains(ok, "not healthy") {
		t.Errorf("quiet cycle:\n%s", ok)
	}
	d.Log = fakeLog{lines: []string{"2026-11-05T11:00:00Z ALERT [high] [c:t] d: x"}}
	_, _, nc := get(t, New(d, Options{Loopback: true}), "/watch")
	if !strings.Contains(nc, "no cycle line") {
		t.Errorf("a log with no heartbeat must say it cannot tell:\n%s", nc)
	}
}

func TestEstatePagesShowProvenanceAndCaveatOnEveryNodeAndEdge(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	for _, p := range []string{"/estate", "/estate/node?g=e1&id=ip:192.0.2.10", "/estate/node?g=e1&id=host:edge.example.com", "/estate/edge?g=e1&i=0"} {
		code, _, body := get(t, h, p)
		if code != 200 {
			t.Fatalf("%s = %d", p, code)
		}
		for _, w := range []string{"rdns", "ownership, not operators", "PTR", "2026-11-06T10:00:00Z"} {
			if !strings.Contains(body, w) {
				t.Errorf("%s lacks %q", p, w)
			}
		}
	}
	_, _, list := get(t, h, "/estate")
	if !strings.Contains(list, "<svg") || !strings.Contains(list, "not_found") {
		t.Errorf("estate list should draw the graph and show absences:\n%s", list)
	}
}

// Facts show with their source, method and time. An assessment sits under its own heading
// with a fixed notice, never in a node table, and the notice does not depend on the
// caveat of the file.
func TestEstateShowsFactsAndMarksAssessmentsAsOpinion(t *testing.T) {
	d := newDeps(hostileFake())
	g := hostileEstate()
	g.Caveat = "" // a caveat that says nothing about opinion must not change the notice
	d.Estate = fakeEstate{g: []core.EstateGraph{g}}
	h := New(d, Options{Loopback: true})
	node := "/estate/node?g=e1&id=ip:192.0.2.10"
	for _, p := range []string{"/estate", node} {
		_, _, body := get(t, h, p)
		for _, w := range []string{"Assessments (opinion)", assessmentNotice, "suspicious", "2026-11-06T12:00:00Z"} {
			if !strings.Contains(body, w) {
				t.Errorf("%s lacks %q", p, w)
			}
		}
	}
	_, _, body := get(t, h, node)
	for _, w := range []string{"Facts", "port.open", "443", "scan-cache", "import of a synthetic export", "ip:192.0.2.10#port.open"} {
		if !strings.Contains(body, w) {
			t.Errorf("node record lacks %q:\n%s", w, body)
		}
	}
	// A node with no assessment says so and still shows no judgement.
	_, _, other := get(t, h, "/estate/node?g=e1&id=host:edge.example.com")
	if strings.Contains(other, "suspicious") || !strings.Contains(other, "Assessments (opinion)") {
		t.Errorf("a node without an assessment shows the heading and no judgement:\n%s", other)
	}
	// The assessment is not in the node table of the estate page.
	_, _, list := get(t, h, "/estate")
	i, j := strings.Index(list, "<h3>Nodes"), strings.Index(list, "<h3>Edges")
	if i < 0 || j < i || strings.Contains(list[i:j], "suspicious") {
		t.Errorf("an assessment must not appear in the node table")
	}
	// A service node is drawn like any node.
	if !strings.Contains(list, "Example DNS Provider") {
		t.Errorf("service node missing:\n%s", list)
	}
}

func TestStaticServesOnlyTheNamedFiles(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	for name, prefix := range map[string]string{"tailwind.css": "text/css", "htmx.min.js": "text/javascript", "d3.min.js": "text/javascript", "estate.js": "text/javascript", "d3.LICENSE.txt": "text/plain", "htmx.LICENSE.txt": "text/plain"} {
		code, hd, body := get(t, h, "/static/"+name)
		if code != 200 || !strings.HasPrefix(hd.Get("Content-Type"), prefix) || len(body) == 0 {
			t.Errorf("%s: %d %q (%d bytes)", name, code, hd.Get("Content-Type"), len(body))
		}
	}
	for _, p := range []string{"/static/", "/static", "/static/../web.go", "/static/nope.js", "/static/%2e%2e/web.go", "/static/style.css", "/static/templates/layout.templ", "/static/assets/input.css"} {
		if code, _, _ := get(t, h, p); code == 200 {
			t.Errorf("%s served", p)
		}
	}
}

func TestCheckAddr(t *testing.T) {
	ok := map[string]string{
		"127.0.0.1:8090": "127.0.0.1:8090", "localhost:8090": "127.0.0.1:8090", "[::1]:8090": "[::1]:8090",
		"127.0.0.1:0": "127.0.0.1:0", "127.5.5.5:80": "127.5.5.5:80",
	}
	for in, want := range ok {
		got, remote, err := CheckAddr(in, false)
		if err != nil || got != want || remote {
			t.Errorf("CheckAddr(%q) = %q, %v, %v; want %q", in, got, remote, err, want)
		}
	}
	for _, in := range []string{":8090", "0.0.0.0:8090", "[::]:8090", "192.0.2.1:8090", "example.com:8090", "10.0.0.5:80"} {
		if _, _, err := CheckAddr(in, false); !errors.Is(err, ErrNotLoopback) || strings.Contains(err.Error(), "--") {
			t.Errorf("CheckAddr(%q) = %v: a non-loopback address must be refused with ErrNotLoopback and a flag-neutral message", in, err)
		}
		got, remote, err := CheckAddr(in, true)
		if err != nil || !remote || got != in {
			t.Errorf("CheckAddr(%q, allow) = %q, %v, %v", in, got, remote, err)
		}
	}
	for _, in := range []string{"", "8090", "127.0.0.1", "127.0.0.1:notaport", "127.0.0.1:99999", "127.0.0.1:-1"} {
		if _, _, err := CheckAddr(in, true); !errors.Is(err, ErrBadAddr) || strings.Contains(err.Error(), "--") {
			t.Errorf("CheckAddr(%q) = %v: want ErrBadAddr and a flag-neutral message", in, err)
		}
	}
}

func TestServerHasTimeouts(t *testing.T) {
	s := NewServer(New(newDeps(hostileFake()), Options{Loopback: true}))
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes <= 0 || s.MaxHeaderBytes > 64<<10 {
		t.Errorf("server limits not set: %+v", s)
	}
}

func TestServeStopsWhenContextEnds(t *testing.T) {
	ln, err := newLoopbackListener()
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, NewServer(New(newDeps(hostileFake()), Options{Loopback: true})), ln) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil on a clean stop", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func hostStatus(t *testing.T, o Options, host string) (int, http.Header) {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	New(newDeps(hostileFake()), o).ServeHTTP(rec, req)
	return rec.Code, rec.Header()
}

func TestAllowedHostsReplacesTheLoopbackRule(t *testing.T) {
	o := Options{Loopback: true, AllowedHosts: []string{"Dash.Example.com", "198.51.100.7:8443", "[2001:db8::1]:8090"}}
	for _, host := range []string{"dash.example.com", "DASH.example.COM", "198.51.100.7:8443", "[2001:db8::1]:8090"} {
		if code, _ := hostStatus(t, o, host); code != http.StatusOK {
			t.Errorf("allowed Host %q = %d, want 200", host, code)
		}
	}
	// Exact match: another port, a missing port, a suffix, a prefix, loopback (replaced), empty.
	for _, host := range []string{"dash.example.com:8090", "198.51.100.7", "198.51.100.7:8444", "evil.dash.example.com", "dash.example.com.evil.test", "dash.example.co", "127.0.0.1:8090", "localhost", ""} {
		if code, _ := hostStatus(t, o, host); code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q = %d, want 421", host, code)
		}
	}
	// With the list set, Loopback=false does not switch the check off.
	o.Loopback = false
	if code, _ := hostStatus(t, o, "evil.example.com"); code != http.StatusMisdirectedRequest {
		t.Errorf("AllowedHosts with Loopback=false: foreign Host = %d, want 421", code)
	}
	if code, _ := hostStatus(t, o, "dash.example.com"); code != http.StatusOK {
		t.Errorf("AllowedHosts with Loopback=false: allowed Host = %d, want 200", code)
	}
}

func TestEmptyAllowedHostsKeepsTodaysBehaviour(t *testing.T) {
	for _, hosts := range [][]string{nil, {}} {
		if code, _ := hostStatus(t, Options{Loopback: true, AllowedHosts: hosts}, "evil.example.com"); code != http.StatusMisdirectedRequest {
			t.Errorf("loopback, empty list: foreign Host = %d, want 421", code)
		}
		if code, _ := hostStatus(t, Options{Loopback: true, AllowedHosts: hosts}, "localhost:8090"); code != http.StatusOK {
			t.Errorf("loopback, empty list: localhost = %d, want 200", code)
		}
		if code, _ := hostStatus(t, Options{Loopback: false, AllowedHosts: hosts}, "evil.example.com"); code != http.StatusOK {
			t.Errorf("remote, empty list: Host must not be filtered, got %d", code)
		}
	}
}

func TestAllowedHostsRefusedAtConstruction(t *testing.T) {
	long := make([]string, 17)
	for i := range long {
		long[i] = fmt.Sprintf("h%d.example.com", i)
	}
	bad := map[string][]string{
		"wildcard":         {"*.example.com"},
		"bare wildcard":    {"*"},
		"empty string":     {""},
		"blank":            {"  "},
		"too many":         long,
		"scheme":           {"https://dash.example.com"},
		"path":             {"dash.example.com/x"},
		"userinfo":         {"a@dash.example.com"},
		"space":            {"dash example.com"},
		"port zero":        {"dash.example.com:0"},
		"port too big":     {"dash.example.com:70000"},
		"port not number":  {"dash.example.com:http"},
		"empty port":       {"dash.example.com:"},
		"bare ipv6":        {"2001:db8::1"},
		"empty label":      {"a..example.com"},
		"leading dash":     {"-a.example.com"},
		"one good one bad": {"dash.example.com", "*"},
	}
	for name, hosts := range bad {
		o := Options{AllowedHosts: hosts}
		if err := o.Validate(); !errors.Is(err, ErrBadAllowedHosts) {
			t.Errorf("%s: Validate = %v, want ErrBadAllowedHosts", name, err)
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: New accepted the list", name)
				}
			}()
			New(newDeps(hostileFake()), o)
		}()
	}
	good := make([]string, 16)
	for i := range good {
		good[i] = fmt.Sprintf("h%d.example.com:8090", i)
	}
	for _, hosts := range [][]string{good, {"localhost"}, {"dash.example.com:443"}, {"[::1]:8090"}, {"203.0.113.9"}} {
		if err := (Options{AllowedHosts: hosts}).Validate(); err != nil {
			t.Errorf("Validate(%v) = %v", hosts, err)
		}
	}
}

func TestAllowedHostsKeepsHeadersAndReadOnly(t *testing.T) {
	o := Options{AllowedHosts: []string{"dash.example.com"}}
	code, hd := hostStatus(t, o, "dash.example.com")
	if code != http.StatusOK || hd.Get("Content-Security-Policy") != csp || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Cache-Control") != "no-store" {
		t.Errorf("allowed host: %d %v", code, hd)
	}
	code, hd = hostStatus(t, o, "evil.example.com")
	if code != http.StatusMisdirectedRequest || hd.Get("Content-Security-Policy") != csp {
		t.Errorf("refused host: %d %v", code, hd)
	}
	h := New(newDeps(hostileFake()), o)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		req := httptest.NewRequest(m, "/", nil)
		req.Host = "dash.example.com"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s with an allowed Host = %d, want 405", m, rec.Code)
		}
	}
}
