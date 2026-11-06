package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// ---- the fake store answers the overlay questions and counts them ----

func (f *fake) Reputation(_ context.Context, fl core.ReputationFilter) ([]core.Reputation, error) {
	f.overlayCalls++
	f.repFilter = fl
	if f.repErr != nil {
		return nil, f.repErr
	}
	var out []core.Reputation
	for _, r := range f.rep {
		for _, ind := range fl.Indicators {
			if r.Indicator == ind {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func (f *fake) LastSeen(ctx context.Context, field, value string, since time.Time) (time.Time, bool, error) {
	f.overlayCalls++
	f.seenField, f.seenValue, f.seenSince = field, value, since
	if f.seenBlock {
		<-ctx.Done()
		return time.Time{}, false, ctx.Err()
	}
	return f.seenAt, f.seenOK, f.seenErr
}

const (
	estNode  = "/estate/node?g=e1&id=ip:192.0.2.10"
	estOver  = "/estate/overlay?g=e1&id=ip:192.0.2.10"
	t0       = "2026-11-05T10:00:00Z"
	staleObs = "2026-06-01T10:00:00Z" // more than 90 days before the test clock
)

// weightEstate has one edge claimed by three sources (one of them twice), one claimed by
// one stale source, and nodes of several kinds with hostile labels.
func weightEstate() core.EstateGraph {
	n := func(id, kind, label string) core.EstateNode {
		return core.EstateNode{ID: id, Kind: kind, Label: label, Source: "dns", Method: "m", Observed: t0}
	}
	e := func(from, to, rel, src, obs string) core.EstateEdge {
		return core.EstateEdge{From: from, To: to, Relation: rel, Source: src, Method: "m", Observed: obs, Confidence: "stated"}
	}
	return core.EstateGraph{ID: "e1", Caveat: "c",
		Nodes: []core.EstateNode{
			n("ip:192.0.2.10", "ip", hostileSum),
			n("host:a.example.com", "host", "a.example.com"),
			n("domain:example.com", "domain", "example.com"),
			n("service:dns-provider", "service", "Example DNS Provider"),
		},
		Edges: []core.EstateEdge{
			e("ip:192.0.2.10", "host:a.example.com", "ptr", "rdns", t0),
			e("ip:192.0.2.10", "host:a.example.com", "ptr", "dns", t0),
			e("ip:192.0.2.10", "host:a.example.com", "ptr", "dns", staleObs),
			e("ip:192.0.2.10", "host:a.example.com", "ptr", "passive-dns", staleObs),
			e("domain:example.com", "ip:192.0.2.10", "resolves_to", "passive-dns", staleObs),
			e("domain:example.com", "service:dns-provider", "uses", "dns", t0),
		},
	}
}

func depsWith(f *fake, g core.EstateGraph) Deps {
	d := newDeps(f)
	d.Estate = fakeEstate{g: []core.EstateGraph{g}}
	return d
}

// ---- edge weight ----

type jsonEdgeOut struct {
	Source, Target, Relation string
	Weight                   int
	Stale                    bool
	Newest                   string
	Sources                  []string
}

func graphOut(t *testing.T, body string) (nodes []struct{ ID, Kind string }, edges []jsonEdgeOut, raw map[string]any) {
	t.Helper()
	var g struct {
		Nodes []struct{ ID, Kind string }
		Edges []jsonEdgeOut
	}
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(body), &raw)
	return g.Nodes, g.Edges, raw
}

func TestGraphJSONCarriesWeightStaleAndNewestTime(t *testing.T) {
	h := New(depsWith(hostileFake(), weightEstate()), Options{Loopback: true})
	_, _, body := get(t, h, "/estate/graph.json?g=e1")
	_, edges, _ := graphOut(t, body)
	if len(edges) != 6 {
		t.Fatalf("edges = %d", len(edges))
	}
	// ptr: rdns, dns (twice) and passive-dns are three distinct sources; the newest claim is
	// fresh. resolves_to: one source, 158 days old.
	for _, e := range edges[:4] {
		if e.Relation != "ptr" || e.Weight != 3 || e.Stale || e.Newest != t0 {
			t.Errorf("ptr edge = %+v, want weight 3, fresh, newest %s", e, t0)
		}
	}
	if r := edges[4]; r.Relation != "resolves_to" || r.Weight != 1 || !r.Stale || r.Newest != staleObs {
		t.Errorf("resolves_to edge = %+v, want weight 1, stale", r)
	}
	if u := edges[5]; u.Weight != 1 || u.Stale {
		t.Errorf("uses edge = %+v", u)
	}
}

func TestGraphJSONStaleIsMeasuredAgainstTheInjectedClock(t *testing.T) {
	g := weightEstate()
	g.Edges = g.Edges[4:5] // observed 2026-06-01
	d := depsWith(hostileFake(), g)
	d.Now = func() time.Time { return time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC) }
	_, _, body := get(t, New(d, Options{Loopback: true}), "/estate/graph.json?g=e1")
	if _, edges, _ := graphOut(t, body); edges[0].Stale {
		t.Error("19 days old must not be stale")
	}
}

func TestTheFileStoresNoWeightAndTheCodeHasNoStrengthTable(t *testing.T) {
	h := New(depsWith(hostileFake(), weightEstate()), Options{Loopback: true})
	for _, p := range []string{"/estate", "/estate/edge?g=e1&i=0", "/static/estate.js"} {
		_, _, body := get(t, h, p)
		for _, bad := range []string{"strong", "moderate", "weak"} {
			if strings.Contains(strings.ToLower(body), bad) {
				t.Errorf("%s still mentions %q", p, bad)
			}
		}
	}
}

func TestEdgeRecordListsTheSourcesAndTheNewestTime(t *testing.T) {
	h := New(depsWith(hostileFake(), weightEstate()), Options{Loopback: true})
	_, _, body := get(t, h, "/estate/edge?g=e1&i=0")
	for _, w := range []string{"corroboration", "3 distinct sources", "dns, passive-dns, rdns", "newest claim", t0} {
		if !strings.Contains(body, w) {
			t.Errorf("edge record lacks %q:\n%s", w, body)
		}
	}
	if strings.Contains(body, "stale") {
		t.Errorf("a fresh edge must not be called stale:\n%s", body)
	}
	_, _, old := get(t, h, "/estate/edge?g=e1&i=4")
	for _, w := range []string{"1 distinct source", "passive-dns", staleObs, "older than 90 days"} {
		if !strings.Contains(old, w) {
			t.Errorf("stale edge record lacks %q:\n%s", w, old)
		}
	}
}

func TestEstateJSScalesStrokeByWeightAndDashesStaleWithoutInlineStyleMarkup(t *testing.T) {
	_, _, js := get(t, New(newDeps(hostileFake()), Options{Loopback: true}), "/static/estate.js")
	for _, w := range []string{"d.weight", "d.stale", "stroke-width", "stroke-dasharray", "htmx:afterSwap"} {
		if !strings.Contains(js, w) {
			t.Errorf("estate.js lacks %q", w)
		}
	}
	if strings.Contains(js, `setAttribute("style"`) || strings.Contains(js, ".innerHTML") || strings.Contains(js, "insertAdjacentHTML") || strings.Contains(js, "eval(") {
		t.Error("estate.js must not write markup or an inline style attribute: the CSP allows neither")
	}
}

// ---- kind filter ----

func kindsEstate() core.EstateGraph { return weightEstate() }

func TestKindFilterFragmentListsOnlyTheChosenKinds(t *testing.T) {
	h := New(depsWith(hostileFake(), kindsEstate()), Options{Loopback: true})
	code, hd, frag := getHX(t, h, "/estate?kind=domain&kind=service")
	if code != 200 || !strings.Contains(hd.Get("Vary"), "HX-Request") {
		t.Fatalf("%d, Vary %q", code, hd.Get("Vary"))
	}
	if strings.Contains(strings.ToLower(frag), "<html") || strings.Contains(frag, "<header") {
		t.Errorf("an htmx request must get a fragment:\n%.300s", frag)
	}
	for _, want := range []string{"example.com", "Example DNS Provider", "kind=domain", "kind=service"} {
		if !strings.Contains(frag, want) {
			t.Errorf("fragment lacks %q", want)
		}
	}
	for _, not := range []string{"a.example.com", "ip:192.0.2.10"} {
		if strings.Contains(frag, ">"+not+"<") || strings.Contains(frag, "id="+not) {
			t.Errorf("fragment lists %q although its kind was not chosen", not)
		}
	}
	// The edge table keeps only edges whose two ends are both shown.
	i, j := strings.Index(frag, "<h3>Edges"), strings.Index(frag, "<h3>Absences")
	if i < 0 || j < i {
		t.Fatalf("no edge table:\n%s", frag)
	}
	if !strings.Contains(frag[i:j], "uses") || strings.Contains(frag[i:j], "ptr") || strings.Contains(frag[i:j], "resolves_to") {
		t.Errorf("edge table = %s", frag[i:j])
	}
}

func TestKindFilterFragmentEscapesEveryValue(t *testing.T) {
	h := New(depsWith(hostileFake(), kindsEstate()), Options{Loopback: true})
	_, _, frag := getHX(t, h, "/estate?kind=ip")
	for _, bad := range rawAttack {
		if strings.Contains(frag, bad) {
			t.Errorf("fragment contains raw %q", bad)
		}
	}
	if !strings.Contains(frag, "&lt;script&gt;") {
		t.Errorf("the hostile label should appear escaped:\n%s", frag)
	}
}

func TestUnknownKindsAreIgnoredAndNeverReflected(t *testing.T) {
	h := New(depsWith(hostileFake(), kindsEstate()), Options{Loopback: true})
	evil := `"><script>alert(1)</script>`
	_, _, plain := get(t, h, "/estate")
	for _, q := range []string{"/estate?kind=" + escQuery(evil), "/estate?kind=", "/estate?kind=nosuch&kind=" + escQuery(evil)} {
		_, _, body := get(t, h, q)
		if body != plain {
			t.Errorf("%s: unknown kinds must leave the page unchanged", q)
		}
	}
	_, _, js := get(t, h, "/estate/graph.json?g=e1&kind="+escQuery(evil))
	if nodes, _, _ := graphOut(t, js); len(nodes) != 4 {
		t.Errorf("an unknown kind must not filter: %d nodes", len(nodes))
	}
}

func TestUnfilteredPageOffersTheFilterAndDrawsEveryNode(t *testing.T) {
	h := New(depsWith(hostileFake(), kindsEstate()), Options{Loopback: true})
	_, _, page := get(t, h, "/estate")
	for _, w := range []string{`id="estate-graphs"`, `action="/estate"`, `method="get"`, `name="kind"`, `hx-get="/estate"`, `hx-target="#estate-graphs"`, `value="service"`, `class="graph" data-src="/estate/graph.json?g=e1"`} {
		if !strings.Contains(page, w) {
			t.Errorf("page lacks %q", w)
		}
	}
	if strings.Contains(page, "checked") {
		t.Error("no kind is chosen on the plain page")
	}
	_, _, chosen := get(t, h, "/estate?kind=ip")
	if !regexp.MustCompile(`value="ip"[^>]*checked`).MatchString(chosen) || strings.Contains(chosen, `value="host" checked`) {
		t.Errorf("the chosen kind should be checked:\n%s", chosen)
	}
	if !strings.Contains(chosen, `data-src="/estate/graph.json?g=e1&amp;kind=ip"`) && !strings.Contains(chosen, `data-src="/estate/graph.json?g=e1&kind=ip"`) {
		t.Errorf("the graph box should ask for the filtered data:\n%s", chosen)
	}
}

func TestGraphJSONFilterKeepsChosenKindsAndSaysSo(t *testing.T) {
	h := New(depsWith(hostileFake(), kindsEstate()), Options{Loopback: true})
	_, _, body := get(t, h, "/estate/graph.json?g=e1&kind=ip&kind=host")
	nodes, edges, raw := graphOut(t, body)
	if len(nodes) != 2 || len(edges) != 4 || raw["filtered"] != true || raw["nodeTotal"].(float64) != 4 {
		t.Errorf("nodes=%v edges=%d raw=%v", nodes, len(edges), raw)
	}
	// An edge keeps its file index in its link, so the record is the same one.
	var g struct{ Edges []struct{ Href string } }
	_ = json.Unmarshal([]byte(body), &g)
	if g.Edges[0].Href != "/estate/edge?g=e1&i=0" {
		t.Errorf("href = %q", g.Edges[0].Href)
	}
	_, _, all := get(t, h, "/estate/graph.json?g=e1")
	if _, _, raw := graphOut(t, all); raw["filtered"] != false {
		t.Errorf("unfiltered graph says filtered: %v", raw["filtered"])
	}
}

func TestKindFilterNeverQueriesTheStore(t *testing.T) {
	f := hostileFake()
	opens := 0
	d := depsWith(f, kindsEstate())
	d.Open = func(context.Context) (core.DashboardStore, error) { opens++; return f, nil }
	h := New(d, Options{Loopback: true})
	for _, p := range []string{"/estate", "/estate?kind=ip", "/estate/graph.json?g=e1", "/estate/graph.json?g=e1&kind=ip", estNode, "/estate/edge?g=e1&i=0"} {
		get(t, h, p)
		getHX(t, h, p)
	}
	if opens != 0 || f.overlayCalls != 0 {
		t.Errorf("opens = %d, overlay queries = %d: loading the map and its records must not read the store", opens, f.overlayCalls)
	}
}

// ---- overlays ----

func overlayFake() *fake {
	f := hostileFake()
	f.rep = []core.Reputation{
		{Indicator: "192.0.2.10", Verdict: "malicious", Observed: time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC), Source: "greynoise"},
		{Indicator: "192.0.2.10", Verdict: "benign", Observed: time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC), Source: "abuseipdb"},
		{Indicator: "192.0.2.99", Verdict: "malicious", Observed: now, Source: "other"},
	}
	f.seenAt, f.seenOK = time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC), true
	return f
}

func do(t *testing.T, h http.Handler, method, target string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = "127.0.0.1:8090"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Header(), rec.Body.String()
}

func TestOverlayShowsLatestReputationPerSourceAndLastSeen(t *testing.T) {
	f := overlayFake()
	h := New(depsWith(f, weightEstate()), Options{Loopback: true})
	code, hd, frag := getHX(t, h, estOver)
	if code != 200 || !strings.Contains(hd.Get("Vary"), "HX-Request") {
		t.Fatalf("%d, Vary %q", code, hd.Get("Vary"))
	}
	for _, w := range []string{"reputation: malicious (greynoise, observed 2026-11-03)", "reputation: benign (abuseipdb, observed 2026-10-30)", "last seen in logs: 2026-11-04"} {
		if !strings.Contains(frag, w) {
			t.Errorf("overlay lacks %q:\n%s", w, frag)
		}
	}
	if strings.Contains(frag, "other") || strings.Contains(frag, "192.0.2.99") {
		t.Error("another address's row leaked into the overlay")
	}
	if strings.Contains(strings.ToLower(frag), "<html") {
		t.Error("an htmx request must get a fragment")
	}
	// The question asked of the store: bound values, the canonical address, the latest row per
	// source, the key field of serve, and a window of 30 days ending at the injected clock.
	if got := f.repFilter; len(got.Indicators) != 1 || got.Indicators[0] != "192.0.2.10" || !got.Latest || got.Limit <= 0 {
		t.Errorf("reputation filter = %+v", got)
	}
	if f.seenField != "client_ip" || f.seenValue != "192.0.2.10" || !f.seenSince.Equal(now.Add(-30*24*time.Hour)) {
		t.Errorf("last-seen question = %q %q %v", f.seenField, f.seenValue, f.seenSince)
	}
	if f.overlayCalls != 2 || f.closed != 1 {
		t.Errorf("one open, two questions, one close expected: calls %d, closed %d", f.overlayCalls, f.closed)
	}
}

func TestOverlayHasFourDistinctTextsThatAreNeverMerged(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fake, *Deps)
		want   []string
		not    []string
	}{
		{"result", func(*fake, *Deps) {}, []string{"reputation: malicious (greynoise", "last seen in logs: 2026-11-04"},
			[]string{"never looked up", "none in the last 30 days", "could not read the store"}},
		{"none in 30 days, never looked up", func(f *fake, _ *Deps) { f.rep, f.seenOK = nil, false },
			[]string{"reputation: never looked up", "last seen in logs: none in the last 30 days"},
			[]string{"could not read the store", "malicious", "reputation: none in the last 30 days"}},
		{"could not read", func(f *fake, _ *Deps) { f.repErr, f.seenErr = errors.New("io: boom"), errors.New("io: boom") },
			[]string{"reputation: could not read the store", "last seen in logs: could not read the store"},
			[]string{"never looked up", "none in the last 30 days", "malicious", "boom"}},
		{"the open fails", func(_ *fake, d *Deps) {
			d.Open = func(context.Context) (core.DashboardStore, error) { return nil, errors.New("database is locked") }
		}, []string{"reputation: could not read the store", "last seen in logs: could not read the store"},
			[]string{"never looked up", "none in the last 30 days", "locked"}},
		{"the database is absent", func(_ *fake, d *Deps) {
			d.Open = func(context.Context) (core.DashboardStore, error) { return nil, core.ErrAbsent }
		}, []string{"reputation: could not read the store", "last seen in logs: could not read the store"},
			[]string{"never looked up", "none in the last 30 days"}},
		{"one half fails", func(f *fake, _ *Deps) { f.seenErr = errors.New("io") },
			[]string{"reputation: malicious", "last seen in logs: could not read the store"},
			[]string{"none in the last 30 days"}},
	}
	for _, tc := range cases {
		f := overlayFake()
		d := depsWith(f, weightEstate())
		tc.mutate(f, &d)
		_, _, frag := getHX(t, New(d, Options{Loopback: true}), estOver)
		for _, w := range tc.want {
			if !strings.Contains(frag, w) {
				t.Errorf("%s: lacks %q:\n%s", tc.name, w, frag)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(frag, n) {
				t.Errorf("%s: must not contain %q:\n%s", tc.name, n, frag)
			}
		}
	}
}

func TestSlowOverlayQueryHitsTheTimeLimitAndShowsCouldNotRead(t *testing.T) {
	old := overlayBudget
	overlayBudget = 30 * time.Millisecond
	t.Cleanup(func() { overlayBudget = old })
	f := overlayFake()
	f.seenBlock = true
	start := time.Now()
	_, _, frag := getHX(t, New(depsWith(f, weightEstate()), Options{Loopback: true}), estOver)
	if time.Since(start) > 5*time.Second {
		t.Fatal("the slow query was not stopped")
	}
	if !strings.Contains(frag, "last seen in logs: could not read the store") || !strings.Contains(frag, "reputation: malicious") {
		t.Errorf("a timed-out query is 'could not read', not 'none':\n%s", frag)
	}
	if strings.Contains(frag, "none in the last 30 days") {
		t.Error("a timeout must never read as an empty result")
	}
}

func TestOverlayCarriesNoVerdictColourAndEscapesStoredText(t *testing.T) {
	f := overlayFake()
	f.rep[0].Verdict = hostileUA
	f.rep[0].Source = hostileSum
	_, _, frag := getHX(t, New(depsWith(f, weightEstate()), Options{Loopback: true}), estOver)
	for _, bad := range rawAttack {
		if strings.Contains(frag, bad) {
			t.Errorf("overlay contains raw %q", bad)
		}
	}
	if strings.Contains(frag, "<script") {
		t.Error("script in overlay")
	}
	for _, m := range regexp.MustCompile(`class="([^"]*)"`).FindAllStringSubmatch(frag, -1) {
		if regexp.MustCompile(`destructive|warning|success|bad|warn|good|danger|red|green|badge|alert`).MatchString(m[1]) {
			t.Errorf("overlay carries a verdict colour class: %q", m[1])
		}
	}
	// A very long stored string is cut like any stored text.
	f.rep[0].Verdict = strings.Repeat("v", 2000)
	_, _, long := getHX(t, New(depsWith(f, weightEstate()), Options{Loopback: true}), estOver)
	if strings.Contains(long, strings.Repeat("v", textCap+1)) {
		t.Error("overlay text is not bounded")
	}
}

func TestOverlayRefusesWhatIsNotAnIPNodeOfALoadedMap(t *testing.T) {
	f := overlayFake()
	h := New(depsWith(f, weightEstate()), Options{Loopback: true})
	for _, p := range []string{
		"/estate/overlay?g=e1&id=host:a.example.com", // not an ip node
		"/estate/overlay?g=e1&id=ip:192.0.2.77",      // not in the file
		"/estate/overlay?g=nope&id=ip:192.0.2.10",    // no such map
		"/estate/overlay?g=e1",                       // no id
		"/estate/overlay?g=e1&id=" + escQuery("ip:' OR 1=1 --"),
	} {
		if code, _, _ := getHX(t, h, p); code != 404 {
			t.Errorf("%s = %d, want 404", p, code)
		}
	}
	if f.overlayCalls != 0 {
		t.Errorf("a refused request asked the store %d times: the id must be checked against the loaded estate first", f.overlayCalls)
	}
}

func TestOverlayRefusesAnIPNodeWhoseIdIsNotAnAddress(t *testing.T) {
	g := weightEstate()
	g.Nodes[0].ID = "ip:192.0.2.10'; DROP TABLE events; --"
	g.Edges = nil
	f := overlayFake()
	h := New(depsWith(f, g), Options{Loopback: true})
	code, _, _ := getHX(t, h, "/estate/overlay?g=e1&id="+escQuery(g.Nodes[0].ID))
	if code != 404 || f.overlayCalls != 0 {
		t.Errorf("code %d, store questions %d: only a parsed address may reach the store", code, f.overlayCalls)
	}
}

func TestOverlayIsGETOnly(t *testing.T) {
	h := New(depsWith(overlayFake(), weightEstate()), Options{Loopback: true})
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		code, _, _ := do(t, h, m, estOver)
		if code != 405 {
			t.Errorf("%s = %d, want 405", m, code)
		}
	}
}

func TestOverlayPageWithoutHTMXIsAFullPageWithTheSecurityHeaders(t *testing.T) {
	h := New(depsWith(overlayFake(), weightEstate()), Options{Loopback: true})
	code, hd, body := get(t, h, estOver)
	if code != 200 || !strings.Contains(body, "<html") || !strings.Contains(hd.Get("Vary"), "HX-Request") || hd.Get("Content-Security-Policy") != csp {
		t.Errorf("%d, vary %q, csp %q", code, hd.Get("Vary"), hd.Get("Content-Security-Policy"))
	}
}

func TestIPRecordOpensTheOverlayLazilyAndOtherKindsDoNot(t *testing.T) {
	h := New(depsWith(overlayFake(), weightEstate()), Options{Loopback: true})
	_, _, frag := getHX(t, h, estNode)
	if !strings.Contains(frag, `hx-get="/estate/overlay?g=e1&amp;id=ip%3A192.0.2.10"`) && !strings.Contains(frag, `hx-get="/estate/overlay?g=e1&id=ip%3A192.0.2.10"`) {
		t.Errorf("the ip record in the sheet lacks the lazy overlay:\n%s", frag)
	}
	if !strings.Contains(frag, `hx-trigger="load"`) {
		t.Error("the overlay should load when the record opens")
	}
	_, _, page := get(t, h, estNode)
	if strings.Contains(page, "hx-get") || !strings.Contains(page, "/estate/overlay?g=e1") {
		t.Errorf("a full page has no panel: the overlay is a plain link there:\n%s", page)
	}
	_, _, host := getHX(t, h, "/estate/node?g=e1&id=host:a.example.com")
	if strings.Contains(host, "/estate/overlay") {
		t.Error("only ip nodes get an overlay")
	}
}

func TestMapLoadAndRecordOpenMakeNoOverlayQuery(t *testing.T) {
	f := overlayFake()
	h := New(depsWith(f, weightEstate()), Options{Loopback: true})
	for _, p := range []string{"/estate", "/estate/graph.json?g=e1", estNode, "/estate/edge?g=e1&i=0"} {
		get(t, h, p)
		getHX(t, h, p)
	}
	if f.overlayCalls != 0 {
		t.Errorf("%d overlay queries before any overlay was asked for", f.overlayCalls)
	}
	getHX(t, h, estOver)
	if f.overlayCalls != 2 {
		t.Errorf("one opened record = %d queries, want 2 (reputation, last seen)", f.overlayCalls)
	}
}

func TestOverlayWithoutAConfiguredKeyFieldSaysSo(t *testing.T) {
	f := overlayFake()
	d := depsWith(f, weightEstate())
	d.Fields.Key = ""
	_, _, frag := getHX(t, New(d, Options{Loopback: true}), estOver)
	if !strings.Contains(frag, "last seen in logs: no key field is configured") || f.seenField != "" {
		t.Errorf("without a key field the log question must not be asked:\n%s", frag)
	}
}
