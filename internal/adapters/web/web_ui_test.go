package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func getHX(t *testing.T, h http.Handler, target string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	req.Host = "127.0.0.1:8090"
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Header(), rec.Body.String()
}

func TestHTMXAsksGetFragmentsAndEveryPageVariesOnIt(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	for _, p := range []string{"/findings", "/watch", "/estate/node?g=e1&id=ip:192.0.2.10", "/estate/edge?g=e1&i=0"} {
		code, hd, frag := getHX(t, h, p)
		if code != 200 {
			t.Fatalf("%s (htmx) = %d", p, code)
		}
		if strings.Contains(strings.ToLower(frag), "<html") || strings.Contains(strings.ToLower(frag), "<!doctype") || strings.Contains(frag, "<header") {
			t.Errorf("%s: an htmx request must get a fragment, not the page:\n%.300s", p, frag)
		}
		if !strings.Contains(hd.Get("Vary"), "HX-Request") {
			t.Errorf("%s: Vary = %q, must name HX-Request", p, hd.Get("Vary"))
		}
		_, hd2, full := get(t, h, p)
		if !strings.Contains(full, "<html") || !strings.Contains(hd2.Get("Vary"), "HX-Request") {
			t.Errorf("%s: a plain request must get the whole page", p)
		}
		for _, bad := range rawAttack {
			if strings.Contains(frag, bad) {
				t.Errorf("%s: fragment contains raw %q", p, bad)
			}
		}
	}
}

func TestNothingInTheMarkupCanChangeState(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	bad := regexp.MustCompile(`(?i)hx-(post|put|patch|delete)|method="(post|put|patch|delete)"|hx-on|hx-vals|hx-headers`)
	for _, p := range allPages {
		_, _, body := get(t, h, p)
		if m := bad.FindString(body); m != "" {
			t.Errorf("%s: %q: the dashboard is GET only", p, m)
		}
	}
}

func TestHTMXIsConfiguredNotToEvaluateTextRunScriptsOrKeepPages(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	_, _, body := get(t, h, "/")
	m := regexp.MustCompile(`<meta name="htmx-config" content="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no htmx-config meta")
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &cfg); err != nil {
		t.Fatalf("htmx-config is not JSON: %v", err)
	}
	for k, want := range map[string]any{"allowEval": false, "allowScriptTags": false, "includeIndicatorStyles": false, "historyEnabled": false, "refreshOnHistoryMiss": false, "selfRequestsOnly": true} {
		if cfg[k] != want {
			t.Errorf("htmx config %s = %v, want %v", k, cfg[k], want)
		}
	}
}

func manyFindings() *fake {
	f := hostileFake()
	f.findings = []core.StoredFinding{
		{Run: "watch-1", Finding: core.Finding{Detector: "authspike", Tag: "spray:192.0.2.7", Severity: core.SevHigh, Summary: hostileSum}},
		{Run: "watch-1", Finding: core.Finding{Detector: "behaviour", Tag: "rare:probe", Severity: core.SevActivity, Summary: "a rare action"}},
		{Run: "hunt-2", Finding: core.Finding{Detector: "signup", Tag: "burst:x", Severity: core.SevInfo, Summary: "signup burst"}},
	}
	return f
}

func TestFindingsFilterNarrowsByTextAndSeverityAndSaysSo(t *testing.T) {
	h := New(newDeps(manyFindings()), Options{Loopback: true})
	_, _, body := getHX2(t, h, "/findings?q=rare")
	if !strings.Contains(body, "rare:probe") || strings.Contains(body, "spray:192.0.2.7") || !strings.Contains(body, "1 of 3 match the filter") {
		t.Errorf("text filter:\n%s", body)
	}
	_, _, body = getHX2(t, h, "/findings?sev=high")
	if !strings.Contains(body, "spray:192.0.2.7") || strings.Contains(body, "rare:probe") {
		t.Errorf("severity filter:\n%s", body)
	}
	// A filter that matches nothing is not "no findings": it says the findings are stored.
	_, _, body = getHX2(t, h, "/findings?q=zzz")
	if !strings.Contains(body, "matches this filter") || !strings.Contains(body, "3 are stored") || strings.Contains(body, "no findings stored: no hunt") {
		t.Errorf("an empty filter result must not read as an empty store:\n%s", body)
	}
	// An unknown severity is ignored, never an error and never reflected.
	_, _, body = getHX2(t, h, "/findings?sev=<script>")
	if strings.Contains(body, "<script") || !strings.Contains(body, "rare:probe") {
		t.Errorf("bad severity:\n%s", body)
	}
}

// getHX2 asks as htmx does, and returns the same triple as get.
func getHX2(t *testing.T, h http.Handler, target string) (int, http.Header, string) {
	t.Helper()
	return getHX(t, h, target)
}

func TestFindingsFilterEchoIsEscapedAndBounded(t *testing.T) {
	h := New(newDeps(manyFindings()), Options{Loopback: true})
	evil := `"><script>alert(1)</script>`
	_, _, body := get(t, h, "/findings?q="+escQuery(evil))
	body = ownScript.ReplaceAllString(body, "")
	if strings.Contains(body, "<script") || strings.Contains(body, evil) || !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the filter text was reflected unescaped, or not reflected at all:\n%s", body)
	}
	_, _, body = get(t, h, "/findings?q="+strings.Repeat("a", 500))
	if strings.Contains(body, strings.Repeat("a", 101)) {
		t.Error("the filter text is not bounded")
	}
}

func TestFilterFormWorksWithoutScript(t *testing.T) {
	h := New(newDeps(manyFindings()), Options{Loopback: true})
	_, _, body := get(t, h, "/findings")
	for _, want := range []string{`action="/findings"`, `method="get"`, "<noscript>", `name="q"`, `name="sev"`} {
		if !strings.Contains(body, want) {
			t.Errorf("filter form lacks %q", want)
		}
	}
}

func TestEstateGraphJSON(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	code, hd, body := get(t, h, "/estate/graph.json?g=e1")
	if code != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "application/json") || hd.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %q", code, hd.Get("Content-Type"))
	}
	// The hostile label is data in a JSON string: < and > are escaped, so the document is
	// inert even if something served it as HTML.
	if strings.Contains(body, "<script") || !strings.Contains(body, `\u003cscript\u003e`) {
		t.Errorf("hostile text not escaped in the JSON:\n%s", body)
	}
	var g struct {
		ID         string `json:"id"`
		NodeTotal  int    `json:"nodeTotal"`
		EdgeTotal  int    `json:"edgeTotal"`
		Components int    `json:"components"`
		Cut        bool   `json:"cut"`
		Nodes      []struct{ ID, Kind, Label, Href string }
		Edges      []struct{ Source, Target, Relation, Href string }
	}
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatal(err)
	}
	if g.ID != "e1" || len(g.Nodes) != 2 || len(g.Edges) != 1 || g.Components != 1 || g.Cut {
		t.Errorf("graph = %+v", g)
	}
	for _, n := range g.Nodes {
		if !strings.HasPrefix(n.Href, "/estate/node?g=e1&id=") {
			t.Errorf("node link %q is not one this dashboard built", n.Href)
		}
	}
	if g.Edges[0].Href != "/estate/edge?g=e1&i=0" {
		t.Errorf("edge link = %q", g.Edges[0].Href)
	}
	if code, _, _ := get(t, h, "/estate/graph.json?g=nope"); code != 404 {
		t.Errorf("unknown map = %d, want 404", code)
	}
}

func TestEstateGraphJSONIsBounded(t *testing.T) {
	g := core.EstateGraph{ID: "big", Caveat: "c"}
	for i := range 350 {
		g.Nodes = append(g.Nodes, core.EstateNode{ID: fmt.Sprintf("ip:10.0.%d.%d", i/250, i%250), Kind: "ip", Label: "n", Source: "rdns", Method: "m", Observed: "t"})
	}
	d := newDeps(hostileFake())
	d.Estate = fakeEstate{g: []core.EstateGraph{g}}
	_, _, body := get(t, New(d, Options{Loopback: true}), "/estate/graph.json?g=big")
	var out struct {
		NodeTotal int  `json:"nodeTotal"`
		Cut       bool `json:"cut"`
		Nodes     []struct{}
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Nodes) != graphJSONNodes || out.NodeTotal != 350 || !out.Cut {
		t.Errorf("kept %d of %d, cut=%v", len(out.Nodes), out.NodeTotal, out.Cut)
	}
}

func TestPanelLinksOnlyWhereThereIsAPanel(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	_, _, list := get(t, h, "/estate")
	if !strings.Contains(list, `id="estate-detail"`) || !strings.Contains(list, `hx-target="#estate-detail"`) || !strings.Contains(list, `class="graph" data-src="/estate/graph.json?g=e1"`) {
		t.Errorf("the estate page lacks the panel, its htmx links or the graph container")
	}
	if !strings.Contains(list, `<figure class="static-graph">`) || !strings.Contains(list, "<svg") {
		t.Error("the drawing that needs no script is gone")
	}
	_, _, page := get(t, h, "/estate/node?g=e1&id=ip:192.0.2.10")
	if strings.Contains(page, "hx-get") || strings.Contains(page, "hx-target") {
		t.Error("a full node page has no panel, so its links must be plain links")
	}
	_, _, frag := getHX(t, h, "/estate/node?g=e1&id=ip:192.0.2.10")
	if !strings.Contains(frag, `hx-target="#estate-detail"`) || !strings.Contains(frag, "open this record as a page") {
		t.Errorf("the panel fragment lacks htmx links or the way out to a page:\n%s", frag)
	}
}

// The vendored libraries are the exact files published to npm, pinned by hash. A change
// to either file must be a deliberate edit of this test.
func TestVendoredLibrariesArePinned(t *testing.T) {
	for name, want := range map[string]string{
		"d3.min.js":   "f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539", // d3 7.9.0, npm tarball integrity verified
		"htmx.min.js": "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717", // htmx.org 2.0.11, npm tarball integrity verified
	} {
		b, err := staticFS.ReadFile("static/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s sha256 = %s, want the pinned %s", name, got, want)
		}
	}
	for _, name := range []string{"d3.LICENSE.txt", "htmx.LICENSE.txt"} {
		b, err := staticFS.ReadFile("static/" + name)
		if err != nil || len(b) < 100 {
			t.Errorf("%s: a vendored library ships with its licence (%v)", name, err)
		}
	}
	d3, _ := staticFS.ReadFile("static/d3.min.js")
	if !strings.HasPrefix(string(d3), "// https://d3js.org v7.9.0") {
		t.Error("d3.min.js is not 7.9.0")
	}
}

func TestEscQuery(t *testing.T) {
	for in, want := range map[string]string{
		"abc-._~09":  "abc-._~09",
		"a b&c=d":    "a%20b%26c%3Dd",
		"ip:1.2.3.4": "ip%3A1.2.3.4",
		`"><`:        "%22%3E%3C",
		"é":          "%C3%A9",
		"":           "",
	} {
		if got := escQuery(in); got != want {
			t.Errorf("escQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func renderSheet(t *testing.T, p sheetProps) string {
	t.Helper()
	var b strings.Builder
	if err := sheet(p).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// The sheet primitive's markup is a contract with sheet.js and with assistive
// technology: a dialog named by its visible title, honest about being modal, closed and
// inert until opened, with a close control that says what it closes.
func TestSheetMarkupContract(t *testing.T) {
	h := renderSheet(t, sheetProps{ID: "s1", Title: "Record", Description: "what it shows"})
	for _, want := range []string{
		`id="s1"`, `role="dialog"`, `aria-modal="false"`, `aria-labelledby="s1-title"`, `id="s1-title"`,
		`aria-describedby="s1-desc"`, `id="s1-desc"`, `data-sheet`, `data-state="closed"`, `data-side="right"`,
		`data-modal="false"`, `tabindex="-1"`, ` inert`, `data-sheet-close`, `aria-label="Close Record"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("sheet lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "sheet-overlay") {
		t.Error("a non-modal sheet has no overlay")
	}
	// Without a description there is no aria-describedby pointing at nothing.
	if h2 := renderSheet(t, sheetProps{ID: "s2", Title: "T"}); strings.Contains(h2, "aria-describedby") || strings.Contains(h2, "s2-desc") {
		t.Errorf("a sheet with no description must not reference one:\n%s", h2)
	}
}

func TestSheetModalAndSideVariants(t *testing.T) {
	m := renderSheet(t, sheetProps{ID: "m", Title: "T", Modal: true, Side: "left"})
	for _, want := range []string{`aria-modal="true"`, `data-modal="true"`, `data-side="left"`, `data-sheet-overlay="m"`, `class="sheet-overlay"`} {
		if !strings.Contains(m, want) {
			t.Errorf("modal sheet lacks %q", want)
		}
	}
	if b := renderSheet(t, sheetProps{ID: "b", Title: "T", Side: "bottom"}); !strings.Contains(b, `data-side="bottom"`) {
		t.Error("bottom side lost")
	}
	// An unknown side is the default, never a value that reaches an attribute.
	if x := renderSheet(t, sheetProps{ID: "x", Title: "T", Side: `"><script>`}); !strings.Contains(x, `data-side="right"`) || strings.Contains(x, "<script") {
		t.Errorf("unknown side:\n%s", x)
	}
}

func TestSheetEscapesItsText(t *testing.T) {
	h := renderSheet(t, sheetProps{ID: "e", Title: `<script>alert(1)</script>`, Description: `"onmouseover="x`})
	if strings.Contains(h, "<script") || strings.Contains(h, `"onmouseover="`) || !strings.Contains(h, "&lt;script&gt;") {
		t.Errorf("sheet text was not escaped:\n%s", h)
	}
}

func TestEstatePageHasTheSheetThatHTMXFills(t *testing.T) {
	h := New(newDeps(hostileFake()), Options{Loopback: true})
	_, _, page := get(t, h, "/estate")
	i, j := strings.Index(page, `id="estate-sheet"`), strings.Index(page, `id="estate-detail"`)
	if i < 0 || j < i {
		t.Fatal("the htmx target #estate-detail must sit inside the sheet #estate-sheet")
	}
	if a, b, c := strings.Index(page, "/static/sheet.js"), strings.Index(page, "/static/d3.min.js"), strings.Index(page, "/static/estate.js"); !(a > 0 && a < b && b < c) {
		t.Errorf("script order must be sheet, d3, estate: %d %d %d", a, b, c)
	}
}
