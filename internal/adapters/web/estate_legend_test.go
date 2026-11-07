package web

import (
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const evilRel = `rel"><script>alert(21)</script>`

// legendGraph has stated and inferred edges of several relations, one with a hostile name.
func legendGraph(id, subject string) core.EstateGraph {
	n := func(nid, kind string) core.EstateNode {
		return core.EstateNode{ID: nid, Kind: kind, Label: nid, Source: "dns", Method: "m", Observed: t0}
	}
	e := func(from, to, rel, src, conf string) core.EstateEdge {
		return core.EstateEdge{From: from, To: to, Relation: rel, Source: src, Method: "m", Observed: t0, Confidence: conf}
	}
	return core.EstateGraph{ID: id, Subject: subject, Caveat: "c",
		Nodes: []core.EstateNode{n("ip:192.0.2.10", "ip"), n("host:a.example.com", "host"), n("domain:example.com", "domain"), n("service:dns-provider", "service")},
		Edges: []core.EstateEdge{
			e("ip:192.0.2.10", "host:a.example.com", "ptr", "rdns", "stated"),
			e("ip:192.0.2.10", "host:a.example.com", "ptr", "dns", "stated"),
			e("domain:example.com", "ip:192.0.2.10", "resolves_to", "passive-dns", "inferred"),
			e("domain:example.com", "host:a.example.com", "ct_candidate", "crt.sh", "inferred"),
			e("domain:example.com", "service:dns-provider", "uses", "dns", "stated"),
			e("domain:example.com", "service:dns-provider", evilRel, "dns", "stated"),
		},
	}
}

func legendHandler(gs ...core.EstateGraph) http.Handler {
	d := newDeps(hostileFake())
	d.Estate = fakeEstate{g: gs}
	return New(d, Options{Loopback: true})
}

var legendLine = regexp.MustCompile(`<li>([^<]+): (\d+)</li>`)

// legendsOf reads every legend in a body: relation (as text) to count, one map per graph.
func legendsOf(t *testing.T, body string) []map[string]int {
	t.Helper()
	var out []map[string]int
	for rest := body; ; {
		i := strings.Index(rest, `<ul id="legend-`)
		if i < 0 {
			break
		}
		rest = rest[i:]
		end := strings.Index(rest, "</ul>")
		m := map[string]int{}
		for _, l := range legendLine.FindAllStringSubmatch(rest[:end], -1) {
			n, _ := strconv.Atoi(l[2])
			m[html.UnescapeString(l[1])] = n
		}
		out = append(out, m)
		rest = rest[end:]
	}
	return out
}

func drawnRelations(t *testing.T, h http.Handler, g, q string) map[string]int {
	t.Helper()
	_, _, js := get(t, h, "/estate/graph.json?g="+g+"&"+q)
	_, edges, _ := graphOut(t, js)
	m := map[string]int{}
	for _, e := range edges {
		m[e.Relation]++
	}
	return m
}

func sameCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestLegendCountsMatchTheDrawnEdges(t *testing.T) {
	h := legendHandler(legendGraph("e1", ""))
	for _, q := range []string{"", "kind=ip&kind=host", "confidence=inferred", "confidence=stated&kind=domain&kind=service", "kind=domain&kind=ip&confidence=inferred&confidence=stated"} {
		_, _, frag := getHX(t, h, "/estate?"+q)
		ls := legendsOf(t, frag)
		if len(ls) != 1 {
			t.Fatalf("%q: want one legend, got %d:\n%s", q, len(ls), frag)
		}
		if want := drawnRelations(t, h, "e1", q); !sameCounts(ls[0], want) {
			t.Errorf("%q: legend %v does not match the drawn edges %v", q, ls[0], want)
		}
	}
	_, _, all := getHX(t, h, "/estate")
	if l := legendsOf(t, all)[0]; l["ptr"] != 2 || l["resolves_to"] != 1 || l[evilRel] != 1 || len(l) != 5 {
		t.Errorf("unfiltered legend = %v", l)
	}
	if strings.Contains(all, "<script>alert(21)") || strings.Contains(all, evilRel) {
		t.Error("a hostile relation reached the legend unescaped")
	}
}

func TestConfidenceFilterKeepsOnlyChosenEdgesAndTheirRecordIndexes(t *testing.T) {
	h := legendHandler(legendGraph("e1", ""))
	_, _, js := get(t, h, "/estate/graph.json?g=e1&confidence=inferred")
	_, edges, _ := graphOut(t, js)
	if len(edges) != 2 {
		t.Fatalf("inferred edges = %d, want 2: %+v", len(edges), edges)
	}
	if drawnRelations(t, h, "e1", "confidence=inferred")["resolves_to"] != 1 || drawnRelations(t, h, "e1", "confidence=stated")["resolves_to"] != 0 {
		t.Error("confidence filter keeps the wrong edges")
	}
	// An edge keeps its file index: resolves_to is the third claim.
	if !strings.Contains(js, `"/estate/edge?g=e1\u0026i=2"`) && !strings.Contains(js, `/estate/edge?g=e1&i=2`) {
		t.Errorf("filtered edge lost its file index:\n%s", js)
	}
	// Both chosen, or an unknown value, is the same as none.
	_, _, plain := get(t, h, "/estate/graph.json?g=e1")
	for _, q := range []string{"confidence=stated&confidence=inferred", "confidence=bogus", "confidence=" + escQuery(`"><script>`)} {
		if _, _, b := get(t, h, "/estate/graph.json?g=e1&"+q); b != plain {
			t.Errorf("%q should not filter", q)
		}
	}
	// The edge table follows the filter and says so.
	_, _, frag := getHX(t, h, "/estate?confidence=inferred")
	i, j := strings.Index(frag, "<h3>Edges"), strings.Index(frag, "<h3>Absences")
	if i < 0 || j < i || !strings.Contains(frag[i:j], "(2 of 6") || strings.Contains(frag[i:j], ">ptr<") || !strings.Contains(frag[i:j], "ct_candidate") {
		t.Errorf("edge table does not follow the confidence filter:\n%s", frag)
	}
}

func TestConfidenceFilterWorksWithKindFilterAndLayers(t *testing.T) {
	h := legendHandler(legendGraph("op1", "operated"), legendGraph("adv1", "adversary"))
	q := "kind=ip&kind=host&kind=domain&confidence=inferred"
	_, _, frag := getHX(t, h, "/estate?"+q)
	if !strings.Contains(frag, ">Operated<") || !strings.Contains(frag, ">Adversary and third-party<") {
		t.Errorf("layers lost:\n%s", frag)
	}
	ls := legendsOf(t, frag)
	if len(ls) != 2 {
		t.Fatalf("want a legend per graph, got %d", len(ls))
	}
	for i, g := range []string{"op1", "adv1"} {
		want := drawnRelations(t, h, g, q)
		if !sameCounts(ls[i], want) || want["resolves_to"] != 1 || want["ct_candidate"] != 1 || len(want) != 2 {
			t.Errorf("%s: legend %v, drawn %v", g, ls[i], want)
		}
	}
	// The graph box asks for the data with both filters, and the form keeps both checked.
	for _, w := range []string{"kind=ip", "confidence=inferred"} {
		if !strings.Contains(frag, w) {
			t.Errorf("data-src lacks %q", w)
		}
	}
	_, _, page := get(t, h, "/estate?"+q)
	if !regexp.MustCompile(`name="confidence" value="inferred"[^>]*checked`).MatchString(page) || regexp.MustCompile(`name="confidence" value="stated"[^>]*checked`).MatchString(page) {
		t.Errorf("only inferred should be checked:\n%s", page)
	}
	if !regexp.MustCompile(`name="kind" value="ip"[^>]*checked`).MatchString(page) {
		t.Error("the kind filter must stay checked beside the confidence filter")
	}
	// The one form drives the same fragment target, with no script of its own.
	if !strings.Contains(page, `hx-target="#estate-graphs"`) || strings.Count(page, `name="confidence"`) != 2 {
		t.Errorf("confidence checkboxes missing from the filter form:\n%s", page)
	}
}

func TestConfidenceFilterNeverQueriesTheStore(t *testing.T) {
	f := hostileFake()
	h := New(depsWith(f, legendGraph("e1", "")), Options{Loopback: true})
	get(t, h, "/estate?confidence=inferred")
	getHX(t, h, "/estate?confidence=inferred&kind=ip")
	get(t, h, "/estate/graph.json?g=e1&confidence=inferred")
	if f.overlayCalls != 0 {
		t.Errorf("overlay queries = %d", f.overlayCalls)
	}
}
