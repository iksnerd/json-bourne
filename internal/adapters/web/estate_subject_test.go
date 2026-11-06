package web

import (
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// subjGraph is a small map with one ip node and one ptr edge from one source, so its
// edge weight is 1 whatever any other file says.
func subjGraph(id, subject string) core.EstateGraph {
	n := func(nid, kind string) core.EstateNode {
		return core.EstateNode{ID: nid, Kind: kind, Label: nid, Source: "rdns", Method: "m", Observed: t0}
	}
	return core.EstateGraph{ID: id, Subject: subject, Caveat: "c",
		Nodes: []core.EstateNode{n("ip:192.0.2.10", "ip"), n("host:a.example.com", "host")},
		Edges: []core.EstateEdge{{From: "ip:192.0.2.10", To: "host:a.example.com", Relation: "ptr", Source: "rdns", Method: "m", Observed: t0, Confidence: "stated"}},
	}
}

func subjDeps(gs ...core.EstateGraph) Deps {
	d := newDeps(hostileFake())
	d.Estate = fakeEstate{g: gs}
	return d
}

func TestEstateGroupsGraphsUnderThreeFixedHeadings(t *testing.T) {
	h := New(subjDeps(subjGraph("u1", ""), subjGraph("adv1", "adversary"), subjGraph("op1", "operated")), Options{Loopback: true})
	_, _, body := get(t, h, "/estate")
	iOp := strings.Index(body, ">Operated<")
	iAdv := strings.Index(body, ">Adversary and third-party<")
	iUn := strings.Index(body, ">Unclassified<")
	if iOp < 0 || iAdv < 0 || iUn < 0 || !(iOp < iAdv && iAdv < iUn) {
		t.Fatalf("headings missing or out of order (%d %d %d):\n%s", iOp, iAdv, iUn, body)
	}
	at := func(id string) int { return strings.Index(body, ">"+id+"<") }
	if !(iOp < at("op1") && at("op1") < iAdv && iAdv < at("adv1") && at("adv1") < iUn && iUn < at("u1")) {
		t.Errorf("a graph is under the wrong heading: op1 %d adv1 %d u1 %d", at("op1"), at("adv1"), at("u1"))
	}
	// The htmx fragment (kind filter) keeps the grouping.
	_, _, frag := getHX(t, h, "/estate?kind=ip")
	if !strings.Contains(frag, ">Operated<") || !strings.Contains(frag, ">Adversary and third-party<") {
		t.Errorf("the filtered fragment lost the headings:\n%s", frag)
	}
}

func TestEstateOmitsAnEmptyLayerHeading(t *testing.T) {
	h := New(subjDeps(subjGraph("op1", "operated")), Options{Loopback: true})
	_, _, body := get(t, h, "/estate")
	if !strings.Contains(body, ">Operated<") || strings.Contains(body, "Adversary and third-party") || strings.Contains(body, ">Unclassified<") {
		t.Errorf("only layers that hold a graph get a heading:\n%s", body)
	}
}

func TestHostileSubjectNeverReachesThePage(t *testing.T) {
	evil := `"><script>alert(1)</script>`
	h := New(subjDeps(subjGraph("g1", evil)), Options{Loopback: true})
	for _, target := range []string{"/estate", "/estate?kind=ip", "/estate/graph.json?g=g1", "/estate/node?g=g1&id=ip:192.0.2.10"} {
		_, _, body := getHX(t, h, target)
		if strings.Contains(body, "alert(1)") || strings.Contains(body, evil) {
			t.Errorf("%s reflects the subject:\n%s", target, body)
		}
	}
	_, _, body := get(t, h, "/estate")
	if !strings.Contains(body, ">Unclassified<") {
		t.Errorf("an unknown subject falls under Unclassified, never under its own text:\n%s", body)
	}
}

func TestSameNodeInTwoLayersIsNotMergedAndWeightIsPerFile(t *testing.T) {
	op, adv := subjGraph("op1", "operated"), subjGraph("adv1", "adversary")
	// The adversary file holds the same claim from two more sources: weight 3 there.
	adv.Edges = append(adv.Edges,
		core.EstateEdge{From: "ip:192.0.2.10", To: "host:a.example.com", Relation: "ptr", Source: "dns", Method: "m", Observed: t0, Confidence: "stated"},
		core.EstateEdge{From: "ip:192.0.2.10", To: "host:a.example.com", Relation: "ptr", Source: "passive-dns", Method: "m", Observed: t0, Confidence: "stated"})
	h := New(subjDeps(op, adv), Options{Loopback: true})

	_, _, b1 := get(t, h, "/estate/graph.json?g=op1")
	n1, e1, _ := graphOut(t, b1)
	_, _, b2 := get(t, h, "/estate/graph.json?g=adv1")
	n2, e2, _ := graphOut(t, b2)
	if len(n1) != 2 || len(n2) != 2 || len(e1) != 1 || len(e2) != 3 {
		t.Fatalf("each file draws only its own nodes and edges: %d/%d nodes, %d/%d edges", len(n1), len(n2), len(e1), len(e2))
	}
	if e1[0].Weight != 1 {
		t.Errorf("operated edge weight = %d: corroboration must not cross files", e1[0].Weight)
	}
	for _, e := range e2 {
		if e.Weight != 3 {
			t.Errorf("adversary edge weight = %d, want 3 (its own file)", e.Weight)
		}
	}
	// The page shows the node under each heading: two occurrences, no line between layers.
	_, _, page := get(t, h, "/estate")
	for _, g := range []string{"op1", "adv1"} {
		if !strings.Contains(page, `href="/estate/node?g=`+g+`&amp;id=`) && !strings.Contains(page, `href="/estate/node?g=`+g+`&id=`) {
			t.Errorf("the ip node must be drawn in layer %s:\n%s", g, page)
		}
	}
}
