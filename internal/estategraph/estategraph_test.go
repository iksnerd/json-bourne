package estategraph

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func node(id, kind string) core.EstateNode { return core.EstateNode{ID: id, Kind: kind, Label: id} }
func edge(from, to, rel string) core.EstateEdge {
	return core.EstateEdge{From: from, To: to, Relation: rel, Source: "dns", Confidence: "stated"}
}

// Two islands: {ip:a, host:a, network:a} and {ip:b, domain:b}.
func twoIslands() core.EstateGraph {
	return core.EstateGraph{ID: "g",
		Nodes: []core.EstateNode{node("ip:a", "ip"), node("host:a", "host"), node("network:a", "network"), node("ip:b", "ip"), node("domain:b", "domain")},
		Edges: []core.EstateEdge{edge("ip:a", "host:a", "ptr"), edge("ip:a", "network:a", "within"), edge("domain:b", "ip:b", "resolves_to")},
	}
}

func byID(l Layout) map[string]Node {
	m := map[string]Node{}
	for _, n := range l.Nodes {
		m[n.ID] = n
	}
	return m
}

func TestDegreeAndComponents(t *testing.T) {
	l := Build(twoIslands(), 100)
	n := byID(l)
	if l.Components != 2 {
		t.Errorf("components = %d, want 2", l.Components)
	}
	if n["ip:a"].Degree != 2 || n["host:a"].Degree != 1 || n["domain:b"].Degree != 1 {
		t.Errorf("degrees = ip:a %d, host:a %d, domain:b %d", n["ip:a"].Degree, n["host:a"].Degree, n["domain:b"].Degree)
	}
	if n["ip:a"].Component != n["host:a"].Component || n["ip:a"].Component == n["ip:b"].Component {
		t.Errorf("components wrong: %+v", n)
	}
	if n["ip:a"].Component != 0 {
		t.Errorf("components are numbered from the first node in file order, got %d", n["ip:a"].Component)
	}
}

// Two observations of one pair (another source or relation) are two edges in the file
// and one neighbour in the topology: the degree counts neighbours, the list keeps both.
func TestTwoObservationsOfOnePairKeepBothEdgesAndCountOneNeighbour(t *testing.T) {
	g := core.EstateGraph{Nodes: []core.EstateNode{node("ip:a", "ip"), node("host:a", "host")},
		Edges: []core.EstateEdge{edge("ip:a", "host:a", "ptr"), edge("host:a", "ip:a", "resolves_to"), edge("ip:a", "host:a", "ptr")}}
	l := Build(g, 10)
	if len(l.Edges) != 3 {
		t.Fatalf("edges = %d, want 3 (every observation is kept)", len(l.Edges))
	}
	if d := byID(l)["ip:a"].Degree; d != 1 {
		t.Errorf("degree = %d, want 1", d)
	}
	for i, e := range l.Edges {
		if e.Index != i {
			t.Errorf("edge %d carries index %d: the detail page is addressed by file index", i, e.Index)
		}
	}
}

func TestDanglingAndSelfEdgesAreIgnoredNotFatal(t *testing.T) {
	g := core.EstateGraph{Nodes: []core.EstateNode{node("ip:a", "ip")},
		Edges: []core.EstateEdge{edge("ip:a", "host:missing", "ptr"), edge("ip:a", "ip:a", "self")}}
	l := Build(g, 10)
	if len(l.Edges) != 0 || len(l.Nodes) != 1 || byID(l)["ip:a"].Degree != 0 {
		t.Errorf("got %d nodes, %d edges, degree %d", len(l.Nodes), len(l.Edges), byID(l)["ip:a"].Degree)
	}
}

func TestEmptyGraph(t *testing.T) {
	l := Build(core.EstateGraph{}, 10)
	if len(l.Nodes) != 0 || len(l.Edges) != 0 || l.Cut || l.NodeTotal != 0 {
		t.Errorf("empty graph gave %+v", l)
	}
}

func TestOverTheLimitKeepsTheMostConnectedNodesAndSaysSo(t *testing.T) {
	g := core.EstateGraph{Nodes: []core.EstateNode{node("host:leaf1", "host"), node("host:leaf2", "host"), node("ip:hub", "ip"), node("host:leaf3", "host"), node("ip:lone", "ip")}}
	for _, leaf := range []string{"host:leaf1", "host:leaf2", "host:leaf3"} {
		g.Edges = append(g.Edges, edge("ip:hub", leaf, "ptr"))
	}
	l := Build(g, 2)
	if !l.Cut || l.NodeTotal != 5 || len(l.Nodes) != 2 {
		t.Fatalf("cut=%v total=%d kept=%d", l.Cut, l.NodeTotal, len(l.Nodes))
	}
	n := byID(l)
	if _, ok := n["ip:hub"]; !ok {
		t.Errorf("the hub (degree 3) was dropped: %v", n)
	}
	if _, ok := n["host:leaf1"]; !ok {
		t.Errorf("ties keep file order, so host:leaf1 stays: %v", n)
	}
	for _, e := range l.Edges {
		if _, a := n[e.From]; !a {
			t.Errorf("edge %+v leaves the drawn nodes", e)
		}
		if _, b := n[e.To]; !b {
			t.Errorf("edge %+v leaves the drawn nodes", e)
		}
	}
	if byID(l)["ip:hub"].Degree != 3 {
		t.Errorf("degree is over the whole graph, not the drawn part: %d", byID(l)["ip:hub"].Degree)
	}
}

func TestLayoutIsDeterministic(t *testing.T) {
	a, b := Build(twoIslands(), 100), Build(twoIslands(), 100)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("two builds differ:\n%+v\n%+v", a, b)
	}
}

func TestLayoutPutsKindsInColumnsInOrderWithoutOverlap(t *testing.T) {
	l := Build(twoIslands(), 100)
	colX := map[string]int{}
	seen := map[[2]int]string{}
	for _, n := range l.Nodes {
		if x, ok := colX[n.Kind]; ok && x != n.X {
			t.Errorf("kind %s is in two columns", n.Kind)
		}
		colX[n.Kind] = n.X
		if other, dup := seen[[2]int{n.X, n.Y}]; dup {
			t.Errorf("%s and %s share a position", n.ID, other)
		}
		seen[[2]int{n.X, n.Y}] = n.ID
		if n.X < 0 || n.Y < 0 || n.X > l.Width || n.Y > l.Height {
			t.Errorf("%s at (%d,%d) is outside %dx%d", n.ID, n.X, n.Y, l.Width, l.Height)
		}
	}
	// network, then ip, then host, then domain, left to right.
	if !(colX["network"] < colX["ip"] && colX["ip"] < colX["host"] && colX["host"] < colX["domain"]) {
		t.Errorf("column order wrong: %v", colX)
	}
}

func TestManyNodesStayInsideTheCanvas(t *testing.T) {
	var g core.EstateGraph
	for i := range 60 {
		g.Nodes = append(g.Nodes, node(fmt.Sprintf("ip:10.0.0.%d", i), "ip"))
	}
	l := Build(g, 100)
	for _, n := range l.Nodes {
		if n.Y > l.Height {
			t.Fatalf("%s at y=%d is below the canvas (%d)", n.ID, n.Y, l.Height)
		}
	}
}
