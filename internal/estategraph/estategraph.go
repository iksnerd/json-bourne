// Package estategraph turns a loaded estate file into what the dashboard draws: the
// nodes worth showing when there are too many, each node's degree and component, and a
// deterministic layered layout for the drawing that needs no script. The interactive
// view lays the same nodes out itself in the browser.
//
// The topology (neighbours, components) is computed with github.com/dominikbraun/graph.
// The package reads only core types: it never sees a file, a store or a request, and
// it never changes a label or a value, so the escaping stays with the page that prints
// them.
package estategraph

import (
	"errors"
	"math"
	"sort"

	"github.com/dominikbraun/graph"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Node is one drawn node.
type Node struct {
	ID, Kind, Label string
	// Degree is the number of distinct neighbours in the whole graph, not only the drawn
	// part, so a hub is recognisable when its neighbours were cut.
	Degree int
	// Component numbers the connected pieces of the whole graph from 0, in the order of
	// their first node in the file.
	Component int
	// X, Y are the node's place in the layered layout.
	X, Y int
}

// Edge is one observation between two drawn nodes. Index is its position in the file,
// which is how the detail page addresses it.
type Edge struct {
	From, To, Relation, Source, Confidence string
	Index                                  int
}

// Layout is the drawn part of a graph.
type Layout struct {
	Nodes         []Node
	Edges         []Edge
	NodeTotal     int  // nodes in the file
	Cut           bool // some nodes were left out
	Components    int  // connected pieces of the whole graph
	Width, Height int  // the canvas the layout fits in
}

// Layout constants, in SVG user units.
const (
	colWidth = 170
	rowGap   = 30
	margin   = 24
)

// kindOrder is the left-to-right order of the layers: who announces and owns the space
// first, what answers on it last. A kind not listed goes after the last one.
var kindOrder = []string{"asn", "org", "network", "ip", "host", "domain"}

// Build draws at most limit nodes of g. When there are more, it keeps the most
// connected ones (ties keep file order), because a hub says more than a leaf.
func Build(g core.EstateGraph, limit int) Layout {
	topo := graph.New(graph.StringHash)
	pos := map[string]int{} // node id -> index of its first appearance
	var nodes []core.EstateNode
	for _, n := range g.Nodes {
		if _, dup := pos[n.ID]; dup {
			continue
		}
		pos[n.ID] = len(nodes)
		nodes = append(nodes, n)
		_ = topo.AddVertex(n.ID)
	}
	var edges []indexedEdge
	for i, e := range g.Edges {
		_, a := pos[e.From]
		_, b := pos[e.To]
		if !a || !b || e.From == e.To {
			continue
		}
		edges = append(edges, indexedEdge{e, i})
		// A second observation of the same pair is allowed in an estate file and refused
		// by the topology, which counts a pair once. The list keeps both.
		if err := topo.AddEdge(e.From, e.To); err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
			continue
		}
	}

	adj, _ := topo.AdjacencyMap()
	degree := map[string]int{}
	for id, nb := range adj {
		degree[id] = len(nb)
	}
	comp := map[string]int{}
	components := 0
	for _, n := range nodes {
		if _, seen := comp[n.ID]; seen {
			continue
		}
		c := components
		_ = graph.BFS(topo, n.ID, func(id string) bool { comp[id] = c; return false })
		components++
	}

	l := Layout{NodeTotal: len(nodes), Components: components}
	keep := nodes
	if limit >= 0 && len(nodes) > limit {
		order := make([]int, len(nodes))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return degree[nodes[order[a]].ID] > degree[nodes[order[b]].ID] })
		order = order[:limit]
		sort.Ints(order)
		keep = make([]core.EstateNode, 0, limit)
		for _, i := range order {
			keep = append(keep, nodes[i])
		}
		l.Cut = true
	}
	drawn := map[string]bool{}
	for _, n := range keep {
		drawn[n.ID] = true
		l.Nodes = append(l.Nodes, Node{ID: n.ID, Kind: n.Kind, Label: n.Label, Degree: degree[n.ID], Component: comp[n.ID]})
	}
	for _, e := range edges {
		if drawn[e.From] && drawn[e.To] {
			l.Edges = append(l.Edges, Edge{From: e.From, To: e.To, Relation: e.Relation, Source: e.Source, Confidence: e.Confidence, Index: e.i})
		}
	}
	place(&l)
	return l
}

type indexedEdge struct {
	core.EstateEdge
	i int
}

// place gives every node a column by kind and a row inside it. Rows are ordered by
// component and then by the average row of the neighbours already placed to the left,
// which keeps most edges short and the picture readable without a force simulation.
func place(l *Layout) {
	if len(l.Nodes) == 0 {
		return
	}
	rank := func(kind string) int {
		for i, k := range kindOrder {
			if k == kind {
				return i
			}
		}
		return len(kindOrder)
	}
	cols := map[int][]int{} // rank -> node indexes
	for i, n := range l.Nodes {
		r := rank(n.Kind)
		cols[r] = append(cols[r], i)
	}
	ranks := make([]int, 0, len(cols))
	for r := range cols {
		ranks = append(ranks, r)
	}
	sort.Ints(ranks)

	neighbours := map[string][]string{}
	for _, e := range l.Edges {
		neighbours[e.From] = append(neighbours[e.From], e.To)
		neighbours[e.To] = append(neighbours[e.To], e.From)
	}
	row := map[string]int{} // node id -> row, once placed
	maxRows := 0
	for c, r := range ranks {
		idx := cols[r]
		bary := func(i int) float64 {
			var sum float64
			var n int
			for _, nb := range neighbours[l.Nodes[i].ID] {
				if y, ok := row[nb]; ok {
					sum += float64(y)
					n++
				}
			}
			if n == 0 {
				return math.MaxFloat64
			}
			return sum / float64(n)
		}
		key := make(map[int]float64, len(idx))
		for _, i := range idx {
			key[i] = bary(i)
		}
		sort.SliceStable(idx, func(a, b int) bool {
			na, nb := l.Nodes[idx[a]], l.Nodes[idx[b]]
			if na.Component != nb.Component {
				return na.Component < nb.Component
			}
			return key[idx[a]] < key[idx[b]]
		})
		for y, i := range idx {
			row[l.Nodes[i].ID] = y
			l.Nodes[i].X = margin + c*colWidth
			l.Nodes[i].Y = margin + y*rowGap
		}
		maxRows = max(maxRows, len(idx))
	}
	l.Width = 2*margin + len(ranks)*colWidth
	l.Height = 2*margin + (maxRows-1)*rowGap
}
