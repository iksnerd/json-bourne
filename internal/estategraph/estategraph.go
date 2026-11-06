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
	"time"

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
	// Weight (1 to 3), Sources, Newest and Stale describe the corroboration and age of
	// the edge this claim belongs to (see Weigh).
	Weight  int
	Sources []string
	Newest  time.Time
	Stale   bool
}

// StaleAfter is how old the newest claim of an edge may be before the viewer draws it
// dashed. It is a viewer default, not a part of the file.
const StaleAfter = 90 * 24 * time.Hour

// Weight is what the file counts about one edge: the distinct sources that claim the
// same two nodes with the same relation (in the same direction), and how recent the
// newest of those claims is. It judges nothing about the relation itself.
type Weight struct {
	// Weight is 1 for one distinct source, 2 for two and 3 for three or more.
	Weight int
	// Sources are the distinct sources, sorted. Two claims by one source count once.
	Sources []string
	// Newest is the latest observed time among the claims; zero when none can be read.
	Newest time.Time
	// Stale is true when Newest is older than StaleAfter before now. An edge whose time
	// cannot be read is not called stale: an unknown age is not an old one.
	Stale bool
}

// Weigh returns the weight of every edge claim of g, indexed like g.Edges. Claims of one
// edge share the same value. It reads no clock: now is the caller's.
func Weigh(g core.EstateGraph, now time.Time) []Weight {
	type key struct{ from, to, rel string }
	type acc struct {
		sources map[string]bool
		newest  time.Time
	}
	groups := map[key]*acc{}
	for _, e := range g.Edges {
		k := key{e.From, e.To, e.Relation}
		a := groups[k]
		if a == nil {
			a = &acc{sources: map[string]bool{}}
			groups[k] = a
		}
		a.sources[e.Source] = true
		if t, err := time.Parse(time.RFC3339, e.Observed); err == nil && t.After(a.newest) {
			a.newest = t
		}
	}
	done := map[key]Weight{}
	out := make([]Weight, len(g.Edges))
	for i, e := range g.Edges {
		k := key{e.From, e.To, e.Relation}
		w, ok := done[k]
		if !ok {
			a := groups[k]
			for s := range a.sources {
				w.Sources = append(w.Sources, s)
			}
			sort.Strings(w.Sources)
			w.Weight = min(len(w.Sources), 3)
			w.Newest = a.newest
			w.Stale = !a.newest.IsZero() && now.Sub(a.newest) > StaleAfter
			done[k] = w
		}
		out[i] = w
	}
	return out
}

// Kinds are the node kinds a file may hold, in the order a filter lists them.
var Kinds = []string{"ip", "host", "domain", "asn", "org", "network", "service"}

// Options say what Build draws.
type Options struct {
	// Limit is the most nodes drawn; a negative value means no limit.
	Limit int
	// Now is the time edge age is measured against.
	Now time.Time
	// Kinds, when not empty, keeps only nodes of these kinds. The caller validates them
	// against Kinds.
	Kinds []string
}

// Layout is the drawn part of a graph.
type Layout struct {
	Nodes         []Node
	Edges         []Edge
	NodeTotal     int  // nodes in the file
	Filtered      bool // a kind filter was applied
	Cut           bool // some nodes were left out by the limit
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

// Build draws at most o.Limit nodes of g, of the kinds in o.Kinds when that is not
// empty. When there are more, it keeps the most connected ones (ties keep file order),
// because a hub says more than a leaf. Degree and component describe the whole graph,
// not the filtered part.
func Build(g core.EstateGraph, o Options) Layout {
	limit := o.Limit
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
	if len(o.Kinds) > 0 {
		want := map[string]bool{}
		for _, k := range o.Kinds {
			want[k] = true
		}
		keep = nil
		for _, n := range nodes {
			if want[n.Kind] {
				keep = append(keep, n)
			}
		}
		l.Filtered = true
	}
	if limit >= 0 && len(keep) > limit {
		nodes := keep
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
	weights := Weigh(g, o.Now)
	for _, e := range edges {
		if drawn[e.From] && drawn[e.To] {
			w := weights[e.i]
			l.Edges = append(l.Edges, Edge{From: e.From, To: e.To, Relation: e.Relation, Source: e.Source, Confidence: e.Confidence, Index: e.i,
				Weight: w.Weight, Sources: w.Sources, Newest: w.Newest, Stale: w.Stale})
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
