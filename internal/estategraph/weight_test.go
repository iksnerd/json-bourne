package estategraph

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var refNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func claim(src string, observed time.Time) core.EstateEdge {
	return core.EstateEdge{From: "ip:a", To: "host:a", Relation: "ptr", Source: src, Observed: observed.Format(time.RFC3339), Confidence: "stated"}
}

func weighOne(es ...core.EstateEdge) Weight {
	g := core.EstateGraph{Nodes: []core.EstateNode{node("ip:a", "ip"), node("host:a", "host")}, Edges: es}
	return Weigh(g, refNow)[0]
}

func TestWeightIsTheNumberOfDistinctSourcesCappedAtThree(t *testing.T) {
	fresh := refNow.Add(-time.Hour)
	for _, tc := range []struct {
		name string
		es   []core.EstateEdge
		want int
	}{
		{"one", []core.EstateEdge{claim("dns", fresh)}, 1},
		{"two", []core.EstateEdge{claim("dns", fresh), claim("rdns", fresh)}, 2},
		{"three", []core.EstateEdge{claim("dns", fresh), claim("rdns", fresh), claim("bgp", fresh)}, 3},
		{"four", []core.EstateEdge{claim("dns", fresh), claim("rdns", fresh), claim("bgp", fresh), claim("whois", fresh)}, 3},
		// Two claims by the same source are one witness.
		{"same source twice", []core.EstateEdge{claim("dns", fresh), claim("dns", fresh.Add(-time.Minute))}, 1},
		{"same source twice and one other", []core.EstateEdge{claim("dns", fresh), claim("dns", fresh), claim("rdns", fresh)}, 2},
	} {
		if got := weighOne(tc.es...); got.Weight != tc.want {
			t.Errorf("%s: weight = %d, want %d", tc.name, got.Weight, tc.want)
		}
	}
}

func TestWeightListsTheSourcesOnceEachInOrder(t *testing.T) {
	w := weighOne(claim("rdns", refNow), claim("dns", refNow), claim("rdns", refNow))
	if !reflect.DeepEqual(w.Sources, []string{"dns", "rdns"}) {
		t.Errorf("sources = %v", w.Sources)
	}
}

func TestStaleMeansNewestClaimOlderThanNinetyDays(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		name  string
		ago   time.Duration
		stale bool
	}{
		{"fresh", day, false},
		{"89 days", 89 * day, false},
		{"exactly 90 days is not older than 90 days", 90 * day, false},
		{"one second past 90 days", 90*day + time.Second, true},
		{"a year", 365 * day, true},
	} {
		if got := weighOne(claim("dns", refNow.Add(-tc.ago))); got.Stale != tc.stale {
			t.Errorf("%s: stale = %v, want %v", tc.name, got.Stale, tc.stale)
		}
	}
	// The newest claim decides, not the oldest.
	w := weighOne(claim("dns", refNow.Add(-400*day)), claim("rdns", refNow.Add(-day)))
	if w.Stale || !w.Newest.Equal(refNow.Add(-day)) {
		t.Errorf("newest claim must decide: %+v", w)
	}
}

func TestClaimsOfOtherRelationsOrDirectionsDoNotCorroborate(t *testing.T) {
	a := claim("dns", refNow)
	b := claim("rdns", refNow)
	b.Relation = "resolves_to"
	c := claim("bgp", refNow)
	c.From, c.To = c.To, c.From
	g := core.EstateGraph{Nodes: []core.EstateNode{node("ip:a", "ip"), node("host:a", "host")}, Edges: []core.EstateEdge{a, b, c}}
	for i, w := range Weigh(g, refNow) {
		if w.Weight != 1 {
			t.Errorf("edge %d: weight = %d, want 1", i, w.Weight)
		}
	}
}

func TestAClaimWithoutAReadableTimeIsNotCalledStale(t *testing.T) {
	e := claim("dns", refNow)
	e.Observed = "not a time"
	if w := weighOne(e); w.Stale || !w.Newest.IsZero() {
		t.Errorf("unknown age must stay unknown: %+v", w)
	}
}

func TestBuildCarriesTheWeightOfEveryDrawnEdge(t *testing.T) {
	g := core.EstateGraph{Nodes: []core.EstateNode{node("ip:a", "ip"), node("host:a", "host")},
		Edges: []core.EstateEdge{claim("dns", refNow), claim("rdns", refNow.Add(-200*24*time.Hour))}}
	l := Build(g, Options{Limit: 10, Now: refNow})
	for i, e := range l.Edges {
		if e.Weight != 2 || e.Stale || !e.Newest.Equal(refNow) {
			t.Errorf("edge %d: %+v", i, e)
		}
	}
}

func TestKindFilterKeepsOnlyChosenKindsAndTheEdgesBetweenThem(t *testing.T) {
	l := Build(twoIslands(), Options{Limit: 100, Kinds: []string{"ip", "host"}})
	n := byID(l)
	if len(l.Nodes) != 3 || n["network:a"].ID != "" || n["domain:b"].ID != "" {
		t.Errorf("nodes = %+v", l.Nodes)
	}
	if len(l.Edges) != 1 || l.Edges[0].Relation != "ptr" {
		t.Errorf("edges = %+v", l.Edges)
	}
	if !l.Filtered || l.Cut || l.NodeTotal != 5 {
		t.Errorf("filtered=%v cut=%v total=%d", l.Filtered, l.Cut, l.NodeTotal)
	}
	// Degree and components still describe the whole graph, so a hub stays recognisable.
	if n["ip:a"].Degree != 2 || l.Components != 2 {
		t.Errorf("degree %d, components %d", n["ip:a"].Degree, l.Components)
	}
	// An edge keeps its index in the file, which is how the detail page finds it.
	if l.Edges[0].Index != 0 {
		t.Errorf("index = %d", l.Edges[0].Index)
	}
}

func TestNoKindsMeansNoFilter(t *testing.T) {
	l := Build(twoIslands(), Options{Limit: 100})
	if l.Filtered || len(l.Nodes) != 5 || len(l.Edges) != 3 {
		t.Errorf("%+v", l)
	}
}

func TestKindsAreTheLoadersKinds(t *testing.T) {
	want := []string{"asn", "domain", "host", "ip", "network", "org", "service"}
	got := append([]string(nil), Kinds...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Kinds = %v", got)
	}
}
