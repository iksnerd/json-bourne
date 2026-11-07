package web

import (
	"slices"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// orderGraph has facts of one key at different times, assessments in different time zones,
// and absences, all in a deliberately wrong order.
func orderGraph() core.EstateGraph {
	f := func(k, v, obs string) core.EstateFact {
		return core.EstateFact{Key: k, Value: v, Source: "s", Method: "m", Observed: obs}
	}
	a := func(id, decided string) core.EstateAssessment {
		return core.EstateAssessment{ID: id, Subject: "ip:192.0.2.10", Label: "l-" + id, By: "x", Decided: decided, Basis: []string{"ip:192.0.2.10"}, Note: "n"}
	}
	ab := func(src, ans string) core.EstateAbsence {
		return core.EstateAbsence{Subject: "ip:192.0.2.10", Source: src, Method: "m", Observed: t0, Answer: ans}
	}
	return core.EstateGraph{ID: "e1", Caveat: "c",
		Nodes: []core.EstateNode{{ID: "ip:192.0.2.10", Kind: "ip", Label: "a", Source: "s", Method: "m", Observed: t0, Facts: []core.EstateFact{
			f("k", "zz", "2026-11-03T10:00:00Z"), f("k", "aa", "2026-11-05T10:00:00Z"), f("k", "mm", "2026-11-01T10:00:00Z"), f("a", "v", t0), f("k", "bb", "2026-11-05T10:00:00Z"),
		}}},
		Absences: []core.EstateAbsence{ab("s2", "no"), ab("s1", "no"), ab("s1", "maybe")},
		Assessments: []core.EstateAssessment{
			a("c", "2026-11-07T01:00:00Z"),
			a("b", "2026-11-06T23:00:00-05:00"), // 04:00Z on the 7th: later than "c" despite sorting earlier as text
			a("a2", "2026-11-06T12:00:00Z"),
			a("a1", "2026-11-06T12:00:00Z"),
		}}
}

func renderOrder(t *testing.T, g core.EstateGraph) string {
	t.Helper()
	d := newDeps(hostileFake())
	d.Estate = fakeEstate{g: []core.EstateGraph{g}}
	_, _, body := get(t, New(d, Options{Loopback: true}), "/estate/node?g=e1&id=ip:192.0.2.10")
	return body
}

func TestNodeSheetOrdersFactsAndAssessmentsByTheRule(t *testing.T) {
	body := renderOrder(t, orderGraph())
	// Facts of key k: observed time, then value.
	var at []int
	for _, v := range []string{">mm<", ">zz<", ">aa<", ">bb<"} {
		at = append(at, strings.Index(body, v))
	}
	if !slices.IsSorted(at) || at[0] < 0 {
		t.Errorf("facts of one key should run by observed time then value (mm zz aa bb): %v", at)
	}
	// Assessments: decided instant, then id.
	at = nil
	for _, v := range []string{">l-a1<", ">l-a2<", ">l-c<", ">l-b<"} {
		at = append(at, strings.Index(body, v))
	}
	if !slices.IsSorted(at) || at[0] < 0 {
		t.Errorf("assessments should run by decided time then id (a1 a2 c b): %v", at)
	}
	// Absences: source, method, observed, answer.
	i1, i2, i3 := strings.Index(body, ">maybe<"), strings.Index(body, ">no<"), strings.LastIndex(body, ">no<")
	if !(i1 >= 0 && i1 < i2 && i2 < i3) {
		t.Errorf("absences out of order: %d %d %d", i1, i2, i3)
	}
}

func TestNodeSheetIsByteIdenticalAcrossLoadsAndInputOrder(t *testing.T) {
	g := orderGraph()
	want := renderOrder(t, g)
	if again := renderOrder(t, g); again != want {
		t.Fatal("two loads of unchanged data differ")
	}
	shuffles := []func(core.EstateGraph) core.EstateGraph{
		func(g core.EstateGraph) core.EstateGraph { // reverse all three lists
			slices.Reverse(g.Nodes[0].Facts)
			slices.Reverse(g.Assessments)
			slices.Reverse(g.Absences)
			return g
		},
		func(g core.EstateGraph) core.EstateGraph { // rotate by one
			f, a, ab := g.Nodes[0].Facts, g.Assessments, g.Absences
			g.Nodes[0].Facts = append(append([]core.EstateFact{}, f[1:]...), f[0])
			g.Assessments = append(append([]core.EstateAssessment{}, a[1:]...), a[0])
			g.Absences = append(append([]core.EstateAbsence{}, ab[1:]...), ab[0])
			return g
		},
	}
	for i, sh := range shuffles {
		c := orderGraph()
		if got := renderOrder(t, sh(c)); got != want {
			t.Errorf("shuffle %d changed the page", i)
		}
	}
}
