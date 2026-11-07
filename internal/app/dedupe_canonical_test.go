package app

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// docAt is an event for the document id, with its own time and Raw: the same document
// has the same time whichever source returns it.
func docAt(src, id, raw string, at time.Time) core.Event {
	e := ev(src, at)
	e.DocKey = "idx/" + id
	e.Raw = []byte(raw)
	return e
}

func sourceOf(name string, evs ...core.Event) scopedSource {
	return scopedSource{&fakeSource{name: name, events: evs}, "https://es.example.com"}
}

// snapshot is what a store holds for a run: the sorted raw documents per source label.
func snapshot(m *memStore, run string, names ...string) map[string][]string {
	out := map[string][]string{}
	for _, n := range names {
		for _, e := range m.runs[SourceRun(run, n)] {
			out[n] = append(out[n], string(e.Raw))
		}
		sort.Strings(out[n])
	}
	return out
}

// Hunting the same data twice with the sources in the other order stores the same rows
// under the same labels, and the second run replaces the first instead of adding to it.
func TestHuntStoredCopyIsIndependentOfSourceOrder(t *testing.T) {
	build := func() (core.Source, core.Source) {
		return scoped("a", "https://es.example.com", "d1", "d2"), scoped("b", "https://es.example.com", "d1", "d2")
	}
	m := newMem()
	det := []core.Detector{fakeDetector{"d", fixed()}}
	a, b := build()
	if _, err := Hunt(context.Background(), Deps{Sources: []core.Source{a, b}, Detectors: det, Sink: m, Reader: m, Concurrency: 1}, "r", win()); err != nil {
		t.Fatal(err)
	}
	first := snapshot(m, "r", "a", "b")
	a, b = build()
	if _, err := Hunt(context.Background(), Deps{Sources: []core.Source{b, a}, Detectors: det, Sink: m, Reader: m, Concurrency: 1}, "r", win()); err != nil {
		t.Fatal(err)
	}
	second := snapshot(m, "r", "a", "b")
	if n := totalStored(m, "r", "a", "b"); n != 2 {
		t.Fatalf("%d rows stored after hunting twice, want 2: %v", n, second)
	}
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("source order changed the stored copy: %v then %v", first, second)
	}
	if len(second["a"]) != 2 {
		t.Errorf("the documents are stored under %v, want the smallest source name a", second)
	}
}

// Whatever the layout, the read order and the concurrency, the stored rows and the
// counts are the same, and each document sits under the smallest source that returned it.
func TestInvariantStoredCopyIsCanonical(t *testing.T) {
	for seed := int64(1); seed <= 80; seed++ {
		r := rand.New(rand.NewSource(seed))
		l := randomLayout(r, 3+r.Intn(10))
		want := map[string][]string{}
		for _, id := range l.all {
			for _, n := range slices.Sorted(slices.Values(l.names)) {
				if slices.Contains(l.ids[n], id) {
					want[n] = append(want[n], rawOf(id))
					break
				}
			}
		}
		for n := range want {
			sort.Strings(want[n])
		}
		var prevCounts string
		for round := 0; round < 4; round++ {
			m := newMem()
			res, err := Hunt(context.Background(), Deps{
				Sources:   l.sources(r),
				Detectors: []core.Detector{fakeDetector{"d", fixed()}},
				Sink:      m, Reader: m, Concurrency: 1 + r.Intn(4),
			}, "r", win())
			if err != nil || !res.Complete() {
				t.Fatalf("seed %d: err %v failed %v", seed, err, res.Failed())
			}
			got := snapshot(m, "r", l.names...)
			for n := range got {
				if len(got[n]) == 0 {
					delete(got, n)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("seed %d round %d: stored %v, want %v", seed, round, got, want)
			}
			counts := ""
			for _, n := range l.names {
				for _, s := range res.Sources {
					if s.Name == n {
						counts += fmt.Sprintf("%s:%d/%d ", n, s.Events, s.Duplicates)
					}
				}
			}
			if round > 0 && counts != prevCounts {
				t.Fatalf("seed %d: counts changed between runs: %q then %q", seed, prevCounts, counts)
			}
			prevCounts = counts
		}
	}
}

// Two different documents with identical contents are two documents: a detector scoped
// to the source that returned only one of them reads exactly one.
func TestHuntIdenticalContentsAreDistinctDocuments(t *testing.T) {
	at := t0.Add(-10 * time.Minute)
	raw := `{"msg":"same"}`
	cases := map[string]struct {
		mk   func() (core.Source, core.Source)
		want map[string]int // detector scope to documents read
	}{
		// both copies are stored under a; b returned only x1
		"shared copy": {func() (core.Source, core.Source) {
			return sourceOf("a", docAt("a", "x1", raw, at), docAt("a", "x2", raw, at)), sourceOf("b", docAt("b", "x1", raw, at))
		}, map[string]int{"a": 2, "b": 1}},
		// each source returned a different one
		"disjoint": {func() (core.Source, core.Source) {
			return sourceOf("a", docAt("a", "x1", raw, at)), sourceOf("b", docAt("b", "x2", raw, at))
		}, map[string]int{"a": 1, "b": 1}},
	}
	for name, c := range cases {
		for _, scope := range []string{"a", "b"} {
			t.Run(name+"/"+scope, func(t *testing.T) {
				m := newMem()
				a, b := c.mk()
				got := map[string]int{}
				var mu sync.Mutex
				res, err := Hunt(context.Background(), Deps{
					Sources:   []core.Source{a, b},
					Detectors: []core.Detector{counter("scoped", got, &mu), counter("all", got, &mu)},
					Scopes:    map[string][]string{"scoped": {scope}},
					Sink:      m, Reader: m, Concurrency: 1,
				}, "r", win())
				if err != nil || !res.Complete() {
					t.Fatalf("err %v failed %v", err, res.Failed())
				}
				if got["scoped"] != c.want[scope] {
					t.Errorf("scoped to %s read %d documents, want %d", scope, got["scoped"], c.want[scope])
				}
				if got["all"] != 2 {
					t.Errorf("unscoped detector read %d, want 2", got["all"])
				}
			})
		}
	}
}

// A document the source gave no identity is never merged with another, and belongs only
// to the source that returned it.
func TestHuntDocumentWithoutIdentityStaysWithItsSource(t *testing.T) {
	at := t0.Add(-10 * time.Minute)
	a := sourceOf("a", docAt("a", "x1", `{"m":1}`, at))
	nokey := docAt("b", "x1", `{"m":1}`, at)
	nokey.DocKey = ""
	b := sourceOf("b", docAt("b", "x1", `{"m":1}`, at), nokey, nokey)
	m := newMem()
	got := map[string]int{}
	var mu sync.Mutex
	res, err := Hunt(context.Background(), Deps{
		Sources:   []core.Source{a, b},
		Detectors: []core.Detector{counter("onlyA", got, &mu), counter("onlyB", got, &mu)},
		Scopes:    map[string][]string{"onlyA": {"a"}, "onlyB": {"b"}},
		Sink:      m, Reader: m, Concurrency: 1,
	}, "r", win())
	if err != nil || !res.Complete() {
		t.Fatalf("err %v failed %v", err, res.Failed())
	}
	if got["onlyA"] != 1 || got["onlyB"] != 3 {
		t.Errorf("onlyA read %d (want 1), onlyB read %d (want x1 and the two keyless, 3)", got["onlyA"], got["onlyB"])
	}
}

// The source that lost the shared documents is the larger name; a detector scoped to it
// still gets them, whichever order the sources were given in.
func TestHuntScopedToLosingSourceGetsItsDocumentsWhateverTheOrder(t *testing.T) {
	for _, order := range [][]string{{"a", "b"}, {"b", "a"}} {
		m := newMem()
		by := map[string]core.Source{
			"a": scoped("a", "https://es.example.com", "d1", "d2"),
			"b": scoped("b", "https://es.example.com", "d2", "d3"),
		}
		got := map[string]int{}
		var mu sync.Mutex
		res, err := Hunt(context.Background(), Deps{
			Sources:   []core.Source{by[order[0]], by[order[1]]},
			Detectors: []core.Detector{counter("onlyB", got, &mu), counter("onlyA", got, &mu)},
			Scopes:    map[string][]string{"onlyB": {"b"}, "onlyA": {"a"}},
			Sink:      m, Reader: m, Concurrency: 1,
		}, "r", win())
		if err != nil || !res.Complete() {
			t.Fatalf("%v: err %v failed %v", order, err, res.Failed())
		}
		if got["onlyB"] != 2 || got["onlyA"] != 2 {
			t.Errorf("%v: onlyB read %d, onlyA read %d, want 2 each", order, got["onlyB"], got["onlyA"])
		}
	}
}
