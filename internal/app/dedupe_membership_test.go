package app

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// A document that source b returned in an earlier hunt is still b's when a later hunt
// does not return it: the store keeps who returned it, not only the current fetch.
func TestHuntScopedDetectorKeepsStoredMembership(t *testing.T) {
	m := newMem()
	const cluster = "https://es.example.com"
	count := func(run string, srcs ...core.Source) int {
		got := map[string]int{}
		var mu sync.Mutex
		res, err := Hunt(context.Background(), Deps{
			Sources:   srcs,
			Detectors: []core.Detector{counter("onlyB", got, &mu)},
			Scopes:    map[string][]string{"onlyB": {"b"}},
			Sink:      m, Reader: m, Concurrency: 1,
		}, run, win())
		if err != nil || !res.Complete() {
			t.Fatalf("%s: err %v failed %v", run, err, res.Failed())
		}
		return got["onlyB"]
	}
	if n := count("r1", scoped("a", cluster, "d1"), scoped("b", cluster, "d1")); n != 1 {
		t.Fatalf("first hunt: onlyB read %d, want 1", n)
	}
	// Second hunt: both return d2; d1 is not returned again but is still in the store.
	if n := count("r2", scoped("a", cluster, "d2"), scoped("b", cluster, "d2")); n != 2 {
		t.Errorf("second hunt: onlyB read %d, want 2 (d1 from the store, d2 from this fetch)", n)
	}
}

// A source that failed does not own the shared documents: a healthy source that returned
// them stores them, so the evidence is not lost with the failed one.
func TestHuntFailedSourceDoesNotOwnSharedDocuments(t *testing.T) {
	const cluster = "https://es.example.com"
	for _, scope := range []string{"a", "b"} {
		m := newMem()
		a := scoped("a", cluster, "d1", "d2")
		a.err = errors.New("search failed")
		b := scoped("b", cluster, "d1")
		got := map[string]int{}
		var mu sync.Mutex
		res, err := Hunt(context.Background(), Deps{
			Sources:   []core.Source{a, b},
			Detectors: []core.Detector{counter("scoped", got, &mu)},
			Scopes:    map[string][]string{"scoped": {scope}},
			Sink:      m, Reader: m, Concurrency: 1,
		}, "r", win())
		if err != nil {
			t.Fatal(err)
		}
		if res.Complete() {
			t.Fatal("a source failed: the hunt must be incomplete")
		}
		want := map[string]int{"a": 0, "b": 1}[scope] // a's own run is rolled back; b stored d1
		if scope == "a" {
			want = 1 // a returned d1 too: it is a's document, held by b's healthy copy
		}
		if got["scoped"] != want {
			t.Errorf("scope %s read %d, want %d", scope, got["scoped"], want)
		}
		if n := len(m.runs[SourceRun("r", "b")]); n != 1 {
			t.Errorf("b stored %d rows, want d1", n)
		}
	}
}
