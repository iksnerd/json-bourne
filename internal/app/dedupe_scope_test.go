package app

import (
	"context"
	"sync"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// counter is a detector that records how many events it read in the current window.
func counter(name string, got map[string]int, mu *sync.Mutex) fakeDetector {
	return fakeDetector{name, func(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
		for _, err := range cur.Events(ctx, w) {
			if err != nil {
				return nil, err
			}
			mu.Lock()
			got[name]++
			mu.Unlock()
		}
		return nil, nil
	}}
}

// Two sources on one cluster return the same documents. The store keeps one copy, but a
// detector scoped to either source, or to both, or to none, must read each document once.
func TestHuntScopedDetectorsSeeSharedDocuments(t *testing.T) {
	m := newMem()
	a := scoped("a", "https://es.example.com", "d1", "d2")
	b := scoped("b", "https://es.example.com", "d1", "d2")
	got := map[string]int{}
	var mu sync.Mutex
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{a, b},
		Detectors: []core.Detector{
			counter("onlyA", got, &mu), counter("onlyB", got, &mu), counter("both", got, &mu), counter("all", got, &mu),
		},
		Scopes: map[string][]string{"onlyA": {"a"}, "onlyB": {"b"}, "both": {"a", "b"}},
		Sink:   m, Reader: m, Concurrency: 1,
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() {
		t.Fatalf("hunt incomplete: %v", res.Failed())
	}
	for _, name := range []string{"onlyA", "onlyB", "both", "all"} {
		if got[name] != 2 {
			t.Errorf("detector %s read %d events, want the 2 shared documents once each", name, got[name])
		}
	}
	if n := totalStored(m, "r", "a", "b"); n != 2 {
		t.Errorf("%d rows stored, want 2", n)
	}
	if res.Sources[0].Events != 2 || res.Sources[1].Events != 0 || res.Sources[1].Duplicates != 2 {
		t.Errorf("accounting changed: %+v", res.Sources)
	}
}

// A detector scoped to the source that lost the shared documents still gets them, and the
// documents only the other source returned stay out of its view.
func TestHuntScopedToSecondSourceGetsItsDocuments(t *testing.T) {
	m := newMem()
	a := scoped("a", "https://es.example.com", "d1", "d2")
	b := scoped("b", "https://es.example.com", "d2", "d3")
	got := map[string]int{}
	var mu sync.Mutex
	res, err := Hunt(context.Background(), Deps{
		Sources:   []core.Source{a, b},
		Detectors: []core.Detector{counter("onlyB", got, &mu), counter("all", got, &mu)},
		Scopes:    map[string][]string{"onlyB": {"b"}},
		Sink:      m, Reader: m, Concurrency: 1,
	}, "r", win())
	if err != nil || !res.Complete() {
		t.Fatalf("err %v, failed %v", err, res.Failed())
	}
	if got["onlyB"] != 2 || got["all"] != 3 {
		t.Errorf("onlyB read %d (want d2 and d3), all read %d (want 3)", got["onlyB"], got["all"])
	}
}
