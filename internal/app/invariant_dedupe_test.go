package app

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// layout is a random assignment of documents to overlapping sources on one cluster.
type layout struct {
	names []string
	ids   map[string][]string // source name to the document ids it returns
	all   []string            // every distinct document id
}

// randomLayout puts nDocs documents on 1 to 3 sources of one cluster. Every source
// returns at least one document (an empty source is a different case) and every document
// is returned by at least one source.
func randomLayout(r *rand.Rand, nDocs int) layout {
	k := 1 + r.Intn(3)
	if nDocs < k {
		nDocs = k
	}
	l := layout{ids: map[string][]string{}}
	for i := 0; i < k; i++ {
		l.names = append(l.names, fmt.Sprintf("s%d", i))
	}
	for d := 0; d < nDocs; d++ {
		id := fmt.Sprintf("doc%02d", d)
		l.all = append(l.all, id)
		in := false
		for i, n := range l.names {
			if r.Intn(2) == 0 || (!in && i == k-1) || (d < k && i == d) {
				l.ids[n] = append(l.ids[n], id)
				in = true
			}
		}
	}
	return l
}

// sources builds the fake sources in a random order, each reading its documents in a
// random order.
func (l layout) sources(r *rand.Rand) []core.Source {
	var out []core.Source
	for _, n := range l.names {
		ids := slices.Clone(l.ids[n])
		r.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
		out = append(out, scoped(n, "https://es.example.com", ids...))
	}
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// readDocs is a detector that records every document it reads, as the original document.
func readDocs(name string, into map[string][]string, mu *sync.Mutex) fakeDetector {
	return fakeDetector{name, func(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
		for e, err := range cur.Events(ctx, w) {
			if err != nil {
				return nil, err
			}
			mu.Lock()
			into[name] = append(into[name], string(e.Raw))
			mu.Unlock()
		}
		return nil, nil
	}}
}

func rawOf(id string) string { return `{"_id":"` + id + `"}` }

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Invariant: whatever the source order and the overlap, a detector scoped to a set of
// sources reads exactly the union of the documents those sources returned, each once.
func TestInvariantScopedDetectorsReadTheUnionOfTheirSourcesOnce(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		r := rand.New(rand.NewSource(seed))
		l := randomLayout(r, 3+r.Intn(10))

		got := map[string][]string{}
		var mu sync.Mutex
		dets := []core.Detector{readDocs("all", got, &mu)}
		scopes := map[string][]string{}
		want := map[string]map[string]bool{"all": {}}
		for _, id := range l.all {
			want["all"][rawOf(id)] = true
		}
		for i := 0; i < 4; i++ {
			name := fmt.Sprintf("det%d", i)
			var scope []string
			for _, n := range l.names {
				if r.Intn(2) == 0 {
					scope = append(scope, n)
				}
			}
			if len(scope) == 0 {
				scope = []string{l.names[r.Intn(len(l.names))]}
			}
			dets = append(dets, readDocs(name, got, &mu))
			scopes[name] = scope
			want[name] = map[string]bool{}
			for _, n := range scope {
				for _, id := range l.ids[n] {
					want[name][rawOf(id)] = true
				}
			}
		}

		m := newMem()
		res, err := Hunt(context.Background(), Deps{
			Sources: l.sources(r), Detectors: dets, Scopes: scopes, Sink: m, Reader: m,
			Concurrency: 1 + r.Intn(4),
		}, "r", win())
		if err != nil || !res.Complete() {
			t.Fatalf("seed %d: err %v failed %v", seed, err, res.Failed())
		}
		for name, w := range want {
			g := slices.Clone(got[name])
			sort.Strings(g)
			if len(slices.Compact(slices.Clone(g))) != len(g) {
				t.Errorf("seed %d: detector %s read a document twice: %v", seed, name, g)
			}
			if ws := sortedKeys(w); !slices.Equal(g, ws) {
				t.Errorf("seed %d: detector %s (scope %v) read %v, want %v", seed, name, scopes[name], g, ws)
			}
		}
	}
}

// Invariant: overlapping sources count each underlying document once, and the run's
// accounting adds up: documents fetched = documents stored + duplicates removed.
func TestInvariantOverlapAccountingAddsUp(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		r := rand.New(rand.NewSource(seed))
		l := randomLayout(r, 2+r.Intn(12))
		fetched := 0
		for _, ids := range l.ids {
			fetched += len(ids)
		}
		got := map[string][]string{}
		var mu sync.Mutex
		m := newMem()
		res, err := Hunt(context.Background(), Deps{
			Sources: l.sources(r), Detectors: []core.Detector{readDocs("all", got, &mu)},
			Sink: m, Reader: m, Concurrency: 1 + r.Intn(4),
		}, "r", win())
		if err != nil || !res.Complete() {
			t.Fatalf("seed %d: err %v failed %v", seed, err, res.Failed())
		}
		var events, dups int64
		stored := 0
		for _, s := range res.Sources {
			events += s.Events
			dups += s.Duplicates
			stored += len(m.runs[SourceRun("r", s.Name)])
		}
		if events != int64(len(l.all)) {
			t.Errorf("seed %d: %d events counted, want %d distinct documents", seed, events, len(l.all))
		}
		if events+dups != int64(fetched) {
			t.Errorf("seed %d: fetched %d != events %d + duplicates %d", seed, fetched, events, dups)
		}
		if int64(stored) != events {
			t.Errorf("seed %d: %d rows stored, %d events reported", seed, stored, events)
		}
		if len(got["all"]) != len(l.all) {
			t.Errorf("seed %d: a detector over all sources read %d documents, want %d", seed, len(got["all"]), len(l.all))
		}
	}
}
