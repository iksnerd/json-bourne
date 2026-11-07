package app

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// countFinding is a detector whose finding carries what it read, so a change in what a
// detector sees shows up in the findings.
func countFinding(name string) fakeDetector {
	return fakeDetector{name, func(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
		n := 0
		for _, err := range cur.Events(ctx, w) {
			if err != nil {
				return nil, err
			}
			n++
		}
		return []core.Finding{{Detector: name, Tag: fmt.Sprintf("%s-read-%d", name, n), Severity: core.SevHigh, Summary: "read"}}, nil
	}}
}

type huntAnswer struct {
	findings []string
	status   map[string]Status
	complete bool
}

func huntAnswerOf(res Result) huntAnswer {
	a := huntAnswer{status: map[string]Status{}, complete: res.Complete()}
	for _, f := range res.Findings {
		a.findings = append(a.findings, f.Detector+"/"+f.Tag)
	}
	sort.Strings(a.findings)
	for _, s := range res.Sources {
		a.status["source "+s.Name] = s.Status
	}
	for _, d := range res.Detectors {
		a.status["detector "+d.Name] = d.Status
	}
	return a
}

func (a huntAnswer) equal(b huntAnswer) bool {
	if a.complete != b.complete || !slices.Equal(a.findings, b.findings) || len(a.status) != len(b.status) {
		return false
	}
	for k, v := range a.status {
		if b.status[k] != v {
			return false
		}
	}
	return true
}

// Invariant: permuting the sources and the detectors, and running them concurrently,
// changes neither the findings nor the status of any component. Run with -race.
func TestInvariantSourceOrderAndConcurrencyDoNotChangeTheAnswer(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		r := rand.New(rand.NewSource(seed))
		l := randomLayout(r, 4+r.Intn(8))
		scopes := map[string][]string{}
		var detNames []string
		for i := 0; i < 5; i++ {
			name := fmt.Sprintf("det%d", i)
			detNames = append(detNames, name)
			if r.Intn(3) > 0 {
				s := []string{l.names[r.Intn(len(l.names))], l.names[r.Intn(len(l.names))]}
				slices.Sort(s)
				scopes[name] = slices.Compact(s)
			}
		}
		// One detector fails beside a finding, whatever its position.
		bad := fakeDetector{"broken", func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
			return []core.Finding{finding("broken", "kept", core.SevCheck)}, errors.New("rule two could not be judged")
		}}

		var base *huntAnswer
		for run := 0; run < 6; run++ {
			dets := []core.Detector{bad}
			for _, n := range detNames {
				dets = append(dets, countFinding(n))
			}
			r.Shuffle(len(dets), func(i, j int) { dets[i], dets[j] = dets[j], dets[i] })
			m := newMem()
			res, err := Hunt(context.Background(), Deps{
				Sources: l.sources(r), Detectors: dets, Scopes: scopes, Sink: m, Reader: m,
				Concurrency: []int{1, 2, 4, 16}[run%4],
			}, "r", win())
			if err != nil {
				t.Fatalf("seed %d run %d: %v", seed, run, err)
			}
			a := huntAnswerOf(res)
			if base == nil {
				base = &a
				if a.complete {
					t.Fatalf("seed %d: the broken detector left the hunt complete", seed)
				}
				continue
			}
			if !a.equal(*base) {
				t.Fatalf("seed %d run %d: huntAnswer changed\n got %+v\nwant %+v", seed, run, a, *base)
			}
		}
	}
}
