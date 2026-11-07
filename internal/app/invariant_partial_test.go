package app

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// failAt is a source that returns k of its n documents and then fails: it fails at page
// index k. k == n fails after the last document, k == 0 before the first. A source that
// failed is never a complete one, whatever it yielded first.
func failAt(name string, n, k int, err error) *fakeSource {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%s-doc%d", name, i)
	}
	evs := docEvents(name, ids...)
	return &fakeSource{name: name, events: evs[:k], err: err}
}

var partialErrs = map[string]error{
	"plain error": errors.New("page 3: connection reset"),
	"unavailable": fmt.Errorf("%w: partial response (shard failed)", core.ErrSourceUnavailable),
	"no records":  fmt.Errorf("%w: reply cut off", core.ErrNoRecords),
}

// Invariant (RFC 0012): a source that fails at any page index makes the hunt incomplete,
// never clean, and the findings a detector proved from the healthy sources are kept.
func TestInvariantSourceFailureAtAnyPageIsIncompleteAndKeepsFindings(t *testing.T) {
	const n = 6
	for ename, e := range partialErrs {
		for k := 0; k <= n; k++ {
			t.Run(fmt.Sprintf("%s/page%d", ename, k), func(t *testing.T) {
				m := newMem()
				res, err := Hunt(context.Background(), Deps{
					Sources:   []core.Source{failAt("bad", n, k, e), okSource("good")},
					Detectors: []core.Detector{fakeDetector{"d", fixed(finding("d", "proven", core.SevHigh))}},
					Sink:      m, Reader: m,
				}, "r", win())
				if err != nil {
					t.Fatalf("a failing source must not fail the hunt itself: %v", err)
				}
				if res.Complete() {
					t.Fatalf("source failed at page %d but the hunt is complete: %+v", k, res.Sources)
				}
				if res.Sources[0].Status == StatusOK || res.Sources[0].Err == nil {
					t.Errorf("failed source reports %+v", res.Sources[0])
				}
				if res.Sources[1].Status != StatusOK {
					t.Errorf("healthy source dragged down: %+v", res.Sources[1])
				}
				if len(res.Findings) != 1 || res.Findings[0].Tag != "proven" {
					t.Errorf("findings proven beside the failure were lost: %+v", res.Findings)
				}
				if len(m.findings["r"]) != 1 {
					t.Errorf("stored findings = %v, want the proven one", m.findings["r"])
				}
			})
		}
	}
}

// The same failure seen through Activity is INCOMPLETE, never QUIET.
func TestInvariantSourceFailureAtAnyPageIsNeverQuiet(t *testing.T) {
	const n = 4
	for ename, e := range partialErrs {
		for k := 0; k <= n; k++ {
			res := runActivity(t, []core.Source{failAt("bad", n, k, e), okSource("good")},
				repDetector{name: "beh", report: quietReport()})
			if res.Verdict == VerdictQuiet || res.Complete() {
				t.Errorf("%s at page %d: verdict %s complete %v", ename, k, res.Verdict, res.Complete())
			}
		}
	}
}
