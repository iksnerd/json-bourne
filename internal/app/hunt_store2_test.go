package app_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Two identical lines in one fetch are two events; the same fetch repeated under another
// run id, and again after a reopen, must not grow the count.
func TestSeqIdenticalLinesCountOncePerOccurrenceAcrossRuns(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	srcs := []*seqSource{src("a", "", "d1", "d1", "d2")}
	for _, run := range []string{"hunt-1", "hunt-2", "hunt-3"} {
		if res, err := e.hunt(run, nil, srcs, []core.Detector{all}, nil); err != nil || !res.Complete() {
			t.Fatal(err, res.Failed())
		}
		eq(t, run, all.cur, []string{"d1", "d1", "d2"})
		e.reopen()
	}
}

// A source that fails after reading a document another source also returned still counts
// as a returner of it (it did read it), so a detector scoped to the failed source keeps
// the document its rolled-back run lost.
func TestSeqFailedSourceStillReturnsWhatItReadBeforeFailing(t *testing.T) {
	e := newSeqEnv(t)
	onlyB := &seqDet{name: "onlyB"}
	a := src("a", es, "d1", "d2")
	b := src("b", es, "d2", "d3")
	b.err, b.failAfter = errors.New("boom"), 1
	res, err := e.hunt("hunt-1", nil, []*seqSource{a, b}, []core.Detector{onlyB}, map[string][]string{"onlyB": {"b"}})
	if err != nil || !slices.Equal(res.Failed(), []string{"source b"}) {
		t.Fatal(err, res.Failed())
	}
	eq(t, "onlyB", onlyB.cur, []string{"d2"})
}
