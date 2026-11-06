package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// partialDet returns findings and an error together, as a detector with several
// independent rules does when one rule cannot be judged (RFC 0012).
func partialDet(name string, err error, fs ...core.Finding) core.Detector {
	return fakeDetector{name: name, fn: func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
		return fs, err
	}}
}

func huntWith(t *testing.T, dets ...core.Detector) (Result, *memStore) {
	t.Helper()
	m := newMem()
	res, err := Hunt(context.Background(), Deps{Sources: []core.Source{okSource("a")}, Detectors: dets, Sink: m, Reader: m}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	return res, m
}

func TestHuntKeepsFindingsReturnedBesideAnError(t *testing.T) {
	boom := errors.New("rule two could not be judged")
	res, m := huntWith(t, partialDet("d", boom, finding("d", "rule-one", core.SevHigh)))
	if len(res.Findings) != 1 || res.Findings[0].Tag != "rule-one" {
		t.Fatalf("findings = %+v, want the one the detector proved", res.Findings)
	}
	d := res.Detectors[0]
	if d.Status != StatusError || d.Findings != 1 || !errors.Is(d.Err, boom) {
		t.Errorf("detector result = %+v", d)
	}
	if res.Complete() {
		t.Error("a detector that did not finish left the hunt complete")
	}
	if got := m.findings["r"]; len(got) != 1 {
		t.Errorf("stored findings = %v, want the partial finding stored", got)
	}
}

func TestHuntKeepsFindingsBesideNoRecordsToo(t *testing.T) {
	res, _ := huntWith(t, partialDet("d", core.ErrNoRecords, finding("d", "t", core.SevCheck)))
	if len(res.Findings) != 1 || res.Detectors[0].Status != StatusNoRecords || res.Complete() {
		t.Fatalf("findings=%v result=%+v complete=%v", res.Findings, res.Detectors[0], res.Complete())
	}
}

// A plain error with no findings is unchanged: no findings, status error.
func TestHuntErrorWithoutFindingsStaysEmpty(t *testing.T) {
	res, m := huntWith(t, partialDet("d", errors.New("boom")))
	if len(res.Findings) != 0 || res.Detectors[0].Findings != 0 || res.Detectors[0].Status != StatusError || res.Complete() {
		t.Fatalf("findings=%v result=%+v", res.Findings, res.Detectors[0])
	}
	if len(m.findings["r"]) != 0 {
		t.Errorf("stored %v", m.findings["r"])
	}
}

func TestWatchAlertsAPartialFindingOnceAndRaisesIncomplete(t *testing.T) {
	r := newRig(t, partialDet("d", errors.New("rule two could not be judged"), finding("d", "rule-one", core.SevHigh)))
	rep := r.cycle()
	if rep.New != 1 || rep.Status != CycleIncomplete {
		t.Fatalf("new=%d status=%s", rep.New, rep.Status)
	}
	if n := len(r.sink.kind(core.AlertFinding)); n != 1 {
		t.Errorf("finding alerts = %d, want 1", n)
	}
	if n := len(r.sink.kind(core.AlertIncomplete)); n != 1 {
		t.Errorf("incomplete alerts = %d, want 1", n)
	}
	if hb := r.sink.kind(core.AlertCycle); len(hb) != 1 || !strings.Contains(hb[0].Text, "INCOMPLETE") {
		t.Errorf("heartbeat %+v", hb)
	}
	// The same cycle again: the finding is deduped by tag, the outage is held back.
	r.cycle()
	if n := len(r.sink.kind(core.AlertFinding)); n != 1 {
		t.Errorf("finding alerted again: %d", n)
	}
}

// activityPartial gives a detector the Activity method Activity requires.
type activityPartial struct{ core.Detector }

func (activityPartial) Activity(context.Context, core.EventReader, core.EventReader, core.Window) (core.ActivityReport, error) {
	return core.ActivityReport{}, nil
}

func TestActivityOfAnIncompleteDetectorWithAFindingIsActiveAndIncomplete(t *testing.T) {
	d := activityPartial{partialDet("d", errors.New("rule two could not be judged"), finding("d", "rule-one", core.SevHigh))}
	res := runActivity(t, []core.Source{okSource("a")}, d)
	if res.Verdict != VerdictActive || res.Complete() {
		t.Fatalf("verdict=%s complete=%v reasons=%v", res.Verdict, res.Complete(), res.Reasons)
	}
	if !strings.Contains(strings.Join(res.Reasons, ";"), "detector d did not finish") {
		t.Errorf("reasons %v", res.Reasons)
	}
	// Without a finding the same failure stays INCOMPLETE, never QUIET.
	q := runActivity(t, []core.Source{okSource("a")}, activityPartial{partialDet("d", errors.New("boom"))})
	if q.Verdict != VerdictIncomplete {
		t.Errorf("verdict = %s", q.Verdict)
	}
}
