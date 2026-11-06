package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

type memStatus struct {
	got []core.WatchStatus
	err error
}

func (m *memStatus) Save(_ context.Context, s core.WatchStatus) error {
	if m.err != nil {
		return m.err
	}
	m.got = append(m.got, s)
	return nil
}

func (r *rig) watch(once bool, cycles int) (CycleReport, error) {
	r.opts.Once = once
	n := 0
	r.deps.Wait = func(context.Context, time.Duration) bool {
		n++
		r.now = r.now.Add(r.opts.Every)
		return n < cycles
	}
	return Watch(context.Background(), r.deps, r.opts, WatchRunPrefixFor(r.deps.Name))
}

func TestWatchPublishesStatusAtStartAndAfterEveryCycle(t *testing.T) {
	r := newRig(t, det("d"))
	st := &memStatus{}
	r.deps.Status = st
	r.opts.Keep, r.opts.Repeat = 48*time.Hour, 30*time.Minute
	if _, err := r.watch(false, 2); err != nil {
		t.Fatal(err)
	}
	// start, cycle 1, cycle 2
	if len(st.got) != 3 {
		t.Fatalf("status saved %d times, want 3", len(st.got))
	}
	first := st.got[0]
	if first.Last != nil || !first.NextDue.Equal(t0) || first.Every != 5*time.Minute || first.Window != time.Hour || first.Keep != 48*time.Hour || first.Repeat != 30*time.Minute {
		t.Errorf("start record = %+v", first)
	}
	one := st.got[1]
	if one.Last == nil || one.Last.Verdict != "QUIET" || one.Last.Run != "watch-"+t0.Format("20060102T150405Z") {
		t.Fatalf("cycle 1 record = %+v", one.Last)
	}
	if !one.NextDue.Equal(t0.Add(5 * time.Minute)) {
		t.Errorf("nextDue = %v, want start + every", one.NextDue)
	}
	if !st.got[2].Last.Ended.After(one.Last.Ended) {
		t.Error("cycle 2 did not move the ended time")
	}
}

func TestWatchStatusVerdictAndFailedComponents(t *testing.T) {
	r := newRig(t, failingDet("broken", errors.New("boom password=hunter2")), det("ok", finding("ok", "t1", core.SevHigh)))
	st := &memStatus{}
	r.deps.Status = st
	if _, err := r.watch(true, 1); err != nil {
		t.Fatal(err)
	}
	last := st.got[len(st.got)-1]
	if last.Last == nil || last.Last.Verdict != "INCOMPLETE" || last.Last.New != 1 {
		t.Fatalf("record = %+v", last.Last)
	}
	if len(last.Last.Failed) != 1 || strings.Contains(last.Last.Failed[0], "hunter2") {
		t.Errorf("failed = %v: names only, never an error text", last.Last.Failed)
	}
	if !last.NextDue.IsZero() {
		t.Errorf("a one-cycle run has no next cycle, got %v", last.NextDue)
	}
}

func TestWatchStatusSaveFailureIsAnAlertNotSilence(t *testing.T) {
	r := newRig(t, det("d"))
	r.deps.Status = &memStatus{err: errors.New("disk full")}
	if _, err := r.watch(true, 1); err != nil {
		t.Fatal(err)
	}
	a := r.sink.kind(core.AlertError)
	if len(a) == 0 || a[0].Tag != TagStatusSave || a[0].Severity != "high" {
		t.Fatalf("no %s alert: %+v", TagStatusSave, r.sink.got)
	}
}

func TestWatchWithoutAStatusSinkStillRuns(t *testing.T) {
	r := newRig(t, det("d"))
	if rep, err := r.watch(true, 1); err != nil || rep.Status != CycleQuiet {
		t.Fatalf("rep=%v err=%v", rep.Status, err)
	}
}
