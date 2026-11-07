package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// runSchedule runs the real Watch loop on a fake clock: cycle i starts at t0 + i*Every,
// and the source is down for the cycles in [downFrom, downTo) of each pair in outages.
// It returns the rig after total cycles.
func runSchedule(t *testing.T, total int, outages [][2]int) *rig {
	t.Helper()
	r := newRig(t, det("d"))
	r.opts.Repeat = 24 * time.Hour // so the outage alert is delivered once per outage
	down := func(i int) bool {
		for _, o := range outages {
			if i >= o[0] && i < o[1] {
				return true
			}
		}
		return false
	}
	i := 0
	r.src.err = nil
	if down(0) {
		r.src.err = core.ErrSourceUnavailable
	}
	r.deps.Wait = func(context.Context, time.Duration) bool {
		i++
		r.now = t0.Add(time.Duration(i) * r.opts.Every)
		r.src.err = nil
		if down(i) {
			r.src.err = core.ErrSourceUnavailable
		}
		return i < total
	}
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch"); err != nil {
		t.Fatal(err)
	}
	return r
}

func gapAlerts(r *rig) []core.Alert {
	var out []core.Alert
	for _, a := range r.sink.got {
		if a.Tag == TagGap {
			out = append(out, a)
		}
	}
	return out
}

// runAt is the run name of cycle i of the schedule in runSchedule.
func runAt(r *rig, i int) string {
	return "watch-" + t0.Add(time.Duration(i)*r.opts.Every).Format("20060102T150405Z")
}

func heartbeat(r *rig, run string) string {
	for _, a := range r.sink.kind(core.AlertCycle) {
		if a.Run == run {
			return a.Text
		}
	}
	return ""
}

// (a) and (b): a 95 minute outage under a 1 hour window leaves 40 minutes that no
// completed window covered. The gap is reported once, on the cycle that recovers, and
// not on the incomplete cycles in between.
func TestWatchGapIsReportedOnceOnTheRecoveryCycleAfterALongOutage(t *testing.T) {
	r := runSchedule(t, 24, [][2]int{{1, 20}}) // cycles 1..19 down (95 minutes), 20 recovers
	gaps := gapAlerts(r)
	if len(gaps) != 1 {
		t.Fatalf("gap alerts over the run = %d, want exactly 1: %+v", len(gaps), gaps)
	}
	if gaps[0].Run != runAt(r, 20) {
		t.Errorf("gap on %s, want the recovery cycle %s", gaps[0].Run, runAt(r, 20))
	}
	if !strings.Contains(gaps[0].Text, "40m0s") || !strings.Contains(gaps[0].Text, "never examined") {
		t.Errorf("gap text = %q, want 40m0s never examined", gaps[0].Text)
	}
	if !strings.Contains(heartbeat(r, runAt(r, 20)), "gap=true") {
		t.Errorf("recovery cycle line = %q, want gap=true", heartbeat(r, runAt(r, 20)))
	}
	for i := 1; i < 20; i++ {
		if hb := heartbeat(r, runAt(r, i)); !strings.Contains(hb, "gap=false") {
			t.Errorf("incomplete cycle %d line = %q, want gap=false", i, hb)
		}
	}
	if hb := heartbeat(r, runAt(r, 21)); !strings.Contains(hb, "QUIET") {
		t.Errorf("cycle after the recovery = %q, want quiet (the gap is reported once)", hb)
	}
	if n := len(r.sink.kind(core.AlertIncomplete)) - len(gaps); n != 1 {
		t.Errorf("source outage alerts = %d, want 1 (deduped by --repeat)", n)
	}
	if n := len(r.sink.kind(core.AlertRecovered)); n != 1 {
		t.Errorf("recovery alerts = %d, want 1", n)
	}
}

// (c): an outage the next window reaches back over leaves nothing unexamined.
func TestWatchNoGapWhenTheOutageIsShorterThanTheWindow(t *testing.T) {
	for _, down := range []int{3, 10, 11} { // 11 cycles: the recovery window starts exactly at the last completed end
		r := runSchedule(t, down+8, [][2]int{{1, 1 + down}})
		if g := gapAlerts(r); len(g) != 0 {
			t.Errorf("%d cycles down: gap alerts = %+v, want none", down, g)
		}
		for i := 0; i < down+8; i++ {
			if strings.Contains(heartbeat(r, runAt(r, i)), "gap=true") {
				t.Errorf("%d cycles down: cycle %d says gap=true", down, i)
			}
		}
	}
}

// (d) and (e): a run with no failures, and the first cycle of a process, have no gap.
func TestWatchNoGapWithoutFailuresOrOnTheFirstCycle(t *testing.T) {
	r := runSchedule(t, 30, nil)
	if g := gapAlerts(r); len(g) != 0 {
		t.Errorf("clean run: gap alerts = %+v", g)
	}
	r = runSchedule(t, 1, nil)
	if g := gapAlerts(r); len(g) != 0 {
		t.Errorf("first cycle: gap alerts = %+v", g)
	}
	// A process that starts while the source is down has no history either: the first
	// cycle is incomplete, and the cycle after the recovery has nothing to measure from.
	r = runSchedule(t, 30, [][2]int{{0, 20}})
	if g := gapAlerts(r); len(g) != 0 {
		t.Errorf("down from the first cycle: gap alerts = %+v", g)
	}
}

// (f): two outages, each longer than the window, are two gaps with their own durations.
func TestWatchTwoLongOutagesAreTwoGaps(t *testing.T) {
	// Down 1..19 (recover at 20, last completed end t0, gap 40m). Completed through 30.
	// Down 31..55 (recover at 56: window starts at 56*5-60 = 220m, last completed end 150m: 70m).
	r := runSchedule(t, 60, [][2]int{{1, 20}, {31, 56}})
	gaps := gapAlerts(r)
	if len(gaps) != 2 {
		t.Fatalf("gap alerts = %d, want 2: %+v", len(gaps), gaps)
	}
	if gaps[0].Run != runAt(r, 20) || !strings.Contains(gaps[0].Text, "40m0s") {
		t.Errorf("first gap = %s %q, want cycle 20, 40m0s", gaps[0].Run, gaps[0].Text)
	}
	if gaps[1].Run != runAt(r, 56) || !strings.Contains(gaps[1].Text, "1h10m0s") {
		t.Errorf("second gap = %s %q, want cycle 56, 1h10m0s", gaps[1].Run, gaps[1].Text)
	}
}

// A component that fails while another finishes still makes the cycle not complete: the
// window was not fully examined, so it must not count as covered.
func TestWatchPartialFailureDoesNotAdvanceTheCompletedEdge(t *testing.T) {
	r := newRig(t, det("d"))
	r.opts.Repeat = 24 * time.Hour
	bad := false
	r.deps.Hunt = func(ctx context.Context, run string, w core.Window) (Result, error) {
		res := Result{Run: run, Window: w, Baseline: w.Previous(), Sources: []SourceResult{{Name: "a", Status: StatusOK}, {Name: "b", Status: StatusOK}}}
		if bad {
			res.Sources[1] = SourceResult{Name: "b", Status: StatusUnavailable, Err: core.ErrSourceUnavailable}
		}
		return res, nil
	}
	i := 0
	r.deps.Wait = func(context.Context, time.Duration) bool {
		i++
		r.now = t0.Add(time.Duration(i) * r.opts.Every)
		bad = i >= 1 && i < 20
		return i < 24
	}
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch"); err != nil {
		t.Fatal(err)
	}
	gaps := gapAlerts(r)
	if len(gaps) != 1 || gaps[0].Run != runAt(r, 20) {
		t.Fatalf("gap alerts = %+v, want one on cycle 20", gaps)
	}
}
