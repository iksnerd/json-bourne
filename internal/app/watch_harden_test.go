package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func (r *rig) advance(d time.Duration) { r.now = r.now.Add(d) }

func (r *rig) outageAlerts() []core.Alert { return r.sink.kind(core.AlertIncomplete) }

func (r *rig) lastHeartbeat() string {
	hb := r.sink.kind(core.AlertCycle)
	return hb[len(hb)-1].Text
}

func down(msg string) error { return fmt.Errorf("%w: %s", core.ErrSourceUnavailable, msg) }

// ---- outage repeat suppression ----

func TestWatchIdenticalOutageAlertsOnceThenHeartbeatOnly(t *testing.T) {
	r := newRig(t, det("d"))
	r.opts.Repeat = 30 * time.Minute
	r.src.err = down("502 bad gateway")

	rep := r.cycle()
	if rep.Status != CycleIncomplete || len(r.outageAlerts()) != 1 {
		t.Fatalf("first cycle: status %s, outage alerts %d (the first alert must be immediate)", rep.Status, len(r.outageAlerts()))
	}
	for i := 1; i <= 5; i++ { // 5, 10, ... 25 minutes: inside the repeat interval
		r.advance(5 * time.Minute)
		rep = r.cycle()
		if len(r.outageAlerts()) != 1 {
			t.Fatalf("cycle %d re-alerted an identical outage (%d alerts)", i+1, len(r.outageAlerts()))
		}
		// A held-back alert must not make the cycle look better.
		if rep.Status != CycleIncomplete || rep.Status.Healthy() || rep.Repeated != 1 {
			t.Fatalf("cycle %d: status %s repeated %d", i+1, rep.Status, rep.Repeated)
		}
		hb := r.lastHeartbeat()
		if !strings.Contains(hb, "CYCLE INCOMPLETE") || !strings.Contains(hb, "still down") || strings.Contains(hb, "QUIET") {
			t.Fatalf("heartbeat does not say the source is still down: %q", hb)
		}
	}
	r.advance(5 * time.Minute) // 30 minutes after the alert: due again
	if rep = r.cycle(); len(r.outageAlerts()) != 2 || rep.Repeated != 0 {
		t.Fatalf("no repeat after the interval: %d alerts, repeated %d", len(r.outageAlerts()), rep.Repeated)
	}
}

func TestWatchChangedFailureTextAlertsImmediately(t *testing.T) {
	r := newRig(t, det("d"))
	r.src.err = down("502 bad gateway")
	r.cycle()
	r.advance(5 * time.Minute)
	r.src.err = down("503 service unavailable")
	r.cycle()
	got := r.outageAlerts()
	if len(got) != 2 || !strings.Contains(got[1].Text, "503") {
		t.Fatalf("a changed failure was held back: %+v", got)
	}
}

func TestWatchRecoveryAlertsImmediatelyAndResetsTheClock(t *testing.T) {
	r := newRig(t, det("d"))
	r.src.err = down("502")
	r.cycle()
	r.advance(5 * time.Minute)
	r.src.err = nil
	rep := r.cycle()
	rec := r.sink.kind(core.AlertRecovered)
	if len(rec) != 1 || rec[0].Tag != TagRecovered || rep.Recovered != 1 || rep.Status != CycleQuiet {
		t.Fatalf("recovery: %+v status %s", rec, rep.Status)
	}
	if !strings.Contains(r.lastHeartbeat(), "recovered") {
		t.Errorf("heartbeat: %q", r.lastHeartbeat())
	}
	if len(r.state.st.Health) != 0 {
		t.Errorf("recovered outage still remembered: %+v", r.state.st.Health)
	}
	// Down again two minutes later with the same text: a new outage, alerted at once.
	r.advance(2 * time.Minute)
	r.src.err = down("502")
	r.cycle()
	if len(r.outageAlerts()) != 2 {
		t.Fatalf("an outage after a recovery was treated as a repeat: %d alerts", len(r.outageAlerts()))
	}
	// A recovery is announced once.
	r.advance(5 * time.Minute)
	r.src.err = nil
	r.cycle()
	r.advance(5 * time.Minute)
	r.cycle()
	if n := len(r.sink.kind(core.AlertRecovered)); n != 2 {
		t.Errorf("recovered alerts = %d, want 2 (one per recovery)", n)
	}
}

func TestWatchFindingsAreNeverHeldBackDuringAnOutage(t *testing.T) {
	r := newRig(t)
	r.src.err = down("502")
	for i := 0; i < 3; i++ {
		tag := fmt.Sprintf("t%d", i)
		r.dets = []core.Detector{det("d", finding("d", tag, core.SevHigh), core.Finding{Detector: "d", Severity: core.SevCheck, Summary: "untagged"})}
		rep := r.cycle()
		if rep.New != 2 {
			t.Fatalf("cycle %d surfaced %d findings, want 2", i+1, rep.New)
		}
		r.advance(5 * time.Minute)
	}
	if n := len(r.sink.kind(core.AlertFinding)); n != 6 {
		t.Errorf("finding alerts = %d, want 6", n)
	}
	if n := len(r.outageAlerts()); n != 1 {
		t.Errorf("outage alerts = %d, want 1", n)
	}
}

func TestWatchOutageKeysAreIndependent(t *testing.T) {
	r := newRig(t, failingDet("one", errors.New("boom")))
	r.src.err = down("502")
	r.cycle()
	r.advance(5 * time.Minute)
	r.dets = []core.Detector{failingDet("one", errors.New("boom")), failingDet("two", errors.New("boom"))}
	r.cycle() // source and detector one are repeats; detector two is new
	got := r.outageAlerts()
	if len(got) != 3 || got[2].Detector != "detector two" {
		t.Fatalf("alerts: %+v", got)
	}
}

func TestWatchHuntErrorRepeatsAreHeldBackAndHuntRecoveryAlerts(t *testing.T) {
	r := newRig(t, det("d"))
	r.huntErr = errors.New("disk full")
	r.cycle()
	r.advance(5 * time.Minute)
	if rep := r.cycle(); rep.Status != CycleFailed || rep.Repeated != 1 {
		t.Fatalf("status %s repeated %d", rep.Status, rep.Repeated)
	}
	if n := len(r.sink.kind(core.AlertError)); n != 1 {
		t.Fatalf("hunt error alerts = %d, want 1", n)
	}
	r.advance(5 * time.Minute)
	r.huntErr = nil
	r.cycle()
	if rec := r.sink.kind(core.AlertRecovered); len(rec) != 1 || !strings.Contains(rec[0].Text, "hunt recovered") {
		t.Fatalf("recovered: %+v", rec)
	}
}

// When the hunt itself broke, no component reported. Their silence is not a recovery.
func TestWatchComponentIsNotRecoveredByAHuntThatDidNotRun(t *testing.T) {
	r := newRig(t, det("d"))
	r.src.err = down("502")
	r.cycle()
	r.advance(5 * time.Minute)
	r.deps.Hunt = func(_ context.Context, run string, w core.Window) (Result, error) { // broke before any component ran
		return Result{Run: run, Window: w, Baseline: w.Previous()}, errors.New("disk full")
	}
	r.cycle()
	if n := len(r.sink.kind(core.AlertRecovered)); n != 0 {
		t.Fatalf("source declared recovered by a cycle that never ran it: %+v", r.sink.got)
	}
	if _, ok := r.state.st.Health[TagIncomplete+"|source s"]; !ok {
		t.Errorf("outage forgotten: %+v", r.state.st.Health)
	}
}

func TestWatchUndeliveredOutageAlertIsNotRemembered(t *testing.T) {
	r := newRig(t, det("d"))
	r.src.err = down("502")
	r.sink.failTag = TagIncomplete
	r.cycle()
	r.advance(5 * time.Minute)
	r.sink.failTag = ""
	r.cycle()
	if len(r.outageAlerts()) != 1 {
		t.Fatalf("an alert that never arrived was counted as sent: %+v", r.sink.got)
	}
}

func TestFingerprintIgnoresRunAndTimestampsOnly(t *testing.T) {
	a := fingerprint("get [2026-11-05T11:00:00Z, 2026-11-05T12:00:00Z) in watch-20261105T120000Z: 502", "watch-20261105T120000Z")
	b := fingerprint("get [2026-11-05T11:05:00Z, 2026-11-05T12:05:00+01:00) in watch-20261105T120500Z:   502", "watch-20261105T120500Z")
	if a != b {
		t.Errorf("same failure fingerprints differently:\n%q\n%q", a, b)
	}
	if got := fingerprint("save findings for run \"watch-test\": boom", "watch-test"); strings.Contains(got, "watch-test") {
		t.Errorf("run id left in the fingerprint: %q", got)
	}
	if fingerprint("status 502", "r") == fingerprint("status 503", "r") {
		t.Error("different status codes share a fingerprint")
	}
}

func TestWatchOptionsRepeatAndKeepValidation(t *testing.T) {
	base := WatchOptions{Every: 5 * time.Minute, Window: time.Hour}
	for name, mut := range map[string]func(*WatchOptions){
		"negative repeat":        func(o *WatchOptions) { o.Repeat = -1 },
		"negative keep":          func(o *WatchOptions) { o.Keep = -1 },
		"keep below two windows": func(o *WatchOptions) { o.Keep = 90 * time.Minute },
	} {
		o := base
		mut(&o)
		if err := o.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	o := base
	o.Keep = 2 * time.Hour
	if err := o.Validate(); err != nil {
		t.Errorf("keep of exactly two windows refused: %v", err)
	}
}

// ---- retention ----

func TestWatchPrunesAfterEachCycleAndReportsIt(t *testing.T) {
	r := newRig(t, det("d"))
	r.opts.Keep = 6 * time.Hour
	var cutoffs []time.Time
	r.deps.Prune = func(_ context.Context, before time.Time) (core.PruneResult, error) {
		cutoffs = append(cutoffs, before)
		return core.PruneResult{Runs: 4, Events: 120, Findings: 2}, nil
	}
	rep := r.cycle()
	if len(cutoffs) != 1 || !cutoffs[0].Equal(t0.Add(-6*time.Hour)) {
		t.Fatalf("cutoffs = %v, want one at now-6h", cutoffs)
	}
	if rep.Pruned == nil || rep.Pruned.Events != 120 {
		t.Fatalf("pruned = %+v", rep.Pruned)
	}
	if hb := r.lastHeartbeat(); !strings.Contains(hb, "pruned 4 run(s), 120 event(s), 2 finding(s)") {
		t.Errorf("the cycle line does not report the pruning: %q", hb)
	}
}

func TestWatchPrunesAfterAnIncompleteCycleToo(t *testing.T) {
	r := newRig(t, det("d"))
	r.src.err = down("502")
	calls := 0
	r.deps.Prune = func(context.Context, time.Time) (core.PruneResult, error) { calls++; return core.PruneResult{}, nil }
	r.cycle()
	if calls != 1 {
		t.Errorf("prune calls = %d: a source that stays down must not let the store grow", calls)
	}
}

func TestWatchDefaultKeepIs48Hours(t *testing.T) {
	r := newRig(t, det("d"))
	var got time.Time
	r.deps.Prune = func(_ context.Context, before time.Time) (core.PruneResult, error) {
		got = before
		return core.PruneResult{}, nil
	}
	r.cycle()
	if !got.Equal(t0.Add(-48 * time.Hour)) {
		t.Errorf("cutoff = %v, want now-48h", got)
	}
}

func TestWatchPruneFailureIsAnAlertAndAFailedCycle(t *testing.T) {
	r := newRig(t, det("d"))
	r.deps.Prune = func(context.Context, time.Time) (core.PruneResult, error) {
		return core.PruneResult{}, errors.New("database is locked")
	}
	rep := r.cycle()
	if rep.Status != CycleFailed || rep.Pruned != nil {
		t.Fatalf("status %s pruned %+v", rep.Status, rep.Pruned)
	}
	a := r.sink.kind(core.AlertError)
	if len(a) != 1 || a[0].Tag != TagPrune || a[0].Severity != "high" || !strings.Contains(a[0].Text, "database is locked") {
		t.Fatalf("no alert for the failed prune: %+v", r.sink.got)
	}
	if hb := r.lastHeartbeat(); !strings.Contains(hb, "CYCLE FAILED") || strings.Contains(hb, "pruned") {
		t.Errorf("heartbeat: %q", hb)
	}
	// Every cycle it fails, it says so: pruning is not an outage that goes quiet.
	r.advance(5 * time.Minute)
	r.cycle()
	if n := len(r.sink.kind(core.AlertError)); n != 2 {
		t.Errorf("prune failure alerts = %d, want 2", n)
	}
}

// ---- unparsable documents on the cycle line ----

type parseSrc struct {
	*fakeSource
	n int
}

func (p parseSrc) Unparsable() int { return p.n }

func TestWatchCycleLineShowsUnparsableShare(t *testing.T) {
	for name, tc := range map[string]struct {
		n        int
		want     []string
		wantNone string
	}{
		"none":      {n: 0, wantNone: "unparsable"},
		"low share": {n: 1, want: []string{"1 unparsable document(s)", "4.8%"}, wantNone: "HIGH"}, // 20 events parse
		"high":      {n: 8, want: []string{"8 unparsable document(s)", "28.6%", "HIGH"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, det("d"))
			fs := r.src
			for i := 0; i < 18; i++ { // 20 parsed events in all
				fs.events = append(fs.events, core.Event{Time: t0.Add(-time.Duration(11+i) * time.Minute), Source: "s", Kind: "k"})
			}
			r.deps.Hunt = func(ctx context.Context, run string, w core.Window) (Result, error) {
				mem := newMem()
				return Hunt(ctx, Deps{Sources: []core.Source{parseSrc{fs, tc.n}}, Detectors: r.dets, Sink: mem, Reader: mem}, run, w)
			}
			rep := r.cycle()
			hb := r.lastHeartbeat()
			for _, w := range tc.want {
				if !strings.Contains(hb, w) {
					t.Errorf("cycle line lacks %q: %s", w, hb)
				}
			}
			if tc.wantNone != "" && strings.Contains(hb, tc.wantNone) {
				t.Errorf("cycle line has %q: %s", tc.wantNone, hb)
			}
			if rep.Status != CycleQuiet {
				t.Errorf("status = %s: unparsable documents are reported, they do not change the verdict", rep.Status)
			}
		})
	}
}

func TestWatchRefusesARunPrefixRetentionCannotFind(t *testing.T) {
	r := newRig(t, det("d"))
	r.deps.Prune = func(context.Context, time.Time) (core.PruneResult, error) { return core.PruneResult{}, nil }
	r.opts.Once = true
	if _, err := Watch(context.Background(), r.deps, r.opts, "hunt"); err == nil {
		t.Fatal("Watch accepted a run prefix that retention would never match")
	}
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch"); err != nil {
		t.Fatalf("the real prefix was refused: %v", err)
	}
}
