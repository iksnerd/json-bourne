package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// diskState behaves like the state file: Load and Save copy, so a cycle that mutates
// what it loaded changes nothing on "disk" unless Save succeeded. (memState hands out
// its own maps, which hides a lost save.) Every cycle reloads, which is a restart.
type diskState struct {
	disk    core.WatchState
	saveErr error
}

func cloneState(s core.WatchState) core.WatchState {
	out := core.WatchState{Seen: map[string]core.SeenTag{}}
	for k, v := range s.Seen {
		out.Seen[k] = v
	}
	if len(s.Health) > 0 {
		out.Health = map[string]core.HealthSeen{}
		for k, v := range s.Health {
			out.Health[k] = v
		}
	}
	return out
}

func (d *diskState) Load(context.Context) (core.WatchState, error) { return cloneState(d.disk), nil }
func (d *diskState) Save(_ context.Context, s core.WatchState) error {
	if d.saveErr != nil {
		return d.saveErr
	}
	d.disk = cloneState(s)
	return nil
}

func seqRig(t *testing.T, dets ...core.Detector) (*rig, *diskState) {
	r := newRig(t, dets...)
	ds := &diskState{}
	r.deps.State = ds
	return r, ds
}

func findingAlerts(r *rig, tag string) int {
	n := 0
	for _, a := range r.sink.kind(core.AlertFinding) {
		if a.Tag == tag {
			n++
		}
	}
	return n
}

// (b) The finding is delivered, the state file cannot be saved. The alert repeats on the
// next cycle (at-least-once, documented), the save failure itself is an alert and a
// failed cycle, and once a save works the repeat stops.
func TestSeqStateSaveFailureAfterDeliveryRepeatsOnceThenStops(t *testing.T) {
	r, ds := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	ds.saveErr = errors.New("disk full")
	rep := r.cycle()
	if rep.Status != CycleFailed || rep.New != 1 {
		t.Fatalf("cycle 1: status=%s new=%d", rep.Status, rep.New)
	}
	if errs := r.sink.kind(core.AlertError); len(errs) != 1 || errs[0].Tag != TagStateSave {
		t.Fatalf("save failure is not an alert: %+v", r.sink.got)
	}
	if _, ok := ds.disk.Seen["x"]; ok {
		t.Fatal("disk has a tag whose save failed")
	}
	r.advance(5 * time.Minute)
	ds.saveErr = nil
	if rep := r.cycle(); rep.New != 1 || rep.Status != CycleFindings {
		t.Fatalf("cycle 2: status=%s new=%d, want the documented repeat", rep.Status, rep.New)
	}
	r.advance(5 * time.Minute)
	if rep := r.cycle(); rep.New != 0 || rep.Suppressed != 1 {
		t.Fatalf("cycle 3: new=%d suppressed=%d", rep.New, rep.Suppressed)
	}
	if findingAlerts(r, "x") != 2 {
		t.Fatalf("finding delivered %d times, want 2", findingAlerts(r, "x"))
	}
}

// A failed save must not lose what was already on disk: the old memory still suppresses.
func TestSeqStateSaveFailureKeepsThePreviousFileAndItsSuppression(t *testing.T) {
	r, ds := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	r.cycle() // x remembered
	before := cloneState(ds.disk)
	r.dets = []core.Detector{det("a", finding("a", "x", core.SevHigh), finding("a", "y", core.SevHigh))}
	ds.saveErr = errors.New("read-only file system")
	r.advance(5 * time.Minute)
	rep := r.cycle()
	if rep.New != 1 || rep.Suppressed != 1 {
		t.Fatalf("new=%d suppressed=%d", rep.New, rep.Suppressed)
	}
	if len(ds.disk.Seen) != len(before.Seen) || ds.disk.Seen["x"] != before.Seen["x"] {
		t.Fatalf("disk changed by a failed save: %+v", ds.disk)
	}
}

// (c) Required sink down for one tag: it stays eligible and is persisted as unseen;
// optional sinks never saw it. Then the optional sink fails: required delivery stands,
// the cycle fails, the tag is remembered on disk and not repeated afterwards.
func TestSeqRequiredThenOptionalFailureAcrossRestarts(t *testing.T) {
	r, ds := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	hook := &optSink{}
	r.deps.Alerts = core.FanOut{Required: r.sink, Optional: []core.AlertSink{hook}}
	r.sink.failTag = "x"
	if rep := r.cycle(); rep.New != 0 || rep.Status != CycleFailed {
		t.Fatalf("cycle 1: new=%d status=%s", rep.New, rep.Status)
	}
	if _, ok := ds.disk.Seen["x"]; ok {
		t.Fatal("remembered without the required sink")
	}
	for _, a := range hook.got {
		if a.Tag == "x" {
			t.Fatal("optional sink attempted after the required sink failed")
		}
	}
	r.sink.failTag = ""
	hook.down = true
	r.advance(5 * time.Minute)
	rep := r.cycle()
	if rep.New != 1 || rep.OptionalFailed < 2 || rep.Status != CycleFailed {
		t.Fatalf("cycle 2: new=%d optionalFailed=%d status=%s", rep.New, rep.OptionalFailed, rep.Status)
	}
	if _, ok := ds.disk.Seen["x"]; !ok {
		t.Fatal("required delivery not committed to disk")
	}
	hook.down = false
	r.advance(5 * time.Minute)
	if rep := r.cycle(); rep.New != 0 || rep.Status != CycleQuiet {
		t.Fatalf("cycle 3: new=%d status=%s", rep.New, rep.Status)
	}
	if findingAlerts(r, "x") != 1 {
		t.Fatalf("log holds %d copies", findingAlerts(r, "x"))
	}
}

// (d) Future-dated entries (clock step, edited file) do not suppress, are replaced by a
// real delivery, and an unrelated future-dated entry does not survive the save.
func TestSeqFutureDatedSeenAndHealthDoNotSuppress(t *testing.T) {
	r, ds := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	future := r.now.Add(2 * time.Hour)
	ds.disk = core.WatchState{
		Seen:   map[string]core.SeenTag{"x": {At: future, Severity: core.SevCritical}, "stale": {At: future, Severity: core.SevHigh}},
		Health: map[string]core.HealthSeen{TagIncomplete + "|source s": {At: future, Fingerprint: fingerprint("unavailable: "+down("502").Error(), "watch-test")}},
	}
	r.src.err = down("502")
	rep := r.cycle()
	if rep.New != 1 || rep.Repeated != 0 {
		t.Fatalf("new=%d repeated=%d", rep.New, rep.Repeated)
	}
	if got := ds.disk.Seen["x"]; !got.At.Equal(r.now.Truncate(time.Second)) || got.Severity != core.SevHigh {
		t.Errorf("future entry not replaced: %+v", got)
	}
	if _, ok := ds.disk.Seen["stale"]; ok {
		t.Error("future-dated entry survived the save")
	}
	if len(r.outageAlerts()) != 1 {
		t.Errorf("outage with a future-dated memory was not delivered: %+v", r.sink.got)
	}
}

// (d) TTL expiry and escalation re-deliver, and the persisted severity is what was last
// delivered.
func TestSeqTTLExpiryAndEscalationRedeliver(t *testing.T) {
	r, ds := seqRig(t, det("a", finding("a", "x", core.SevCheck)))
	r.cycle()
	r.advance(10 * time.Minute)
	if rep := r.cycle(); rep.New != 0 || rep.Suppressed != 1 {
		t.Fatalf("within ttl: new=%d", rep.New)
	}
	r.dets = []core.Detector{det("a", finding("a", "x", core.SevCritical))}
	r.advance(10 * time.Minute)
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("escalation not delivered")
	}
	if ds.disk.Seen["x"].Severity != core.SevCritical {
		t.Fatalf("persisted severity = %v", ds.disk.Seen["x"].Severity)
	}
	r.advance(10 * time.Minute) // back down: still muted by the critical memory
	r.dets = []core.Detector{det("a", finding("a", "x", core.SevCheck))}
	if rep := r.cycle(); rep.New != 0 {
		t.Fatalf("de-escalation re-alerted")
	}
	r.advance(r.opts.TTL)
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("ttl expiry did not re-deliver")
	}
}

// Two findings under one tag in one cycle are one condition: one alert, and the memory
// keeps the highest severity, so the next cycle at that severity is suppressed.
func TestSeqSameTagTwiceInOneCycleIsOneAlertAtTheHighestSeverity(t *testing.T) {
	r, ds := seqRig(t, det("a", finding("a", "x", core.SevCritical), finding("a", "x", core.SevCheck)))
	rep := r.cycle()
	if rep.New != 1 || findingAlerts(r, "x") != 1 {
		t.Fatalf("new=%d alerts=%d", rep.New, findingAlerts(r, "x"))
	}
	if ds.disk.Seen["x"].Severity != core.SevCritical {
		t.Fatalf("remembered severity = %v, want critical", ds.disk.Seen["x"].Severity)
	}
	r.advance(5 * time.Minute)
	r.dets = []core.Detector{det("a", finding("a", "x", core.SevCritical))}
	if rep := r.cycle(); rep.New != 0 {
		t.Fatalf("critical re-alerted because a lower duplicate overwrote the memory")
	}
}

// (e) A component that is simply absent from a hunt that finished has not recovered.
func TestSeqComponentAbsentFromAFinishedHuntIsNotRecovered(t *testing.T) {
	r, ds := seqRig(t, det("d"))
	r.src.err = down("502")
	r.cycle()
	key := TagIncomplete + "|source s"
	if _, ok := ds.disk.Health[key]; !ok {
		t.Fatalf("no outage recorded: %+v", ds.disk.Health)
	}
	realHunt := r.deps.Hunt
	r.advance(5 * time.Minute)
	r.deps.Hunt = func(_ context.Context, run string, w core.Window) (Result, error) {
		return Result{Run: run, Window: w, Baseline: w.Previous(),
			Sources: []SourceResult{{Name: "other", Status: StatusOK}}}, nil
	}
	r.cycle()
	if n := len(r.sink.kind(core.AlertRecovered)); n != 0 {
		t.Fatalf("declared recovered a source that never ran: %+v", r.sink.got)
	}
	if _, ok := ds.disk.Health[key]; !ok {
		t.Fatal("outage forgotten")
	}
	// It does recover once it reports OK.
	r.advance(5 * time.Minute)
	r.deps.Hunt = realHunt
	r.src.err = nil
	r.cycle()
	if n := len(r.sink.kind(core.AlertRecovered)); n != 1 {
		t.Fatalf("recoveries = %d", n)
	}
	if _, ok := ds.disk.Health[key]; ok {
		t.Fatal("recovered outage still remembered")
	}
}

// (e) A recovery alert the required sink refused leaves the outage pending, across a
// restart, and is delivered next time.
func TestSeqRecoveryDeliveryFailureLeavesTheOutagePending(t *testing.T) {
	r, ds := seqRig(t, det("d"))
	r.src.err = down("502")
	r.cycle()
	r.src.err = nil
	r.sink.failTag = TagRecovered
	r.advance(5 * time.Minute)
	if rep := r.cycle(); rep.Recovered != 0 || rep.Status != CycleFailed {
		t.Fatalf("recovered=%d status=%s", rep.Recovered, rep.Status)
	}
	if len(ds.disk.Health) != 1 {
		t.Fatalf("outage dropped: %+v", ds.disk.Health)
	}
	r.sink.failTag = ""
	r.advance(5 * time.Minute)
	if rep := r.cycle(); rep.Recovered != 1 || len(ds.disk.Health) != 0 {
		t.Fatalf("recovered=%d health=%+v", rep.Recovered, ds.disk.Health)
	}
}

// (f) A gap alert the required sink refused must not be forgotten: the next completed
// cycle still reports the unexamined time.
func TestSeqUndeliveredGapAlertIsReportedAgain(t *testing.T) {
	r, _ := seqRig(t, det("d"))
	r.opts.Every = 30 * time.Minute
	r.opts.Window = 30 * time.Minute
	r.opts.TTL = time.Hour
	r.opts.Repeat = 24 * time.Hour
	i := 0
	// cycle 0 ok, cycles 1-3 down, cycle 4 recovers (gap alert refused), cycle 5 ok.
	r.deps.Wait = func(context.Context, time.Duration) bool {
		i++
		r.now = t0.Add(time.Duration(i) * 30 * time.Minute)
		r.src.err = nil
		if i >= 1 && i <= 3 {
			r.src.err = core.ErrSourceUnavailable
		}
		r.sink.failTag = ""
		if i == 4 {
			r.sink.failTag = TagGap
		}
		return i < 6
	}
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch"); err != nil {
		t.Fatal(err)
	}
	if n := len(gapAlerts(r)); n != 1 {
		t.Fatalf("gap alerts delivered = %d, want 1 (cycle 4's was refused, so cycle 5 must report it)", n)
	}
}

// (a) The heartbeat is the last thing delivered. If it is refused the report is FAILED
// although the heartbeat text, built before, said otherwise; nothing else changes.
func TestSeqHeartbeatFailureFailsTheReportAndOnlyThat(t *testing.T) {
	r, ds := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	r.sink.failTag = TagCycle
	rep := r.cycle()
	if rep.Status != CycleFailed || rep.Err == nil || rep.New != 1 {
		t.Fatalf("status=%s err=%v new=%d", rep.Status, rep.Err, rep.New)
	}
	if !strings.Contains(rep.Err.Error(), "cycle line") {
		t.Errorf("err = %v", rep.Err)
	}
	if _, ok := ds.disk.Seen["x"]; !ok {
		t.Error("the delivered finding was not remembered because the heartbeat failed")
	}
	// Optional-only failure of the heartbeat is pinned by
	// TestSeqOptionalHeartbeatFailureWritesOneFailedLine.
}

func cycleLines(r *rig) []core.Alert { return r.sink.kind(core.AlertCycle) }

// The webhook (optional) refuses only the heartbeat. The log gets ONE cycle line and it
// says FAILED, the same verdict as the report; the webhook was offered exactly one
// heartbeat, with the text it always got (the verdict before its own refusal).
func TestSeqOptionalHeartbeatFailureWritesOneFailedLine(t *testing.T) {
	r, _ := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	hook := &optSink{downTag: TagCycle}
	r.deps.Alerts = core.FanOut{Required: r.sink, Optional: []core.AlertSink{hook}}
	rep := r.cycle()
	if rep.Status != CycleFailed || rep.OptionalFailed == 0 {
		t.Fatalf("status=%s optionalFailed=%d", rep.Status, rep.OptionalFailed)
	}
	lines := cycleLines(r)
	if len(lines) != 1 {
		t.Fatalf("cycle lines in the log = %d, want 1", len(lines))
	}
	if !strings.HasPrefix(lines[0].Text, "CYCLE FAILED") || !strings.Contains(lines[0].Text, "optional sink") {
		t.Errorf("log line = %q, want CYCLE FAILED noting the optional sink", lines[0].Text)
	}
	var hb []core.Alert
	for _, a := range hook.got {
		if a.Kind == core.AlertCycle {
			hb = append(hb, a)
		}
	}
	if len(hb) != 1 || !strings.HasPrefix(hb[0].Text, "CYCLE FINDINGS") {
		t.Errorf("webhook heartbeats = %+v, want exactly one saying CYCLE FINDINGS", hb)
	}
}

// A healthy webhook: one line in the log, one heartbeat at the webhook, same verdict.
func TestSeqOptionalHeartbeatDeliveredOnceEachSameText(t *testing.T) {
	r, _ := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	hook := &optSink{}
	r.deps.Alerts = core.FanOut{Required: r.sink, Optional: []core.AlertSink{hook}}
	rep := r.cycle()
	if rep.Status != CycleFindings {
		t.Fatalf("status=%s", rep.Status)
	}
	lines := cycleLines(r)
	n := 0
	for _, a := range hook.got {
		if a.Kind == core.AlertCycle {
			n++
			if len(lines) == 1 && a.Text != lines[0].Text {
				t.Errorf("webhook text %q differs from log %q", a.Text, lines[0].Text)
			}
		}
	}
	if len(lines) != 1 || n != 1 {
		t.Fatalf("log lines=%d webhook heartbeats=%d, want 1 and 1", len(lines), n)
	}
}

// The log (required) refuses the heartbeat while a webhook is configured: the report is
// FAILED, no line reached the log.
func TestSeqRequiredHeartbeatFailureWithWebhookFailsTheReport(t *testing.T) {
	r, _ := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	r.sink.failTag = TagCycle
	r.deps.Alerts = core.FanOut{Required: r.sink, Optional: []core.AlertSink{&optSink{}}}
	rep := r.cycle()
	if rep.Status != CycleFailed || rep.Err == nil || !strings.Contains(rep.Err.Error(), "cycle line") {
		t.Fatalf("status=%s err=%v", rep.Status, rep.Err)
	}
	if n := len(cycleLines(r)); n != 0 {
		t.Errorf("cycle lines in the log = %d, want 0", n)
	}
}

// No optional sink: one line per cycle, as before.
func TestSeqNoOptionalSinkOneCycleLinePerCycle(t *testing.T) {
	r, _ := seqRig(t, det("a", finding("a", "x", core.SevHigh)))
	r.deps.Alerts = core.FanOut{Required: r.sink}
	for i := 1; i <= 2; i++ {
		r.cycle()
		r.advance(5 * time.Minute)
		if n := len(cycleLines(r)); n != i {
			t.Fatalf("after cycle %d: %d cycle lines", i, n)
		}
	}
	if !strings.HasPrefix(cycleLines(r)[0].Text, "CYCLE FINDINGS") {
		t.Errorf("line = %q", cycleLines(r)[0].Text)
	}
}
