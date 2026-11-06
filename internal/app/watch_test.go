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

// recSink records alerts; failTag makes delivery of that tag fail.
type recSink struct {
	got     []core.Alert
	failTag string
}

func (r *recSink) Deliver(_ context.Context, a core.Alert) error {
	if r.failTag != "" && a.Tag == r.failTag {
		return errors.New("sink down")
	}
	r.got = append(r.got, a)
	return nil
}

func (r *recSink) kind(k string) []core.Alert {
	var out []core.Alert
	for _, a := range r.got {
		if a.Kind == k {
			out = append(out, a)
		}
	}
	return out
}

type memState struct {
	st      core.WatchState
	loadErr error
	saveErr error
	saves   int
}

func (m *memState) Load(context.Context) (core.WatchState, error) { return m.st, m.loadErr }
func (m *memState) Save(_ context.Context, s core.WatchState) error {
	m.saves++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.st = s
	return nil
}

// rig wires a real Hunt over in-memory fakes, so the watch tests exercise the same
// INCOMPLETE rule the CLI uses rather than a stand-in for it.
type rig struct {
	t       *testing.T
	now     time.Time
	src     *fakeSource
	dets    []core.Detector
	sink    *recSink
	state   *memState
	huntErr error // returned by the hunt after it ran
	deps    WatchDeps
	opts    WatchOptions
	waits   []time.Duration
}

func newRig(t *testing.T, dets ...core.Detector) *rig {
	r := &rig{t: t, now: t0, sink: &recSink{}, state: &memState{}, dets: dets,
		opts: WatchOptions{Every: 5 * time.Minute, Window: time.Hour, TTL: time.Hour}}
	r.src = &fakeSource{name: "s", events: []core.Event{{Time: t0.Add(-10 * time.Minute), Source: "s", Kind: "k"}, {Time: t0.Add(-90 * time.Minute), Source: "s", Kind: "k"}}}
	r.deps = WatchDeps{
		Now:    func() time.Time { return r.now },
		State:  r.state,
		Alerts: r.sink,
		Hunt: func(ctx context.Context, run string, w core.Window) (Result, error) {
			mem := newMem()
			res, err := Hunt(ctx, Deps{Sources: []core.Source{r.src}, Detectors: r.dets, Sink: mem, Reader: mem}, run, w)
			if err == nil {
				err = r.huntErr
			}
			return res, err
		},
		Wait: func(context.Context, time.Duration) bool { return false },
	}
	return r
}

func (r *rig) cycle() CycleReport {
	r.t.Helper()
	rep, err := WatchCycle(context.Background(), r.deps, r.opts, "watch-test")
	if err != nil {
		r.t.Fatalf("WatchCycle: %v", err)
	}
	return rep
}

func det(name string, fs ...core.Finding) core.Detector {
	return fakeDetector{name: name, fn: fixed(fs...)}
}

func failingDet(name string, err error) core.Detector {
	return fakeDetector{name: name, fn: func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
		return nil, err
	}}
}

func TestWatchQuietCycleIsQuietAndSaysSo(t *testing.T) {
	r := newRig(t, det("d"))
	rep := r.cycle()
	if rep.Status != CycleQuiet || !rep.Status.Healthy() {
		t.Fatalf("status = %s", rep.Status)
	}
	hb := r.sink.kind(core.AlertCycle)
	if len(hb) != 1 || !strings.Contains(hb[0].Text, "CYCLE QUIET") {
		t.Fatalf("no quiet heartbeat: %+v", r.sink.got)
	}
	if len(r.sink.kind(core.AlertFinding))+len(r.sink.kind(core.AlertIncomplete)) != 0 {
		t.Errorf("unexpected alerts: %+v", r.sink.got)
	}
}

// Rule 1 and 2: a source or detector that did not finish is an alert and the cycle
// is not quiet, whatever else it found.
func TestWatchIncompleteHuntIsAnAlertNotSilence(t *testing.T) {
	cases := map[string]func(r *rig){
		"detector errors":    func(r *rig) { r.dets = []core.Detector{failingDet("broken", errors.New("boom"))} },
		"detector no data":   func(r *rig) { r.dets = []core.Detector{failingDet("empty", core.ErrNoRecords)} },
		"source unavailable": func(r *rig) { r.src.err = core.ErrSourceUnavailable },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, det("d"))
			setup(r)
			rep := r.cycle()
			if rep.Status != CycleIncomplete || rep.Status.Healthy() {
				t.Fatalf("status = %s, want incomplete", rep.Status)
			}
			inc := r.sink.kind(core.AlertIncomplete)
			if len(inc) == 0 || inc[0].Severity != "high" || inc[0].Tag != TagIncomplete {
				t.Fatalf("no incomplete alert: %+v", r.sink.got)
			}
			if hb := r.sink.kind(core.AlertCycle); len(hb) != 1 || !strings.Contains(hb[0].Text, "INCOMPLETE") || strings.Contains(hb[0].Text, "QUIET") {
				t.Errorf("heartbeat reads as quiet: %+v", hb)
			}
		})
	}
}

// wha's Cycle dropped the alerts of a detector that errored. Here the failing
// detector and a healthy one run together: the healthy one's finding still surfaces,
// and the failure is still reported.
func TestWatchFailingDetectorDoesNotHideOthersOrItself(t *testing.T) {
	r := newRig(t, failingDet("broken", errors.New("boom")), det("ok", finding("ok", "t1", core.SevHigh)))
	rep := r.cycle()
	if rep.New != 1 || rep.Status != CycleIncomplete {
		t.Fatalf("new=%d status=%s", rep.New, rep.Status)
	}
	if len(r.sink.kind(core.AlertIncomplete)) != 1 || len(r.sink.kind(core.AlertFinding)) != 1 {
		t.Errorf("alerts: %+v", r.sink.got)
	}
}

func TestWatchHuntErrorIsAFailedCycleWithAnAlert(t *testing.T) {
	r := newRig(t, det("d"))
	r.huntErr = errors.New("save findings: disk full")
	rep := r.cycle()
	if rep.Status != CycleFailed {
		t.Fatalf("status = %s", rep.Status)
	}
	if a := r.sink.kind(core.AlertError); len(a) != 1 || a[0].Tag != TagCycleError || !strings.Contains(a[0].Text, "disk full") {
		t.Errorf("alerts: %+v", r.sink.got)
	}
}

// Rule 3: the key is the tag alone. Same tag from another detector with other prose
// is the same condition.
func TestWatchDedupesOnTagOnly(t *testing.T) {
	r := newRig(t)
	r.dets = []core.Detector{det("a", core.Finding{Detector: "a", Tag: "x", Severity: core.SevHigh, Summary: "count 40"})}
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("first cycle new = %d", rep.New)
	}
	r.now = r.now.Add(5 * time.Minute)
	r.dets = []core.Detector{det("b", core.Finding{Detector: "b", Tag: "x", Severity: core.SevHigh, Summary: "count 41, different prose"})}
	rep := r.cycle()
	if rep.New != 0 || rep.Suppressed != 1 || rep.Status != CycleQuiet {
		t.Fatalf("new=%d suppressed=%d status=%s", rep.New, rep.Suppressed, rep.Status)
	}
	if len(r.sink.kind(core.AlertFinding)) != 1 {
		t.Errorf("finding alerts = %d, want 1", len(r.sink.kind(core.AlertFinding)))
	}
	if hb := r.sink.kind(core.AlertCycle); !strings.Contains(hb[1].Text, "1 held back by ttl") {
		t.Errorf("suppression not reported: %q", hb[1].Text)
	}
}

func TestWatchTTLExpiryRealerts(t *testing.T) {
	r := newRig(t, det("a", finding("a", "x", core.SevHigh)))
	r.cycle()
	r.now = r.now.Add(r.opts.TTL - time.Second)
	if rep := r.cycle(); rep.New != 0 {
		t.Fatal("alerted again inside the ttl")
	}
	r.now = r.now.Add(time.Second) // exactly ttl since the first alert
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("not re-alerted at ttl: new=%d", rep.New)
	}
}

// The tag is the key, but a condition getting worse must not be muted by its
// earlier, milder alert.
func TestWatchEscalationBreaksThroughTheTTL(t *testing.T) {
	r := newRig(t, det("a", finding("a", "x", core.SevCheck)))
	r.cycle()
	r.dets = []core.Detector{det("a", finding("a", "x", core.SevCritical))}
	r.now = r.now.Add(5 * time.Minute)
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("escalation suppressed: new=%d", rep.New)
	}
	r.dets = []core.Detector{det("a", finding("a", "x", core.SevCheck))} // de-escalation stays quiet
	r.now = r.now.Add(5 * time.Minute)
	if rep := r.cycle(); rep.New != 0 {
		t.Fatalf("de-escalation re-alerted: new=%d", rep.New)
	}
}

// A detector that raises a floor on an action keeps its tag. The raised severity
// alerts again inside the TTL; the lower one does not (watchCycle: f.Severity <=
// prev.Severity).
func TestWatchRaisedSeverityUnderUnchangedTagAlertsAndLowerDoesNot(t *testing.T) {
	r := newRig(t, det("a", finding("a", "behaviour:admin-console-login", core.SevActivity)))
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("first: new=%d", rep.New)
	}
	r.dets = []core.Detector{det("a", finding("a", "behaviour:admin-console-login", core.SevCritical))}
	r.now = r.now.Add(5 * time.Minute)
	if rep := r.cycle(); rep.New != 1 || rep.Suppressed != 0 {
		t.Fatalf("raised severity: new=%d suppressed=%d", rep.New, rep.Suppressed)
	}
	r.dets = []core.Detector{det("a", finding("a", "behaviour:admin-console-login", core.SevActivity))}
	r.now = r.now.Add(5 * time.Minute)
	if rep := r.cycle(); rep.New != 0 || rep.Suppressed != 1 {
		t.Fatalf("lower severity: new=%d suppressed=%d", rep.New, rep.Suppressed)
	}
}

func TestWatchFutureDatedStateDoesNotMuteATag(t *testing.T) {
	r := newRig(t, det("a", finding("a", "x", core.SevHigh)))
	r.state.st = core.WatchState{Seen: map[string]core.SeenTag{"x": {At: t0.Add(100 * 24 * time.Hour), Severity: core.SevCritical}}}
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("future-dated entry muted the tag: new=%d", rep.New)
	}
}

func TestWatchUntaggedFindingsAreNeverSuppressed(t *testing.T) {
	r := newRig(t, det("a", core.Finding{Detector: "a", Severity: core.SevHigh, Summary: "no identity"}))
	r.cycle()
	r.now = r.now.Add(time.Minute)
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("untagged finding suppressed: new=%d", rep.New)
	}
}

func TestWatchSeverityOrder(t *testing.T) {
	r := newRig(t, det("a",
		finding("a", "low", core.SevCheck), finding("a", "crit", core.SevCritical),
		finding("a", "mid", core.SevActivity), finding("a", "hi", core.SevHigh)))
	r.cycle()
	var got []string
	for _, a := range r.sink.kind(core.AlertFinding) {
		got = append(got, a.Severity)
	}
	if want := "critical high activity check"; strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

// An alert that was not delivered must not be remembered as delivered.
func TestWatchUndeliveredAlertIsOfferedAgain(t *testing.T) {
	r := newRig(t, det("a", finding("a", "x", core.SevHigh)))
	r.sink.failTag = "x"
	rep := r.cycle()
	if rep.New != 0 || rep.Status != CycleFailed {
		t.Fatalf("new=%d status=%s", rep.New, rep.Status)
	}
	if _, ok := r.state.st.Seen["x"]; ok {
		t.Fatal("tag recorded as seen without being delivered")
	}
	r.sink.failTag = ""
	r.now = r.now.Add(5 * time.Minute)
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("not re-offered: new=%d", rep.New)
	}
}

func TestWatchStateProblemsAreAlerts(t *testing.T) {
	t.Run("corrupt state", func(t *testing.T) {
		r := newRig(t, det("a", finding("a", "x", core.SevHigh)))
		r.state.loadErr = fmt.Errorf("%w: bad", core.ErrStateCorrupt)
		rep := r.cycle()
		if rep.Status != CycleFailed || rep.New != 1 {
			t.Fatalf("status=%s new=%d (a corrupt state must still watch)", rep.Status, rep.New)
		}
		if a := r.sink.kind(core.AlertError); len(a) != 1 || a[0].Tag != TagStateLoad {
			t.Errorf("alerts: %+v", r.sink.got)
		}
	})
	t.Run("save fails", func(t *testing.T) {
		r := newRig(t, det("a"))
		r.state.saveErr = errors.New("read-only filesystem")
		rep := r.cycle()
		if rep.Status != CycleFailed {
			t.Fatalf("status = %s", rep.Status)
		}
		if a := r.sink.kind(core.AlertError); len(a) != 1 || a[0].Tag != TagStateSave {
			t.Errorf("alerts: %+v", r.sink.got)
		}
	})
}

func TestWatchOptionsRefuseGaps(t *testing.T) {
	o := WatchOptions{Every: 10 * time.Minute, Window: 5 * time.Minute}
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "never be examined") {
		t.Fatalf("err = %v", err)
	}
	r := newRig(t, det("d"))
	r.opts = o
	if _, err := WatchCycle(context.Background(), r.deps, o, "x"); err == nil {
		t.Fatal("WatchCycle ran with a window shorter than the interval")
	}
}

func TestWatchLoopSurvivesAFailingCycleAndStopsOnCancel(t *testing.T) {
	r := newRig(t, det("a", finding("a", "x", core.SevHigh)))
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	r.deps.Hunt = func(ctx context.Context, run string, w core.Window) (Result, error) {
		calls++
		if calls == 2 {
			return Result{Run: run, Window: w, Baseline: w.Previous()}, errors.New("transient")
		}
		return Result{Run: run, Window: w, Baseline: w.Previous(), Sources: []SourceResult{{Name: "s", Status: StatusOK}}}, nil
	}
	r.deps.Wait = func(context.Context, time.Duration) bool {
		r.now = r.now.Add(r.opts.Every)
		if calls == 4 {
			cancel()
			return false
		}
		return true
	}
	rep, err := Watch(ctx, r.deps, r.opts, "watch")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("hunts = %d, want 4 (the loop stopped on the failing cycle)", calls)
	}
	if rep.Status != CycleQuiet {
		t.Errorf("last cycle = %s", rep.Status)
	}
	if n := len(r.sink.kind(core.AlertCycle)); n != 4 {
		t.Errorf("heartbeats = %d, want 4", n)
	}
	if n := len(r.sink.kind(core.AlertError)); n != 1 {
		t.Errorf("error alerts = %d, want 1", n)
	}
}

func TestWatchOnceRunsExactlyOneCycle(t *testing.T) {
	r := newRig(t, det("d"))
	r.opts.Once = true
	r.deps.Wait = func(context.Context, time.Duration) bool { t.Fatal("waited after --once"); return true }
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch"); err != nil {
		t.Fatal(err)
	}
	if n := len(r.sink.kind(core.AlertCycle)); n != 1 {
		t.Errorf("cycles = %d", n)
	}
}

// If a cycle starts later than the window can reach back, the hole is reported.
func TestWatchReportsTimeNoWindowCovered(t *testing.T) {
	r := newRig(t, det("d"))
	n := 0
	r.deps.Wait = func(context.Context, time.Duration) bool {
		n++
		r.now = r.now.Add(3 * time.Hour) // a stalled host, a suspended laptop
		return n < 2
	}
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch"); err != nil {
		t.Fatal(err)
	}
	gaps := 0
	for _, a := range r.sink.got {
		if a.Tag == TagGap {
			gaps++
		}
	}
	if gaps != 1 {
		t.Fatalf("gap alerts = %d: %+v", gaps, r.sink.got)
	}
}

// optSink is a stand-in for a webhook: it fails every delivery when down.
type optSink struct {
	down bool
	got  []core.Alert
}

func (o *optSink) Deliver(_ context.Context, a core.Alert) error {
	o.got = append(o.got, a)
	if o.down {
		return errors.New("webhook: HTTP 503")
	}
	return nil
}

// The log (required sink) took the alert, the webhook did not: the tag is remembered,
// because the log is the source of truth and a retry would duplicate the line, but the
// cycle is FAILED, not quiet and not "findings".
func TestWatchOptionalSinkFailureFailsTheCycleButKeepsTheAlertDelivered(t *testing.T) {
	r := newRig(t, det("a", finding("a", "x", core.SevHigh)))
	hook := &optSink{down: true}
	r.deps.Alerts = core.FanOut{Required: r.sink, Optional: []core.AlertSink{hook}}
	rep := r.cycle()
	if rep.Status != CycleFailed || rep.Status.Healthy() {
		t.Fatalf("status = %s, want failed", rep.Status)
	}
	if rep.Err == nil || !strings.Contains(rep.Err.Error(), "HTTP 503") {
		t.Errorf("the webhook failure is not reported: %v", rep.Err)
	}
	if rep.New != 1 || rep.OptionalFailed < 2 { // the finding and the cycle line
		t.Errorf("new=%d optionalFailed=%d", rep.New, rep.OptionalFailed)
	}
	if _, ok := r.state.st.Seen["x"]; !ok {
		t.Error("an alert the log has was not remembered: the next cycle would write it twice")
	}
	if len(r.sink.kind(core.AlertFinding)) != 1 {
		t.Errorf("log holds %d finding alerts", len(r.sink.kind(core.AlertFinding)))
	}
	if hb := r.sink.kind(core.AlertCycle); len(hb) != 1 || !strings.Contains(hb[0].Text, "CYCLE FAILED") || !strings.Contains(hb[0].Text, "not delivered to an optional sink") {
		t.Errorf("heartbeat in the log: %+v", hb)
	}
	// Next cycle: nothing repeats in the log.
	r.now = r.now.Add(5 * time.Minute)
	hook.down = false
	if rep := r.cycle(); rep.New != 0 || rep.Status != CycleQuiet {
		t.Errorf("second cycle new=%d status=%s", rep.New, rep.Status)
	}
	if len(r.sink.kind(core.AlertFinding)) != 1 {
		t.Error("the finding was written to the log twice")
	}
}

// A required-sink failure is the old rule: not delivered, not remembered, offered again.
func TestWatchRequiredSinkFailureStillMeansNotDelivered(t *testing.T) {
	r := newRig(t, det("a", finding("a", "x", core.SevHigh)))
	hook := &optSink{}
	r.sink.failTag = "x"
	r.deps.Alerts = core.FanOut{Required: r.sink, Optional: []core.AlertSink{hook}}
	rep := r.cycle()
	if rep.New != 0 || rep.Status != CycleFailed {
		t.Fatalf("new=%d status=%s", rep.New, rep.Status)
	}
	if _, ok := r.state.st.Seen["x"]; ok {
		t.Fatal("remembered without the log having it")
	}
	for _, a := range hook.got {
		if a.Tag == "x" {
			t.Error("the webhook got an alert the log did not: the retry would duplicate it there")
		}
	}
	r.sink.failTag = ""
	r.now = r.now.Add(5 * time.Minute)
	if rep := r.cycle(); rep.New != 1 {
		t.Fatalf("not re-offered: %d", rep.New)
	}
}

// With --once the exit status comes from the cycle status; a webhook failure makes it 1.
func TestWatchOptionalFailureIsNotHealthy(t *testing.T) {
	r := newRig(t, det("d"))
	r.deps.Alerts = core.FanOut{Required: r.sink, Optional: []core.AlertSink{&optSink{down: true}}}
	rep, err := Watch(context.Background(), r.deps, WatchOptions{Every: 5 * time.Minute, Window: time.Hour, TTL: time.Hour, Once: true}, "watch")
	if err != nil || rep.Status.Healthy() {
		t.Fatalf("status = %s err = %v", rep.Status, err)
	}
}
