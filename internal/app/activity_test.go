package app

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// liveSource is a source whose filter matched nothing in a live index.
type liveSource struct {
	fakeSource
	live       core.Liveness
	unparsable int
}

func (l *liveSource) Liveness() core.Liveness { return l.live }
func (l *liveSource) Unparsable() int         { return l.unparsable }

// repDetector is a detector that reports activity. Detect succeeds with nothing; the
// report or the error is what the test sets.
type repDetector struct {
	name      string
	detectErr error
	report    core.ActivityReport
	repErr    error
}

func (r repDetector) Name() string { return r.name }
func (r repDetector) Detect(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
	return nil, r.detectErr
}
func (r repDetector) Activity(context.Context, core.EventReader, core.EventReader, core.Window) (core.ActivityReport, error) {
	return r.report, r.repErr
}

func sub(name string, cur, prev int, active bool) core.ActivitySubject {
	s := core.ActivitySubject{Subject: name, Kind: "actor", Current: cur, Previous: prev, Active: active}
	if active {
		s.Last = t0.Add(-5 * time.Minute)
	}
	return s
}

func runActivity(t *testing.T, srcs []core.Source, dets ...core.Detector) ActivityResult {
	t.Helper()
	m := newMem()
	res, err := Activity(context.Background(), Deps{Sources: srcs, Detectors: dets, Sink: m, Reader: m}, "act1", win())
	if err != nil {
		t.Fatalf("Activity: %v", err)
	}
	return res
}

func manyEvents(src string, n int) []core.Event {
	var out []core.Event
	for i := range n {
		out = append(out, ev(src, t0.Add(-time.Duration(i+1)*time.Minute)))
	}
	return out
}

func quietReport() core.ActivityReport {
	return core.ActivityReport{Seen: 100, Subjects: []core.ActivitySubject{sub("actor-a", 0, 3, false)}}
}

func TestActivityVerdicts(t *testing.T) {
	active := core.ActivityReport{Seen: 100, Subjects: []core.ActivitySubject{sub("actor-a", 4, 1, true)}}
	for name, tc := range map[string]struct {
		srcs    []core.Source
		det     repDetector
		want    Verdict
		reasons string
	}{
		"genuine event": {[]core.Source{okSource("a")}, repDetector{name: "fp", report: active}, VerdictActive, ""},
		"nothing found": {[]core.Source{okSource("a")}, repDetector{name: "fp", report: quietReport()}, VerdictQuiet, ""},
		"source failed": {
			[]core.Source{&fakeSource{name: "down", err: fmt.Errorf("%w: HTTP 502", core.ErrSourceUnavailable)}},
			repDetector{name: "fp", report: quietReport()}, VerdictIncomplete, "source down did not finish",
		},
		"source silent": {
			[]core.Source{&fakeSource{name: "empty", err: fmt.Errorf("%w: no hits", core.ErrNoRecords)}},
			repDetector{name: "fp", report: quietReport()}, VerdictIncomplete, "source empty did not finish",
		},
		"one of two sources failed": {
			[]core.Source{okSource("a"), &fakeSource{name: "down", err: errors.New("boom")}},
			repDetector{name: "fp", report: quietReport()}, VerdictIncomplete, "source down",
		},
		"detector failed": {
			[]core.Source{okSource("a")},
			repDetector{name: "fp", detectErr: fmt.Errorf("%w: nothing to judge", core.ErrNoRecords)}, VerdictIncomplete, "detector fp did not finish",
		},
		"detector report failed": {
			[]core.Source{okSource("a")},
			repDetector{name: "fp", repErr: errors.New("store read failed")}, VerdictIncomplete, "detector fp did not finish",
		},
		"detector truncated": {
			[]core.Source{okSource("a")},
			repDetector{name: "fp", report: core.ActivityReport{Seen: 10, Truncated: true, Subjects: quietReport().Subjects}}, VerdictIncomplete, "lower bounds",
		},
		"detector mostly unparsable": {
			[]core.Source{okSource("a")},
			repDetector{name: "fp", report: core.ActivityReport{Seen: 100, Unparsable: 25, Subjects: quietReport().Subjects}}, VerdictIncomplete, "could not judge 25%",
		},
		"source mostly unparsable": {
			[]core.Source{&liveSource{fakeSource: *okSource("a"), unparsable: 50}},
			repDetector{name: "fp", report: quietReport()}, VerdictIncomplete, "could not be parsed",
		},
		"a little unparsable is fine": {
			[]core.Source{&liveSource{fakeSource: fakeSource{name: "a", events: manyEvents("a", 10)}, unparsable: 1}},
			repDetector{name: "fp", report: core.ActivityReport{Seen: 100, Unparsable: 5, Subjects: quietReport().Subjects}}, VerdictQuiet, "",
		},
		"active stands despite a failed source": {
			[]core.Source{okSource("a"), &fakeSource{name: "down", err: errors.New("boom")}},
			repDetector{name: "fp", report: active}, VerdictActive, "source down",
		},
	} {
		t.Run(name, func(t *testing.T) {
			res := runActivity(t, tc.srcs, tc.det)
			if res.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s (reasons %v)", res.Verdict, tc.want, res.Reasons)
			}
			if got := strings.Join(res.Reasons, "; "); !strings.Contains(got, tc.reasons) {
				t.Fatalf("reasons = %q, want it to contain %q", got, tc.reasons)
			}
			if tc.want == VerdictQuiet && !res.Complete() {
				t.Fatalf("QUIET with reasons %v", res.Reasons)
			}
			if tc.want == VerdictIncomplete && res.Complete() {
				t.Fatal("INCOMPLETE without a reason")
			}
		})
	}
}

// QUIET is a claim about everything that could have shown activity. One detector that
// found nothing cannot make it QUIET while another did not finish.
func TestActivityOneFailedDetectorBlocksQuiet(t *testing.T) {
	res := runActivity(t, []core.Source{okSource("a")},
		repDetector{name: "fp", report: quietReport()},
		repDetector{name: "beh", detectErr: errors.New("boom")})
	if res.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %s, want INCOMPLETE", res.Verdict)
	}
}

func TestActivityCountsAndLast(t *testing.T) {
	a := core.ActivityReport{Seen: 10, Subjects: []core.ActivitySubject{sub("x", 4, 1, true), sub("y", 0, 2, false)}}
	b := core.ActivityReport{Seen: 10, Subjects: []core.ActivitySubject{{Subject: "z", Kind: "rare", Current: 2, Previous: 0, Active: true, Last: t0.Add(-time.Minute)}}}
	res := runActivity(t, []core.Source{okSource("a")}, repDetector{name: "fp", report: a}, repDetector{name: "beh", report: b})
	if res.Current != 6 || res.Previous != 3 {
		t.Fatalf("counts = %d/%d, want 6/3 (summed from the reports, nothing else)", res.Current, res.Previous)
	}
	if last, ok := res.Last(); !ok || !last.Equal(t0.Add(-5*time.Minute)) {
		t.Fatalf("last = %v %v, want the actor's time (-5m), not the later rare action's", last, ok)
	}
	if res.SourceEvents() != 2 {
		t.Fatalf("source events = %d, want the 2 the fake source yielded", res.SourceEvents())
	}
}

// An inactive subject's Last is not a "last genuine event": only an active subject is.
func TestActivityLastIgnoresInactiveSubjects(t *testing.T) {
	s := sub("x", 0, 0, false)
	s.Last = t0.Add(-time.Minute)
	res := runActivity(t, []core.Source{okSource("a")}, repDetector{name: "fp", report: core.ActivityReport{Seen: 5, Subjects: []core.ActivitySubject{s}}})
	if _, ok := res.Last(); ok {
		t.Fatal("an inactive subject supplied a last genuine time")
	}
}

// The headline time belongs to the actor: a rare action (another party's password reset)
// that is later keeps its own time in its row and does not become "the actor was last seen".
func TestActivityLastActivityPrefersTheActor(t *testing.T) {
	actor := sub("pago-actor", 3, 0, true)
	actor.Last = t0.Add(-3 * time.Hour)
	rare := core.ActivitySubject{Subject: "password-reset", Kind: "rare", Current: 1, Active: true, Last: t0.Add(-time.Hour)}
	res := runActivity(t, []core.Source{okSource("a")},
		repDetector{name: "beh", report: core.ActivityReport{Seen: 5, Subjects: []core.ActivitySubject{rare}}},
		repDetector{name: "fp", report: core.ActivityReport{Seen: 5, Subjects: []core.ActivitySubject{actor}}})
	s, ok := res.LastActivity()
	if !ok || s.Subject != "pago-actor" || !s.Last.Equal(t0.Add(-3*time.Hour)) {
		t.Fatalf("LastActivity = %+v %v, want pago-actor at -3h", s, ok)
	}
	if last, _ := res.Last(); !last.Equal(s.Last) {
		t.Fatalf("Last = %v, want it to agree with LastActivity (%v)", last, s.Last)
	}
	if got := res.Detectors[0].Report.Subjects[0].Last; !got.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("the rare action lost its own time: %v", got)
	}
}

// With no active actor, the newest active rare action makes the verdict ACTIVE and is named.
func TestActivityLastActivityFallsBackToANamedRareAction(t *testing.T) {
	rare := core.ActivitySubject{Subject: "device-code", Kind: "rare", Current: 1, Active: true, Last: t0.Add(-time.Hour)}
	older := core.ActivitySubject{Subject: "password-reset", Kind: "rare", Current: 1, Active: true, Last: t0.Add(-2 * time.Hour)}
	res := runActivity(t, []core.Source{okSource("a")},
		repDetector{name: "beh", report: core.ActivityReport{Seen: 5, Subjects: []core.ActivitySubject{older, rare}}},
		repDetector{name: "fp", report: quietReport()})
	s, ok := res.LastActivity()
	if !ok || s.Subject != "device-code" || s.Kind != "rare" {
		t.Fatalf("LastActivity = %+v %v, want device-code (rare)", s, ok)
	}
}

type plainDetector struct{}

func (plainDetector) Name() string { return "plain" }
func (plainDetector) Detect(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
	return nil, nil
}

func TestActivityRefusesADetectorThatCannotReport(t *testing.T) {
	m := newMem()
	_, err := Activity(context.Background(), Deps{Sources: []core.Source{okSource("a")}, Detectors: []core.Detector{plainDetector{}}, Sink: m, Reader: m}, "r", win())
	if err == nil || !strings.Contains(err.Error(), "cannot report activity") {
		t.Fatalf("err = %v", err)
	}
}

func TestActivityCanceledIsNeverQuiet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := newMem()
	src := &fakeSource{name: "slow", block: true}
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	res, err := Activity(ctx, Deps{Sources: []core.Source{src}, Detectors: []core.Detector{repDetector{name: "fp", report: quietReport()}}, Sink: m, Reader: m}, "r", win())
	if err == nil {
		t.Fatal("no error after cancel")
	}
	if res.Verdict == VerdictQuiet {
		t.Fatal("a canceled check was called QUIET")
	}
}

// The sink refuses an empty save as no_records. A source that matched nothing through a
// filter and then showed its index alive has answered; a source that failed has not.
func TestHuntFilteredEmptyOnALiveIndexIsOKAndSaysSo(t *testing.T) {
	m := newMem()
	live := &liveSource{fakeSource: fakeSource{name: "live"}, live: core.Liveness{Probed: true, IndexTotal: 1234}}
	res, err := Hunt(context.Background(), Deps{
		Sources:   []core.Source{live},
		Detectors: []core.Detector{fakeDetector{"d", fixed()}},
		Sink:      m, Reader: m,
	}, "run1", win())
	if err != nil {
		t.Fatal(err)
	}
	s := res.Sources[0]
	if s.Status != StatusOK || s.Events != 0 || !s.IndexAlive || s.IndexDocs != 1234 || !s.NoMatch() {
		t.Fatalf("source = %+v", s)
	}
	if got := s.Outcome(); got != "no match; index alive" {
		t.Fatalf("outcome = %q", got)
	}
	if _, saved := m.runs[SourceRun("run1", "live")]; saved {
		t.Fatal("an empty run was saved")
	}
}

func TestHuntFilteredEmptyWithoutAProbeOrWithASourceErrorStaysAFailure(t *testing.T) {
	for name, src := range map[string]core.Source{
		"no probe ran":       &liveSource{fakeSource: fakeSource{name: "s"}},
		"silent index":       &liveSource{fakeSource: fakeSource{name: "s", err: fmt.Errorf("%w: no hits", core.ErrNoRecords)}},
		"probe then failure": &liveSource{fakeSource: fakeSource{name: "s", err: fmt.Errorf("%w: gone", core.ErrNoRecords)}, live: core.Liveness{Probed: true, IndexTotal: 5}},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMem()
			res, err := Hunt(context.Background(), Deps{Sources: []core.Source{src}, Detectors: []core.Detector{fakeDetector{"d", fixed()}}, Sink: m, Reader: m}, "r", win())
			if err != nil {
				t.Fatal(err)
			}
			s := res.Sources[0]
			if s.Status != StatusNoRecords || s.NoMatch() || s.IndexAlive {
				t.Fatalf("source = %+v, want no_records and not alive", s)
			}
			if s.Outcome() != "index empty or nothing readable" {
				t.Fatalf("outcome = %q", s.Outcome())
			}
		})
	}
}

func TestOutcomeNamesEachFailure(t *testing.T) {
	for st, want := range map[Status]string{
		StatusUnavailable: "unreachable", StatusCanceled: "canceled", StatusError: "failed", StatusNoRecords: "index empty or nothing readable",
	} {
		if got := (SourceResult{Status: st}).Outcome(); got != want {
			t.Errorf("%s: %q, want %q", st, got, want)
		}
	}
	if got := (SourceResult{Status: StatusOK, Events: 3}).Outcome(); got != "matched" {
		t.Errorf("matched: %q", got)
	}
}

type fakeFinder struct{}

func (fakeFinder) EventsByField(context.Context, string, string) iter.Seq2[core.Event, error] {
	return func(func(core.Event, error) bool) {}
}

type histDetector struct {
	plainDetector
	h []core.ActorHistory
}

func (d histDetector) History(context.Context, core.FieldEventFinder) ([]core.ActorHistory, error) {
	return d.h, nil
}

func TestActorStatus(t *testing.T) {
	got, err := ActorStatus(context.Background(), ActorStatusDeps{
		Detectors: []core.Detector{plainDetector{}, histDetector{h: []core.ActorHistory{{Actor: "a"}}}},
		Finder:    fakeFinder{},
	})
	if err != nil || len(got) != 1 || got[0].Actor != "a" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := ActorStatus(context.Background(), ActorStatusDeps{Detectors: []core.Detector{plainDetector{}}, Finder: fakeFinder{}}); err == nil {
		t.Fatal("no actor-keeping detector was accepted")
	}
	if _, err := ActorStatus(context.Background(), ActorStatusDeps{Detectors: []core.Detector{histDetector{}}}); err == nil {
		t.Fatal("no finder was accepted")
	}
}
