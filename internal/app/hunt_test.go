package app

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func win() core.Window { return core.Window{From: t0.Add(-time.Hour), To: t0} }

// memStore is a Sink and an EventReader over memory. It behaves like the real
// store where it matters: a stream error or an empty stream fails the save.
type memStore struct {
	mu          sync.Mutex
	runs        map[string][]core.Event
	findings    map[string][]core.Finding
	findingsSet map[string]bool
	inSink      atomic.Int32
	overlap     atomic.Bool
	failFinding error
}

func newMem() *memStore {
	return &memStore{runs: map[string][]core.Event{}, findings: map[string][]core.Finding{}, findingsSet: map[string]bool{}}
}

func (m *memStore) enter() func() {
	if m.inSink.Add(1) > 1 {
		m.overlap.Store(true)
	}
	time.Sleep(2 * time.Millisecond) // widen the window in which an overlap would show
	return func() { m.inSink.Add(-1) }
}

func (m *memStore) SaveEvents(ctx context.Context, run string, evs iter.Seq2[core.Event, error]) error {
	defer m.enter()()
	var got []core.Event
	for ev, err := range evs {
		if err != nil {
			return fmt.Errorf("event stream for run %q: %w", run, err)
		}
		got = append(got, ev)
	}
	if len(got) == 0 {
		return fmt.Errorf("save events for run %q: %w", run, core.ErrNoRecords)
	}
	m.mu.Lock()
	m.runs[run] = got
	m.mu.Unlock()
	return nil
}

func (m *memStore) SaveFindings(ctx context.Context, run string, fs []core.Finding) error {
	defer m.enter()()
	if m.failFinding != nil {
		return m.failFinding
	}
	m.mu.Lock()
	m.findings[run], m.findingsSet[run] = fs, true
	m.mu.Unlock()
	return nil
}

func (m *memStore) Events(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		m.mu.Lock()
		var out []core.Event
		for _, evs := range m.runs {
			for _, e := range evs {
				if !e.Time.Before(w.From) && e.Time.Before(w.To) {
					out = append(out, e)
				}
			}
		}
		m.mu.Unlock()
		for _, e := range out {
			if !yield(e, nil) {
				return
			}
		}
	}
}

type fakeSource struct {
	name   string
	events []core.Event
	err    error // yielded after the events
	block  bool  // wait for ctx instead of yielding
	gotWin core.Window
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Fetch(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	f.gotWin = w
	return func(yield func(core.Event, error) bool) {
		if f.block {
			<-ctx.Done()
			yield(core.Event{}, ctx.Err())
			return
		}
		for _, e := range f.events {
			if !yield(e, nil) {
				return
			}
		}
		if f.err != nil {
			yield(core.Event{}, f.err)
		}
	}
}

type fakeDetector struct {
	name string
	fn   func(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error)
}

func (f fakeDetector) Name() string { return f.name }
func (f fakeDetector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	return f.fn(ctx, cur, prev, w)
}

func finding(det, tag string, sev core.Severity) core.Finding {
	return core.Finding{Detector: det, Tag: tag, Severity: sev, Summary: det + " saw " + tag}
}

func fixed(fs ...core.Finding) func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
	return func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
		return fs, nil
	}
}

func ev(src string, at time.Time) core.Event {
	return core.Event{Time: at, Source: src, Kind: "auth", Fields: map[string]any{"client_ip": "192.0.2.10"}}
}

func okSource(name string) *fakeSource {
	return &fakeSource{name: name, events: []core.Event{ev(name, t0.Add(-10*time.Minute)), ev(name, t0.Add(-90*time.Minute))}}
}

func TestHuntHappyPath(t *testing.T) {
	m := newMem()
	a, b := okSource("a"), okSource("b")
	res, err := Hunt(context.Background(), Deps{
		Sources:   []core.Source{a, b},
		Detectors: []core.Detector{fakeDetector{"d1", fixed(finding("d1", "spike", core.SevHigh))}},
		Sink:      m, Reader: m,
	}, "run1", win())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || len(res.Findings) != 1 {
		t.Fatalf("complete=%v findings=%d failed=%v", res.Complete(), len(res.Findings), res.Failed())
	}
	for _, s := range res.Sources {
		if s.Status != StatusOK || s.Events != 2 {
			t.Errorf("source %s: %+v", s.Name, s)
		}
	}
	// Distinct run ids per source: sharing one would let the second replace the first.
	if len(m.runs[SourceRun("run1", "a")]) != 2 || len(m.runs[SourceRun("run1", "b")]) != 2 {
		t.Errorf("runs saved: %v", m.runs)
	}
	if got := m.findings["run1"]; len(got) != 1 {
		t.Errorf("saved findings = %v", got)
	}
	// The baseline is fetched too, or no detector could compare anything.
	if want := (core.Window{From: t0.Add(-2 * time.Hour), To: t0}); a.gotWin != want {
		t.Errorf("fetched window = %v, want %v", a.gotWin, want)
	}
	if m.overlap.Load() {
		t.Error("sink calls overlapped")
	}
}

func TestHuntSourceFailuresAreReportedAndDoNotAbortOthers(t *testing.T) {
	m := newMem()
	empty := &fakeSource{name: "empty", err: fmt.Errorf("%w: no hits", core.ErrNoRecords)}
	down := &fakeSource{name: "down", err: fmt.Errorf("%w: HTTP 502", core.ErrSourceUnavailable)}
	bad := &fakeSource{name: "bad", err: errors.New("map hit 7: boom")}
	good := okSource("good")
	ranDetector := false
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{empty, down, bad, good},
		Detectors: []core.Detector{fakeDetector{"d", func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
			ranDetector = true
			return nil, nil
		}}},
		Sink: m, Reader: m,
	}, "r", win())
	if err != nil {
		t.Fatalf("a failing source must not fail the hunt: %v", err)
	}
	want := map[string]Status{"empty": StatusNoRecords, "down": StatusUnavailable, "bad": StatusError, "good": StatusOK}
	for _, s := range res.Sources {
		if s.Status != want[s.Name] {
			t.Errorf("source %s: status %s, want %s", s.Name, s.Status, want[s.Name])
		}
		if s.Status != StatusOK && s.Err == nil {
			t.Errorf("source %s: failure without an error", s.Name)
		}
	}
	if res.Complete() {
		t.Error("a hunt with three failed sources was reported complete")
	}
	if len(res.Failed()) != 3 {
		t.Errorf("Failed() = %v", res.Failed())
	}
	if !ranDetector {
		t.Error("detectors did not run after a source failure")
	}
	if len(m.runs[SourceRun("r", "good")]) != 2 {
		t.Error("the healthy source was not stored")
	}
}

func TestHuntDetectorFailuresAreReportedAndDoNotAbortOthers(t *testing.T) {
	m := newMem()
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{okSource("a")},
		Detectors: []core.Detector{
			fakeDetector{"quiet", func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
				return nil, fmt.Errorf("authspike: %w", core.ErrNoRecords)
			}},
			fakeDetector{"broken", func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
				return nil, errors.New("read events: disk full")
			}},
			fakeDetector{"loud", fixed(finding("loud", "t1", core.SevCritical))},
		},
		Sink: m, Reader: m,
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Status{}
	for _, d := range res.Detectors {
		got[d.Name] = d.Status
	}
	if got["quiet"] != StatusNoRecords || got["broken"] != StatusError || got["loud"] != StatusOK {
		t.Errorf("statuses = %v", got)
	}
	if res.Complete() {
		t.Error("a hunt whose detector found no records was reported complete")
	}
	if len(res.Findings) != 1 || res.Findings[0].Tag != "t1" {
		t.Errorf("findings = %v", res.Findings)
	}
}

func TestHuntDedupesFindingsByTag(t *testing.T) {
	m := newMem()
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{okSource("a")},
		Detectors: []core.Detector{
			fakeDetector{"d1", fixed(finding("d1", "same", core.SevCheck), finding("d1", "", core.SevInfo))},
			fakeDetector{"d2", fixed(finding("d2", "same", core.SevHigh), finding("d2", "", core.SevInfo), finding("d2", "other", core.SevActivity))},
		},
		Sink: m, Reader: m,
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	var same, untagged int
	for _, f := range res.Findings {
		switch f.Tag {
		case "same":
			same++
			if f.Severity != core.SevHigh {
				t.Errorf("kept severity %d, want the most severe", f.Severity)
			}
		case "":
			untagged++
		}
	}
	if same != 1 {
		t.Errorf("tag 'same' appears %d times", same)
	}
	if untagged != 2 {
		t.Errorf("findings with no tag have no identity and must all be kept; got %d", untagged)
	}
	if len(m.findings["r"]) != len(res.Findings) {
		t.Errorf("saved %d findings, returned %d", len(m.findings["r"]), len(res.Findings))
	}
	if res.Findings[0].Severity < res.Findings[len(res.Findings)-1].Severity {
		t.Error("findings are not ordered most severe first")
	}
}

func TestHuntSavesEmptyFindingsSoARerunReplaces(t *testing.T) {
	m := newMem()
	if _, err := Hunt(context.Background(), Deps{
		Sources:   []core.Source{okSource("a")},
		Detectors: []core.Detector{fakeDetector{"d", fixed()}},
		Sink:      m, Reader: m,
	}, "r", win()); err != nil {
		t.Fatal(err)
	}
	if !m.findingsSet["r"] {
		t.Error("SaveFindings was not called for a hunt with none; a stale run would survive")
	}
}

func TestHuntContextCancelStopsEverything(t *testing.T) {
	m := newMem()
	ctx, cancel := context.WithCancel(context.Background())
	detRan := false
	done := make(chan struct{})
	var (
		res Result
		err error
	)
	go func() {
		defer close(done)
		res, err = Hunt(ctx, Deps{
			Sources: []core.Source{&fakeSource{name: "slow", block: true}, &fakeSource{name: "slow2", block: true}},
			Detectors: []core.Detector{fakeDetector{"d", func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
				detRan = true
				return nil, nil
			}}},
			Sink: m, Reader: m, Concurrency: 1,
		}, "r", win())
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Hunt did not return after cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if detRan {
		t.Error("detectors ran after cancellation")
	}
	if m.findingsSet["r"] {
		t.Error("findings were saved after cancellation")
	}
	for _, s := range res.Sources {
		if s.Status != StatusCanceled {
			t.Errorf("source %s status %s, want canceled", s.Name, s.Status)
		}
	}
}

func TestHuntSinkWritesAreSerialisedAndDetectorsBounded(t *testing.T) {
	m := newMem()
	var srcs []core.Source
	for i := range 6 {
		srcs = append(srcs, okSource(fmt.Sprintf("s%d", i)))
	}
	var inflight, peak atomic.Int32
	var dets []core.Detector
	for i := range 6 {
		dets = append(dets, fakeDetector{fmt.Sprintf("d%d", i), func(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
			n := inflight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inflight.Add(-1)
			return nil, nil
		}})
	}
	if _, err := Hunt(context.Background(), Deps{Sources: srcs, Detectors: dets, Sink: m, Reader: m, Concurrency: 2}, "r", win()); err != nil {
		t.Fatal(err)
	}
	if m.overlap.Load() {
		t.Error("two sink writes ran at once")
	}
	if p := peak.Load(); p != 2 {
		t.Errorf("peak concurrent detectors = %d, want exactly the bound 2", p)
	}
}

func TestHuntDetectorsOnlySeeTheirOwnWindow(t *testing.T) {
	m := newMem()
	var curN, prevN int
	count := func(r core.EventReader, w core.Window) int {
		n := 0
		// Ask for far more than the window: the reader must clamp it.
		wide := core.Window{From: w.From.Add(-24 * time.Hour), To: w.To.Add(24 * time.Hour)}
		for _, err := range r.Events(context.Background(), wide) {
			if err != nil {
				t.Error(err)
			}
			n++
		}
		return n
	}
	_, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{okSource("a")}, // one event in each window
		Detectors: []core.Detector{fakeDetector{"d", func(_ context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
			curN, prevN = count(cur, w), count(prev, w.Previous())
			return nil, nil
		}}},
		Sink: m, Reader: m,
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	if curN != 1 || prevN != 1 {
		t.Errorf("cur=%d prev=%d, want 1 and 1", curN, prevN)
	}
}

func TestHuntValidation(t *testing.T) {
	m := newMem()
	okd := []core.Detector{fakeDetector{"d", fixed()}}
	cases := map[string]struct {
		d   Deps
		run string
		w   core.Window
	}{
		"empty run":      {Deps{Sources: []core.Source{okSource("a")}, Detectors: okd, Sink: m, Reader: m}, "", win()},
		"inverted":       {Deps{Sources: []core.Source{okSource("a")}, Detectors: okd, Sink: m, Reader: m}, "r", core.Window{From: t0, To: t0.Add(-time.Hour)}},
		"no sources":     {Deps{Detectors: okd, Sink: m, Reader: m}, "r", win()},
		"no detectors":   {Deps{Sources: []core.Source{okSource("a")}, Sink: m, Reader: m}, "r", win()},
		"no sink":        {Deps{Sources: []core.Source{okSource("a")}, Detectors: okd, Reader: m}, "r", win()},
		"duplicate name": {Deps{Sources: []core.Source{okSource("a"), okSource("a")}, Detectors: okd, Sink: m, Reader: m}, "r", win()},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Hunt(context.Background(), c.d, c.run, c.w); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestHuntFindingsSaveFailureIsAnError(t *testing.T) {
	m := newMem()
	m.failFinding = errors.New("disk full")
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{okSource("a")}, Detectors: []core.Detector{fakeDetector{"d", fixed(finding("d", "t", core.SevHigh))}},
		Sink: m, Reader: m,
	}, "r", win())
	if err == nil {
		t.Fatal("findings that were not saved must fail the hunt")
	}
	if len(res.Findings) != 1 {
		t.Error("the result should still carry the findings that were computed")
	}
}
