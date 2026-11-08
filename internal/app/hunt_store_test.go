package app_test

// Sequence tests: repeated hunts against the real DuckDB store. They assert what a
// detector reads, what is stored and what the Result says, across runs and reopens.
// Times derive from time.Now(): the store reads the real clock.

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
)

type seqEnv struct {
	t    *testing.T
	path string
	st   *duckdb.Store
	now  time.Time
}

func newSeqEnv(t *testing.T) *seqEnv {
	t.Helper()
	e := &seqEnv{t: t, path: filepath.Join(t.TempDir(), "jb.duckdb"), now: time.Now().UTC().Truncate(time.Second)}
	e.open()
	t.Cleanup(func() {
		if e.st != nil {
			_ = e.st.Close()
		}
	})
	return e
}

func (e *seqEnv) open() {
	e.t.Helper()
	st, err := duckdb.Open(e.path, false)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := st.Migrate(); err != nil {
		e.t.Fatal(err)
	}
	e.st = st
}

// reopen closes the store and opens the same file again, as the next process would.
func (e *seqEnv) reopen() {
	e.t.Helper()
	if err := e.st.Close(); err != nil {
		e.t.Fatal(err)
	}
	e.open()
}

func (e *seqEnv) window() core.Window {
	return core.Window{From: e.now.Add(-time.Hour), To: e.now}
}

// at is a time in the current window (age before the window end).
func (e *seqEnv) at(age time.Duration) time.Time { return e.now.Add(-age) }

type seqSource struct {
	name  string
	scope string
	docs  []string // ids returned, in order
	// failAfter: yield this error after that many events (-1: never).
	failAfter int
	err       error
	age       time.Duration
	live      bool
	zeroTime  bool
	noKey     bool // the source names a scope but its events carry no document key
}

func (s *seqSource) Name() string { return s.name }

// DocScope is the scope the test names, or one private to the source: every real source
// names a scope, and a private one never makes two sources share documents.
func (s *seqSource) DocScope() string {
	if s.scope == "" {
		return "private-scope/" + s.name
	}
	return s.scope
}
func (s *seqSource) Liveness() core.Liveness {
	return core.Liveness{Probed: s.live, IndexTotal: 10}
}

func (s *seqSource) fetch(now time.Time) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		for i, id := range s.docs {
			if s.err != nil && i == s.failAfter {
				yield(core.Event{}, s.err)
				return
			}
			ev := core.Event{Time: now.Add(-s.age), Kind: "auth", Fields: map[string]any{"id": id}, Raw: []byte(id)}
			if s.zeroTime {
				ev.Time = time.Time{}
			}
			if !s.noKey {
				ev.DocKey = id
			}
			if !yield(ev, nil) {
				return
			}
		}
		if s.err != nil && s.failAfter >= len(s.docs) {
			yield(core.Event{}, s.err)
		}
	}
}

type boundSource struct {
	*seqSource
	now time.Time
}

func (b boundSource) Fetch(_ context.Context, _ core.Window) iter.Seq2[core.Event, error] {
	return b.fetch(b.now)
}

// seqDet reads the current and preceding window and records the ids it saw.
type seqDet struct {
	name string
	mu   sync.Mutex
	cur  []string
	prev []string
	err  error
}

func (d *seqDet) Name() string { return d.name }
func (d *seqDet) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	d.cur, d.prev = nil, nil
	for ev, err := range cur.Events(ctx, w) {
		if err != nil {
			return nil, err
		}
		d.cur = append(d.cur, ev.Fields["id"].(string))
	}
	for ev, err := range prev.Events(ctx, w.Previous()) {
		if err != nil {
			return nil, err
		}
		d.prev = append(d.prev, ev.Fields["id"].(string))
	}
	slices.Sort(d.cur)
	slices.Sort(d.prev)
	return []core.Finding{{Detector: d.name, Tag: d.name + ":seen", Summary: fmt.Sprint(len(d.cur))}}, d.err
}

type failFindingsSink struct {
	core.Sink
	fail bool
}

func (f *failFindingsSink) SaveFindings(ctx context.Context, run string, fs []core.Finding) error {
	if f.fail {
		return errors.New("sink: disk full")
	}
	return f.Sink.SaveFindings(ctx, run, fs)
}

func (e *seqEnv) hunt(run string, sink core.Sink, srcs []*seqSource, dets []core.Detector, scopes map[string][]string) (app.Result, error) {
	e.t.Helper()
	var cs []core.Source
	for _, s := range srcs {
		cs = append(cs, boundSource{s, e.now})
	}
	if sink == nil {
		sink = e.st
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return app.Hunt(ctx, app.Deps{Sources: cs, Detectors: dets, Sink: sink, Reader: e.st, Scopes: scopes, Concurrency: 1}, run, e.window())
}

func (e *seqEnv) findings(run string) []core.Finding {
	e.t.Helper()
	fs, err := e.st.Findings(context.Background(), run)
	if err != nil {
		e.t.Fatal(err)
	}
	return fs
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func src(name, scope string, ids ...string) *seqSource {
	return &seqSource{name: name, scope: scope, docs: ids, failAfter: -1, age: 10 * time.Minute}
}

const es = "https://es.example.com"

// Overlapping sources, hunted twice with a reopen between: every detector, scoped or not,
// reads each document once, before and after the reopen, and the second hunt (all
// duplicates of the first, under another run id) changes nothing a detector reads.
func TestSeqOverlappingSourcesAcrossRunsAndReopen(t *testing.T) {
	e := newSeqEnv(t)
	all, onlyB := &seqDet{name: "all"}, &seqDet{name: "onlyB"}
	dets := []core.Detector{all, onlyB}
	scopes := map[string][]string{"onlyB": {"b"}}
	srcs := []*seqSource{src("a", es, "d1", "d2"), src("b", es, "d2", "d3")}

	for i, run := range []string{"hunt-1", "hunt-2"} {
		res, err := e.hunt(run, nil, srcs, dets, scopes)
		if err != nil || !res.Complete() {
			t.Fatalf("hunt %d: err %v failed %v", i, err, res.Failed())
		}
		eq(t, run+" all", all.cur, []string{"d1", "d2", "d3"})
		eq(t, run+" onlyB", onlyB.cur, []string{"d2", "d3"})
		e.reopen()
	}
	// After the reopen a third hunt that reads nothing new still sees the same.
	res, err := e.hunt("hunt-3", nil, srcs, dets, scopes)
	if err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	eq(t, "hunt-3 onlyB", onlyB.cur, []string{"d2", "d3"})
}

// One source fails mid-stream in the second hunt. The Result says so and is incomplete, the
// failed source's run is not half stored, the first hunt's evidence still reaches the
// detectors, and the other source's evidence is kept.
func TestSeqSourceFailsMidStreamInLaterHunt(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	dets := []core.Detector{all}
	a, b := src("a", es, "d1", "d2"), src("b", es, "d3", "d4")
	if res, err := e.hunt("hunt-1", nil, []*seqSource{a, b}, dets, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	e.reopen()

	b2 := src("b", es, "d3", "d5", "d6")
	b2.err, b2.failAfter = fmt.Errorf("%w: connection reset", core.ErrSourceUnavailable), 2
	res, err := e.hunt("hunt-2", nil, []*seqSource{a, b2}, dets, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || !slices.Equal(res.Failed(), []string{"source b"}) {
		t.Fatalf("failed = %v, want only source b", res.Failed())
	}
	if res.Sources[1].Status != app.StatusUnavailable {
		t.Errorf("status %q", res.Sources[1].Status)
	}
	// d5 was read before the failure but b's run rolled back; d3 is held by hunt 1.
	eq(t, "all", all.cur, []string{"d1", "d2", "d3", "d4"})
	// The detector still produced its finding; the run is stored with it.
	if fs := e.findings("hunt-2"); len(fs) != 1 {
		t.Errorf("findings of hunt-2 = %v", fs)
	}
}

// Every source returning a document fails: the document is lost with them and reported,
// while a source that read cleanly owns the documents it shares with a failed one.
func TestSeqFailedSourceDoesNotOwnSharedDocument(t *testing.T) {
	e := newSeqEnv(t)
	all, onlyB := &seqDet{name: "all"}, &seqDet{name: "onlyB"}
	a := src("a", es, "d1", "d2", "d3")
	a.err, a.failAfter = errors.New("boom"), 3
	b := src("b", es, "d2")
	res, err := e.hunt("hunt-1", nil, []*seqSource{a, b}, []core.Detector{all, onlyB}, map[string][]string{"onlyB": {"b"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Failed(), []string{"source a"}) {
		t.Fatalf("failed = %v", res.Failed())
	}
	eq(t, "all", all.cur, []string{"d2"}) // d1, d3 died with a's rolled back run
	eq(t, "onlyB", onlyB.cur, []string{"d2"})
}

// The sink refuses the findings: Hunt returns the error, the events of the hunt are stored,
// and a retry under the same run id succeeds and stores the findings.
func TestSeqFindingsSinkFailureKeepsEvidenceAndRetries(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	srcs := []*seqSource{src("a", es, "d1", "d2")}
	bad := &failFindingsSink{Sink: e.st, fail: true}
	res, err := e.hunt("hunt-1", bad, srcs, []core.Detector{all}, nil)
	if err == nil {
		t.Fatal("want the sink error")
	}
	if !res.Complete() || len(res.Findings) != 1 {
		t.Errorf("the Result must still carry what was completed: %+v", res)
	}
	if got := e.findings("hunt-1"); len(got) != 0 {
		t.Errorf("findings stored despite the failure: %v", got)
	}
	e.reopen()
	if res, err := e.hunt("hunt-1", nil, srcs, []core.Detector{all}, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	eq(t, "all", all.cur, []string{"d1", "d2"})
	if got := e.findings("hunt-1"); len(got) != 1 {
		t.Errorf("findings = %v", got)
	}
}

// A healthy source that matched nothing (index alive) is ok and saves nothing; the
// earlier hunts' evidence is still what detectors read. A source with no liveness proof that
// returns nothing is no_records, and the hunt is incomplete.
func TestSeqEmptyHealthyFetchVersusEmptyUnproven(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	dets := []core.Detector{all}
	if res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", "", "d1")}, dets, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	e.reopen()

	empty := src("a", "")
	empty.live = true
	res, err := e.hunt("hunt-2", nil, []*seqSource{empty}, dets, nil)
	if err != nil || !res.Complete() || !res.Sources[0].NoMatch() {
		t.Fatalf("err %v, failed %v, source %+v", err, res.Failed(), res.Sources[0])
	}
	eq(t, "all after a healthy empty hunt", all.cur, []string{"d1"})

	empty.live = false
	res, err = e.hunt("hunt-3", nil, []*seqSource{empty}, dets, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || res.Sources[0].Status != app.StatusNoRecords {
		t.Errorf("empty unproven source must be no_records and incomplete: %+v", res.Sources[0])
	}
}

// `--until` hunts reuse a run id (prefix-until-STAMP-wNs). Re-running one with a source that
// now returns nothing (healthy) saves nothing: SaveEvents refuses to replace a run with
// nothing, as it does for any run id, so the earlier events stay. That matches a fresh run
// id (evidence is never retracted); this test pins it so a change is deliberate.
func TestSeqSameRunIDRerunWithEmptyFetchKeepsTheRunsEvidence(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	dets := []core.Detector{all}
	if res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", "", "d1", "d2")}, dets, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	empty := src("a", "")
	empty.live = true
	res, err := e.hunt("hunt-1", nil, []*seqSource{empty}, dets, nil)
	if err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	eq(t, "all", all.cur, []string{"d1", "d2"})
	// The source answered, so the status stays ok; the outcome says the old events were kept.
	s := res.Sources[0]
	want := "no match in this fetch; kept 2 event(s) stored under this run id earlier; index alive"
	if s.Status != app.StatusOK || !s.NoMatch() || s.Kept != 2 || s.Outcome() != want {
		t.Errorf("source = %+v, outcome %q, want %q", s, s.Outcome(), want)
	}
}

// A fresh run id with an empty live fetch keeps the plain wording, even when other runs
// stored events for the same source and window: only this run id's own events count.
func TestSeqFreshRunIDEmptyFetchKeepsPlainNoMatchWording(t *testing.T) {
	e := newSeqEnv(t)
	dets := []core.Detector{&seqDet{name: "all"}}
	if res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", "", "d1")}, dets, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	empty := src("a", "")
	empty.live = true
	res, err := e.hunt("hunt-2", nil, []*seqSource{empty}, dets, nil)
	if err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	if s := res.Sources[0]; s.Kept != 0 || s.Outcome() != "no match; index alive" {
		t.Errorf("source = %+v, outcome %q", s, s.Outcome())
	}
}

type failSourceSink struct {
	core.Sink
	failRun string
}

func (f failSourceSink) SaveEvents(ctx context.Context, run string, evs iter.Seq2[core.Event, error]) error {
	if run == f.failRun {
		for range evs { // drain, then refuse at commit
		}
		return errors.New("sink: commit failed")
	}
	return f.Sink.SaveEvents(ctx, run, evs)
}

// The sink refuses one source's events: that source is an error and the hunt incomplete,
// the other source is stored and read, and the failing source's earlier evidence is intact.
func TestSeqSinkRefusesOneSourcesEvents(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	dets := []core.Detector{all}
	if res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", "", "d1"), src("b", "", "d2")}, dets, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	e.reopen()
	sink := failSourceSink{Sink: e.st, failRun: app.SourceRun("hunt-2", "b")}
	res, err := e.hunt("hunt-2", sink, []*seqSource{src("a", "", "d1", "d3"), src("b", "", "d4")}, dets, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Failed(), []string{"source b"}) || res.Sources[1].Status != app.StatusError {
		t.Fatalf("failed = %v, %+v", res.Failed(), res.Sources)
	}
	eq(t, "all", all.cur, []string{"d1", "d2", "d3"})
}

// An event with no time is a mapper bug: the source is an error, its run is not stored,
// and the other sources are unaffected.
func TestSeqZeroTimeEventFailsOnlyItsSource(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	bad := src("b", "", "d9")
	bad.zeroTime = true
	res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", "", "d1"), bad}, []core.Detector{all}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Failed(), []string{"source b"}) {
		t.Fatalf("failed = %v", res.Failed())
	}
	eq(t, "all", all.cur, []string{"d1"})
}

// An event with no document identity is refused by the store: the source that produced it
// ends INCOMPLETE with the store's message, nothing of its run is stored, and the other
// sources are unaffected.
func TestSeqKeylessEventEndsItsSourceIncompleteAndStoresNothing(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	bad := src("b", "", "d9")
	bad.noKey = true
	res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", "", "d1"), bad}, []core.Detector{all}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || !slices.Equal(res.Failed(), []string{"source b"}) || res.Sources[1].Status != app.StatusError {
		t.Fatalf("failed = %v, %+v", res.Failed(), res.Sources)
	}
	if !errors.Is(res.Sources[1].Err, core.ErrNoDocIdentity) {
		t.Fatalf("err = %v, want core.ErrNoDocIdentity", res.Sources[1].Err)
	}
	want := fmt.Sprintf("event 0 of run %q has no document identity: its source named no document scope or no document key", app.SourceRun("hunt-1", "b"))
	if !strings.Contains(res.Sources[1].Err.Error(), want) {
		t.Fatalf("err = %q, want it to contain %q", res.Sources[1].Err, want)
	}
	eq(t, "all", all.cur, []string{"d1"})
}

// The same for a source that shares a scope with another (its events are collected before
// they are stored): a keyless event of a shared-scope source is refused too.
func TestSeqKeylessEventOfSharedScopeSourceEndsIncomplete(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	bad := src("b", es, "d9")
	bad.noKey = true
	res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", es, "d1"), bad}, []core.Detector{all}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Failed(), []string{"source b"}) || !errors.Is(res.Sources[1].Err, core.ErrNoDocIdentity) {
		t.Fatalf("failed = %v, %+v", res.Failed(), res.Sources)
	}
	eq(t, "all", all.cur, []string{"d1"})
}

// A later hunt over a shifted-in subset: evidence a source no longer returns is still
// stored (evidence is not retracted), and the baseline window is read from the store.
func TestSeqLaterSubsetKeepsEarlierEvidenceAndBaseline(t *testing.T) {
	e := newSeqEnv(t)
	all := &seqDet{name: "all"}
	dets := []core.Detector{all}
	a := src("a", "", "d1", "d2")
	old := src("p", "", "p1")
	old.age = 90 * time.Minute // baseline window
	if res, err := e.hunt("hunt-1", nil, []*seqSource{a, old}, dets, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	e.reopen()
	a2 := src("a", "", "d2")
	old2 := src("p", "", "p2")
	old2.age = 90 * time.Minute
	if res, err := e.hunt("hunt-2", nil, []*seqSource{a2, old2}, dets, nil); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	eq(t, "cur", all.cur, []string{"d1", "d2"})
	eq(t, "prev", all.prev, []string{"p1", "p2"})
}

// Scoped detectors across runs: a document returned by both a and b in hunt 1 is owned by
// a; in hunt 2 only a is configured. A detector scoped to b must not be handed more than
// b ever returned, and one scoped to a keeps reading it.
func TestSeqScopedReadsAcrossRuns(t *testing.T) {
	e := newSeqEnv(t)
	onlyA, onlyB := &seqDet{name: "onlyA"}, &seqDet{name: "onlyB"}
	dets := []core.Detector{onlyA, onlyB}
	scopes := map[string][]string{"onlyA": {"a"}, "onlyB": {"b"}}
	if res, err := e.hunt("hunt-1", nil, []*seqSource{src("a", es, "d1", "d2"), src("b", es, "d2", "d3")}, dets, scopes); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	eq(t, "onlyA", onlyA.cur, []string{"d1", "d2"})
	eq(t, "onlyB", onlyB.cur, []string{"d2", "d3"})
	e.reopen()
	// Second hunt: b is healthy but empty (alive), a returns d1 only.
	b := src("b", es)
	b.live = true
	if res, err := e.hunt("hunt-2", nil, []*seqSource{src("a", es, "d1"), b}, dets, scopes); err != nil || !res.Complete() {
		t.Fatal(err, res.Failed())
	}
	eq(t, "onlyA", onlyA.cur, []string{"d1", "d2"})
	eq(t, "onlyB", onlyB.cur, []string{"d2", "d3"})
}

// A detector that fails beside findings makes the hunt incomplete, and the findings are
// stored; the next hunt, without the error, is complete and replaces nothing of the first.
func TestSeqDetectorErrorThenRecovery(t *testing.T) {
	e := newSeqEnv(t)
	d := &seqDet{name: "d", err: errors.New("partial")}
	srcs := []*seqSource{src("a", "", "d1")}
	res, err := e.hunt("hunt-1", nil, srcs, []core.Detector{d}, nil)
	if err != nil || res.Complete() || len(e.findings("hunt-1")) != 1 {
		t.Fatalf("err %v failed %v findings %v", err, res.Failed(), e.findings("hunt-1"))
	}
	e.reopen()
	d.err = nil
	res, err = e.hunt("hunt-2", nil, srcs, []core.Detector{d}, nil)
	if err != nil || !res.Complete() || len(e.findings("hunt-1")) != 1 {
		t.Fatalf("err %v failed %v", err, res.Failed())
	}
}
