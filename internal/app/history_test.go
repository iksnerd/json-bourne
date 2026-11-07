package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// countSrc is a fake source that can count keys: a cluster (DocScope), an index and a
// table of counts. calls records what the probe asked.
type countSrc struct {
	*fakeSource
	scope, index, mode string
	field, timeField   string // the probe settings other than the index list
	counts             map[string]int64
	all                int64
	keyErr             error
	unions             []string // the index targets the probe asked this source to count

	mu         sync.Mutex
	keyCalls   int
	allCalls   int
	lastWindow core.Window
}

func newCountSrc(name, scope, index string, counts map[string]int64) *countSrc {
	return &countSrc{fakeSource: okSource(name), scope: scope, index: index, mode: "phrase", field: "message", timeField: "@timestamp", counts: counts, all: 1000}
}

func (c *countSrc) DocScope() string  { return c.scope }
func (c *countSrc) IndexName() string { return c.index }
func (c *countSrc) KeyMode() string   { return c.mode }

// ProbeKey is what makes two sources interchangeable for one request: field, mode and time field.
func (c *countSrc) ProbeKey() string { return c.field + "\x00" + c.mode + "\x00" + c.timeField }

func (c *countSrc) CountKeys(_ context.Context, keys []string, w core.Window) (map[string]int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyCalls++
	c.lastWindow = w
	if c.keyErr != nil {
		return nil, c.keyErr
	}
	out := map[string]int64{}
	for _, k := range keys {
		out[k] = c.counts[k]
	}
	return out, nil
}

func (c *countSrc) CountAll(context.Context, core.Window) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allCalls++
	return c.all, nil
}

// CountingIndices is how the probe asks one source to count a cluster over the union of
// its sources' index expressions. The fake answers with its own table, as Elasticsearch
// does when a document matches more than one expression: once.
func (c *countSrc) CountingIndices(indices []string) (core.KeyCounter, error) {
	c.mu.Lock()
	c.unions = append(c.unions, strings.Join(indices, ","))
	c.mu.Unlock()
	return c, nil
}

var lookWin = core.Window{From: t0.Add(-8 * 24 * time.Hour), To: t0.Add(-time.Hour)}

func TestHistorySameClusterAndIndexIsCountedOnce(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	b := newCountSrc("b", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	h := newKeyHistory([]core.Source{a, b})
	got, err := h.Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
	if err != nil {
		t.Fatal(err)
	}
	if got["192.0.2.7"] != 30 {
		t.Errorf("count = %d, want 30: two sources on one cluster and index are one index", got["192.0.2.7"])
	}
	if a.keyCalls+b.keyCalls != 1 || a.allCalls+b.allCalls != 1 {
		t.Errorf("requests: keys %d all %d, want one of each for the one index", a.keyCalls+b.keyCalls, a.allCalls+b.allCalls)
	}
}

// Two sources on one cluster with overlapping patterns return the same 30 documents. The
// cluster is probed once over both patterns, so the documents count once; a second cluster adds.
func TestHistoryOverlappingPatternsOnOneClusterCountOnce(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-*", map[string]int64{"192.0.2.7": 30})
	b := newCountSrc("b", "https://kibana.example.com", "logs-web-*", map[string]int64{"192.0.2.7": 30})
	c := newCountSrc("c", "https://other.example.com", "logs-1", map[string]int64{"192.0.2.7": 5})
	got, err := newKeyHistory([]core.Source{a, b, c}).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
	if err != nil {
		t.Fatal(err)
	}
	if got["192.0.2.7"] != 35 {
		t.Errorf("count = %d, want 35: the 30 shared documents once, plus 5 from the other cluster", got["192.0.2.7"])
	}
	if len(a.unions) != 1 || a.unions[0] != "logs-*,logs-web-*" || len(b.unions) != 0 {
		t.Errorf("union requests: a %v, b %v, want both patterns asked once, through the first source", a.unions, b.unions)
	}
	if a.keyCalls+b.keyCalls+c.keyCalls != 2 || a.allCalls+b.allCalls+c.allCalls != 2 {
		t.Errorf("keys requests %d, all requests %d, want one per cluster each", a.keyCalls+b.keyCalls+c.keyCalls, a.allCalls+b.allCalls+c.allCalls)
	}
	if a.lastWindow != lookWin {
		t.Errorf("window = %v, want %v", a.lastWindow, lookWin)
	}
}

func TestHistorySourceWithoutThePortIsAnErrorNamingIt(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", nil)
	plain := okSource("plain-source")
	_, err := newKeyHistory([]core.Source{a, plain}).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
	if err == nil || !strings.Contains(err.Error(), "plain-source") {
		t.Fatalf("err = %v, want a refusal naming the source", err)
	}
	if a.keyCalls != 0 {
		t.Error("a probe ran although a source cannot count")
	}
}

func TestHistoryAnIndexWithNoEventsInTheLookbackCannotShowHistory(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	b := newCountSrc("b", "https://other.example.com", "logs-2", nil)
	b.all = 0
	_, err := newKeyHistory([]core.Source{a, b}).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
	if err == nil || !strings.Contains(err.Error(), "logs-2") || !strings.Contains(err.Error(), "cannot show history") {
		t.Fatalf("err = %v, want the blind index named: a zero is not an answer", err)
	}
	if a.keyCalls+b.keyCalls != 0 {
		t.Error("keys were counted before every index proved it could see")
	}
}

func TestHistoryProbeErrorIsReturnedWithoutTheKey(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", nil)
	a.keyErr = errors.New("kibana returned HTTP 502")
	_, err := newKeyHistory([]core.Source{a}).Counts(context.Background(), []string{"192.0.2.7"}, lookWin)
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") || strings.Contains(err.Error(), "192.0.2.7") {
		t.Fatalf("err = %v", err)
	}
}

func TestHistoryMatchModeReportsOneModeOrMixed(t *testing.T) {
	a := newCountSrc("a", "u", "i1", nil)
	b := newCountSrc("b", "v", "i2", nil)
	if m := newKeyHistory([]core.Source{a, b}).MatchMode(); m != "phrase" {
		t.Errorf("mode = %q", m)
	}
	b.mode = "term"
	if m := newKeyHistory([]core.Source{a, b}).MatchMode(); m != "phrase+term" {
		t.Errorf("mode = %q", m)
	}
}

// histDet is a HistoryDetector that records which entry point the host used.
type histDet struct {
	name     string
	plain    atomic.Int32
	withHist atomic.Int32
	got      core.KeyHistory
	counts   map[string]int64
	mu       sync.Mutex
	err      error
}

func (d *histDet) Name() string { return d.name }
func (d *histDet) Detect(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
	d.plain.Add(1)
	return nil, errors.New("plain Detect must not run")
}
func (d *histDet) DetectWithHistory(ctx context.Context, _, _ core.EventReader, w core.Window, h core.KeyHistory) ([]core.Finding, error) {
	d.withHist.Add(1)
	d.mu.Lock()
	d.got = h
	d.mu.Unlock()
	c, err := h.Counts(ctx, []string{"192.0.2.7"}, core.Window{From: w.From.Add(-7 * 24 * time.Hour), To: w.From})
	d.err = err
	d.counts = c
	return nil, err
}
func (d *histDet) Activity(context.Context, core.EventReader, core.EventReader, core.Window) (core.ActivityReport, error) {
	return core.ActivityReport{Seen: 1}, nil
}

func huntHist(t *testing.T, scopes map[string][]string, srcs []core.Source, dets ...core.Detector) Result {
	t.Helper()
	m := newMem()
	res, err := Hunt(context.Background(), Deps{Sources: srcs, Detectors: dets, Sink: m, Reader: m, Scopes: scopes}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestHuntPrefersDetectWithHistoryAndBuildsItFromTheScope(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	b := newCountSrc("b", "https://other.example.com", "logs-2", map[string]int64{"192.0.2.7": 900})
	d := &histDet{name: "nk"}
	res := huntHist(t, map[string][]string{"nk": {"a"}}, []core.Source{a, b}, d)
	if d.plain.Load() != 0 || d.withHist.Load() != 1 {
		t.Fatalf("plain %d withHistory %d", d.plain.Load(), d.withHist.Load())
	}
	if d.counts["192.0.2.7"] != 30 || b.keyCalls != 0 {
		t.Errorf("counts %v, b asked %d times: the detector reads only source a", d.counts, b.keyCalls)
	}
	if !res.Complete() {
		t.Errorf("result incomplete: %+v", res.Detectors)
	}
}

func TestHuntUnscopedHistoryReadsEverySource(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	b := newCountSrc("b", "https://other.example.com", "logs-2", map[string]int64{"192.0.2.7": 900})
	d := &histDet{name: "nk"}
	huntHist(t, nil, []core.Source{a, b}, d)
	if d.counts["192.0.2.7"] != 930 {
		t.Errorf("counts %v, want 930", d.counts)
	}
}

func TestHuntHistoryErrorMakesTheDetectorFailNotQuiet(t *testing.T) {
	d := &histDet{name: "nk"}
	res := huntHist(t, nil, []core.Source{okSource("plain-source")}, d)
	if res.Complete() || res.Detectors[0].Status != StatusError || !strings.Contains(res.Detectors[0].Err.Error(), "plain-source") {
		t.Fatalf("result %+v", res.Detectors[0])
	}
}

func TestHuntConcurrentDetectorsEachGetTheirOwnHistory(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	var dets []core.Detector
	var hd []*histDet
	for _, n := range []string{"d1", "d2", "d3", "d4", "d5", "d6"} {
		d := &histDet{name: n}
		hd = append(hd, d)
		dets = append(dets, d)
	}
	huntHist(t, nil, []core.Source{a}, dets...)
	seen := map[core.KeyHistory]bool{}
	for _, d := range hd {
		if d.counts["192.0.2.7"] != 30 {
			t.Errorf("%s counts %v", d.name, d.counts)
		}
		if seen[d.got] {
			t.Error("two detectors share one history value")
		}
		seen[d.got] = true
	}
}

func TestHistoryDetectorWithoutAHistoryNeverNeedsOne(t *testing.T) {
	// A source that cannot count is fine for a history-capable detector that does not ask.
	d := fakeHistoryLess{name: "nk"}
	res := huntHist(t, nil, []core.Source{okSource("plain-source")}, d)
	if !res.Complete() {
		t.Fatalf("result %+v: the history was demanded though the detector never asked", res.Detectors)
	}
}

type fakeHistoryLess struct{ name string }

func (d fakeHistoryLess) Name() string { return d.name }
func (d fakeHistoryLess) Detect(context.Context, core.EventReader, core.EventReader, core.Window) ([]core.Finding, error) {
	return nil, nil
}
func (d fakeHistoryLess) DetectWithHistory(ctx context.Context, cur, prev core.EventReader, w core.Window, _ core.KeyHistory) ([]core.Finding, error) {
	return d.Detect(ctx, cur, prev, w)
}

func TestActivityAndWatchRunTheSameHistoryPath(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	d := &histDet{name: "nk"}
	res := runActivity(t, []core.Source{a}, d)
	if d.plain.Load() != 0 || d.withHist.Load() == 0 || res.Detectors[0].Status != StatusOK {
		t.Fatalf("activity: plain %d withHistory %d status %s", d.plain.Load(), d.withHist.Load(), res.Detectors[0].Status)
	}

	w := &histDet{name: "nk"}
	r := newRig(t, w)
	r.src = a.fakeSource
	r.deps.Hunt = func(ctx context.Context, run string, win core.Window) (Result, error) {
		m := newMem()
		return Hunt(ctx, Deps{Sources: []core.Source{a}, Detectors: []core.Detector{w}, Sink: m, Reader: m}, run, win)
	}
	r.cycle()
	if w.plain.Load() != 0 || w.withHist.Load() != 1 || w.counts["192.0.2.7"] != 30 {
		t.Errorf("watch: plain %d withHistory %d counts %v", w.plain.Load(), w.withHist.Load(), w.counts)
	}
}

func TestHistoryWindowFollowsTheHuntWindowNotTheClock(t *testing.T) {
	a := newCountSrc("a", "https://kibana.example.com", "logs-1", map[string]int64{"192.0.2.7": 30})
	d := &histDet{name: "nk"}
	m := newMem()
	for _, until := range []time.Time{t0, t0.Add(-48 * time.Hour)} {
		w := core.Window{From: until.Add(-time.Hour), To: until}
		if _, err := Hunt(context.Background(), Deps{Sources: []core.Source{a}, Detectors: []core.Detector{d}, Sink: m, Reader: m}, "r", w); err != nil {
			t.Fatal(err)
		}
		if want := (core.Window{From: w.From.Add(-7 * 24 * time.Hour), To: w.From}); a.lastWindow != want {
			t.Errorf("until %v: probe window %v, want %v", until, a.lastWindow, want)
		}
	}
}
