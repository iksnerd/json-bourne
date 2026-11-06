package newkey

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

// All data is synthetic: RFC 5737 documentation addresses and invented paths.
const (
	newcomer = "198.51.100.7"
	regular  = "192.0.2.10"
	other    = "192.0.2.11"
)

var (
	t0  = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	win = core.Window{From: t0, To: t0.Add(10 * time.Minute)}
)

type fakeReader struct {
	evs    []core.Event
	err    error
	onEnd  func()
	gotWin *core.Window
}

// Events ignores ctx on purpose: stopping must be the detector's doing.
func (f fakeReader) Events(_ context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		if f.gotWin != nil {
			*f.gotWin = w
		}
		for _, ev := range f.evs {
			if !yield(ev, nil) {
				return
			}
		}
		if f.onEnd != nil {
			f.onEnd()
		}
		if f.err != nil {
			yield(core.Event{}, f.err)
		}
	}
}

type hit struct {
	key   string
	path  string
	n     int
	noKey bool
}

func evs(hs ...hit) []core.Event {
	var out []core.Event
	for _, h := range hs {
		n := h.n
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			f := map[string]any{"path": h.path}
			if !h.noKey {
				f["client"] = h.key
			}
			out = append(out, core.Event{Time: t0, Source: "synthetic", Kind: "http", Fields: f})
		}
	}
	return out
}

func sens(key string, n int) hit  { return hit{key: key, path: "/v1/secret/ops", n: n} }
func plain(key string, n int) hit { return hit{key: key, path: "/v1/home", n: n} }

func baseCfg() Config {
	return Config{KeyField: "client", PathField: "path", SensitivePaths: []string{"/secret/", "/admin/export"}}
}

func mustNew(t *testing.T, c Config) *Detector {
	t.Helper()
	d, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func detect(t *testing.T, c Config, cur, prev []core.Event) ([]core.Finding, error) {
	t.Helper()
	return mustNew(t, c).Detect(context.Background(), fakeReader{evs: cur}, fakeReader{evs: prev}, win)
}

// history is a populated preceding window in which other clients were active.
func history() []core.Event { return evs(plain(regular, 40), plain(other, 40)) }

func TestNewKeyOnSensitivePathsIsRaised(t *testing.T) {
	cur := evs(sens(newcomer, 3), plain(regular, 30))
	fs, err := detect(t, baseCfg(), cur, history())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %+v", fs)
	}
	f := fs[0]
	if f.Tag != "newkey:"+newcomer || f.Detector != "newkey" || f.Severity != core.SevHigh {
		t.Errorf("tag %q detector %q severity %v", f.Tag, f.Detector, f.Severity)
	}
	if f.Detail["key_cur_sensitive_hits"] != 3 || f.Detail["key_prev_events"] != 0 ||
		f.Detail["baseline_empty"] != false || f.Detail["key"] != newcomer || f.Detail["key_field"] != "client" {
		t.Errorf("detail %v", f.Detail)
	}
	if f.Baseline != win.Previous() {
		t.Errorf("baseline %v", f.Baseline)
	}
}

func TestKeyWithHistoryIsNotNew(t *testing.T) {
	// regular was present in the preceding window, so even 50 sensitive hits are
	// not "a client with no history". Another detector's job.
	fs, err := detect(t, baseCfg(), evs(sens(regular, 50)), history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestHistoryOnAnyPathCounts(t *testing.T) {
	// One earlier request, on a path that is not sensitive, is still history.
	prev := append(history(), evs(plain(newcomer, 1))...)
	fs, err := detect(t, baseCfg(), evs(sens(newcomer, 9)), prev)
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestOtherKeysHistoryIsNotThisKeysHistory(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(sens(newcomer, 3)), evs(plain(other, 100)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestBelowMinHitsIsQuiet(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(sens(newcomer, 2)), history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("default min_hits is 3: %v %v", fs, err)
	}
	c := baseCfg()
	c.MinHits = 5
	fs, err = detect(t, c, evs(sens(newcomer, 4)), history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
	fs, err = detect(t, c, evs(sens(newcomer, 5)), history())
	if err != nil || len(fs) != 1 {
		t.Fatalf("exactly min_hits raises: %v %v", fs, err)
	}
}

func TestVolumeOnOrdinaryPathsIsNotEnough(t *testing.T) {
	// A new client making 500 requests to ordinary paths is a new customer
	// opening the app, not a finding.
	fs, err := detect(t, baseCfg(), evs(plain(newcomer, 500), sens(newcomer, 2)), history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestSensitivePathsMatchAcrossEntries(t *testing.T) {
	cur := evs(hit{key: newcomer, path: "/v1/secret/ops?x=1"}, hit{key: newcomer, path: "/admin/export/all"}, hit{key: newcomer, path: "/v1/SECRET/ops"})
	fs, err := detect(t, baseCfg(), cur, history())
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
	by, _ := fs[0].Detail["sensitive_paths_hit"].(map[string]int)
	if by["/secret/"] != 2 || by["/admin/export"] != 1 || fs[0].Detail["key_cur_sensitive_hits"] != 3 {
		t.Errorf("per-entry counts %v / %v", by, fs[0].Detail)
	}
}

func TestEmptyBaselineReportedAndSeverityLowered(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(sens(newcomer, 3)), nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[0].Severity != core.SevActivity || fs[0].Detail["baseline_empty"] != true {
		t.Errorf("want activity + baseline_empty: %v %v", fs[0].Severity, fs[0].Detail)
	}
	if !strings.Contains(fs[0].Summary, "no preceding") {
		t.Errorf("summary must say nothing was compared: %q", fs[0].Summary)
	}
}

func TestEmptyCurrentWindowIsErrNoRecords(t *testing.T) {
	for name, cur := range map[string][]core.Event{
		"no events":     nil,
		"no key at all": evs(hit{noKey: true, path: "/v1/secret/ops", n: 10}),
	} {
		fs, err := detect(t, baseCfg(), cur, history())
		if !errors.Is(err, core.ErrNoRecords) || fs != nil {
			t.Errorf("%s: want ErrNoRecords, got %v %v", name, fs, err)
		}
	}
}

func TestEmptyAndIgnoredKeysAreNeverSuspects(t *testing.T) {
	c := baseCfg()
	c.IgnoreKeys = []string{" " + newcomer + " "}
	cur := evs(sens(newcomer, 9), hit{noKey: true, path: "/v1/secret/ops", n: 9}, sens("", 9), sens(regular, 1))
	fs, err := detect(t, c, cur, history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
	// All keys ignored or empty: nothing to judge, which is not a clean answer.
	fs, err = detect(t, c, evs(sens(newcomer, 9), sens("", 3)), history())
	if !errors.Is(err, core.ErrNoRecords) || fs != nil {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestIgnoredKeysDoNotMakeBaselineNonEmpty(t *testing.T) {
	c := baseCfg()
	c.IgnoreKeys = []string{other}
	fs, err := detect(t, c, evs(sens(newcomer, 3)), evs(plain(other, 100)))
	if err != nil || len(fs) != 1 || fs[0].Detail["baseline_empty"] != true {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestSeveralNewKeysSortedAndOneTagEach(t *testing.T) {
	cur := evs(sens("198.51.100.9", 4), sens("198.51.100.2", 3))
	fs, err := detect(t, baseCfg(), cur, history())
	if err != nil || len(fs) != 2 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[0].Tag != "newkey:198.51.100.2" || fs[1].Tag != "newkey:198.51.100.9" {
		t.Errorf("order/tags %q %q", fs[0].Tag, fs[1].Tag)
	}
	// Same input, same tags: dedupes across runs.
	fs2, _ := detect(t, baseCfg(), cur, history())
	if fs2[0].Tag != fs[0].Tag {
		t.Error("tag not stable")
	}
}

func TestReaderErrorsPropagate(t *testing.T) {
	boom := errors.New("backend down")
	d := mustNew(t, baseCfg())
	_, err := d.Detect(context.Background(), fakeReader{evs: evs(sens(newcomer, 3)), err: boom}, fakeReader{}, win)
	if !errors.Is(err, boom) || errors.Is(err, core.ErrNoRecords) {
		t.Errorf("current: %v", err)
	}
	_, err = d.Detect(context.Background(), fakeReader{evs: evs(sens(newcomer, 3))}, fakeReader{evs: history(), err: boom}, win)
	if !errors.Is(err, boom) {
		t.Errorf("a failed baseline read must not be an empty baseline: %v", err)
	}
}

func TestCancellationIsAnErrorNotAShortWindow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cur := fakeReader{evs: evs(sens(newcomer, 3)), onEnd: cancel}
	fs, err := mustNew(t, baseCfg()).Detect(ctx, cur, fakeReader{evs: history()}, win)
	if !errors.Is(err, context.Canceled) || fs != nil {
		t.Fatalf("%v %v", fs, err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	prev := fakeReader{evs: history(), onEnd: cancel2}
	fs, err = mustNew(t, baseCfg()).Detect(ctx2, fakeReader{evs: evs(sens(newcomer, 3))}, prev, win)
	if !errors.Is(err, context.Canceled) || fs != nil {
		t.Fatalf("cancelled baseline read must not look like an empty baseline: %v %v", fs, err)
	}
}

func TestBaselineIsReadFromPreviousWindow(t *testing.T) {
	var got core.Window
	_, err := mustNew(t, baseCfg()).Detect(context.Background(), fakeReader{evs: evs(sens(newcomer, 3))}, fakeReader{gotWin: &got}, win)
	if err != nil {
		t.Fatal(err)
	}
	if got != win.Previous() {
		t.Errorf("prev read %v, want %v", got, win.Previous())
	}
}

func TestNoCandidateSkipsBaselineRead(t *testing.T) {
	// Nothing to compare means no second read; a broken baseline reader must not
	// turn a quiet window into an error.
	fs, err := mustNew(t, baseCfg()).Detect(context.Background(),
		fakeReader{evs: evs(plain(newcomer, 5))}, fakeReader{err: errors.New("unused")}, win)
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestNonTextKeyAndPathAreIgnoredNotCrashing(t *testing.T) {
	cur := []core.Event{
		{Time: t0, Fields: map[string]any{"client": 42, "path": "/v1/secret/ops"}},
		{Time: t0, Fields: map[string]any{"client": newcomer, "path": 7}},
		{Time: t0, Fields: nil},
	}
	cur = append(cur, evs(plain(regular, 1))...)
	fs, err := detect(t, baseCfg(), cur, history())
	if err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
}

func TestNewValidation(t *testing.T) {
	bad := map[string]func(*Config){
		"no key field":    func(c *Config) { c.KeyField = " " },
		"no path field":   func(c *Config) { c.PathField = "" },
		"no sensitive":    func(c *Config) { c.SensitivePaths = nil },
		"blank sensitive": func(c *Config) { c.SensitivePaths = []string{"/ok", " "} },
		"negative hits":   func(c *Config) { c.MinHits = -1 },
		"bad name":        func(c *Config) { c.Name = "Has Space" },
	}
	for name, mut := range bad {
		c := baseCfg()
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if d := mustNew(t, baseCfg()); d.Name() != "newkey" {
		t.Errorf("default name %q", d.Name())
	}
	c := baseCfg()
	c.Name = "new-client"
	if mustNew(t, c).Name() != "new-client" {
		t.Error("name not applied")
	}
}

func TestNewCopiesCallerSlices(t *testing.T) {
	c := baseCfg()
	d := mustNew(t, c)
	c.SensitivePaths[0] = "/elsewhere/"
	c.SensitivePaths[1] = "/elsewhere/"
	fs, err := d.Detect(context.Background(), fakeReader{evs: evs(sens(newcomer, 3))}, fakeReader{evs: history()}, win)
	if err != nil || len(fs) != 1 {
		t.Fatalf("detector must own its config: %v %v", fs, err)
	}
}

func TestManyKeysManyEvents(t *testing.T) {
	var cur []core.Event
	for i := 0; i < 200; i++ {
		cur = append(cur, evs(plain(fmt.Sprintf("203.0.113.%d", i), 3))...)
	}
	cur = append(cur, evs(sens(newcomer, 3))...)
	fs, err := detect(t, baseCfg(), cur, history())
	if err != nil || len(fs) != 1 || fs[0].Detail["pop_cur_keys"] != 201 {
		t.Fatalf("%v %v", fs, err)
	}
}
