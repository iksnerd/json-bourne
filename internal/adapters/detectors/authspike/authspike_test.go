package authspike

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// All data is synthetic: RFC 5737 documentation addresses only.
const (
	attacker = "198.51.100.7"
	other    = "198.51.100.99"
)

var (
	t0  = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	win = core.Window{From: t0, To: t0.Add(10 * time.Minute)}
)

// group describes a block of events for one client.
type group struct {
	key        string
	noKey      bool // omit the key field entirely
	path       string
	ok, fail   int
	unparsable int
	okStatus   any
	failStatus any
	failNil    bool // fail events carry a nil status
}

// events renders groups as events inside w.
func events(w core.Window, gs ...group) []core.Event {
	var evs []core.Event
	add := func(g group, status any) {
		f := map[string]any{"status": status, "path": "/login"}
		if g.path != "" {
			f["path"] = g.path
		}
		if !g.noKey {
			f["client"] = g.key
		}
		evs = append(evs, core.Event{
			Time:   w.From.Add(time.Duration(len(evs)) * time.Millisecond),
			Source: "synthetic",
			Kind:   "auth",
			Fields: f,
		})
	}
	for _, g := range gs {
		ok, fail := g.okStatus, g.failStatus
		if ok == nil {
			ok = 200
		}
		if fail == nil {
			fail = 401
		}
		if g.failNil {
			fail = nil
		}
		for i := 0; i < g.fail; i++ {
			add(g, fail)
		}
		for i := 0; i < g.ok; i++ {
			add(g, ok)
		}
		for i := 0; i < g.unparsable; i++ {
			add(g, "n/a")
		}
	}
	return evs
}

// quiet is ordinary traffic: five clients, 100 events, 5 failures (5%).
func quiet() []group {
	var gs []group
	for i := 10; i < 15; i++ {
		gs = append(gs, group{key: fmt.Sprintf("192.0.2.%d", i), ok: 19, fail: 1})
	}
	return gs
}

func with(extra ...group) []group { return append(quiet(), extra...) }

type fakeReader struct {
	evs     []core.Event
	err     error // yielded after the events
	yielded *int
	gotWin  *core.Window
	onYield func(i int)
	onEnd   func() // runs after the last event was delivered
}

// Events ignores ctx on purpose: stopping must be the detector's doing.
func (f fakeReader) Events(_ context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		if f.gotWin != nil {
			*f.gotWin = w
		}
		for i, ev := range f.evs {
			if f.onYield != nil {
				f.onYield(i)
			}
			if f.yielded != nil {
				*f.yielded++
			}
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

func baseCfg() Config {
	return Config{Name: "login-spike", KeyField: "client", StatusField: "status", PathField: "path", PathContains: "/login"}
}

func mustNew(t *testing.T, c Config) *Detector {
	t.Helper()
	d, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

type want struct {
	key           string
	sev           core.Severity
	baselineEmpty bool
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func(*Config)
		cur     []core.Event
		prev    []core.Event
		wantErr error
		want    []want
	}{
		{
			name: "spray from a key new to the window is raised",
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "spray from a known key whose failure share rose is raised",
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 95, fail: 5})...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "volume up tenfold with zero failures is a busy platform",
			cur:  events(win, with(group{key: attacker, ok: 500})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 50})...),
		},
		{
			name: "volume up tenfold with the same failure share is a busy platform",
			cur:  events(win, with(group{key: attacker, ok: 450, fail: 50})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 45, fail: 5})...),
		},
		{
			name: "same surge but failures dominate is raised",
			cur:  events(win, with(group{key: attacker, ok: 50, fail: 450})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 45, fail: 5})...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "everyone failing at once is an outage, not a spray",
			cur: events(win,
				group{key: "192.0.2.10", fail: 20}, group{key: "192.0.2.11", fail: 20},
				group{key: "192.0.2.12", fail: 20}, group{key: "192.0.2.13", fail: 20}),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "below MinEvents by one is not raised",
			cur:  events(win, with(group{key: attacker, fail: 19})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "exactly MinEvents is raised",
			cur:  events(win, with(group{key: attacker, fail: 20})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "lowered MinEvents raises a smaller burst",
			cfg:  func(c *Config) { c.MinEvents = 10 },
			cur:  events(win, with(group{key: attacker, fail: 15})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "unparsable statuses do not count towards MinEvents",
			cur:  events(win, with(group{key: attacker, fail: 10, unparsable: 40})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "unparsable statuses are not successes",
			// 12 fail + 8 ok = 20 parsable (60%); counting the 40 unparsable
			// as successes would dilute it to 20% and hide the spray.
			cur:  events(win, with(group{key: attacker, fail: 12, ok: 8, unparsable: 40})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "ignored key is never a suspect",
			cfg:  func(c *Config) { c.IgnoreKeys = []string{attacker} },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "ignoring a different key leaves the suspect raised",
			cfg:  func(c *Config) { c.IgnoreKeys = []string{other} },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "empty key value is never a suspect",
			cur:  events(win, with(group{key: "", ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "missing key field is never a suspect",
			cur:  events(win, with(group{noKey: true, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "empty baseline: raised one step down",
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			want: []want{{attacker, core.SevActivity, true}},
		},
		{
			name: "empty baseline and no failures is a busy platform",
			cur:  events(win, with(group{key: attacker, ok: 500})...),
		},
		{
			name: "empty baseline needs a failing majority, no ratio is invented",
			cur:  events(win, with(group{key: attacker, ok: 70, fail: 30})...),
		},
		{
			name: "rise exactly at the threshold is raised",
			// 0.6 - 0.4 is 0.19999999999999996 in float64.
			cur:  events(win, with(group{key: attacker, ok: 20, fail: 30})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 30, fail: 20})...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "rise just under the threshold is not raised as rising",
			cfg:  func(c *Config) { c.DisableSustained = true }, // 58% vs 40% is a sustained finding, tested below
			cur:  events(win, with(group{key: attacker, ok: 21, fail: 29})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 30, fail: 20})...),
		},
		{
			name: "stricter threshold suppresses a rise of 0.85",
			cfg:  func(c *Config) { c.MinFailureShareRise = 0.9 },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "looser threshold keeps it",
			cfg:  func(c *Config) { c.MinFailureShareRise = 0.8 },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "failures on another path do not count",
			cur:  events(win, with(group{key: attacker, path: "/api/data", ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "custom fail statuses: 429 counts",
			cfg:  func(c *Config) { c.FailStatuses = []int{429} },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90, failStatus: 429})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}},
		},
		{
			name: "custom fail statuses: 401 no longer counts",
			cfg:  func(c *Config) { c.FailStatuses = []int{429} },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
		},
		{
			name: "two sprayers are raised in key order",
			cur: events(win, with(
				group{key: other, ok: 5, fail: 45},
				group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
			want: []want{{attacker, core.SevHigh, false}, {other, core.SevHigh, false}},
		},
		{
			name:    "zero events is ErrNoRecords, even with a baseline",
			cur:     nil,
			prev:    events(win.Previous(), quiet()...),
			wantErr: core.ErrNoRecords,
		},
		{
			name:    "only off-path events is ErrNoRecords",
			cur:     events(win, group{key: attacker, path: "/api/data", fail: 90}),
			prev:    events(win.Previous(), quiet()...),
			wantErr: core.ErrNoRecords,
		},
		{
			name:    "only unparsable statuses is ErrNoRecords",
			cur:     events(win, group{key: attacker, unparsable: 90}),
			prev:    events(win.Previous(), quiet()...),
			wantErr: core.ErrNoRecords,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseCfg()
			if tt.cfg != nil {
				tt.cfg(&c)
			}
			d := mustNew(t, c)
			got, err := d.Detect(context.Background(), fakeReader{evs: tt.cur}, fakeReader{evs: tt.prev}, win)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v (findings %v)", err, tt.wantErr, got)
				}
				if len(got) != 0 {
					t.Fatalf("findings alongside error: %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings %v, want %d %v", len(got), tags(got), len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				f := got[i]
				if f.Detail["key"] != w.key || f.Severity != w.sev || f.Detail["baseline_empty"] != w.baselineEmpty {
					t.Errorf("finding %d = key %v sev %v baseline_empty %v, want %+v",
						i, f.Detail["key"], f.Severity, f.Detail["baseline_empty"], w)
				}
			}
		})
	}
}

func tags(fs []core.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Tag)
	}
	return out
}

// Numbers are derived by hand from the scenario, not from the code under test.
func TestDetailNumbersAreCountedNotInvented(t *testing.T) {
	d := mustNew(t, baseCfg())
	t.Run("new key, population baseline", func(t *testing.T) {
		got, err := d.Detect(context.Background(),
			fakeReader{evs: events(win, with(group{key: attacker, ok: 10, fail: 90})...)},
			fakeReader{evs: events(win.Previous(), quiet()...)}, win)
		if err != nil || len(got) != 1 {
			t.Fatalf("got %v, %v", got, err)
		}
		f := got[0]
		wantInts := map[string]int{
			"key_cur_events": 100, "key_cur_failures": 90,
			"key_prev_events": 0, "key_prev_failures": 0,
			"pop_cur_events": 200, "pop_cur_failures": 95,
			"pop_prev_events": 100, "pop_prev_failures": 5,
			"min_events": 20, "unparsable_cur": 0, "unparsable_prev": 0,
		}
		for k, v := range wantInts {
			if f.Detail[k] != v {
				t.Errorf("Detail[%q] = %v, want %d", k, f.Detail[k], v)
			}
		}
		if f.Detail["key_cur_failure_share"] != 0.9 || f.Detail["pop_prev_failure_share"] != 0.05 {
			t.Errorf("shares = %v / %v", f.Detail["key_cur_failure_share"], f.Detail["pop_prev_failure_share"])
		}
		if f.Detail["baseline_source"] != "population" || f.Detail["key_baseline_empty"] != true {
			t.Errorf("baseline_source = %v, key_baseline_empty = %v", f.Detail["baseline_source"], f.Detail["key_baseline_empty"])
		}
		if _, has := f.Detail["key_prev_failure_share"]; has {
			t.Error("key_prev_failure_share present although the key had no preceding events")
		}
	})
	t.Run("known key", func(t *testing.T) {
		got, _ := d.Detect(context.Background(),
			fakeReader{evs: events(win, with(group{key: attacker, ok: 10, fail: 90})...)},
			fakeReader{evs: events(win.Previous(), with(group{key: attacker, ok: 95, fail: 5})...)}, win)
		if len(got) != 1 {
			t.Fatalf("got %v", got)
		}
		f := got[0]
		if f.Detail["key_prev_events"] != 100 || f.Detail["key_prev_failures"] != 5 ||
			f.Detail["pop_prev_events"] != 200 || f.Detail["pop_prev_failures"] != 10 {
			t.Errorf("prev counts wrong: %v", f.Detail)
		}
		if f.Detail["baseline_source"] != "key" {
			t.Errorf("baseline_source = %v", f.Detail["baseline_source"])
		}
		if r, _ := f.Detail["failure_share_rise"].(float64); r < 0.849 || r > 0.851 {
			t.Errorf("rise = %v, want 0.85", f.Detail["failure_share_rise"])
		}
	})
	t.Run("empty baseline carries no preceding shares", func(t *testing.T) {
		got, _ := d.Detect(context.Background(),
			fakeReader{evs: events(win, with(group{key: attacker, ok: 10, fail: 90})...)},
			fakeReader{}, win)
		if len(got) != 1 {
			t.Fatalf("got %v", got)
		}
		for _, k := range []string{"pop_prev_failure_share", "key_prev_failure_share", "failure_share_rise"} {
			if _, has := got[0].Detail[k]; has {
				t.Errorf("Detail[%q] present with no preceding events", k)
			}
		}
		if got[0].Detail["pop_prev_events"] != 0 || got[0].Detail["baseline_source"] != "none" {
			t.Errorf("detail = %v", got[0].Detail)
		}
	})
	t.Run("unparsable events are reported, not counted", func(t *testing.T) {
		got, _ := d.Detect(context.Background(),
			fakeReader{evs: events(win, with(group{key: attacker, fail: 12, ok: 8, unparsable: 40})...)},
			fakeReader{evs: events(win.Previous(), quiet()...)}, win)
		if len(got) != 1 || got[0].Detail["unparsable_cur"] != 40 || got[0].Detail["key_cur_events"] != 20 {
			t.Fatalf("got %v", got)
		}
	})
}

func TestDetectReadsTheRightWindows(t *testing.T) {
	var curW, prevW core.Window
	d := mustNew(t, baseCfg())
	got, err := d.Detect(context.Background(),
		fakeReader{evs: events(win, with(group{key: attacker, fail: 90, ok: 10})...), gotWin: &curW},
		fakeReader{evs: events(win.Previous(), quiet()...), gotWin: &prevW}, win)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	if curW != win || prevW != win.Previous() {
		t.Errorf("read cur %v prev %v, want %v and %v", curW, prevW, win, win.Previous())
	}
	if got[0].Window != win || got[0].Baseline != win.Previous() || got[0].Detector != "login-spike" {
		t.Errorf("finding windows/detector wrong: %+v", got[0])
	}
}

// nilStatus stands for a nil status value (a nil failStatus means the default).
type nilStatus struct{}

func TestStatusRepresentations(t *testing.T) {
	tests := []struct {
		name   string
		status any
		fails  bool
	}{
		{"int", 401, true},
		{"int64", int64(401), true},
		{"float64 as JSON decodes it", float64(401), true},
		{"json.Number", json.Number("401"), true},
		{"string", "401", true},
		{"padded string", " 401 ", true},
		{"403 float", float64(403), true},
		{"200 string is a success", "200", false},
		{"fractional float is unparsable", 401.5, false},
		{"word is unparsable", "Unauthorized", false},
		{"nil is unparsable", nilStatus{}, false},
		{"bool is unparsable", true, false},
		{"zero is unparsable", 0, false},
		{"out of range is unparsable", 40100, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 90 events carry the status under test, 10 are successes; with a
			// non-failing status the key has no failures at all.
			_, isNil := tt.status.(nilStatus)
			cur := events(win, with(group{key: attacker, ok: 10, fail: 90, failStatus: tt.status, failNil: isNil})...)
			prev := events(win.Previous(), quiet()...)
			d := mustNew(t, baseCfg())
			got, err := d.Detect(context.Background(), fakeReader{evs: cur}, fakeReader{evs: prev}, win)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if raised := len(got) == 1; raised != tt.fails {
				t.Fatalf("raised = %v, want %v (%v)", raised, tt.fails, got)
			}
		})
	}
}

func TestStableTag(t *testing.T) {
	d := mustNew(t, baseCfg())
	run := func(w core.Window, fail int) core.Finding {
		t.Helper()
		got, err := d.Detect(context.Background(),
			fakeReader{evs: events(w, with(group{key: attacker, ok: 10, fail: fail})...)},
			fakeReader{evs: events(w.Previous(), quiet()...)}, w)
		if err != nil || len(got) != 1 {
			t.Fatalf("got %v, %v", got, err)
		}
		return got[0]
	}
	a := run(win, 90)
	b := run(core.Window{From: win.To, To: win.To.Add(10 * time.Minute)}, 400)
	if a.Tag != b.Tag {
		t.Errorf("tag changed between runs: %q vs %q", a.Tag, b.Tag)
	}
	if a.Tag != "login-spike:"+attacker {
		t.Errorf("tag = %q, want detector and key only", a.Tag)
	}
	if a.Detail["key_cur_failures"] == b.Detail["key_cur_failures"] {
		t.Error("the two runs should differ in counts, or this test proves nothing")
	}
}

func TestContextCancellation(t *testing.T) {
	d := mustNew(t, baseCfg())
	big := events(win, with(group{key: attacker, fail: 500})...)

	t.Run("cancelled mid-stream stops reading and errors", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		n := 0
		cur := fakeReader{evs: big, yielded: &n, onYield: func(i int) {
			if i == 50 {
				cancel()
			}
		}}
		got, err := d.Detect(ctx, cur, fakeReader{evs: events(win.Previous(), quiet()...)}, win)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled (findings %v)", err, got)
		}
		if errors.Is(err, core.ErrNoRecords) || len(got) != 0 {
			t.Fatalf("cancellation must not look like a result: %v %v", got, err)
		}
		// The cancel happened at event 50, so the path was reached and the
		// stream was abandoned long before its end.
		if n < 50 || n > 60 {
			t.Errorf("read %d of %d events; want the loop to stop right after cancel", n, len(big))
		}
	})
	t.Run("cancelled on the last event, reader ends quietly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cur := fakeReader{evs: big, onEnd: cancel}
		got, err := d.Detect(ctx, cur, fakeReader{}, win)
		if !errors.Is(err, context.Canceled) || len(got) != 0 {
			t.Fatalf("a window cut short by cancellation was reported as complete: %v, %v", got, err)
		}
	})
	t.Run("cancelled before the call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := d.Detect(ctx, fakeReader{evs: big}, fakeReader{}, win); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancelled while reading the baseline", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		prev := fakeReader{evs: events(win.Previous(), quiet()...), onYield: func(i int) {
			if i == 3 {
				cancel()
			}
		}}
		got, err := d.Detect(ctx, fakeReader{evs: big}, prev, win)
		if !errors.Is(err, context.Canceled) || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func TestReaderErrorsPropagate(t *testing.T) {
	boom := errors.New("backend refused")
	d := mustNew(t, baseCfg())
	cur := events(win, with(group{key: attacker, ok: 10, fail: 90})...)
	t.Run("current window", func(t *testing.T) {
		got, err := d.Detect(context.Background(), fakeReader{evs: cur, err: boom}, fakeReader{}, win)
		if !errors.Is(err, boom) || errors.Is(err, core.ErrNoRecords) || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("baseline failure is not an empty baseline", func(t *testing.T) {
		got, err := d.Detect(context.Background(), fakeReader{evs: cur}, fakeReader{err: boom}, win)
		if !errors.Is(err, boom) || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("nil readers", func(t *testing.T) {
		if _, err := d.Detect(context.Background(), nil, fakeReader{}, win); err == nil {
			t.Error("nil cur accepted")
		}
		if _, err := d.Detect(context.Background(), fakeReader{evs: cur}, nil, win); err == nil {
			t.Error("nil prev accepted")
		}
	})
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"minimal", Config{KeyField: "k", StatusField: "s"}, ""},
		{"missing key field", Config{StatusField: "s"}, "key_field"},
		{"blank key field", Config{KeyField: "  ", StatusField: "s"}, "key_field"},
		{"missing status field", Config{KeyField: "k"}, "status_field"},
		{"path_contains without path_field", Config{KeyField: "k", StatusField: "s", PathContains: "/x"}, "path_field"},
		{"negative min_events", Config{KeyField: "k", StatusField: "s", MinEvents: -1}, "min_events"},
		{"rise above one", Config{KeyField: "k", StatusField: "s", MinFailureShareRise: 1.5}, "min_failure_share_rise"},
		{"negative rise", Config{KeyField: "k", StatusField: "s", MinFailureShareRise: -0.1}, "min_failure_share_rise"},
		{"bad fail status", Config{KeyField: "k", StatusField: "s", FailStatuses: []int{42}}, "not an HTTP status"},
		{"sustained share above one", Config{KeyField: "k", StatusField: "s", SustainedMinShare: 1.01}, "sustained_min_share"},
		{"negative sustained share", Config{KeyField: "k", StatusField: "s", SustainedMinShare: -0.1}, "sustained_min_share"},
		{"NaN sustained share", Config{KeyField: "k", StatusField: "s", SustainedMinShare: math.NaN()}, "sustained_min_share"},
		{"sustained share of exactly one", Config{KeyField: "k", StatusField: "s", SustainedMinShare: 1}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(tt.cfg)
			if tt.wantErr == "" {
				if err != nil || d == nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}

	t.Run("defaults", func(t *testing.T) {
		d := mustNew(t, Config{KeyField: "k", StatusField: "s"})
		if d.Name() != "authspike" || d.cfg.MinEvents != 20 || d.cfg.MinFailureShareRise != 0.20 {
			t.Errorf("defaults: %q %d %v", d.Name(), d.cfg.MinEvents, d.cfg.MinFailureShareRise)
		}
		if d.cfg.SustainedMinShare != 0.5 || d.cfg.DisableSustained {
			t.Errorf("sustained defaults: %v disabled=%v", d.cfg.SustainedMinShare, d.cfg.DisableSustained)
		}
		if _, ok := d.fail[401]; !ok {
			t.Error("401 not a default fail status")
		}
		if _, ok := d.fail[403]; !ok || len(d.fail) != 2 {
			t.Errorf("fail statuses = %v, want 401 and 403", d.fail)
		}
	})
	t.Run("name is configurable", func(t *testing.T) {
		if got := mustNew(t, Config{Name: "x", KeyField: "k", StatusField: "s"}).Name(); got != "x" {
			t.Errorf("Name = %q", got)
		}
	})
}

const sustainedSuffix = ":sustained"

// Each case lists the exact tags expected, so a duplicate, a missing or a
// wrongly tagged finding all fail. Shares are worked out by hand in the names.
func TestSustained(t *testing.T) {
	risingTag := "login-spike:" + attacker
	sustTag := risingTag + sustainedSuffix
	tests := []struct {
		name string
		cfg  func(*Config)
		cur  []core.Event
		prev []core.Event
		want []string
		sev  core.Severity // of want[0], when set
	}{
		{
			name: "continuing spray, 0.9 in both windows: one sustained, no rising",
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 10, fail: 90})...),
			want: []string{sustTag},
			sev:  core.SevActivity,
		},
		{
			name: "rising spray: only the rising finding, no duplicate sustained",
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), quiet()...),
			want: []string{risingTag},
			sev:  core.SevHigh,
		},
		{
			name: "busy platform with no failures: nothing",
			cur:  events(win, with(group{key: attacker, ok: 500})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 50})...),
		},
		{
			name: "all-keys outage, everyone at 0.9 in both windows: nothing",
			cur: events(win,
				group{key: "192.0.2.10", ok: 2, fail: 18}, group{key: "192.0.2.11", ok: 2, fail: 18},
				group{key: "192.0.2.12", ok: 2, fail: 18}, group{key: "192.0.2.13", ok: 2, fail: 18}),
			prev: events(win.Previous(),
				group{key: "192.0.2.10", ok: 2, fail: 18}, group{key: "192.0.2.11", ok: 2, fail: 18},
				group{key: "192.0.2.12", ok: 2, fail: 18}, group{key: "192.0.2.13", ok: 2, fail: 18}),
		},
		{
			name: "0.45 in both windows is below SustainedMinShare 0.5: nothing",
			cur:  events(win, with(group{key: attacker, ok: 55, fail: 45})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 55, fail: 45})...),
		},
		{
			name: "exactly SustainedMinShare 0.5 fires (compare is >=)",
			cur:  events(win, with(group{key: attacker, ok: 50, fail: 50})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 50, fail: 50})...),
			want: []string{sustTag},
		},
		{
			name: "lowered SustainedMinShare 0.3 catches 0.45, exactly 0.2 over the 0.25 population",
			cfg:  func(c *Config) { c.SustainedMinShare = 0.3 },
			cur:  events(win, with(group{key: attacker, ok: 55, fail: 45})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 55, fail: 45})...),
			want: []string{sustTag},
		},
		{
			name: "first window, no baseline, below SustainedMinShare: nothing",
			cur:  events(win, with(group{key: attacker, ok: 70, fail: 30})...),
		},
		{
			name: "first window, no baseline, spray at 0.9: rising only, not both",
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			want: []string{risingTag},
			sev:  core.SevActivity,
		},
		{
			name: "DisableSustained: a continuing spray is quiet again",
			cfg:  func(c *Config) { c.DisableSustained = true },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 10, fail: 90})...),
		},
		{
			name: "ignored key: nothing",
			cfg:  func(c *Config) { c.IgnoreKeys = []string{attacker} },
			cur:  events(win, with(group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), with(group{key: attacker, ok: 10, fail: 90})...),
		},
		{
			name: "empty key: nothing",
			cur:  events(win, with(group{key: "", ok: 10, fail: 90})...),
			prev: events(win.Previous(), with(group{key: "", ok: 10, fail: 90})...),
		},
		{
			name: "below MinEvents by one: nothing",
			cur:  events(win, with(group{key: attacker, fail: 19})...),
			prev: events(win.Previous(), with(group{key: attacker, fail: 19})...),
		},
		{
			name: "gap to the population under MinFailureShareRise: nothing",
			// Population 0.6 (key 0.7 among heavy failing neighbours): gap 0.1 < 0.2.
			cur: events(win, group{key: attacker, ok: 6, fail: 14},
				group{key: other, ok: 100, fail: 180}),
			prev: events(win.Previous(), group{key: attacker, ok: 6, fail: 14},
				group{key: other, ok: 100, fail: 180}),
		},
		{
			name: "two continuing sprayers: one sustained each, in key order",
			cur: events(win, with(group{key: other, ok: 5, fail: 45},
				group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), with(group{key: other, ok: 5, fail: 45},
				group{key: attacker, ok: 10, fail: 90})...),
			want: []string{sustTag, "login-spike:" + other + sustainedSuffix},
		},
		{
			name: "one rising and one continuing key each get their own kind",
			cur: events(win, with(group{key: other, ok: 5, fail: 45},
				group{key: attacker, ok: 10, fail: 90})...),
			prev: events(win.Previous(), with(group{key: other, ok: 5, fail: 45})...),
			want: []string{risingTag, "login-spike:" + other + sustainedSuffix},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseCfg()
			if tt.cfg != nil {
				tt.cfg(&c)
			}
			got, err := mustNew(t, c).Detect(context.Background(), fakeReader{evs: tt.cur}, fakeReader{evs: tt.prev}, win)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if g := tags(got); strings.Join(g, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("tags = %v, want %v", g, tt.want)
			}
			if len(tt.want) > 0 && tt.sev != 0 && got[0].Severity != tt.sev {
				t.Errorf("severity = %v, want %v", got[0].Severity, tt.sev)
			}
		})
	}
}

// Sustained numbers are derived by hand: cur = 5*20 quiet (5 fail) + 100 attacker
// (90 fail) = 200 events, 95 failures; prev attacker 100 events, 80 failures.
func TestSustainedDetail(t *testing.T) {
	d := mustNew(t, baseCfg())
	got, err := d.Detect(context.Background(),
		fakeReader{evs: events(win, with(group{key: attacker, ok: 10, fail: 90})...)},
		fakeReader{evs: events(win.Previous(), with(group{key: attacker, ok: 20, fail: 80})...)}, win)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	f := got[0]
	exp := map[string]any{
		"key": attacker, "key_cur_events": 100, "key_cur_failures": 90, "key_cur_failure_share": 0.9,
		"pop_cur_events": 200, "pop_cur_failures": 95, "pop_cur_failure_share": 0.475,
		"key_prev_events": 100, "key_prev_failures": 80, "key_prev_failure_share": 0.8,
		"pop_prev_events": 200, "pop_prev_failures": 85, "pop_prev_failure_share": 0.425,
		"sustained": true, "baseline_empty": false,
	}
	for k, v := range exp {
		if f.Detail[k] != v {
			t.Errorf("Detail[%q] = %v, want %v", k, f.Detail[k], v)
		}
	}
	if over, _ := f.Detail["key_over_population_share"].(float64); math.Abs(over-0.425) > 1e-9 {
		t.Errorf("key_over_population_share = %v, want 0.425", f.Detail["key_over_population_share"])
	}
	if !strings.Contains(f.Summary, "continuing, not new") {
		t.Errorf("summary does not say it is continuing: %q", f.Summary)
	}

	// No baseline: prev numbers are absent, not zero-filled shares.
	got, err = d.Detect(context.Background(),
		fakeReader{evs: events(win, with(group{key: attacker, ok: 10, fail: 90})...)}, fakeReader{}, win)
	if err != nil || len(got) != 1 || got[0].Tag != "login-spike:"+attacker {
		t.Fatalf("empty baseline: %v, %v", tags(got), err)
	}
}

func TestSustainedTagStableAndDistinct(t *testing.T) {
	d := mustNew(t, baseCfg())
	run := func(w core.Window, fail int) core.Finding {
		t.Helper()
		got, err := d.Detect(context.Background(),
			fakeReader{evs: events(w, with(group{key: attacker, ok: 100 - fail, fail: fail})...)},
			fakeReader{evs: events(w.Previous(), with(group{key: attacker, ok: 100 - fail, fail: fail})...)}, w)
		if err != nil || len(got) != 1 {
			t.Fatalf("got %v, %v", tags(got), err)
		}
		return got[0]
	}
	a := run(win, 90)
	b := run(core.Window{From: win.To, To: win.To.Add(10 * time.Minute)}, 70)
	if a.Tag != b.Tag {
		t.Errorf("sustained tag changed between windows: %q vs %q", a.Tag, b.Tag)
	}
	if a.Tag != "login-spike:"+attacker+":sustained" {
		t.Errorf("tag = %q", a.Tag)
	}
	if a.Detail["key_cur_failures"] == b.Detail["key_cur_failures"] {
		t.Error("runs should differ in counts, or this proves nothing")
	}
}

func TestSustainedHonoursErrorsAndNilReaders(t *testing.T) {
	d := mustNew(t, baseCfg())
	prev := events(win.Previous(), with(group{key: attacker, ok: 10, fail: 90})...)
	if _, err := d.Detect(context.Background(), fakeReader{}, fakeReader{evs: prev}, win); !errors.Is(err, core.ErrNoRecords) {
		t.Errorf("empty current window: err = %v, want ErrNoRecords", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := d.Detect(ctx, fakeReader{evs: events(win, with(group{key: attacker, ok: 10, fail: 90})...)}, fakeReader{evs: prev}, win); !errors.Is(err, context.Canceled) || len(got) != 0 {
		t.Errorf("cancelled: %v, %v", tags(got), err)
	}
	if _, err := d.Detect(context.Background(), fakeReader{evs: prev}, nil, win); err == nil {
		t.Error("nil prev accepted")
	}
	boom := errors.New("boom")
	if got, err := d.Detect(context.Background(),
		fakeReader{evs: events(win, with(group{key: attacker, ok: 10, fail: 90})...)},
		fakeReader{evs: prev, err: boom}, win); !errors.Is(err, boom) || len(got) != 0 {
		t.Errorf("baseline error must not become a finding: %v, %v", tags(got), err)
	}
}
