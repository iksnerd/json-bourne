package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func TestValidWatchName(t *testing.T) {
	for _, ok := range []string{"", "a", "attack", "attack-1", "health_check", "a0", strings.Repeat("a", 32)} {
		if err := ValidWatchName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"A", "1a", "-a", "_a", "a b", "a/b", "a.b", "..", "a\n", "a:b", "é", strings.Repeat("a", 33)} {
		if err := ValidWatchName(bad); err == nil {
			t.Errorf("%q accepted: it would end up in a file name and a run id", bad)
		}
	}
}

func TestWatchRunPrefixFor(t *testing.T) {
	if got := WatchRunPrefixFor(""); got != "watch" {
		t.Errorf("unnamed = %q: existing run ids must not change", got)
	}
	if got := WatchRunPrefixFor("a"); got != "watch-a" {
		t.Errorf("named = %q", got)
	}
	// Every shape stays under the reserved prefix, so retention applies to it.
	for _, n := range []string{"", "a", "attack-1"} {
		if !strings.HasPrefix(WatchRunPrefixFor(n)+"-", WatchRunPrefix) {
			t.Errorf("%q: run ids would leave the reserved %q prefix", n, WatchRunPrefix)
		}
	}
}

func TestNamedWatchStampsEveryAlertAndRunID(t *testing.T) {
	r := newRig(t, det("d", finding("d", "x", core.SevHigh)))
	r.deps.Name = "attack"
	rep, err := WatchCycle(context.Background(), r.deps, r.opts, "watch-attack-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.sink.got) < 2 {
		t.Fatalf("alerts = %+v", r.sink.got)
	}
	for _, a := range r.sink.got {
		if a.Watcher != "attack" {
			t.Errorf("alert %q (%s) is not attributable: Watcher = %q", a.Tag, a.Kind, a.Watcher)
		}
	}
	if rep.Status != CycleFindings {
		t.Errorf("status = %s", rep.Status)
	}
}

func TestUnnamedWatchLeavesAlertsUnstamped(t *testing.T) {
	r := newRig(t, det("d", finding("d", "x", core.SevHigh)))
	r.cycle()
	for _, a := range r.sink.got {
		if a.Watcher != "" {
			t.Errorf("the unnamed watcher stamped %q on %q", a.Watcher, a.Tag)
		}
	}
}

func TestWatchRefusesAnInvalidNameAndAMismatchedPrefix(t *testing.T) {
	r := newRig(t, det("d"))
	r.deps.Name = "Bad Name"
	if _, err := WatchCycle(context.Background(), r.deps, r.opts, "watch-x"); err == nil {
		t.Error("WatchCycle accepted an invalid name")
	}
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch"); err == nil {
		t.Error("Watch accepted an invalid name")
	}

	// Retention deletes by the watcher's exact prefix; a run prefix that does not match
	// the name would leave the runs unpruned, or pruned as another watcher's.
	r = newRig(t, det("d"))
	r.deps.Prune = func(context.Context, time.Time) (core.PruneResult, error) { return core.PruneResult{}, nil }
	for _, c := range [][2]string{{"a", "watch"}, {"", "watch-a"}, {"ab", "watch-a"}, {"a", "watch-ab"}} {
		r.deps.Name = c[0]
		if _, err := Watch(context.Background(), r.deps, r.opts, c[1]); err == nil {
			t.Errorf("name %q with run prefix %q: accepted", c[0], c[1])
		}
	}
	r.deps.Name = "a"
	r.opts.Once = true
	if _, err := Watch(context.Background(), r.deps, r.opts, "watch-a"); err != nil {
		t.Errorf("matching name and prefix refused: %v", err)
	}
}

func TestCycleLineStatesWhatWasDisabled(t *testing.T) {
	r := newRig(t, det("d"))
	r.deps.Disabled = []Disabled{{"source", "standby"}, {"detector", "spike-standby"}}
	r.cycle()
	hb := r.sink.kind(core.AlertCycle)
	if len(hb) != 1 {
		t.Fatal("no cycle line")
	}
	for _, want := range []string{"CYCLE QUIET", "every enabled source and detector completed", "DISABLED: source standby, detector spike-standby"} {
		if !strings.Contains(hb[0].Text, want) {
			t.Errorf("cycle line lacks %q:\n%s", want, hb[0].Text)
		}
	}

	// Nothing disabled: the line is exactly what it was.
	r = newRig(t, det("d"))
	r.cycle()
	if got := r.sink.kind(core.AlertCycle)[0].Text; strings.Contains(got, "DISABLED") || strings.Contains(got, "enabled") {
		t.Errorf("a cycle with nothing disabled mentions it:\n%s", got)
	}
}

func TestDisabledNote(t *testing.T) {
	if DisabledNote(nil) != "" {
		t.Error("a note for nothing")
	}
	got := DisabledNote([]Disabled{{"source", "a"}})
	if !strings.HasPrefix(got, "DISABLED: source a ") || !strings.Contains(got, "not read, not run") {
		t.Errorf("note = %q", got)
	}
}

func TestHuntCarriesDisabledIntoItsResult(t *testing.T) {
	mem := newMem()
	src := &fakeSource{name: "s", events: []core.Event{{Time: t0.Add(-10 * time.Minute), Source: "s", Kind: "k"}}}
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{src}, Detectors: []core.Detector{det("d")}, Sink: mem, Reader: mem,
		Disabled: []Disabled{{"source", "standby"}},
	}, "r", core.Window{From: t0.Add(-time.Hour), To: t0})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Disabled) != 1 || res.Disabled[0].Name != "standby" {
		t.Errorf("Disabled = %+v", res.Disabled)
	}
	for _, s := range res.Sources {
		if s.Name == "standby" {
			t.Error("a disabled source has a result row")
		}
	}
}
