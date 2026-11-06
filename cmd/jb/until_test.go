package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// untilEnd is the end of the past window the tests hunt: a month before fixedNow.
var untilEnd = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) time.Time { return untilEnd.Add(d) }

// pastDocs: window [end-1h, end) holds two actor events (one exactly on the lower edge),
// the baseline [end-2h, end-1h) one, and four decoys sit outside both: exactly on the
// upper edge (the window is half open), after it, and before the baseline.
func pastDocs() []doc {
	e := func(d time.Duration) doc { return webDoc(at(d), exampleUA, "/login", 200, "203.0.113.11", "x") }
	return []doc{
		e(-150 * time.Minute), // before the baseline
		e(-90 * time.Minute),  // baseline
		e(-60 * time.Minute),  // window, on its lower edge
		e(-30 * time.Minute),  // window
		e(0),                  // on the upper edge: not in [from, to)
		e(30 * time.Minute),   // after the window
	}
}

func depsAt(now time.Time) deps {
	d := testDeps(huntEnv)
	d.now = func() time.Time { return now }
	return d
}

// untilCase is a case over a fake index of docs. pageSize > 0 sets the source's page size.
func untilCase(t *testing.T, docs []doc, pageSize int) (string, *fakeIndex) {
	t.Helper()
	idx := newFakeIndex(t, docs)
	dir := searchCase(t, idx)
	if pageSize > 0 {
		editFile(t, filepath.Join(dir, fpConfigRel), "index: logs-http-*", fmt.Sprintf("index: logs-http-*\n    page_size: %d", pageSize))
	}
	return dir, idx
}

type untilHunt struct {
	Run      string     `json:"run"`
	Until    *time.Time `json:"until"`
	Window   [2]time.Time
	Baseline [2]time.Time
	Complete bool `json:"complete"`
	Findings []struct {
		Detector string         `json:"detector"`
		Tag      string         `json:"tag"`
		Severity string         `json:"severity"`
		Summary  string         `json:"summary"`
		Detail   map[string]any `json:"detail"`
	} `json:"findings"`
	Sources []struct {
		Events *int64 `json:"events"`
	} `json:"sources"`
}

func (u *untilHunt) UnmarshalJSON(b []byte) error {
	type plain untilHunt
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	var w struct {
		Window   [2]time.Time `json:"window"`
		Baseline [2]time.Time `json:"baseline"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*u = untilHunt(p)
	u.Window, u.Baseline = w.Window, w.Baseline
	return nil
}

func untilJSON(t *testing.T, d deps, dir string, args ...string) (untilHunt, string, string) {
	t.Helper()
	all := append([]string{"hunt", "--output", "json", "--case", dir, "--config", fpConfigRel, "--window", "1h"}, args...)
	code, stdout, stderr := run(t, d, all...)
	var out untilHunt
	if err := json.Unmarshal([]byte(stdout), &out); err != nil || code != 0 {
		t.Fatalf("hunt %v: exit %d, %v\n%s\n%s", args, code, err, stdout, stderr)
	}
	return out, stdout, stderr
}

func activityAt(t *testing.T, d deps, dir string, args ...string) activityJSON {
	t.Helper()
	all := append([]string{"activity", "--output", "json", "--case", dir, "--config", fpConfigRel, "--window", "1h"}, args...)
	code, stdout, stderr := run(t, d, all...)
	var out activityJSON
	if err := json.Unmarshal([]byte(stdout), &out); err != nil || code != 0 {
		t.Fatalf("activity %v: exit %d, %v\n%s\n%s", args, code, err, stdout, stderr)
	}
	return out
}

// shape is what must not depend on how the window was named: findings without the run id.
func shape(u untilHunt) any {
	return []any{u.Window, u.Baseline, u.Findings, u.Complete}
}

const untilArg = "2026-10-01T12:00:00Z"

func TestParseUntil(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	ok := map[string]time.Time{
		"2026-10-01T12:00:00Z":      time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		"2026-10-01T14:00:00+02:00": time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), // a zone is converted, not dropped
		"2026-11-05T12:00:00Z":      now,                                           // exactly now is allowed
		"2020-01-01T00:00:00Z":      time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),   // older than any window
	}
	for in, want := range ok {
		got, err := parseUntil(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseUntil(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	bad := map[string]string{
		"2026-10-01T12:00:00":       "zone", // no zone: ambiguous
		"2026-10-01 12:00:00Z":      "RFC 3339",
		"2026-10-01":                "zone",
		"2026-10-01T12:00:00.5Z":    "whole seconds",
		"2026-11-05T12:00:01Z":      "after now",
		"2026-11-05T15:00:00+02:00": "after now", // 13:00Z is in the future
	}
	for in, frag := range bad {
		if _, err := parseUntil(in, now); err == nil || !strings.Contains(err.Error(), frag) {
			t.Errorf("parseUntil(%q) error = %v, want one containing %q", in, err, frag)
		}
	}
}

func TestUntilWindowAndHeader(t *testing.T) {
	dir, _ := untilCase(t, pastDocs(), 0)
	out, _, stderr := untilJSON(t, depsAt(fixedNow), dir, "--until", untilArg)
	if out.Until == nil || !out.Until.Equal(untilEnd) {
		t.Fatalf("until = %v, want %s", out.Until, untilEnd)
	}
	if !out.Window[0].Equal(at(-time.Hour)) || !out.Window[1].Equal(untilEnd) ||
		!out.Baseline[0].Equal(at(-2*time.Hour)) || !out.Baseline[1].Equal(at(-time.Hour)) {
		t.Errorf("window %v baseline %v: want [end-1h, end) and [end-2h, end-1h)", out.Window, out.Baseline)
	}
	if !strings.Contains(stderr, "2026-10-01T11:00:00Z") {
		t.Errorf("stderr does not state the window: %q", stderr)
	}
	// The table header states the absolute times and that until was set.
	code, tbl, _ := run(t, depsAt(fixedNow), "hunt", "--case", dir, "--config", fpConfigRel, "--window", "1h", "--until", untilArg)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, tbl)
	}
	for _, want := range []string{
		"until     2026-10-01T12:00:00Z (historical window; not relative to now)",
		"window    2026-10-01T11:00:00Z to 2026-10-01T12:00:00Z",
		"baseline  2026-10-01T10:00:00Z to 2026-10-01T11:00:00Z",
	} {
		if !strings.Contains(tbl, want) {
			t.Errorf("table lacks %q:\n%s", want, tbl)
		}
	}
	// A live hunt carries no until, in either format.
	live, stdout, _ := untilJSON(t, depsAt(untilEnd), dir)
	if live.Until != nil || strings.Contains(stdout, `"until"`) {
		t.Errorf("a live hunt must not mention until: %s", stdout)
	}
}

// Rule 1: the same absolute window, named as "now" and as --until, judges the same events,
// even when an earlier run stored events after the window.
func TestUntilSeesExactlyTheWindowWhateverTheStoreHolds(t *testing.T) {
	// A: a live hunt whose clock is the window end.
	dirA, _ := untilCase(t, pastDocs(), 0)
	a, _, _ := untilJSON(t, depsAt(untilEnd), dirA)
	// B: the same window by --until, a month later.
	dirB, _ := untilCase(t, pastDocs(), 0)
	b, _, _ := untilJSON(t, depsAt(fixedNow), dirB, "--until", untilArg)
	// C: the store already holds a later live run (it stored the event at end+30m).
	dirC, _ := untilCase(t, pastDocs(), 0)
	later, _, _ := untilJSON(t, depsAt(at(45*time.Minute)), dirC)
	if len(later.Findings) == 0 {
		t.Fatal("setup: the later run should have found the actor, or it stored nothing to leak")
	}
	c, _, _ := untilJSON(t, depsAt(fixedNow), dirC, "--until", untilArg)

	if len(a.Findings) == 0 {
		t.Fatal("setup: the window holds actor events and must raise a finding")
	}
	if !reflect.DeepEqual(shape(a), shape(b)) {
		t.Errorf("now-hunt and --until differ:\nnow:   %+v\nuntil: %+v", shape(a), shape(b))
	}
	if !reflect.DeepEqual(shape(b), shape(c)) {
		t.Errorf("a store holding later events changed the answer:\nfresh: %+v\nwith later run: %+v", shape(b), shape(c))
	}

	// The activity verdict agrees on counts and on the last genuine event.
	actA := activityAt(t, depsAt(untilEnd), dirA)
	actC := activityAt(t, depsAt(fixedNow), dirC, "--until", untilArg)
	if actA.Current != 2 || actA.Previous != 1 {
		t.Fatalf("now-activity counts %d/%d, want 2 in the window and 1 before", actA.Current, actA.Previous)
	}
	if actC.Current != actA.Current || actC.Previous != actA.Previous {
		t.Errorf("--until activity counts %d/%d, now-activity %d/%d", actC.Current, actC.Previous, actA.Current, actA.Previous)
	}
	lastOf := func(o activityJSON) *time.Time { return o.Detectors[0].Subjects[0].Last }
	if l := lastOf(actC); l == nil || !l.Equal(at(-30*time.Minute)) {
		t.Errorf("last genuine = %v, want %s (the event at end+30m is after the window)", l, at(-30*time.Minute))
	}
}

// Rule 2: run ids.
func TestUntilRunIDs(t *testing.T) {
	live := windowPlan{W: windowFor(untilEnd, time.Hour)}
	past := windowPlan{W: windowFor(untilEnd, time.Hour), Until: untilEnd}
	if got := live.runID("hunt"); got != "hunt-20261001T120000Z" {
		t.Errorf("live id = %q: the live format must not change", got)
	}
	if got := past.runID("hunt"); got != "hunt-until-20261001T120000Z-w3600s" {
		t.Errorf("historical id = %q", got)
	}
	if live.runID("hunt") == past.runID("hunt") {
		t.Error("a historical run collides with a live run of the same second")
	}
	long := windowPlan{W: windowFor(untilEnd, 24*time.Hour), Until: untilEnd}
	if long.runID("hunt") == past.runID("hunt") {
		t.Error("windows of different length ending together share a run id, so one would replace the other's events")
	}
	for _, p := range []string{"hunt", "search", "activity"} {
		if strings.HasPrefix(past.runID(p), "watch-") {
			t.Errorf("%s run id would be reaped by watch retention", p)
		}
	}

	dir, _ := untilCase(t, pastDocs(), 0)
	u, _, _ := untilJSON(t, depsAt(untilEnd), dir, "--until", untilArg) // until == now, same second as a live run
	l, _, _ := untilJSON(t, depsAt(untilEnd), dir)
	if u.Run == l.Run || !strings.HasPrefix(u.Run, "hunt-until-20261001T120000Z-") || l.Run != "hunt-20261001T120000Z" {
		t.Errorf("runs %q and %q", u.Run, l.Run)
	}
	// A narrowed run is a search run, historical or not, and says so in its id.
	code, stdout, _ := run(t, depsAt(fixedNow), "hunt", "--output", "json", "--case", dir, "--config", fpConfigRel, "--window", "1h", "--until", untilArg, "--search", "x")
	var sr untilHunt
	if err := json.Unmarshal([]byte(stdout), &sr); err != nil || code != 0 || !strings.HasPrefix(sr.Run, "search-until-20261001T120000Z-w3600s") {
		t.Errorf("search run = %q (exit %d, %v)", sr.Run, code, err)
	}
}

func windowFor(end time.Time, d time.Duration) core.Window {
	return core.Window{From: end.Add(-d), To: end}
}

// Rule 4: hunting the same absolute window again, by either name, counts nothing twice.
func TestUntilRepeatedBackfillDoesNotDoubleCount(t *testing.T) {
	dir, _ := untilCase(t, pastDocs(), 0)
	first := activityAt(t, depsAt(fixedNow), dir, "--until", untilArg)
	if first.Current != 2 || first.Previous != 1 {
		t.Fatalf("first counts %d/%d, want 2/1", first.Current, first.Previous)
	}
	h1, _, _ := untilJSON(t, depsAt(fixedNow), dir, "--until", untilArg)
	h2, _, _ := untilJSON(t, depsAt(fixedNow.Add(time.Hour)), dir, "--until", untilArg) // another day, same window
	live, _, _ := untilJSON(t, depsAt(untilEnd), dir)                                   // the same window as a live run: another run id
	if h1.Run != h2.Run {
		t.Errorf("a repeated backfill of one window must reuse its run id (it replaces itself), got %q then %q", h1.Run, h2.Run)
	}
	for _, o := range []untilHunt{h2, live} {
		if !reflect.DeepEqual(shape(o), shape(h1)) {
			t.Errorf("a repeat changed the findings:\nfirst: %+v\nlater: %+v", shape(h1), shape(o))
		}
	}
	// The counts the detector judges are unchanged after three more runs stored the same events.
	again := activityAt(t, depsAt(fixedNow), dir, "--until", untilArg)
	if again.Current != first.Current || again.Previous != first.Previous {
		t.Errorf("counts moved from %d/%d to %d/%d after repeated runs", first.Current, first.Previous, again.Current, again.Previous)
	}
	if h1.Findings[0].Detail != nil {
		if !reflect.DeepEqual(h1.Findings[0].Detail, live.Findings[0].Detail) {
			t.Errorf("finding detail differs between the backfill and the live run of one window")
		}
	}
}

// Rule 5: bounds, and a past window through a paged fake Kibana.
func TestUntilRefusals(t *testing.T) {
	dir, idx := untilCase(t, pastDocs(), 0)
	cases := map[string][]string{
		"no zone":        {"--until", "2026-10-01T12:00:00"},
		"fraction":       {"--until", "2026-10-01T12:00:00.250Z"},
		"future":         {"--until", "2026-11-05T12:00:01Z"},
		"garbage":        {"--until", "yesterday"},
		"window too big": {"--until", untilArg, "--window", "32d"},
	}
	for name, extra := range cases {
		args := append([]string{"hunt", "--case", dir, "--config", fpConfigRel}, extra...)
		if code, _, stderr := run(t, depsAt(fixedNow), args...); code != exitUsage {
			t.Errorf("%s: exit %d, want %d (usage)\n%s", name, code, exitUsage, stderr)
		}
		args[0] = "activity"
		if code, _, stderr := run(t, depsAt(fixedNow), args...); code != exitUsage {
			t.Errorf("%s (activity): exit %d, want %d\n%s", name, code, exitUsage, stderr)
		}
	}
	if n := len(idx.requests()); n != 0 {
		t.Errorf("%d request(s) reached Kibana for refused input", n)
	}
	// Exactly the maximum is fine; so is an --until older than the window is long.
	if code, _, stderr := run(t, depsAt(fixedNow), "hunt", "--case", dir, "--config", fpConfigRel, "--window", "31d", "--until", "2026-10-30T00:00:00Z"); code != 0 {
		t.Errorf("31d window refused: exit %d\n%s", code, stderr)
	}
	if code, _, stderr := run(t, depsAt(fixedNow), "hunt", "--case", dir, "--config", fpConfigRel, "--window", "1h", "--until", "2020-01-01T00:00:00Z"); code == exitUsage {
		t.Errorf("a very old --until must be accepted (it may find no records): exit %d\n%s", code, stderr)
	}
}

func TestUntilPastWindowPagesAcrossAPageBoundary(t *testing.T) {
	e := func(d time.Duration) doc { return webDoc(at(d), exampleUA, "/login", 200, "203.0.113.11", "x") }
	docs := []doc{
		e(-100 * time.Minute),                                            // baseline
		e(-50 * time.Minute), e(-40 * time.Minute), e(-40 * time.Minute), // a tie straddling the page edge
		e(-20 * time.Minute), e(-10 * time.Minute), e(-5 * time.Minute),
		e(5 * time.Minute), // after the window: must never be requested
	}
	dir, idx := untilCase(t, docs, 3)
	act := activityAt(t, depsAt(fixedNow), dir, "--until", untilArg)
	if act.Current != 6 || act.Previous != 1 {
		t.Fatalf("counts %d/%d, want 6 in the window and 1 before (page size 3, two events on one millisecond across the page edge)", act.Current, act.Previous)
	}
	reqs := idx.requests()
	if len(reqs) < 4 {
		t.Fatalf("%d request(s): the window was not paged", len(reqs))
	}
	for _, r := range reqs {
		b, _ := json.Marshal(filterClauses(r))
		s := string(b)
		if strings.Contains(s, "2026-11-0") {
			t.Errorf("a request mentions the present, not the past window: %s", s)
		}
		if !strings.Contains(s, `"gte":"2026-10-01T10:00:00Z"`) || !strings.Contains(s, `"lt":"2026-10-01T12:00:00Z"`) {
			t.Errorf("a request lacks the past window bounds: %s", s)
		}
	}
}

func TestWatchDoesNotOfferUntil(t *testing.T) {
	cmd := newWatchCmdWith(testDeps(nil))
	if cmd.Flags().Lookup("until") != nil {
		t.Fatal("watch must not have --until: a watch always ends now")
	}
	if code, _, stderr := run(t, testDeps(nil), "watch", "--case", exampleCase, "--until", untilArg); code != exitUsage || !strings.Contains(stderr, "unknown flag") {
		t.Errorf("exit %d: %s", code, stderr)
	}
	for _, name := range []string{"hunt", "activity"} {
		c, _, _ := newRootCmdWith(testDeps(nil)).Find([]string{name})
		f := c.Flags().Lookup("until")
		if f == nil || !strings.Contains(f.Usage, "watch") {
			t.Errorf("%s --until usage must say it is not on watch: %+v", name, f)
		}
	}
	if !strings.Contains(newWatchCmdWith(testDeps(nil)).Long, "--until") {
		t.Error("watch help must say why it has no --until")
	}
}
