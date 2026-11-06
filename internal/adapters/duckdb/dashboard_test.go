package duckdb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func dashEv(at time.Time, src, path, ua, key string, status int) core.Event {
	return core.Event{Time: at, Source: src, Kind: "request", Fields: map[string]any{
		"path": path, "status": float64(status), "client_ip": key, "user_agent": ua}}
}

// dashFixture writes one watch group with two sources and a findings run, one hunt
// group with a finding and no events, and a reputation row; it returns a read-only
// Dashboard on the file.
func dashFixture(t *testing.T) *Dashboard {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.duckdb")
	rw, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Migrate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(rw.SaveEvents(ctx, "watch-1/kibana:a", seq(
		dashEv(base, "kibana:a", "/token?client=1", "UA/1", "192.0.2.7", 401),
		dashEv(base.Add(time.Second), "kibana:a", "/token?client=2", "UA/1", "192.0.2.7", 401),
		dashEv(base.Add(2*time.Second), "kibana:a", "/token#frag", "UA/2", "192.0.2.8", 200),
		dashEv(base.Add(3*time.Second), "kibana:a", "?only=query", "UA/2", "192.0.2.8", 200),
	)))
	must(rw.SaveEvents(ctx, "watch-1/kibana:b", seq(
		dashEv(base.Add(4*time.Second), "kibana:b", "/health", "UA/3", "192.0.2.9", 200),
	)))
	must(rw.SaveFindings(ctx, "watch-1", []core.Finding{
		{Detector: "authspike", Tag: "spray:192.0.2.7", Severity: core.SevHigh, Summary: "192.0.2.7 failed 80%"},
		{Detector: "newkey", Tag: "newkey:192.0.2.9", Severity: core.SevCheck, Summary: "new key"},
	}))
	must(rw.SaveFindings(ctx, "hunt-9", []core.Finding{{Detector: "authspike", Tag: "t", Severity: core.SevInfo, Summary: "only finding"}}))
	must(rw.AppendReputation(ctx, []core.Reputation{{Indicator: "192.0.2.7", Verdict: "malicious", Observed: base, Source: "greynoise"}}))
	must(rw.Close())
	d, err := OpenDashboard(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

var dashFields = core.DashboardFields{Path: "path", Status: "status", Key: "client_ip"}

func TestDashboardRunsGroupAndFlagIncomplete(t *testing.T) {
	d := dashFixture(t)
	runs, err := d.Runs(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]core.RunGroup{}
	for _, r := range runs {
		by[r.ID] = r
	}
	if len(by) != 2 {
		t.Fatalf("runs = %+v, want groups watch-1 and hunt-9", runs)
	}
	w := by["watch-1"]
	if w.EventRuns != 2 || w.Events != 5 || w.Findings != 2 || w.Incomplete() {
		t.Errorf("watch-1 = %+v", w)
	}
	h := by["hunt-9"]
	if h.Events != 0 || !h.Incomplete() || h.Findings != 1 {
		t.Errorf("hunt-9 = %+v: a group with no events must be incomplete", h)
	}
	if g, err := d.Run(context.Background(), "watch-1"); err != nil || g.Events != 5 || g.Findings != 2 || g.EventRuns != 2 {
		t.Errorf("Run(watch-1) = %+v, %v", g, err)
	}
	if _, err := d.Run(context.Background(), "nope"); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("Run(nope) err = %v, want ErrNotFound", err)
	}
	if got, _ := d.Runs(context.Background(), 1); len(got) != 1 {
		t.Errorf("limit not applied: %d rows", len(got))
	}
}

func TestEventSummaryStripsQueryAndNeverLabelsEmpty(t *testing.T) {
	d := dashFixture(t)
	s, err := d.EventSummary(context.Background(), "watch-1", dashFields, 10)
	if err != nil {
		t.Fatal(err)
	}
	if s.Rows != 5 {
		t.Errorf("rows = %d, want 5", s.Rows)
	}
	paths := map[string]int64{}
	for _, c := range s.TopPaths {
		if strings.TrimSpace(c.Label) == "" {
			t.Errorf("a top path has an empty label: %+v", s.TopPaths)
		}
		paths[c.Label] = c.N
	}
	if paths["/token"] != 3 {
		t.Errorf("/token = %d, want 3 (two query strings and a fragment collapse): %+v", paths["/token"], s.TopPaths)
	}
	if paths["(no path)"] != 1 {
		t.Errorf("a path that is only a query string must be labelled, got %+v", s.TopPaths)
	}
	for l := range paths {
		if strings.ContainsAny(l, "?#") {
			t.Errorf("label %q keeps a query string or fragment", l)
		}
	}
	want := map[string]int64{"kibana:a": 4, "kibana:b": 1}
	for _, c := range s.BySource {
		if want[c.Label] != c.N {
			t.Errorf("by source %+v", s.BySource)
		}
	}
	if len(s.ByKind) != 1 || s.ByKind[0].Label != "request" || s.ByKind[0].N != 5 {
		t.Errorf("by kind %+v", s.ByKind)
	}
	st := map[string]int64{}
	for _, c := range s.ByStatus {
		st[c.Label] = c.N
	}
	if st["401"] != 2 || st["200"] != 3 {
		t.Errorf("by status %+v (labels must be 401, not 401.0)", s.ByStatus)
	}
	if len(s.TopKeys) == 0 || s.TopKeys[0].Label != "192.0.2.7" && s.TopKeys[0].Label != "192.0.2.8" {
		t.Errorf("top keys %+v", s.TopKeys)
	}
	if got, _ := d.EventSummary(context.Background(), "watch-1", dashFields, 1); len(got.TopPaths) != 1 {
		t.Errorf("top limit not applied: %d", len(got.TopPaths))
	}
}

func TestEventSummaryRejectsAFieldNameThatCouldCarryAPath(t *testing.T) {
	d := dashFixture(t)
	_, err := d.EventSummary(context.Background(), "watch-1", core.DashboardFields{Path: `a"] OR 1=1 --`, Status: "status", Key: "client_ip"}, 5)
	if err == nil {
		t.Fatal("a field name with quotes must be refused")
	}
}

func TestDashboardFindingsEventsReputation(t *testing.T) {
	d := dashFixture(t)
	ctx := context.Background()
	fs, err := d.RunFindings(ctx, "watch-1", 10)
	if err != nil || len(fs) != 2 || fs[0].Severity != core.SevHigh || fs[0].Run != "watch-1" {
		t.Fatalf("RunFindings = %+v, %v (most severe first)", fs, err)
	}
	all, err := d.LatestFindings(ctx, 2)
	if err != nil || len(all) != 2 {
		t.Fatalf("LatestFindings = %+v, %v", all, err)
	}
	evs, err := d.RecentEvents(ctx, "watch-1", 2)
	if err != nil || len(evs) != 2 || evs[0].Raw != nil {
		t.Fatalf("RecentEvents = %+v, %v (bounded, newest first, no raw)", evs, err)
	}
	if !evs[0].Time.After(evs[1].Time) {
		t.Errorf("not newest first: %v %v", evs[0].Time, evs[1].Time)
	}
	rep, err := d.LatestReputation(ctx, 5)
	if err != nil || len(rep) != 1 || rep[0].Verdict != "malicious" {
		t.Fatalf("LatestReputation = %+v, %v", rep, err)
	}
	st, err := d.Stats(ctx)
	if err != nil || st.Events != 5 || st.Runs != 4 || st.Findings != 3 {
		t.Fatalf("Stats = %+v, %v", st, err)
	}
}

// The dashboard type has no writable constructor, and the handle behind it refuses
// writes whatever SQL arrives (the engine, not a text check).
func TestDashboardHandleIsReadOnly(t *testing.T) {
	d := dashFixture(t)
	for _, q := range []string{`DROP TABLE events`, `SELECT 1; DELETE FROM events`, `INSERT INTO runs (run_id, created_at) VALUES ('x', now())`} {
		if _, err := d.s.db.Exec(q); err == nil {
			t.Errorf("dashboard handle accepted %q", q)
		}
	}
	if st, err := d.Stats(context.Background()); err != nil || st.Events != 5 {
		t.Fatalf("after write attempts: %+v %v", st, err)
	}
}

func TestOpenDashboardMissingFileIsAbsentNotCreated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "none.duckdb")
	if _, err := OpenDashboard(p); !errors.Is(err, core.ErrAbsent) {
		t.Fatalf("err = %v, want ErrAbsent", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("OpenDashboard created %s: a viewer must never create the database (%v)", p, err)
	}
}

func TestDashboardHonoursCancelledContext(t *testing.T) {
	d := dashFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Runs(ctx, 10); err == nil {
		t.Error("a cancelled context must fail the query, not return rows")
	}
}
