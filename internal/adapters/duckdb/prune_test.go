package duckdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var pruneNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// seedHunt stores one hunt the way app.Hunt does: events under id/src, findings under id.
// age is how long before pruneNow its records were created.
func seedHunt(t *testing.T, s *Store, id string, nEvents int, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveEvents(ctx, id+"/src", seq(sample(nEvents)...)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveFindings(ctx, id, []core.Finding{{Detector: "d", Tag: id, Summary: "s"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = ? OR run_id = ?`,
		ts(pruneNow.Add(-age)), id, id+"/src"); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, s *Store, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPruneRemovesOldWatchRunsOnly(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, "watch-20261001T000001Z", 3, 100*time.Hour)
	seedHunt(t, s, "watch-20261001T000002Z", 2, 60*time.Hour)
	seedHunt(t, s, "watch-20261101T000000Z", 4, time.Hour)
	seedHunt(t, s, "hunt-ancient", 5, 900*time.Hour) // not a watch run: never touched
	seedHunt(t, s, "watchdog-ancient", 1, 900*time.Hour)

	res, err := s.PruneRuns(context.Background(), "watch-", pruneNow.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := core.PruneResult{Runs: 4, Events: 5, Findings: 2}
	if res != want {
		t.Fatalf("pruned %+v, want %+v", res, want)
	}
	for id, wantEv := range map[string]int64{"watch-20261001T000001Z/src": 0, "watch-20261001T000002Z/src": 0, "watch-20261101T000000Z/src": 4, "hunt-ancient/src": 5, "watchdog-ancient/src": 1} {
		if got := count(t, s, `SELECT count(*) FROM events WHERE run_id = ?`, id); got != wantEv {
			t.Errorf("events of %s = %d, want %d", id, got, wantEv)
		}
	}
	if got := count(t, s, `SELECT count(*) FROM findings WHERE run_id IN ('watch-20261001T000001Z','watch-20261001T000002Z')`); got != 0 {
		t.Errorf("findings of pruned hunts remain: %d", got)
	}
	if got := count(t, s, `SELECT count(*) FROM findings`); got != 3 {
		t.Errorf("findings left = %d, want 3 (new, hunt, watchdog)", got)
	}
	if got := count(t, s, `SELECT count(*) FROM runs WHERE starts_with(run_id, 'watch-20261001T0000')`); got != 0 {
		t.Errorf("run records of pruned hunts remain: %d", got)
	}
}

func TestPruneNeverRemovesTheLatestWatchRun(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, "watch-20261001T000010Z", 2, 300*time.Hour)
	seedHunt(t, s, "watch-20261001T000020Z", 2, 200*time.Hour) // newest, but older than the cutoff
	res, err := s.PruneRuns(context.Background(), "watch-", pruneNow.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.Runs != 2 || res.Events != 2 || res.Findings != 1 {
		t.Fatalf("pruned %+v, want only watch-20261001T000010Z", res)
	}
	if count(t, s, `SELECT count(*) FROM events WHERE run_id = 'watch-20261001T000020Z/src'`) != 2 {
		t.Error("the latest watch run lost its events")
	}
	// Idempotent: the survivor stays however often it is pruned.
	if res, err = s.PruneRuns(context.Background(), "watch-", pruneNow); err != nil || res != (core.PruneResult{}) {
		t.Fatalf("second prune = %+v, %v", res, err)
	}
}

// A cutoff that lands between the records of one hunt must not split it.
func TestPruneKeepsAHuntWhoseRecordsStraddleTheCutoff(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, "watch-20261001T000030Z", 2, time.Hour)
	seedHunt(t, s, "watch-20261001T000040Z", 2, time.Hour) // so watch-20261001T000030Z is not the newest by accident
	if _, err := s.db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = 'watch-20261001T000030Z/src'`, ts(pruneNow.Add(-100*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = 'watch-20261001T000040Z'`, ts(pruneNow.Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	res, err := s.PruneRuns(context.Background(), "watch-", pruneNow.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res != (core.PruneResult{}) {
		t.Fatalf("pruned %+v; watch-20261001T000030Z has a record newer than the cutoff", res)
	}
}

func TestPruneIsAtomicWhenItFailsHalfWay(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, "watch-20261001T000050Z", 3, 100*time.Hour)
	seedHunt(t, s, "watch-20261101T000000Z", 1, time.Hour)
	boom := errors.New("injected")
	pruneHook = func(table string) error {
		if table == "findings" { // events were already deleted by now
			return boom
		}
		return nil
	}
	t.Cleanup(func() { pruneHook = nil })
	if _, err := s.PruneRuns(context.Background(), "watch-", pruneNow.Add(-48*time.Hour)); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the injected failure", err)
	}
	if got := count(t, s, `SELECT count(*) FROM events WHERE run_id = 'watch-20261001T000050Z/src'`); got != 3 {
		t.Errorf("events of the half-pruned hunt = %d, want 3: the delete was not rolled back", got)
	}
	if got := count(t, s, `SELECT count(*) FROM findings WHERE run_id = 'watch-20261001T000050Z'`) + count(t, s, `SELECT count(*) FROM runs WHERE run_id LIKE 'watch-20261001T000050Z%'`); got != 3 {
		t.Errorf("findings+runs of the hunt = %d, want 3", got)
	}
	// The scratch table must not leak into the next prune.
	pruneHook = nil
	if res, err := s.PruneRuns(context.Background(), "watch-", pruneNow.Add(-48*time.Hour)); err != nil || res.Runs != 2 {
		t.Fatalf("retry = %+v, %v", res, err)
	}
}

func TestPruneRefusesEmptyPrefixAndReadOnly(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, "watch-20261001T000010Z", 1, 100*time.Hour)
	seedHunt(t, s, "watch-20261001T000020Z", 1, time.Hour)
	if _, err := s.PruneRuns(context.Background(), "", pruneNow); err == nil {
		t.Error("an empty prefix was accepted: it would match every run")
	}
	path := s.Path()
	s.Close()
	ro, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := ro.PruneRuns(context.Background(), "watch-", pruneNow); err == nil {
		t.Error("PruneRuns succeeded on a read-only handle")
	}
	if got := count(t, ro, `SELECT count(*) FROM events`); got != 2 {
		t.Errorf("events = %d after the refused prune, want 2", got)
	}
}

// Watchers share one store, so retention must be delimiter-safe in both directions:
// "watch-a-" must not reach the runs of "watch-ab-" or "watch-a-b-", and the unnamed
// watcher's "watch-" must not reach any named watcher's runs. Each watcher has an old
// run (prunable) and a new one, so a prefix that matched too much would delete a
// neighbour's old run and the counts below would not hold.
func TestPruneTouchesOnlyTheRunsOfTheNamedWatcher(t *testing.T) {
	const old, fresh = "20261001T000000Z", "20261101T000000Z"
	ids := []string{"watch-", "watch-a-", "watch-ab-", "watch-a-b-"}
	seed := func(t *testing.T) *Store {
		s := openTest(t)
		for _, p := range ids {
			seedHunt(t, s, p+old, 2, 100*time.Hour)
			seedHunt(t, s, p+fresh, 1, time.Hour)
		}
		return s
	}
	cutoff := pruneNow.Add(-48 * time.Hour)
	for _, prune := range ids {
		t.Run("prune "+prune, func(t *testing.T) {
			s := seed(t)
			res, err := s.PruneRuns(context.Background(), prune, cutoff)
			if err != nil {
				t.Fatal(err)
			}
			if want := (core.PruneResult{Runs: 2, Events: 2, Findings: 1}); res != want {
				t.Fatalf("pruned %+v, want exactly the old run of %q: %+v", res, prune, want)
			}
			for _, p := range ids {
				wantOld := int64(2)
				if p == prune {
					wantOld = 0
				}
				if got := count(t, s, `SELECT count(*) FROM events WHERE run_id = ?`, p+old+"/src"); got != wantOld {
					t.Errorf("after pruning %q, old events of %q = %d, want %d", prune, p, got, wantOld)
				}
				if got := count(t, s, `SELECT count(*) FROM events WHERE run_id = ?`, p+fresh+"/src"); got != 1 {
					t.Errorf("after pruning %q, new events of %q = %d, want 1", prune, p, got)
				}
			}
		})
	}
}

// The newest run is protected per watcher: a watcher whose only run is old keeps it,
// and pruning someone else's prefix does not count it as the newest of theirs.
func TestPruneKeepsEachWatchersNewestRun(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, "watch-solo-20260901T000000Z", 2, 900*time.Hour)
	seedHunt(t, s, "watch-busy-20260901T000000Z", 2, 900*time.Hour)
	seedHunt(t, s, "watch-busy-20261101T000000Z", 1, time.Hour)
	for _, p := range []string{"watch-solo-", "watch-busy-"} {
		if _, err := s.PruneRuns(context.Background(), p, pruneNow.Add(-48*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if got := count(t, s, `SELECT count(*) FROM events WHERE run_id = 'watch-solo-20260901T000000Z/src'`); got != 2 {
		t.Errorf("solo's only run was pruned (%d events left, want 2)", got)
	}
	if got := count(t, s, `SELECT count(*) FROM events WHERE run_id = 'watch-busy-20260901T000000Z/src'`); got != 0 {
		t.Errorf("busy's old run survived (%d events)", got)
	}
}

// Anything that is not prefix + a stamp is out of reach, whatever it starts with.
func TestPruneIgnoresIdsThatOnlyStartWithThePrefix(t *testing.T) {
	s := openTest(t)
	for _, id := range []string{"watch-until-20261001T000000Z-w3600s", "watch-20261001T000000Z-extra", "watch-2026"} {
		seedHunt(t, s, id, 1, 900*time.Hour)
	}
	seedHunt(t, s, "watch-20261101T000000Z", 1, time.Hour)
	res, err := s.PruneRuns(context.Background(), "watch-", pruneNow.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res != (core.PruneResult{}) {
		t.Fatalf("pruned %+v; none of those ids is a watch run", res)
	}
}
