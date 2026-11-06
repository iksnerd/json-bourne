package duckdb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	rOld   = "hunt-20261001T000001Z"               // older than the named runs, same kind
	rA     = "hunt-20261010T000001Z"               // named
	rNew   = "hunt-20261104T000001Z"               // newer than the named runs, same kind
	rShort = "search-until-20261001T000000Z-w60s"  // a prefix of rLong
	rLong  = "search-until-20261001T000000Z-w600s" // never named when rShort is
	rWatch = "watch-20261001T000001Z"
	rActiv = "activity-20261012T000001Z" // named, another kind
	rExtra = rA + "-extra"               // an id that has rA as a prefix, but is not rA
)

func seedByRun(t *testing.T) *Store {
	t.Helper()
	s := openTest(t)
	seedHunt(t, s, rOld, 2, 900*time.Hour)
	seedHunt(t, s, rA, 3, 600*time.Hour)
	seedHunt(t, s, rNew, 5, time.Hour)
	seedHunt(t, s, rShort, 7, 500*time.Hour)
	seedHunt(t, s, rLong, 11, 500*time.Hour)
	seedHunt(t, s, rWatch, 13, 500*time.Hour)
	seedHunt(t, s, rActiv, 17, 400*time.Hour)
	seedHunt(t, s, rExtra, 19, 600*time.Hour)
	if err := s.AppendReputation(context.Background(), []core.Reputation{{Indicator: "192.0.2.1", Verdict: "benign", Observed: pruneNow, Source: "feed.example.com"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

func byRun(ids ...string) core.EventPruneRequest { return core.EventPruneRequest{RunIDs: ids} }

func allEvents(t *testing.T, s *Store) map[string]int64 {
	t.Helper()
	m := map[string]int64{}
	for _, id := range []string{rOld, rA, rNew, rShort, rLong, rWatch, rActiv, rExtra} {
		m[id] = count(t, s, `SELECT count(*) FROM events WHERE run_id = ?`, id+"/src")
	}
	return m
}

func TestPruneByRunIDDryRunPlansOnlyTheNamedRunsAndChangesNothing(t *testing.T) {
	s := seedByRun(t)
	before := allEvents(t, s)
	r := byRun(rA, rActiv)
	r.DryRun = true
	res, err := s.PruneRunEvents(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || !res.ByRunID || len(res.Runs) != 2 || res.Plan.Runs != 2 || res.Plan.Events != 3+17 {
		t.Fatalf("plan = %+v runs=%+v", res.Plan, res.Runs)
	}
	for _, pr := range res.Runs {
		if pr.Action != core.ActionPrune || (pr.ID != rA && pr.ID != rActiv) {
			t.Errorf("unexpected run in plan: %+v", pr)
		}
	}
	after := allEvents(t, s)
	for id, n := range before {
		if after[id] != n {
			t.Errorf("dry run changed %s: %d -> %d", id, n, after[id])
		}
	}
}

func TestPruneByRunIDApplyRemovesOnlyTheNamedRunsEvents(t *testing.T) {
	s := seedByRun(t)
	res, err := s.PruneRunEvents(context.Background(), byRun(rA))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.Deleted.Events != 3 || res.Marked != 2 {
		t.Fatalf("result = %+v marked=%d", res.Deleted, res.Marked)
	}
	want := map[string]int64{rOld: 2, rA: 0, rNew: 5, rShort: 7, rLong: 11, rWatch: 13, rActiv: 17, rExtra: 19}
	for id, n := range allEvents(t, s) {
		if n != want[id] {
			t.Errorf("events of %s = %d, want %d", id, n, want[id])
		}
	}
	// Findings and run records stay; only the named hunt's records are marked.
	if got := count(t, s, `SELECT count(*) FROM findings`); got != 8 {
		t.Errorf("findings = %d, want 8", got)
	}
	if got := count(t, s, `SELECT count(*) FROM runs WHERE pruned_at IS NOT NULL`); got != 2 {
		t.Errorf("marked run records = %d, want 2", got)
	}
	if got := count(t, s, `SELECT count(*) FROM runs WHERE pruned_at IS NOT NULL AND starts_with(run_id, ?)`, rA); got != 2 {
		t.Errorf("marked records of the named hunt = %d, want 2", got)
	}
	if got := count(t, s, `SELECT count(*) FROM reputation`); got != 1 {
		t.Errorf("reputation rows = %d, want 1", got)
	}
}

func TestPruneByRunIDDropFindingsRemovesOnlyTheNamedHunt(t *testing.T) {
	s := seedByRun(t)
	r := byRun(rA)
	r.DropFindings = true
	res, err := s.PruneRunEvents(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted.Findings != 1 || res.Deleted.RunRecords != 2 || res.Deleted.Events != 3 {
		t.Fatalf("deleted = %+v", res.Deleted)
	}
	if got := count(t, s, `SELECT count(*) FROM runs`); got != 14 {
		t.Errorf("run records = %d, want 14", got)
	}
	if got := count(t, s, `SELECT count(*) FROM findings`); got != 7 {
		t.Errorf("findings = %d, want 7", got)
	}
}

func TestPruneByRunIDMatchesTheWholeIDNotAPrefix(t *testing.T) {
	s := seedByRun(t)
	if _, err := s.PruneRunEvents(context.Background(), byRun(rShort)); err != nil {
		t.Fatal(err)
	}
	got := allEvents(t, s)
	if got[rShort] != 0 || got[rLong] != 11 {
		t.Errorf("short=%d (want 0) long=%d (want 11): %s is a prefix of %s", got[rShort], got[rLong], rShort, rLong)
	}
	// An id that merely starts with a named id is another run (here of no prunable kind).
	if _, err := s.PruneRunEvents(context.Background(), byRun(rA)); err != nil {
		t.Fatal(err)
	}
	if allEvents(t, s)[rExtra] != 19 {
		t.Errorf("%s lost events when %s was named", rExtra, rA)
	}
	// A truncated id is a missing run, not a match.
	if _, err := s.PruneRunEvents(context.Background(), byRun(rLong[:len(rLong)-3])); err == nil {
		t.Fatal("a truncated id was accepted")
	}
	if allEvents(t, s)[rLong] != 11 {
		t.Error("the long run lost events")
	}
}

func TestPruneByRunIDMissingRunFailsAndDeletesNothing(t *testing.T) {
	s := seedByRun(t)
	before := allEvents(t, s)
	missing := "hunt-20261020T000001Z"
	for _, dry := range []bool{true, false} {
		r := byRun(rA, missing)
		r.DryRun = dry
		_, err := s.PruneRunEvents(context.Background(), r)
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("dry=%v err = %v, want one naming %s", dry, err, missing)
		}
	}
	after := allEvents(t, s)
	for id, n := range before {
		if after[id] != n {
			t.Errorf("%s changed: %d -> %d", id, n, after[id])
		}
	}
	if got := count(t, s, `SELECT count(*) FROM runs WHERE pruned_at IS NOT NULL`); got != 0 {
		t.Errorf("%d run records were marked", got)
	}
}

func TestPruneByRunIDRefusesWatchOtherSourceRunsAndMixedSelectors(t *testing.T) {
	s := seedByRun(t)
	cases := map[string]core.EventPruneRequest{
		"watch":      byRun(rA, rWatch),
		"other":      byRun("custom-run"),
		"source run": byRun(rA + "/src"),
		"wildcard":   byRun("hunt-%"),
		"empty":      byRun(""),
		"with kinds": {RunIDs: []string{rA}, Kinds: []core.RunKind{core.KindHunt}},
		"with age":   {RunIDs: []string{rA}, Before: pruneNow},
		"with keep":  {RunIDs: []string{rA}, KeepLatest: 1},
	}
	for name, r := range cases {
		if _, err := s.PruneRunEvents(context.Background(), r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.PruneRunEvents(context.Background(), byRun(rWatch)); !errors.Is(err, core.ErrWatchKind) {
		t.Errorf("watch err = %v, want ErrWatchKind", err)
	}
	for id, n := range allEvents(t, s) {
		if n == 0 {
			t.Errorf("%s lost its events", id)
		}
	}
}

func TestPruneByRunIDDuplicatesCountOnceAndTooManyAreRefused(t *testing.T) {
	s := seedByRun(t)
	res, err := s.PruneRunEvents(context.Background(), byRun(rA, rA, rA))
	if err != nil || res.Plan.Runs != 1 || res.Deleted.Events != 3 {
		t.Fatalf("duplicates: %+v, %v", res.Plan, err)
	}
	var many []string
	for i := 0; i <= core.MaxPruneRunIDs; i++ {
		many = append(many, fmt.Sprintf("hunt-20260101T0000%02dZ", i))
	}
	if _, err := s.PruneRunEvents(context.Background(), byRun(many...)); err == nil {
		t.Error("21 run ids accepted")
	}
}
