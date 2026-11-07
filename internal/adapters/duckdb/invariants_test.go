package duckdb

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func invAt() time.Time { return time.Now().UTC().Add(-time.Minute).Truncate(time.Second) }

func invEvent(at time.Time, source string, returners ...string) core.Event {
	return core.Event{
		Time: at, Source: source, Kind: "request",
		Raw: []byte(`{"synthetic":true}`), Fields: map[string]any{"synthetic": true}, Returners: returners,
	}
}

func invRead(t *testing.T, s *Store, at time.Time) []core.Event {
	t.Helper()
	return readAll(t, s, at.Add(-time.Second), at.Add(time.Second))
}

// member is the scoped-read rule of app.Hunt: the owner or any returner.
func member(e core.Event, label string) bool {
	return e.Source == label || slices.Contains(e.Returners, label)
}

// R01: a rename keeps membership coherent for the owner label and for a label that is only a returner.
func TestRenameKeepsMembership(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := invAt()
	if err := s.SaveEvents(ctx, "r", seq(invEvent(at, "a", "a", "b"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenameSource(ctx, core.RenameSourceRequest{Old: "a", New: "renamed"}); err != nil {
		t.Fatal(err)
	}
	got := invRead(t, s, at)
	if len(got) != 1 || got[0].Source != "renamed" {
		t.Fatalf("got %+v", got)
	}
	if !member(got[0], "renamed") || !member(got[0], "b") || member(got[0], "a") {
		t.Fatalf("owner=%s returners=%v after rename", got[0].Source, got[0].Returners)
	}
	if !slices.Equal(got[0].Returners, []string{"b", "renamed"}) {
		t.Fatalf("returners %v, want sorted set [b renamed]", got[0].Returners)
	}
	// b exists only as a returner here: renaming it must work and keep the owner.
	res, err := s.RenameSource(ctx, core.RenameSourceRequest{Old: "b", New: "c"})
	if err != nil {
		t.Fatalf("rename of a returner-only label: %v", err)
	}
	if !res.Applied {
		t.Fatalf("not applied: %+v", res)
	}
	got = invRead(t, s, at)
	if !slices.Equal(got[0].Returners, []string{"c", "renamed"}) || got[0].Source != "renamed" {
		t.Fatalf("owner=%s returners=%v", got[0].Source, got[0].Returners)
	}
	// renaming onto a label already in the set must stay a set
	if _, err := s.RenameSource(ctx, core.RenameSourceRequest{Old: "c", New: "renamed"}); err != nil {
		t.Fatal(err)
	}
	got = invRead(t, s, at)
	if !slices.Equal(got[0].Returners, []string{"renamed"}) {
		t.Fatalf("returners %v, want [renamed]", got[0].Returners)
	}
}

// R01: a merge that drops Old's duplicate rows keeps the membership they carried.
func TestRenameMergeKeepsMembership(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := invAt()
	if err := s.SaveEvents(ctx, "r1", seq(invEvent(at, "old", "old", "other"))); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "r2", seq(invEvent(at, "new"))); err != nil {
		t.Fatal(err)
	}
	res, err := s.RenameSource(ctx, core.RenameSourceRequest{Old: "old", New: "new", Merge: true})
	if err != nil || res.Dropped != 1 {
		t.Fatalf("res %+v err %v", res, err)
	}
	got := invRead(t, s, at)
	if len(got) != 1 || got[0].Source != "new" || !member(got[0], "other") || !member(got[0], "new") || member(got[0], "old") {
		t.Fatalf("got %+v", got)
	}
}

// R02: the copy carries returners.
func TestCompactPreservesReturners(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := invAt()
	if err := s.SaveEvents(ctx, "r", seq(invEvent(at, "a", "a", "b"))); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "copy.duckdb")
	res, err := s.Compact(ctx, core.CompactRequest{Target: target})
	if err != nil || !res.Applied {
		t.Fatalf("res %+v err %v", res, err)
	}
	cp, err := Open(target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	got := invRead(t, cp, at)
	if len(got) != 1 || !slices.Equal(got[0].Returners, []string{"a", "b"}) {
		t.Fatalf("copy lost returners: %+v", got)
	}
}

// R02 guard: every column of every table must be in compactTables. A migration that adds a
// column fails here until the column is added to the copier.
func TestCompactCopiesEveryColumn(t *testing.T) {
	s := openTest(t)
	rows, err := s.db.Query(`SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'main'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	live := map[string][]string{}
	for rows.Next() {
		var tbl, col string
		if err := rows.Scan(&tbl, &col); err != nil {
			t.Fatal(err)
		}
		live[tbl] = append(live[tbl], col)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	copied := map[string]bool{}
	for _, ct := range compactTables {
		copied[ct.name] = true
		var have []string
		for _, c := range strings.Split(ct.cols, ",") {
			have = append(have, strings.TrimSpace(c))
		}
		for _, c := range live[ct.name] {
			if !slices.Contains(have, c) {
				t.Errorf("table %q has column %q that Compact does not copy: add %q to the cols string of the %q entry in compactTables (internal/adapters/duckdb/maintenance.go). Compact verifies a digest over that same list, so adding it there also makes the copy check the column", ct.name, c, c, ct.name)
			}
		}
		for _, c := range have {
			if !slices.Contains(live[ct.name], c) {
				t.Errorf("compactTables lists %q.%q but the schema has no such column", ct.name, c)
			}
		}
	}
	for tbl := range live {
		if !copied[tbl] {
			t.Errorf("table %q is not in compactTables: Compact would drop its rows; add it with all its columns", tbl)
		}
	}
}

// R03: a successful event re-save clears pruned_at; a findings-only save leaves it.
func TestResaveClearsPrunedMarker(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	e := invEvent(invAt(), "a")
	run := "hunt-" + time.Now().UTC().Format("20060102T150405Z")
	if err := s.SaveEvents(ctx, run, seq(e)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneRunEvents(ctx, core.EventPruneRequest{RunIDs: []string{run}}); err != nil {
		t.Fatal(err)
	}
	marked := func() bool {
		var m bool
		if err := s.db.QueryRow(`SELECT pruned_at IS NOT NULL FROM runs WHERE run_id=?`, run).Scan(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if !marked() {
		t.Fatal("prune did not mark the run")
	}
	if err := s.SaveFindings(ctx, run, nil); err != nil {
		t.Fatal(err)
	}
	if !marked() {
		t.Fatal("a findings-only save cleared the marker")
	}
	if err := s.SaveEvents(ctx, run, seq()); err == nil || !marked() {
		t.Fatalf("an empty (refused) save must not clear the marker: err=%v", err)
	}
	if err := s.SaveEvents(ctx, run, seq(e)); err != nil {
		t.Fatal(err)
	}
	if marked() {
		t.Fatal("freshly saved evidence still marked pruned")
	}
}

// C03: Returners is a sorted set that contains the owner; an empty label is refused.
func TestSaveEventsNormalisesReturners(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := invAt()
	e := invEvent(at, "b", "c", "a", "c") // unsorted, duplicate, owner missing
	if err := s.SaveEvents(ctx, "r", seq(e)); err != nil {
		t.Fatal(err)
	}
	got := invRead(t, s, at)
	if len(got) != 1 || !slices.Equal(got[0].Returners, []string{"a", "b", "c"}) {
		t.Fatalf("got %+v, want returners [a b c]", got)
	}
	if e.Returners[0] != "c" || e.Returners[1] != "a" {
		t.Fatalf("the caller's slice was modified: %v", e.Returners)
	}
	err := s.SaveEvents(ctx, "r2", seq(invEvent(at, "a"), invEvent(at, "a", "a", "")))
	if err == nil || !strings.Contains(err.Error(), "event 1") || !strings.Contains(err.Error(), "r2") {
		t.Fatalf("want an error naming event 1 of run r2, got %v", err)
	}
}
