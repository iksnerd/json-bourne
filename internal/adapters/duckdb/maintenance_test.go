package duckdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	h1 = "hunt-20261001T000000Z"
	h2 = "hunt-20261002T000000Z"
	h3 = "hunt-20261003T000000Z"
	hu = "hunt-until-20261001T000000Z-w86400s"
	a1 = "activity-20261001T000000Z"
	a2 = "activity-20261002T000000Z"
	w1 = "watch-20261001T000000Z"
)

func hoursAgo(n int) time.Duration { return time.Duration(n) * time.Hour }

func req(kinds ...core.RunKind) core.EventPruneRequest {
	return core.EventPruneRequest{Kinds: kinds, Before: pruneNow.Add(-48 * time.Hour), KeepLatest: 1}
}

// seedMixed stores hunts of several kinds, newest last, all but the newest of each kind old.
func seedMixed(t *testing.T, s *Store) {
	t.Helper()
	seedHunt(t, s, h1, 4, hoursAgo(300))
	seedHunt(t, s, h2, 3, hoursAgo(200))
	seedHunt(t, s, h3, 2, hoursAgo(1))
	seedHunt(t, s, hu, 5, hoursAgo(400))
	seedHunt(t, s, a1, 6, hoursAgo(300))
	seedHunt(t, s, a2, 7, hoursAgo(250))
	seedHunt(t, s, w1, 8, hoursAgo(500))
}

func events(t *testing.T, s *Store, id string) int64 {
	return count(t, s, `SELECT count(*) FROM events WHERE run_id = ? OR starts_with(run_id, ?)`, id, id+"/")
}

func fileHash(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func TestPruneDryRunChangesNothing(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	path := s.Path()
	s.Close()
	before := fileHash(t, path)
	ro, err := Open(path, true) // the engine refuses writes on this handle
	if err != nil {
		t.Fatal(err)
	}
	r := req(core.KindHunt, core.KindActivity)
	r.DryRun = true
	res, err := ro.PruneRunEvents(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || res.Plan.Events != 4+3+6 || res.Plan.Runs != 3 {
		t.Fatalf("plan = %+v applied=%v", res.Plan, res.Applied)
	}
	if res.Deleted != (core.PruneTotals{}) {
		t.Errorf("a dry run reports deletions: %+v", res.Deleted)
	}
	ro.Close()
	if fileHash(t, path) != before {
		t.Error("the file changed under a dry run")
	}
	// A dry run asked of a read-write handle must not write either.
	rw, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	if _, err := rw.PruneRunEvents(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := events(t, rw, h1) + events(t, rw, h2) + events(t, rw, a1); got != 13 {
		t.Errorf("dry run on a writable handle deleted events: %d left of 13", got)
	}
}

func TestPruneRefusesWatchAndOthers(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	for _, k := range []core.RunKind{core.KindWatch, core.KindOther, "all", ""} {
		_, err := s.PruneRunEvents(context.Background(), core.EventPruneRequest{Kinds: []core.RunKind{k}, Before: pruneNow})
		if err == nil {
			t.Errorf("kind %q accepted", k)
		}
	}
	if _, err := s.PruneRunEvents(context.Background(), core.EventPruneRequest{Kinds: []core.RunKind{core.KindWatch}, Before: pruneNow}); !errors.Is(err, core.ErrWatchKind) {
		t.Errorf("watch: %v", err)
	}
	if _, err := s.PruneRunEvents(context.Background(), core.EventPruneRequest{Before: pruneNow}); err == nil {
		t.Error("no kinds accepted")
	}
	if events(t, s, w1) != 8 {
		t.Error("watch events touched")
	}
}

func TestPruneKeepLatestIsPerKind(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	// Both kinds hold only old hunts except hunt h3; the newest activity (a2) is old
	// but is the newest of its kind and must stay.
	r := req(core.KindHunt, core.KindActivity)
	res, err := s.PruneRunEvents(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatal("not applied")
	}
	for id, want := range map[string]int64{h1: 0, h2: 0, h3: 2, a1: 0, a2: 7, hu: 5, w1: 8} {
		if got := events(t, s, id); got != want {
			t.Errorf("events of %s = %d, want %d", id, got, want)
		}
	}
	actions := map[string]string{}
	for _, pr := range res.Runs {
		actions[pr.ID] = pr.Action
	}
	if actions[a2] != core.ActionKeepLatest || actions[h3] != core.ActionKeepLatest || actions[h1] != core.ActionPrune {
		t.Errorf("actions = %v", actions)
	}
	// keep-latest 0 prunes the newest too (when old enough).
	r.KeepLatest = 0
	if _, err := s.PruneRunEvents(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if events(t, s, a2) != 0 || events(t, s, h3) != 2 {
		t.Errorf("keep-latest 0: a2=%d (want 0), h3=%d (want 2: it is newer than the cutoff)", events(t, s, a2), events(t, s, h3))
	}
	// A larger keep-latest keeps more.
	s2 := openTest(t)
	seedMixed(t, s2)
	r.KeepLatest = 2
	if _, err := s2.PruneRunEvents(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if events(t, s2, h2) != 3 || events(t, s2, h1) != 0 || events(t, s2, a1) != 6 {
		t.Errorf("keep-latest 2: h2=%d a1=%d h1=%d", events(t, s2, h2), events(t, s2, a1), events(t, s2, h1))
	}
}

func TestPruneKeepsFindingsAndMarksPruned(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	res, err := s.PruneRunEvents(context.Background(), req(core.KindHunt))
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted.Events != 7 || res.Marked != 4 || res.Deleted.Findings != 0 || res.Deleted.RunRecords != 0 {
		t.Fatalf("result = %+v", res)
	}
	if got := count(t, s, `SELECT count(*) FROM findings WHERE run_id IN (?, ?)`, h1, h2); got != 2 {
		t.Errorf("findings of pruned hunts = %d, want 2", got)
	}
	// h1, h1/src, h2, h2/src are marked; nothing else is.
	if got := count(t, s, `SELECT count(*) FROM runs WHERE pruned_at IS NOT NULL`); got != 4 {
		t.Errorf("marked records = %d, want 4", got)
	}
	if got := count(t, s, `SELECT count(*) FROM runs WHERE pruned_at IS NOT NULL AND starts_with(run_id, ?)`, h3); got != 0 {
		t.Error("the kept hunt was marked")
	}
	u, err := s.StoreUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range u.Kinds {
		if k.Kind == core.KindHunt && (k.Runs != 3 || k.PrunedRuns != 2) {
			t.Errorf("usage says %d runs, %d pruned; want 3, 2", k.Runs, k.PrunedRuns)
		}
	}
	// A second prune finds nothing left to delete.
	res, err = s.PruneRunEvents(context.Background(), req(core.KindHunt))
	if err != nil {
		t.Fatal(err)
	}
	if res.Plan.Runs != 0 || res.Plan.Events != 0 || res.Marked != 0 {
		t.Errorf("second prune: %+v", res)
	}
	var done int
	for _, pr := range res.Runs {
		if pr.Action == core.ActionAlreadyDone {
			done++
		}
	}
	if done != 2 {
		t.Errorf("already-pruned hunts reported = %d, want 2", done)
	}
}

func TestPruneDropFindings(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	res, err := s.PruneRunEvents(context.Background(), core.EventPruneRequest{
		Kinds: []core.RunKind{core.KindHunt}, Before: pruneNow.Add(-48 * time.Hour), KeepLatest: 1, DropFindings: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted.Events != 7 || res.Deleted.Findings != 2 || res.Deleted.RunRecords != 4 {
		t.Fatalf("deleted = %+v", res.Deleted)
	}
	if got := count(t, s, `SELECT count(*) FROM runs WHERE run_id IN (?, ?, ?, ?)`, h1, h1+"/src", h2, h2+"/src"); got != 0 {
		t.Errorf("run records of dropped hunts left = %d", got)
	}
	if got := count(t, s, `SELECT count(*) FROM runs WHERE starts_with(run_id, ?) OR starts_with(run_id, ?)`, h3, hu); got != 4 {
		t.Errorf("run records of kept hunts = %d, want 4", got)
	}
	if count(t, s, `SELECT count(*) FROM findings WHERE run_id IN (?, ?)`, h1, h2) != 0 {
		t.Error("findings of dropped hunts remain")
	}
	if count(t, s, `SELECT count(*) FROM findings WHERE run_id = ?`, h3) != 1 {
		t.Error("the kept hunt lost its findings")
	}
}

func TestPruneDelimiterSafetyHuntVsHuntUntil(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	// hunt only: the until replay (older than anything) must survive.
	if _, err := s.PruneRunEvents(context.Background(), req(core.KindHunt)); err != nil {
		t.Fatal(err)
	}
	if events(t, s, hu) != 5 {
		t.Fatal("kind hunt reached a hunt-until run")
	}
	// hunt-until only: the live hunts are not touched and the until replay, alone of its
	// kind, is the newest and kept; with keep-latest 0 it goes.
	s2 := openTest(t)
	seedMixed(t, s2)
	r := req(core.KindHuntUntil)
	r.KeepLatest = 0
	if _, err := s2.PruneRunEvents(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if events(t, s2, hu) != 0 || events(t, s2, h1) != 4 || events(t, s2, h2) != 3 {
		t.Errorf("hunt-until prune: hu=%d h1=%d h2=%d", events(t, s2, hu), events(t, s2, h1), events(t, s2, h2))
	}
	// Lookalike ids are never matched by any kind.
	s3 := openTest(t)
	for _, id := range []string{"hunt-ancient", "hunt-20261001T000000Z-extra", "hunt-until-20261001T000000Z", "watchdog-x"} {
		seedHunt(t, s3, id, 2, hoursAgo(900))
	}
	r = req(core.KindHunt, core.KindHuntUntil, core.KindActivity)
	r.KeepLatest = 0
	res, err := s3.PruneRunEvents(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Runs) != 0 || res.Plan.Events != 0 {
		t.Errorf("lookalikes matched: %+v", res.Runs)
	}
}

func TestPruneAgeIsStoredCreatedAtNotTheClock(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, h1, 2, hoursAgo(10))
	seedHunt(t, s, h2, 2, hoursAgo(10))
	seedHunt(t, s, h3, 2, hoursAgo(1))
	// The cutoff is what the caller computed; the row age is what is stored. Whatever
	// time.Now() is, a hunt created 10 hours before pruneNow is older than a 5 hour cutoff
	// and not older than a 20 hour one.
	r := core.EventPruneRequest{Kinds: []core.RunKind{core.KindHunt}, Before: pruneNow.Add(-20 * time.Hour), DryRun: true}
	res, _ := s.PruneRunEvents(context.Background(), r)
	if res.Plan.Runs != 0 {
		t.Errorf("20h cutoff selected %d", res.Plan.Runs)
	}
	r.Before = pruneNow.Add(-5 * time.Hour)
	res, _ = s.PruneRunEvents(context.Background(), r)
	if res.Plan.Runs != 2 { // h1 and h2 are 10h old; h3 is the kept newest
		t.Errorf("5h cutoff selected %d, want 2 (h3 is kept as the newest)", res.Plan.Runs)
	}
	// A hunt's age is its newest record: one fresh record keeps the whole hunt.
	if _, err := s.db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = ?`, ts(pruneNow.Add(-time.Hour)), h1+"/src"); err != nil {
		t.Fatal(err)
	}
	res, _ = s.PruneRunEvents(context.Background(), r)
	if res.Plan.Runs != 1 {
		t.Errorf("a hunt with a fresh record was selected: %d", res.Plan.Runs)
	}
}

func TestPruneRollsBackOnFailureAndOnPlanMismatch(t *testing.T) {
	t.Cleanup(func() { pruneEventsHook = nil })
	for name, hook := range map[string]func(tx *sql.Tx, step string) error{
		"failure before marking": func(tx *sql.Tx, step string) error {
			if step == "mark" {
				return errors.New("boom")
			}
			return nil
		},
		"plan mismatch": func(tx *sql.Tx, step string) error {
			if step == "events" { // remove rows the plan counted, behind its back
				_, err := tx.Exec(`DELETE FROM events WHERE run_id = ?`, h1+"/src")
				return err
			}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := openTest(t)
			seedMixed(t, s)
			pruneEventsHook = hook
			res, err := s.PruneRunEvents(context.Background(), req(core.KindHunt, core.KindActivity))
			pruneEventsHook = nil
			if err == nil || res.Applied {
				t.Fatalf("err = %v, applied = %v", err, res.Applied)
			}
			if name == "plan mismatch" && !strings.Contains(err.Error(), "plan counted") {
				t.Errorf("error does not say the plan differed: %v", err)
			}
			for id, want := range map[string]int64{h1: 4, h2: 3, h3: 2, a1: 6, a2: 7} {
				if got := events(t, s, id); got != want {
					t.Errorf("events of %s = %d, want %d (rolled back)", id, got, want)
				}
			}
			if got := count(t, s, `SELECT count(*) FROM runs WHERE pruned_at IS NOT NULL`); got != 0 {
				t.Errorf("%d records marked after a rollback", got)
			}
		})
	}
}

func TestPruneNeverTouchesReputation(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	if err := s.AppendReputation(context.Background(), []core.Reputation{{Indicator: "192.0.2.1", Verdict: "benign", Observed: pruneNow, Source: "feed.example.com"}}); err != nil {
		t.Fatal(err)
	}
	r := req(core.KindHunt, core.KindActivity)
	r.DropFindings, r.KeepLatest = true, 0
	if _, err := s.PruneRunEvents(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := count(t, s, `SELECT count(*) FROM reputation`); got != 1 {
		t.Errorf("reputation rows = %d", got)
	}
}

func TestStoreUsageEqualsTheData(t *testing.T) {
	s := openTest(t)
	seedMixed(t, s)
	if _, err := s.db.Exec(`CHECKPOINT`); err != nil {
		t.Fatal(err)
	}
	u, err := s.StoreUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[core.RunKind][2]int64{core.KindHunt: {3, 9}, core.KindHuntUntil: {1, 5}, core.KindActivity: {2, 13}, core.KindWatch: {1, 8}}
	var events, raw int64
	for _, k := range u.Kinds {
		events += k.Events
		raw += k.RawBytes
		if w, ok := want[k.Kind]; !ok || k.Runs != w[0] || k.Events != w[1] {
			t.Errorf("kind %s: runs %d events %d; want %v", k.Kind, k.Runs, k.Events, w)
		}
		if k.Events > 0 && (k.RawBytes <= 0 || k.FieldsBytes <= 0 || k.Oldest.IsZero() || k.Newest.Before(k.Oldest)) {
			t.Errorf("kind %s: bytes/time not filled: %+v", k.Kind, k)
		}
	}
	var sumRaw int64
	if err := s.db.QueryRow(`SELECT CAST(sum(octet_length(raw)) AS BIGINT) FROM events`).Scan(&sumRaw); err != nil {
		t.Fatal(err)
	}
	if events != 4+3+2+5+6+7+8 || u.Events != events || raw != sumRaw {
		t.Errorf("events %d (store %d), raw %d (want %d)", events, u.Events, raw, sumRaw)
	}
	if len(u.Labels) != 1 || u.Labels[0].Label != "example.com" || u.Labels[0].Events != events || u.Labels[0].RawBytes != sumRaw || u.Labels[0].Runs != 7 {
		t.Errorf("labels = %+v", u.Labels)
	}
	if u.FileBytes <= 0 || u.UsedBytes <= 0 {
		t.Errorf("file sizes not read: %+v", u)
	}
	if u.Runs != 14 || u.Findings != 7 {
		t.Errorf("runs %d findings %d", u.Runs, u.Findings)
	}
}

func TestStoreUsageSplitsWatchersAndOther(t *testing.T) {
	s := openTest(t)
	seedHunt(t, s, "watch-20261001T000000Z", 1, hoursAgo(5))
	seedHunt(t, s, "watch-a-20261001T000000Z", 2, hoursAgo(5))
	seedHunt(t, s, "watch-ab-20261001T000000Z", 3, hoursAgo(5))
	seedHunt(t, s, "scratch", 4, hoursAgo(5))
	u, err := s.StoreUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, k := range u.Kinds {
		got[string(k.Kind)+":"+k.Watcher] = k.Events
	}
	want := map[string]int64{"watch:": 1, "watch:a": 2, "watch:ab": 3, "other:": 4}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

func TestUsageAndPruneWorkOnAnEmptyStore(t *testing.T) {
	s := openTest(t)
	u, err := s.StoreUsage(context.Background())
	if err != nil || len(u.Kinds) != 0 || u.Events != 0 {
		t.Fatalf("%+v %v", u, err)
	}
	r := req(core.KindHunt)
	r.DryRun = true
	if res, err := s.PruneRunEvents(context.Background(), r); err != nil || res.Plan.Runs != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

// ---- compact ----

func tableDump(t *testing.T, s *Store) string {
	t.Helper()
	var b strings.Builder
	for _, q := range []string{
		`SELECT run_id||'|'||CAST(created_at AS VARCHAR)||'|'||coalesce(CAST(pruned_at AS VARCHAR),'-') FROM runs ORDER BY 1`,
		`SELECT run_id||'|'||seq||'|'||CAST(ts AS VARCHAR)||'|'||source||'|'||kind||'|'||doc_sha256||'|'||coalesce(CAST(fields AS VARCHAR),'')||'|'||coalesce(CAST(raw AS VARCHAR),'') FROM events ORDER BY 1`,
		`SELECT run_id||'|'||seq||'|'||tag||'|'||summary FROM findings ORDER BY 1`,
		`SELECT indicator||'|'||verdict||'|'||CAST(observed_at AS VARCHAR) FROM reputation ORDER BY 1`,
		`SELECT CAST(version AS VARCHAR) FROM schema_migrations ORDER BY 1`,
	} {
		rows, err := s.db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var l string
			rows.Scan(&l)
			b.WriteString(l + "\n")
		}
		rows.Close()
		b.WriteString("--\n")
	}
	return b.String()
}

func seedCompact(t *testing.T) (*Store, string) {
	s := openTest(t)
	seedMixed(t, s)
	if err := s.AppendReputation(context.Background(), []core.Reputation{{Indicator: "192.0.2.1", Verdict: "benign", Observed: pruneNow, Source: "feed.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneRunEvents(context.Background(), req(core.KindHunt)); err != nil { // leaves free space and a pruned_at
		t.Fatal(err)
	}
	return s, filepath.Join(filepath.Dir(s.Path()), "copy.duckdb")
}

func TestCompactCopyIsVerifiedEqualAndOriginalUntouched(t *testing.T) {
	s, target := seedCompact(t)
	want := tableDump(t, s)
	src := s.Path()
	s.Close()
	before := fileHash(t, src)
	rw, err := Open(src, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rw.Compact(context.Background(), core.CompactRequest{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	rw.Close()
	if !res.Applied || res.TargetBytes <= 0 || res.SchemaVersion != Version {
		t.Fatalf("%+v", res)
	}
	if len(res.Source) != 5 || len(res.Copy) != 5 {
		t.Fatalf("counts: %+v %+v", res.Source, res.Copy)
	}
	for i := range res.Source {
		if res.Source[i] != res.Copy[i] {
			t.Errorf("table %s: %d vs %d", res.Source[i].Table, res.Source[i].Rows, res.Copy[i].Rows)
		}
	}
	if fileHash(t, src) != before {
		t.Error("the original file changed")
	}
	fi, err := os.Stat(target)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("target mode = %v, %v", fi.Mode(), err)
	}
	cp, err := Open(target, true)
	if err != nil {
		t.Fatalf("copy does not open read-only: %v", err)
	}
	defer cp.Close()
	if v, _ := cp.SchemaVersion(); v != Version {
		t.Errorf("copy schema = %d", v)
	}
	if got := tableDump(t, cp); got != want {
		t.Error("the copy's contents differ from the source")
	}
	if _, err := cp.Stats(); err != nil {
		t.Error(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".jb-compact-") || strings.HasSuffix(e.Name(), ".wal") && strings.HasPrefix(e.Name(), "copy") {
			t.Errorf("leftover %s", e.Name())
		}
	}
	// The copy is a writable store of the same schema: the primary key came across.
	cp.Close()
	w, err := Open(target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.db.Exec(`INSERT INTO runs (run_id, created_at) VALUES (?, now())`, h3); err == nil {
		t.Error("the copy lost the runs primary key")
	}
}

func TestCompactRefusesToOverwriteAndDryRunWritesNothing(t *testing.T) {
	s, target := seedCompact(t)
	if err := os.WriteFile(target, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Compact(context.Background(), core.CompactRequest{Target: target}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "precious" {
		t.Error("the existing file was changed")
	}
	os.Remove(target)
	if _, err := s.db.Exec(`CHECKPOINT`); err != nil {
		t.Fatal(err)
	}
	res, err := s.Compact(context.Background(), core.CompactRequest{Target: target, DryRun: true})
	if err != nil || res.Applied || res.SourceBytes <= 0 || res.EstimateBytes <= 0 || len(res.Source) != 5 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("a dry run created the target")
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	if len(entries) != 1 { // only the store (and no work directory)
		for _, e := range entries {
			t.Logf("entry %s", e.Name())
		}
	}
}

func TestCompactDiscardsACopyThatFailsVerification(t *testing.T) {
	t.Cleanup(func() { compactHook = nil })
	s, target := seedCompact(t)
	compactHook = func(string) error { return errors.New("simulated verification failure") }
	if _, err := s.Compact(context.Background(), core.CompactRequest{Target: target}); err == nil {
		t.Fatal("no error")
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("a failed copy appeared at the target")
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".jb-compact-") {
			t.Errorf("work directory left behind: %s", e.Name())
		}
	}
}

func TestCompactNeedsAReadWriteHandleToApply(t *testing.T) {
	s, target := seedCompact(t)
	path := s.Path()
	s.Close()
	ro, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := ro.Compact(context.Background(), core.CompactRequest{Target: target}); err == nil {
		t.Error("apply on a read-only handle")
	}
	if res, err := ro.Compact(context.Background(), core.CompactRequest{Target: target, DryRun: true}); err != nil || res.Applied {
		t.Errorf("dry run on read-only: %+v %v", res, err)
	}
}
