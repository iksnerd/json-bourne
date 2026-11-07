package duckdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var (
	_ core.StoreUsageReader = (*Store)(nil)
	_ core.RunEventPruner   = (*Store)(nil)
	_ core.StoreCompactor   = (*Store)(nil)
)

// runRec is one row of runs.
type runRec struct {
	id      string
	created time.Time
	pruned  bool
}

func (s *Store) loadRuns(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]runRec, error) {
	rows, err := q.QueryContext(ctx, `SELECT run_id, created_at, pruned_at IS NOT NULL FROM runs`)
	if err != nil {
		return nil, fmt.Errorf("read run records: %w", err)
	}
	defer rows.Close()
	var out []runRec
	for rows.Next() {
		var r runRec
		if err := rows.Scan(&r.id, &r.created, &r.pruned); err != nil {
			return nil, err
		}
		r.created = r.created.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

type runAgg struct{ events, raw, fields, findings int64 }

// aggSQL sums per run id. octet_length of the raw column is its UNCOMPRESSED size.
const eventAggSQL = `
	SELECT run_id, count(*), CAST(coalesce(sum(octet_length(raw)), 0) AS BIGINT),
	       CAST(coalesce(sum(strlen(CAST(fields AS VARCHAR))), 0) AS BIGINT)
	FROM events %s GROUP BY run_id`

func scanEventAgg(rows *sql.Rows, into map[string]*runAgg) error {
	defer rows.Close()
	for rows.Next() {
		var id string
		var a runAgg
		if err := rows.Scan(&id, &a.events, &a.raw, &a.fields); err != nil {
			return err
		}
		x := into[id]
		if x == nil {
			x = &runAgg{}
			into[id] = x
		}
		x.events, x.raw, x.fields = a.events, a.raw, a.fields
	}
	return rows.Err()
}

// StoreUsage implements core.StoreUsageReader. The queries are fixed text with no
// parameters; run kinds are derived in Go from the whole run-id shape.
func (s *Store) StoreUsage(ctx context.Context) (core.StoreUsage, error) {
	u := core.StoreUsage{Path: s.path}
	st, err := s.Stats()
	if err != nil {
		return u, err
	}
	u.SchemaVersion, u.Runs, u.Events, u.Findings, u.Reputation = st.Version, st.Runs, st.Events, st.Findings, st.Reputation
	if fi, err := os.Stat(s.path); err == nil {
		u.FileBytes = fi.Size()
	}
	if u.UsedBytes, u.FreeBytes, err = s.blockUsage(ctx); err != nil {
		return u, err
	}
	if st.Version == 0 {
		return u, nil
	}
	runs, err := s.loadRuns(ctx, s.db)
	if err != nil {
		return u, err
	}
	aggs := map[string]*runAgg{}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(eventAggSQL, ""))
	if err != nil {
		return u, fmt.Errorf("measure events per run: %w", err)
	}
	if err := scanEventAgg(rows, aggs); err != nil {
		return u, err
	}

	type key struct {
		kind    core.RunKind
		watcher string
	}
	type hunt struct {
		pruned         bool
		oldest, newest time.Time
	}
	kinds := map[key]*core.KindUsage{}
	hunts := map[key]map[string]*hunt{}
	touch := func(runID string, created time.Time, pruned bool) {
		kind, w := core.ClassifyRun(runID)
		k := key{kind, w}
		ku := kinds[k]
		if ku == nil {
			ku = &core.KindUsage{Kind: kind, Watcher: w}
			kinds[k] = ku
			hunts[k] = map[string]*hunt{}
		}
		id := core.HuntID(runID)
		h := hunts[k][id]
		if h == nil {
			h = &hunt{}
			hunts[k][id] = h
		}
		h.pruned = h.pruned || pruned
		if !created.IsZero() {
			if h.oldest.IsZero() || created.Before(h.oldest) {
				h.oldest = created
			}
			if created.After(h.newest) {
				h.newest = created
			}
		}
	}
	known := map[string]bool{}
	for _, r := range runs {
		known[r.id] = true
		touch(r.id, r.created, r.pruned)
	}
	for id, a := range aggs {
		if !known[id] {
			touch(id, time.Time{}, false) // events with no run record: counted, undated
		}
		kind, w := core.ClassifyRun(id)
		ku := kinds[key{kind, w}]
		ku.Events += a.events
		ku.RawBytes += a.raw
		ku.FieldsBytes += a.fields
	}
	for k, ku := range kinds {
		for _, h := range hunts[k] {
			ku.Runs++
			if h.pruned {
				ku.PrunedRuns++
			}
			if !h.oldest.IsZero() && (ku.Oldest.IsZero() || h.oldest.Before(ku.Oldest)) {
				ku.Oldest = h.oldest
			}
			if h.newest.After(ku.Newest) {
				ku.Newest = h.newest
			}
		}
		u.Kinds = append(u.Kinds, *ku)
	}
	order := map[core.RunKind]int{}
	for i, k := range core.AllRunKinds {
		order[k] = i
	}
	sort.Slice(u.Kinds, func(i, j int) bool {
		a, b := u.Kinds[i], u.Kinds[j]
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		return a.Watcher < b.Watcher
	})

	lrows, err := s.db.QueryContext(ctx, `
		SELECT e.source, count(*), count(DISTINCT split_part(e.run_id, '/', 1)),
		       CAST(coalesce(sum(octet_length(e.raw)), 0) AS BIGINT),
		       CAST(coalesce(sum(strlen(CAST(e.fields AS VARCHAR))), 0) AS BIGINT),
		       min(r.created_at), max(r.created_at)
		FROM events e LEFT JOIN runs r ON r.run_id = e.run_id
		GROUP BY e.source ORDER BY 2 DESC, 1`)
	if err != nil {
		return u, fmt.Errorf("measure events per source label: %w", err)
	}
	defer lrows.Close()
	for lrows.Next() {
		var l core.LabelUsage
		var lo, hi sql.NullTime
		if err := lrows.Scan(&l.Label, &l.Events, &l.Runs, &l.RawBytes, &l.FieldsBytes, &lo, &hi); err != nil {
			return u, err
		}
		l.Oldest, l.Newest = nt(lo), nt(hi)
		u.Labels = append(u.Labels, l)
	}
	return u, lrows.Err()
}

// blockUsage reads the engine's own account of the file: blocks in use and blocks free.
func (s *Store) blockUsage(ctx context.Context) (used, free int64, err error) {
	var bs, total, usedB, freeB int64
	err = s.db.QueryRowContext(ctx, `
		SELECT CAST(block_size AS BIGINT), CAST(total_blocks AS BIGINT), CAST(used_blocks AS BIGINT), CAST(free_blocks AS BIGINT)
		FROM pragma_database_size() WHERE database_name = current_database()`).Scan(&bs, &total, &usedB, &freeB)
	if err != nil {
		return 0, 0, fmt.Errorf("read block usage: %w", err)
	}
	_ = total
	return usedB * bs, freeB * bs, nil
}

// pruneEventsHook is a test seam for PruneRunEvents: called with the transaction before each
// write step ("events", "mark", "findings", "runs") so a test can fail it, or change the
// data under it, and prove the transaction rolls everything back. Nil in production.
var pruneEventsHook func(tx *sql.Tx, step string) error

type huntInfo struct {
	id     string
	kind   core.RunKind
	newest time.Time
	runIDs []string
	pruned bool // every run record of the hunt is already marked
}

// PruneRunEvents implements core.RunEventPruner.
//
// Hunts are the groups of run ids that share the part before the first "/". A hunt's
// kind comes from the whole shape of its id (core.ClassifyRun), so hunt- never reaches
// hunt-until-, and only the requested kinds are looked at; watch and other ids are never
// selected. A hunt's age is the newest runs.created_at among its records, as stored.
// Within each kind the KeepLatest newest hunts are kept whatever their age (ranked over
// every hunt of the kind, pruned or not), then a hunt newer than Before is kept.
//
// By default the events of the selected hunts are deleted and their run records are
// stamped pruned_at; findings stay. With DropFindings the findings and run records go
// too. The reputation table is never touched. The plan is counted inside the
// transaction, the deletes' row counts are compared with it, and any difference rolls
// everything back.
func (s *Store) PruneRunEvents(ctx context.Context, req core.EventPruneRequest) (core.EventPruneResult, error) {
	res := core.EventPruneResult{DropFindings: req.DropFindings, Before: req.Before.UTC(), KeepLatest: req.KeepLatest}
	byRun := len(req.RunIDs) > 0
	want := map[core.RunKind]bool{}
	named := map[string]bool{}
	kindOrder := req.Kinds
	if byRun {
		if len(req.Kinds) > 0 || req.KeepLatest != 0 || !req.Before.IsZero() {
			return res, errors.New("prune: run ids cannot be combined with kinds, an age cutoff or keep-latest")
		}
		ids, err := core.ParseRunIDs(req.RunIDs)
		if err != nil {
			return res, err
		}
		res.ByRunID = true
		kindOrder = core.PrunableKinds
		for _, id := range ids {
			named[id] = true
			k, _ := core.ClassifyRun(id)
			want[k] = true
		}
	} else {
		if len(req.Kinds) == 0 {
			return res, errors.New("prune: no run kind named; refusing to match every run")
		}
		if req.KeepLatest < 0 {
			return res, errors.New("prune: keep-latest is negative")
		}
		if req.Before.IsZero() {
			return res, errors.New("prune: no age cutoff")
		}
		for _, k := range req.Kinds {
			ok := false
			for _, pk := range core.PrunableKinds {
				ok = ok || pk == k
			}
			if !ok {
				if k == core.KindWatch {
					return res, core.ErrWatchKind
				}
				return res, fmt.Errorf("prune: %q is not a prunable run kind", k)
			}
			want[k] = true
		}
	}
	if !req.DryRun && s.readOnly {
		return res, errors.New("prune: the store is open read-only")
	}
	if !req.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("prune: begin: %w", err)
	}
	defer tx.Rollback()

	runs, err := s.loadRuns(ctx, tx)
	if err != nil {
		return res, err
	}
	hunts := map[string]*huntInfo{}
	for _, r := range runs {
		kind, _ := core.ClassifyRun(r.id)
		if !want[kind] {
			continue
		}
		id := core.HuntID(r.id)
		if byRun && !named[id] {
			continue
		}
		h := hunts[id]
		if h == nil {
			h = &huntInfo{id: id, kind: kind, pruned: true}
			hunts[id] = h
		}
		h.runIDs = append(h.runIDs, r.id)
		h.pruned = h.pruned && r.pruned
		if r.created.After(h.newest) {
			h.newest = r.created
		}
	}

	if byRun {
		var missing []string
		for _, id := range req.RunIDs {
			if hunts[id] == nil {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			return core.EventPruneResult{}, fmt.Errorf("prune: no such run in the store: %s; nothing was changed", strings.Join(missing, ", "))
		}
	}

	// Measure every hunt of the wanted kinds (kept ones too, so the report can say what
	// is kept), through a scratch table of their run ids.
	if _, err := tx.ExecContext(ctx, `CREATE OR REPLACE TEMP TABLE prune_scope (run_id VARCHAR NOT NULL, sel BOOLEAN NOT NULL)`); err != nil {
		return res, fmt.Errorf("prune: scratch table: %w", err)
	}

	byKind := map[core.RunKind][]*huntInfo{}
	for _, h := range hunts {
		byKind[h.kind] = append(byKind[h.kind], h)
	}
	selected := map[string]bool{}
	var all []*huntInfo
	for _, k := range kindOrder {
		hs := byKind[k]
		sort.Slice(hs, func(i, j int) bool {
			if !hs[i].newest.Equal(hs[j].newest) {
				return hs[i].newest.After(hs[j].newest)
			}
			return hs[i].id > hs[j].id
		})
		for i, h := range hs {
			all = append(all, h)
			switch {
			case !byRun && i < req.KeepLatest:
				res.Runs = append(res.Runs, core.PruneRun{ID: h.id, Kind: k, Created: h.newest, Action: core.ActionKeepLatest})
			case !byRun && !h.newest.Before(req.Before):
				res.Runs = append(res.Runs, core.PruneRun{ID: h.id, Kind: k, Created: h.newest, Action: core.ActionKeepRecent})
			default:
				res.Runs = append(res.Runs, core.PruneRun{ID: h.id, Kind: k, Created: h.newest, Action: core.ActionPrune})
				selected[h.id] = true
			}
		}
	}
	for _, h := range all {
		for _, id := range h.runIDs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO prune_scope VALUES (?, ?)`, id, selected[h.id]); err != nil {
				return res, fmt.Errorf("prune: scratch table: %w", err)
			}
		}
	}

	aggs := map[string]*runAgg{}
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(eventAggSQL, `WHERE run_id IN (SELECT run_id FROM prune_scope)`))
	if err != nil {
		return res, fmt.Errorf("prune: measure events: %w", err)
	}
	if err := scanEventAgg(rows, aggs); err != nil {
		return res, err
	}
	frows, err := tx.QueryContext(ctx, `SELECT run_id, count(*) FROM findings WHERE run_id IN (SELECT run_id FROM prune_scope) GROUP BY run_id`)
	if err != nil {
		return res, fmt.Errorf("prune: measure findings: %w", err)
	}
	for frows.Next() {
		var id string
		var n int64
		if err := frows.Scan(&id, &n); err != nil {
			frows.Close()
			return res, err
		}
		if aggs[id] == nil {
			aggs[id] = &runAgg{}
		}
		aggs[id].findings = n
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return res, err
	}

	// Fold run-id aggregates into their hunts and total the selection.
	idx := map[string]*core.PruneRun{}
	for i := range res.Runs {
		idx[res.Runs[i].ID] = &res.Runs[i]
	}
	var markable int64 // run records that will be stamped (default mode)
	for _, h := range all {
		pr := idx[h.id]
		for _, id := range h.runIDs {
			if a := aggs[id]; a != nil {
				pr.Events += a.events
				pr.RawBytes += a.raw
				pr.FieldsBytes += a.fields
				pr.Findings += a.findings
			}
		}
		if pr.Action != core.ActionPrune {
			continue
		}
		if !req.DropFindings && pr.Events == 0 {
			// Nothing left to delete: the events went in an earlier prune.
			pr.Action = core.ActionAlreadyDone
			selected[h.id] = false
			continue
		}
		res.Plan.Runs++
		res.Plan.RunRecords += int64(len(h.runIDs))
		res.Plan.Events += pr.Events
		res.Plan.RawBytes += pr.RawBytes
		res.Plan.FieldsBytes += pr.FieldsBytes
		res.Plan.Findings += pr.Findings
	}
	if !req.DropFindings {
		// Hunts found to have nothing left to delete leave the selection.
		for _, h := range all {
			if idx[h.id].Action != core.ActionAlreadyDone {
				continue
			}
			for _, id := range h.runIDs {
				if _, err := tx.ExecContext(ctx, `UPDATE prune_scope SET sel = false WHERE run_id = ?`, id); err != nil {
					return res, err
				}
			}
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM runs WHERE pruned_at IS NULL AND run_id IN (SELECT run_id FROM prune_scope WHERE sel)`).Scan(&markable); err != nil {
			return res, fmt.Errorf("prune: count run records: %w", err)
		}
	}
	sort.Slice(res.Runs, func(i, j int) bool {
		if res.Runs[i].Kind != res.Runs[j].Kind {
			return res.Runs[i].Kind < res.Runs[j].Kind
		}
		if !res.Runs[i].Created.Equal(res.Runs[j].Created) {
			return res.Runs[i].Created.After(res.Runs[j].Created)
		}
		return res.Runs[i].ID > res.Runs[j].ID
	})
	if req.DryRun {
		return res, nil
	}

	sel := `run_id IN (SELECT run_id FROM prune_scope WHERE sel)`
	step := func(name, q string, want int64) error {
		if pruneEventsHook != nil {
			if err := pruneEventsHook(tx, name); err != nil {
				return err
			}
		}
		r, err := tx.ExecContext(ctx, q)
		if err != nil {
			return fmt.Errorf("prune: %s: %w", name, err)
		}
		n, err := r.RowsAffected()
		if err != nil {
			return fmt.Errorf("prune: %s: row count: %w", name, err)
		}
		if n != want {
			return fmt.Errorf("prune: %s changed %d rows but the plan counted %d; nothing was changed", name, n, want)
		}
		switch name {
		case "events":
			res.Deleted.Events = n
		case "mark":
			res.Marked = n
		case "findings":
			res.Deleted.Findings = n
		case "runs":
			res.Deleted.RunRecords = n
		}
		return nil
	}
	if err := step("events", `DELETE FROM events WHERE `+sel, res.Plan.Events); err != nil {
		return core.EventPruneResult{}, err
	}
	if req.DropFindings {
		if err := step("findings", `DELETE FROM findings WHERE `+sel, res.Plan.Findings); err != nil {
			return core.EventPruneResult{}, err
		}
		if err := step("runs", `DELETE FROM runs WHERE `+sel, res.Plan.RunRecords); err != nil {
			return core.EventPruneResult{}, err
		}
	} else if err := step("mark", `UPDATE runs SET pruned_at = now() WHERE pruned_at IS NULL AND `+sel, markable); err != nil {
		return core.EventPruneResult{}, err
	}
	res.Deleted.Runs = res.Plan.Runs
	res.Deleted.RawBytes, res.Deleted.FieldsBytes = res.Plan.RawBytes, res.Plan.FieldsBytes
	if _, err := tx.ExecContext(ctx, `DROP TABLE prune_scope`); err != nil {
		return core.EventPruneResult{}, fmt.Errorf("prune: drop scratch table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return core.EventPruneResult{}, fmt.Errorf("prune: commit: %w", err)
	}
	res.Applied = true
	return res, nil
}

// compactTables are the tables the copy carries, in an order that puts the small ones
// first. The schema of the copy is built by this package's own migrations, so it is the
// schema this build writes, not a guess from the source.
var compactTables = []struct {
	name string
	cols string
}{
	{"schema_migrations", "version, applied_at"},
	{"runs", "run_id, created_at, pruned_at"},
	{"findings", "run_id, seq, detector, tag, severity, window_from, window_to, baseline_from, baseline_to, summary, detail"},
	{"reputation", "indicator, verdict, observed_at, source"},
	{"events", "run_id, seq, ts, source, kind, fields, raw, doc_sha256, doc_ident"},
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func quoteLit(s string) string   { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

func (s *Store) tableCounts(ctx context.Context, catalog string) ([]core.TableCount, error) {
	var out []core.TableCount
	for _, t := range compactTables {
		var n int64
		q := `SELECT count(*) FROM ` + quoteIdent(catalog) + `.main.` + t.name
		if err := s.db.QueryRowContext(ctx, q).Scan(&n); err != nil {
			return nil, fmt.Errorf("count %s: %w", t.name, err)
		}
		out = append(out, core.TableCount{Table: t.name, Rows: n})
	}
	return out, nil
}

// compactHook is a test seam called between the copy and its verification. Nil in production.
var compactHook func(step string) error

// Compact implements core.StoreCompactor. DuckDB does not give deleted space back, so
// the copy is built by attaching a NEW file next to the source, creating the schema in
// it from this package's migrations (so schema_migrations carries over exactly) and
// copying each table with INSERT ... SELECT. Nothing is written to the source, which
// the caller holds read-write (and therefore exclusively) for an apply.
//
// The copy is written inside a private directory next to Target, set to mode 0600,
// verified (row counts equal per table, a sum of raw document sizes equal, schema
// version, a read-only open), and only then linked to Target, which must not exist at
// that moment (os.Link fails rather than overwrite). A copy that fails verification is
// removed and never appears at Target.
func (s *Store) Compact(ctx context.Context, req core.CompactRequest) (core.CompactResult, error) {
	res := core.CompactResult{Target: req.Target}
	if req.Target == "" {
		return res, errors.New("compact: no target")
	}
	v, err := s.SchemaVersion()
	if err != nil {
		return res, err
	}
	if v != Version {
		return res, fmt.Errorf("compact: the store is schema %d and this build is %d: run a command that migrates it (a hunt, or `jb db prune --apply`) first", v, Version)
	}
	res.SchemaVersion = v
	if fi, err := os.Stat(s.path); err == nil {
		res.SourceBytes = fi.Size()
	}
	if res.UsedBytes, res.FreeBytes, err = s.blockUsage(ctx); err != nil {
		return res, err
	}
	res.EstimateBytes = res.UsedBytes
	if res.EstimateBytes == 0 {
		res.EstimateBytes = res.SourceBytes // nothing checkpointed yet: the file is all there is to go on
	}
	var src string
	if err := s.db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&src); err != nil {
		return res, err
	}
	if res.Source, err = s.tableCounts(ctx, src); err != nil {
		return res, err
	}
	if req.DryRun {
		return res, nil
	}
	if s.readOnly {
		return res, errors.New("compact: the store is open read-only; an apply holds it read-write so no other process can write while it is copied")
	}
	if _, err := os.Lstat(req.Target); err == nil {
		return res, fmt.Errorf("compact: %s already exists; refusing to overwrite it", req.Target)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(req.Target)
	work, err := os.MkdirTemp(dir, ".jb-compact-")
	if err != nil {
		return res, fmt.Errorf("compact: private work directory: %w", err)
	}
	defer os.RemoveAll(work)
	if err := os.Chmod(work, 0o700); err != nil {
		return res, err
	}
	tmp := filepath.Join(work, "copy.duckdb")
	if err := s.copyInto(ctx, src, tmp); err != nil {
		return res, err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return res, err
	}
	if compactHook != nil {
		if err := compactHook("verify"); err != nil {
			return res, err
		}
	}
	// Verify through a fresh read-only open of the file as written.
	cp, err := OpenContext(ctx, tmp, true, OpenOptions{LockWait: NoLockWait})
	if err != nil {
		return res, fmt.Errorf("compact: the copy does not open read-only: %w", err)
	}
	cv, verr := cp.SchemaVersion()
	var ccounts []core.TableCount
	if verr == nil {
		var cat string
		if verr = cp.db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&cat); verr == nil {
			ccounts, verr = cp.tableCounts(ctx, cat)
		}
	}
	cp.Close()
	if verr != nil {
		return res, fmt.Errorf("compact: verify the copy: %w", verr)
	}
	if cv != v {
		return res, fmt.Errorf("compact: the copy is schema %d, the source %d; the copy was discarded", cv, v)
	}
	res.Copy = ccounts
	for i := range res.Source {
		if res.Source[i] != ccounts[i] {
			return res, fmt.Errorf("compact: table %s has %d rows in the copy and %d in the source; the copy was discarded", res.Source[i].Table, ccounts[i].Rows, res.Source[i].Rows)
		}
	}
	if err := os.Link(tmp, req.Target); err != nil {
		return res, fmt.Errorf("compact: place the copy at %s (it must not exist): %w", req.Target, err)
	}
	if fi, err := os.Stat(req.Target); err == nil {
		res.TargetBytes = fi.Size()
	}
	res.Applied = true
	return res, nil
}

// copyInto builds the compacted file at path. It leaves the connection's default
// database as it found it.
func (s *Store) copyInto(ctx context.Context, src, path string) (err error) {
	cpName := "jb_compact_copy"
	if src == cpName {
		cpName += "_2"
	}
	if _, err := s.db.ExecContext(ctx, `ATTACH `+quoteLit(path)+` AS `+quoteIdent(cpName)); err != nil {
		return fmt.Errorf("compact: create the copy: %w", err)
	}
	attached := true
	defer func() {
		_, _ = s.db.ExecContext(context.WithoutCancel(ctx), `USE `+quoteIdent(src))
		if attached {
			if _, derr := s.db.ExecContext(context.WithoutCancel(ctx), `DETACH `+quoteIdent(cpName)); derr != nil && err == nil {
				err = fmt.Errorf("compact: close the copy: %w", derr)
			}
		}
	}()
	if _, err := s.db.ExecContext(ctx, `USE `+quoteIdent(cpName)); err != nil {
		return fmt.Errorf("compact: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)`); err != nil {
		return fmt.Errorf("compact: create schema_migrations: %w", err)
	}
	for _, m := range migrations {
		if _, err := s.db.ExecContext(ctx, m.SQL); err != nil {
			return fmt.Errorf("compact: apply migration %s to the copy: %w", m.Name, err)
		}
	}
	for _, t := range compactTables {
		q := `INSERT INTO ` + quoteIdent(cpName) + `.main.` + t.name + ` (` + t.cols + `) SELECT ` + t.cols +
			` FROM ` + quoteIdent(src) + `.main.` + t.name
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("compact: copy %s: %w", t.name, err)
		}
	}
	// Row counts and the uncompressed raw size must agree before the copy is closed.
	var a, b int64
	for _, c := range []string{src, cpName} {
		dst := &a
		if c == cpName {
			dst = &b
		}
		if err := s.db.QueryRowContext(ctx, `SELECT CAST(coalesce(sum(octet_length(raw)), 0) AS BIGINT) FROM `+quoteIdent(c)+`.main.events`).Scan(dst); err != nil {
			return fmt.Errorf("compact: measure raw documents: %w", err)
		}
	}
	if a != b {
		return fmt.Errorf("compact: the copy holds %d raw bytes and the source %d; the copy was discarded", b, a)
	}
	if _, err := s.db.ExecContext(ctx, `USE `+quoteIdent(src)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DETACH `+quoteIdent(cpName)); err != nil {
		return fmt.Errorf("compact: close the copy: %w", err)
	}
	attached = false
	return nil
}
