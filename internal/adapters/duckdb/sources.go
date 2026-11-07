package duckdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/iksnerd/json-bourne/internal/core"
)

var (
	_ core.SourceOverlapReader = (*Store)(nil)
	_ core.SourceRelabeler     = (*Store)(nil)
)

// SourceOverlaps implements core.SourceOverlapReader. Two source labels overlap when
// the same document, by (ts, kind, doc_sha256), is stored under both. That is the
// footprint of one set of documents saved under two names (a default kibana:<index>
// label and later an explicit name): the identity rule keys on the label, so a
// detector reading both counts each document twice.
//
// The common case is one label in the window, answered by a single scan of the window's
// narrow source column; only when two or more labels are present is the self-join on
// the distinct keys run. The query is fixed text with bound parameters. A document
// stored without a raw payload digests its label into doc_sha256, so it cannot match
// across labels and is not reported.
func (s *Store) SourceOverlaps(ctx context.Context, w core.Window, limit int) ([]core.SourceOverlap, error) {
	if !w.From.Before(w.To) {
		return nil, nil
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	var labels int
	if err := s.db.QueryRowContext(ctx, `
		SELECT count(DISTINCT source) FROM events
		WHERE ts >= CAST(? AS TIMESTAMPTZ) AND ts < CAST(? AS TIMESTAMPTZ)`, ts(w.From), ts(w.To)).Scan(&labels); err != nil {
		return nil, fmt.Errorf("count source labels: %w", err)
	}
	if labels < 2 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH d AS (
			SELECT DISTINCT ts, kind, doc_sha256, source FROM events
			WHERE ts >= CAST(? AS TIMESTAMPTZ) AND ts < CAST(? AS TIMESTAMPTZ))
		SELECT a.source, b.source, count(*) AS docs
		FROM d a JOIN d b USING (ts, kind, doc_sha256)
		WHERE a.source < b.source
		GROUP BY a.source, b.source
		ORDER BY docs DESC, a.source, b.source
		LIMIT ?`, ts(w.From), ts(w.To), limit)
	if err != nil {
		return nil, fmt.Errorf("find overlapping source labels: %w", err)
	}
	defer rows.Close()
	var out []core.SourceOverlap
	for rows.Next() {
		var o core.SourceOverlap
		if err := rows.Scan(&o.A, &o.B, &o.Docs); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// renameHook is a test seam: called before each write step ("drop", "relabel") of
// RenameSource so a test can fail the rename half-way and prove the transaction rolls
// everything back. Nil in production.
var renameHook func(step string) error

// dropCandidates selects the rows of the old label (?2) that a row under the new label
// (?1) already covers on the identity rule: same (ts, kind, doc_sha256) and an
// run holds no more copies of the document than the most any single run under the new
// label holds. Identical lines inside one run are real events and "the larger count
// wins" as Events reads it, so a run that holds more copies than that is kept whole:
// dropping some of its rows would renumber the rest and lose the extra copies.
const dropCandidates = `
	WITH newk AS (
		SELECT ts, kind, doc_sha256, max(c) AS c FROM (
			SELECT run_id, ts, kind, doc_sha256, count(*) AS c FROM events WHERE source = ? GROUP BY ALL)
		GROUP BY ALL),
	oldr AS (
		SELECT rowid AS rid, ts, kind, doc_sha256,
		       count(*) OVER (PARTITION BY run_id, ts, kind, doc_sha256) AS copies
		FROM events WHERE source = ?)
	SELECT o.rid FROM oldr o JOIN newk n USING (ts, kind, doc_sha256) WHERE o.copies <= n.c`

// RenameSource implements core.SourceRelabeler. Everything runs in one transaction on the
// events table, the only table that stores an event's source label (runs and findings
// are keyed by run id, which is never changed; reputation.source names a feed, a
// different thing). The counts are taken inside the transaction, so they describe
// exactly what the rename did.
//
// New already holding documents Old also holds is refused with core.ErrSourceOverlap
// unless req.Merge, in which case the colliding rows of Old are deleted first. Nothing
// is written when req.DryRun, and a dry run works on a read-only handle: the engine, not
// this code, is what stops a write there.
func (s *Store) RenameSource(ctx context.Context, req core.RenameSourceRequest) (core.RenameSourceResult, error) {
	res := core.RenameSourceResult{Old: req.Old, New: req.New}
	if req.Old == "" || req.New == "" {
		return res, errors.New("rename source: both labels are required")
	}
	if req.Old == req.New {
		return res, errors.New("rename source: the old and new labels are the same")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("rename source: begin: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	one := func(dst *int64, q string, args ...any) error {
		if err := tx.QueryRowContext(ctx, q, args...).Scan(dst); err != nil {
			return fmt.Errorf("rename source: count: %w", err)
		}
		return nil
	}
	if err := one(&res.Events, `SELECT count(*) FROM events WHERE source = ?`, req.Old); err != nil {
		return res, err
	}
	if err := one(&res.Runs, `SELECT count(DISTINCT run_id) FROM events WHERE source = ?`, req.Old); err != nil {
		return res, err
	}
	if err := one(&res.NewEvents, `SELECT count(*) FROM events WHERE source = ?`, req.New); err != nil {
		return res, err
	}
	if err := one(&res.NoRaw, `SELECT count(*) FROM events WHERE source = ? AND (raw IS NULL OR octet_length(raw) = 0)`, req.Old); err != nil {
		return res, err
	}
	if err := one(&res.Overlap, `
		SELECT count(*) FROM (
			SELECT ts, kind, doc_sha256 FROM events WHERE source = ?
			INTERSECT
			SELECT ts, kind, doc_sha256 FROM events WHERE source = ?)`, req.Old, req.New); err != nil {
		return res, err
	}
	// A label that owns no document may still be a returner of documents owned by another
	// label; it exists, and renaming it rewrites that membership.
	var returnerOnly int64
	if err := one(&returnerOnly, `SELECT count(*) FROM events WHERE source <> ? AND list_contains(returners, ?)`, req.Old, req.Old); err != nil {
		return res, err
	}
	if res.Events == 0 && returnerOnly == 0 {
		return res, fmt.Errorf("%w: %q", core.ErrNoSuchSource, req.Old)
	}
	if res.Overlap > 0 && !req.Merge {
		return res, fmt.Errorf("%w: %q and %q share %d document(s)", core.ErrSourceOverlap, req.Old, req.New, res.Overlap)
	}
	if res.Overlap > 0 {
		if err := one(&res.Dropped, `SELECT count(*) FROM (`+dropCandidates+`)`, req.New, req.Old); err != nil {
			return res, err
		}
	}
	res.Relabelled = res.Events - res.Dropped
	if req.DryRun {
		return res, nil
	}

	if res.Dropped > 0 {
		if renameHook != nil {
			if err := renameHook("drop"); err != nil {
				return res, err
			}
		}
		// The rows about to go may carry returners the surviving row does not. Fold them
		// into the survivors (with the new owner, which a survivor stored without a list
		// does not name) first; the relabel step below maps the old label to the new one.
		if _, err := tx.ExecContext(ctx, `
			UPDATE events SET returners = list_sort(list_distinct(list_concat(
				coalesce(events.returners, []::VARCHAR[]), [CAST(? AS VARCHAR)], x.carried)))
			FROM (
				SELECT ts, kind, doc_sha256, flatten(list(returners)) AS carried
				FROM events WHERE rowid IN (`+dropCandidates+`) AND returners IS NOT NULL
				GROUP BY ts, kind, doc_sha256) x
			WHERE events.source = ? AND events.ts = x.ts AND events.kind = x.kind AND events.doc_sha256 = x.doc_sha256`,
			req.New, req.New, req.Old, req.New); err != nil {
			return res, fmt.Errorf("rename source: keep membership of dropped duplicates: %w", err)
		}
		r, err := tx.ExecContext(ctx, `DELETE FROM events WHERE rowid IN (`+dropCandidates+`)`, req.New, req.Old)
		if err != nil {
			return res, fmt.Errorf("rename source: drop duplicates: %w", err)
		}
		if n, _ := r.RowsAffected(); n != res.Dropped {
			return res, fmt.Errorf("rename source: dropped %d rows but counted %d; nothing was changed", n, res.Dropped)
		}
	}
	if renameHook != nil {
		if err := renameHook("relabel"); err != nil {
			return res, err
		}
	}
	// Membership: map the old label to the new one in every returners list (also lists of
	// documents another label owns, and documents whose only link to the old label is that
	// list), keep it a sorted set, and make sure the list of a document being relabelled
	// names its new owner. Rows without a list stay without one.
	oldLit, newLit := quoteLit(req.Old), quoteLit(req.New)
	if _, err := tx.ExecContext(ctx, `
		UPDATE events SET returners = list_sort(list_distinct(list_concat(
			list_transform(returners, lambda r: CASE WHEN r = `+oldLit+` THEN `+newLit+` ELSE r END),
			CASE WHEN source = `+oldLit+` THEN [CAST(`+newLit+` AS VARCHAR)] ELSE []::VARCHAR[] END)))
		WHERE returners IS NOT NULL AND (source = `+oldLit+` OR list_contains(returners, `+oldLit+`))`); err != nil {
		return res, fmt.Errorf("rename source: relabel returners: %w", err)
	}
	r, err := tx.ExecContext(ctx, `UPDATE events SET source = ? WHERE source = ?`, req.New, req.Old)
	if err != nil {
		return res, fmt.Errorf("rename source: relabel: %w", err)
	}
	if n, _ := r.RowsAffected(); n != res.Relabelled {
		return res, fmt.Errorf("rename source: relabelled %d rows but counted %d; nothing was changed", n, res.Relabelled)
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("rename source: commit: %w", err)
	}
	res.Applied = true
	return res, nil
}
