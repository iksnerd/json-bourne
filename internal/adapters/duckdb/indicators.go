package duckdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
)

// LatestRunIndicators returns the distinct non-empty string values of the named event
// fields in the most recent hunt, most frequent first (ties by value), at most limit.
//
// A hunt stores one run per source, named "<hunt>/<source>". "Most recent" is the run
// with the latest created_at, and the hunt is everything before its first "/", so the
// answer covers every source of that hunt and no other hunt. It is an error when the
// store holds no run, or the hunt holds no value in those fields: an empty list would
// read as "nothing to look up", which is not what an empty store means.
func (s *Store) LatestRunIndicators(ctx context.Context, fields []string, limit int) (string, []string, error) {
	if len(fields) == 0 || limit <= 0 {
		return "", nil, errors.New("indicator fields and a positive limit are required")
	}
	var latest string
	err := s.db.QueryRowContext(ctx,
		`SELECT run_id FROM runs ORDER BY created_at DESC NULLS LAST, run_id DESC LIMIT 1`).Scan(&latest)
	if err != nil {
		return "", nil, fmt.Errorf("find the latest run: %w (is the store empty?)", err)
	}
	hunt, _, _ := strings.Cut(latest, "/")

	paths := make([]any, 0, len(fields))
	for _, f := range fields {
		if f == "" || strings.ContainsAny(f, `"\`) {
			return "", nil, fmt.Errorf("invalid indicator field %q", f)
		}
		paths = append(paths, `$."`+f+`"`)
	}
	var union []string
	for range paths {
		union = append(union, `SELECT json_extract_string(fields, ?) AS v FROM events
			WHERE run_id = ? OR starts_with(run_id, ?)`)
	}
	args := make([]any, 0, 3*len(paths)+1)
	for _, p := range paths {
		args = append(args, p, hunt, hunt+"/")
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT v FROM (`+strings.Join(union, " UNION ALL ")+`)
		WHERE v IS NOT NULL AND v <> ''
		GROUP BY v ORDER BY count(*) DESC, v LIMIT ?`, args...)
	if err != nil {
		return "", nil, fmt.Errorf("read indicators of run %s: %w", hunt, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return "", nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	if len(out) == 0 {
		return "", nil, fmt.Errorf("run %s holds no value in %s: nothing to look up", hunt, strings.Join(fields, ", "))
	}
	return hunt, out, nil
}

// EventsByField streams the stored events whose JSON field equals value exactly,
// newest first. The statement is fixed: field and value are bound parameters, and the
// field is refused if it could break out of the JSON path it is bound into. The same
// event saved by two overlapping hunts appears twice here, which a latest-match scan
// does not mind. The caller stops reading when it has what it needs. Raw is not read.
func (s *Store) EventsByField(ctx context.Context, field, value string) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		if field == "" || strings.ContainsAny(field, `"\`) || value == "" {
			yield(core.Event{}, errors.New("event field and value are required, and the field must not contain a quote or backslash"))
			return
		}
		rows, err := s.db.QueryContext(ctx, `
			SELECT ts, source, kind, CAST(fields AS VARCHAR) FROM events
			WHERE json_extract_string(fields, ?) = ?
			ORDER BY ts DESC`, `$."`+field+`"`, value)
		if err != nil {
			yield(core.Event{}, fmt.Errorf("%w: %v", core.ErrSourceUnavailable, err))
			return
		}
		defer rows.Close()
		for rows.Next() {
			var (
				ev     core.Event
				fields sql.NullString
			)
			if err := rows.Scan(&ev.Time, &ev.Source, &ev.Kind, &fields); err != nil {
				yield(core.Event{}, err)
				return
			}
			ev.Time = ev.Time.UTC()
			if ev.Fields, err = decodeObject(fields); err != nil {
				yield(core.Event{}, fmt.Errorf("event fields: %w", err))
				return
			}
			if !yield(ev, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(core.Event{}, err)
		}
	}
}

var _ core.FieldEventFinder = (*Store)(nil)
