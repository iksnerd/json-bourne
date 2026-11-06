package duckdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Dashboard is the read-only view `jb serve` uses. It can only be built over a
// handle opened with access_mode=READ_ONLY, so the engine refuses a write whatever
// SQL reaches it; every query below is fixed text with bound parameters and none is
// built from request input. The one identifier that comes from configuration, an
// event field name, is validated and passed as a bound JSON path.
type Dashboard struct{ s *Store }

var _ core.DashboardStore = (*Dashboard)(nil)

// OpenDashboard opens the database at path read-only. A missing file is
// core.ErrAbsent: a viewer never creates the database.
func OpenDashboard(path string) (*Dashboard, error) {
	return OpenDashboardContext(context.Background(), path)
}

// OpenDashboardContext is OpenDashboard that waits for a lock held by a writing
// process (jb watch, mid-cycle) within the usual budget and gives up when ctx ends.
func OpenDashboardContext(ctx context.Context, path string) (*Dashboard, error) {
	if path == "" {
		path = DefaultPath()
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no evidence database at %s yet", core.ErrAbsent, path)
	}
	s, err := OpenContext(ctx, path, true, OpenOptions{})
	if err != nil {
		return nil, err
	}
	return &Dashboard{s: s}, nil
}

// Close releases the handle, so a writer (jb watch) can open the file again.
func (d *Dashboard) Close() error { return d.s.Close() }

// Stats returns the row counts and the event span.
func (d *Dashboard) Stats(ctx context.Context) (core.StoreStats, error) {
	if err := ctx.Err(); err != nil {
		return core.StoreStats{}, err
	}
	st, err := d.s.Stats()
	if err != nil {
		return core.StoreStats{}, err
	}
	return core.StoreStats{SchemaVersion: st.Version, Runs: st.Runs, Events: st.Events, Findings: st.Findings,
		Reputation: st.Reputation, FirstSeen: st.FirstSeen, LastSeen: st.LastSeen}, nil
}

// groupOf is the run group of a run id: the part before the first "/".
const groupOf = `split_part(run_id, '/', 1)`

// inGroup selects the rows of one group: the findings run and its event runs.
const inGroup = `(run_id = ? OR starts_with(run_id, ?))`

// Runs returns the newest run groups first, at most limit.
func (d *Dashboard) Runs(ctx context.Context, limit int) ([]core.RunGroup, error) {
	rows, err := d.s.db.QueryContext(ctx, `
		WITH g AS (
			SELECT `+groupOf+` AS grp, min(created_at) AS created, count(*) FILTER (WHERE run_id LIKE '%/%') AS eruns
			FROM runs GROUP BY 1 ORDER BY created DESC, grp LIMIT ?),
		e AS (SELECT `+groupOf+` AS grp, count(*) AS n FROM events WHERE `+groupOf+` IN (SELECT grp FROM g) GROUP BY 1),
		f AS (SELECT `+groupOf+` AS grp, count(*) AS n FROM findings WHERE `+groupOf+` IN (SELECT grp FROM g) GROUP BY 1)
		SELECT g.grp, g.created, g.eruns, coalesce(e.n, 0), coalesce(f.n, 0)
		FROM g LEFT JOIN e USING (grp) LEFT JOIN f USING (grp)
		ORDER BY g.created DESC, g.grp`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.RunGroup
	for rows.Next() {
		var r core.RunGroup
		if err := rows.Scan(&r.ID, &r.Created, &r.EventRuns, &r.Events, &r.Findings); err != nil {
			return nil, err
		}
		r.Created = r.Created.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// Run returns one group, or core.ErrNotFound.
func (d *Dashboard) Run(ctx context.Context, group string) (core.RunGroup, error) {
	var (
		r       core.RunGroup
		created sql.NullTime
		total   int64
	)
	if err := d.s.db.QueryRowContext(ctx, `
		SELECT min(created_at), count(*), count(*) FILTER (WHERE run_id LIKE '%/%')
		FROM runs WHERE `+inGroup, group, group+"/").Scan(&created, &total, &r.EventRuns); err != nil {
		return r, err
	}
	if total == 0 {
		return core.RunGroup{}, fmt.Errorf("%w: run %q", core.ErrNotFound, group)
	}
	r.ID, r.Created = group, created.Time.UTC()
	if err := d.s.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE `+inGroup, group, group+"/").Scan(&r.Events); err != nil {
		return r, err
	}
	if err := d.s.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE `+inGroup, group, group+"/").Scan(&r.Findings); err != nil {
		return r, err
	}
	return r, nil
}

var fieldNameRE = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)

// jsonPath turns a configured field name into a bound JSON path. The name is
// validated first, so it cannot carry a quote, a bracket or a second path step.
func jsonPath(name string) (string, error) {
	if !fieldNameRE.MatchString(name) {
		return "", fmt.Errorf("event field name %q is not allowed (letters, digits, _ . @ -, at most 64)", name)
	}
	return `$."` + name + `"`, nil
}

// EventSummary counts the stored events of one group. Paths are grouped after the
// query string and the fragment are removed; an event with no usable path is counted
// under an explicit label, never under an empty one.
func (d *Dashboard) EventSummary(ctx context.Context, group string, f core.DashboardFields, top int) (core.EventSummary, error) {
	var s core.EventSummary
	pp, err := jsonPath(f.Path)
	if err != nil {
		return s, err
	}
	sp, err := jsonPath(f.Status)
	if err != nil {
		return s, err
	}
	kp, err := jsonPath(f.Key)
	if err != nil {
		return s, err
	}
	if err := d.s.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE `+inGroup, group, group+"/").Scan(&s.Rows); err != nil {
		return s, err
	}
	top5 := func(label string, args ...any) ([]core.Count, error) {
		q := `SELECT lbl, count(*) AS n FROM (SELECT ` + label + ` AS lbl FROM events WHERE ` + inGroup + `) GROUP BY lbl ORDER BY n DESC, lbl LIMIT ?`
		rows, err := d.s.db.QueryContext(ctx, q, append(args, top)...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []core.Count
		for rows.Next() {
			var c core.Count
			if err := rows.Scan(&c.Label, &c.N); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
	g := []any{group, group + "/"}
	jf := func(path string) []any { return append([]any{path}, g...) }
	if s.BySource, err = top5(`source`, g...); err != nil {
		return s, err
	}
	if s.ByKind, err = top5(`kind`, g...); err != nil {
		return s, err
	}
	if s.ByStatus, err = top5(`coalesce(nullif(json_extract_string(fields, ?), ''), '(no status)')`, jf(sp)...); err != nil {
		return s, err
	}
	if s.TopPaths, err = top5(`coalesce(nullif(split_part(split_part(json_extract_string(fields, ?), '?', 1), '#', 1), ''), '(no path)')`, jf(pp)...); err != nil {
		return s, err
	}
	if s.TopKeys, err = top5(`coalesce(nullif(json_extract_string(fields, ?), ''), '(no key)')`, jf(kp)...); err != nil {
		return s, err
	}
	return s, nil
}

// RecentEvents returns the newest events of a group, at most limit, without the raw
// document.
func (d *Dashboard) RecentEvents(ctx context.Context, group string, limit int) ([]core.StoredEvent, error) {
	rows, err := d.s.db.QueryContext(ctx, `
		SELECT run_id, ts, source, kind, CAST(fields AS VARCHAR) FROM events WHERE `+inGroup+`
		ORDER BY ts DESC, run_id, seq LIMIT ?`, group, group+"/", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.StoredEvent
	for rows.Next() {
		var (
			e  core.StoredEvent
			fl sql.NullString
		)
		if err := rows.Scan(&e.Run, &e.Time, &e.Source, &e.Kind, &fl); err != nil {
			return nil, err
		}
		e.Time = e.Time.UTC()
		if e.Fields, err = decodeObject(fl); err != nil {
			return nil, fmt.Errorf("event fields: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const findingCols = `f.run_id, f.detector, f.tag, f.severity, f.window_from, f.window_to, f.baseline_from, f.baseline_to, f.summary, CAST(f.detail AS VARCHAR)`

func scanFindings(rows *sql.Rows) ([]core.StoredFinding, error) {
	defer rows.Close()
	var out []core.StoredFinding
	for rows.Next() {
		var (
			f              core.StoredFinding
			sev            int
			wf, wt, bf, bt sql.NullTime
			detail         sql.NullString
		)
		if err := rows.Scan(&f.Run, &f.Detector, &f.Tag, &sev, &wf, &wt, &bf, &bt, &f.Summary, &detail); err != nil {
			return nil, err
		}
		f.Severity = core.Severity(sev)
		f.Window = core.Window{From: nt(wf), To: nt(wt)}
		f.Baseline = core.Window{From: nt(bf), To: nt(bt)}
		var err error
		if f.Detail, err = decodeObject(detail); err != nil {
			return nil, fmt.Errorf("finding %s: detail: %w", f.Tag, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RunFindings returns a group's findings, most severe first, at most limit.
func (d *Dashboard) RunFindings(ctx context.Context, group string, limit int) ([]core.StoredFinding, error) {
	rows, err := d.s.db.QueryContext(ctx, `
		SELECT `+findingCols+` FROM findings f
		WHERE (f.run_id = ? OR starts_with(f.run_id, ?))
		ORDER BY f.severity DESC, f.run_id, f.seq LIMIT ?`, group, group+"/", limit)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

// LatestFindings returns findings of the newest runs first, most severe first within
// a run, at most limit.
func (d *Dashboard) LatestFindings(ctx context.Context, limit int) ([]core.StoredFinding, error) {
	rows, err := d.s.db.QueryContext(ctx, `
		SELECT `+findingCols+` FROM findings f LEFT JOIN runs r ON r.run_id = f.run_id
		ORDER BY r.created_at DESC NULLS LAST, f.run_id, f.severity DESC, f.seq LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

// LatestReputation returns the newest reputation snapshots, at most limit.
func (d *Dashboard) LatestReputation(ctx context.Context, limit int) ([]core.Reputation, error) {
	rows, err := d.s.db.QueryContext(ctx, `
		SELECT indicator, verdict, observed_at, source FROM reputation
		ORDER BY observed_at DESC, indicator, source LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Reputation
	for rows.Next() {
		var r core.Reputation
		if err := rows.Scan(&r.Indicator, &r.Verdict, &r.Observed, &r.Source); err != nil {
			return nil, err
		}
		r.Observed = r.Observed.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}
