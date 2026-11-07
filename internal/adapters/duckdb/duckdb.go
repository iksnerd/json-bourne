// Package duckdb is the DuckDB-backed evidence store. It implements core.Sink and
// core.EventReader on the generic core.Event and core.Finding.
//
// Conventions:
//
//   - One file, path from $JB_DB (default ~/.jb/jb.duckdb).
//   - Schema versioned in schema_migrations from numbered, embedded SQL files. A
//     writer applies what is missing; any handle refuses a file ahead of the build.
//   - One process writes, many read. Read-only is access_mode=READ_ONLY, enforced by
//     the engine, not by inspecting SQL text.
//   - Bulk load from one JSON payload per batch, never row-at-a-time binds.
//   - Saving a run replaces it inside one transaction.
//
// Cgo note: duckdb-go links a prebuilt DuckDB. The local duckdb CLI must be at
// least that storage version to open the file (DuckDB storage compatibility is best effort).
package duckdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"

	"github.com/iksnerd/json-bourne/internal/core"
)

// EnvPath overrides the database location.
const EnvPath = "JB_DB"

var (
	// ErrSchemaAhead means the file was written by a newer build.
	ErrSchemaAhead = errors.New("database schema is newer than this build")
	// ErrSchemaBehind means a read-only handle found a file that needs migrating.
	ErrSchemaBehind = errors.New("database schema is older than this build: open it writable and Migrate")
)

var (
	_ core.Sink        = (*Store)(nil)
	_ core.EventReader = (*Store)(nil)
	_ core.RunPruner   = (*Store)(nil)
)

// DefaultPath is where the database lives when EnvPath is unset.
func DefaultPath() string {
	if p := os.Getenv(EnvPath); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "jb.duckdb"
	}
	return filepath.Join(home, ".jb", "jb.duckdb")
}

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	Version int
	Name    string
	SQL     string
}

// migrations are additive and never edited once released: a change is a new file.
var migrations = mustLoadMigrations()

// Version is the schema version this build expects.
var Version = migrations[len(migrations)-1].Version

func mustLoadMigrations() []migration {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	var ms []migration
	for _, e := range entries {
		name := e.Name()
		num, _, ok := strings.Cut(strings.TrimSuffix(name, ".sql"), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v < 1 {
			panic("duckdb: migration file must be named NNNN_name.sql: " + name)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			panic(err)
		}
		ms = append(ms, migration{Version: v, Name: name, SQL: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Version < ms[j].Version })
	for i, m := range ms {
		if m.Version != i+1 {
			panic(fmt.Sprintf("duckdb: migrations must be numbered 1..n without gaps, got %s at position %d", m.Name, i+1))
		}
	}
	if len(ms) == 0 {
		panic("duckdb: no migrations embedded")
	}
	return ms
}

// Store is a handle on the database. Reads are safe for concurrent use; writes are
// serialised by a mutex because DuckDB allows one writer.
type Store struct {
	db       *sql.DB
	path     string
	readOnly bool
	mu       sync.Mutex
	// tempDir is set only for a store made by OpenTemp; Close removes it.
	tempDir string
}

// Open opens (creating if needed, when writable) the database at path, waiting for a
// lock held by another process as OpenContext does with the default budget.
func Open(path string, readOnly bool) (*Store, error) {
	return OpenContext(context.Background(), path, readOnly, OpenOptions{})
}

// OpenContext opens (creating if needed, when writable) the database at path.
// readOnly opens with access_mode=READ_ONLY, so the engine itself refuses writes and
// several processes may read the same file. A file whose schema is ahead of this
// build is refused; a read-only handle also refuses one that is behind.
//
// A lock held by another process (one read-write process excludes every other, and
// readers exclude a writer) is retried within opt.LockWait, honouring ctx; see
// lock.go. Every other open error fails at once.
func OpenContext(ctx context.Context, path string, readOnly bool, opt OpenOptions) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	if !readOnly {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	db, err := openRetry(ctx, path, readOnly, opt, os.Getenv)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, path: path, readOnly: readOnly}
	have, err := s.SchemaVersion()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if have > Version {
		_ = db.Close()
		return nil, fmt.Errorf("%w: file is schema %d, build is %d: upgrade jb", ErrSchemaAhead, have, Version)
	}
	if readOnly && have < Version {
		_ = db.Close()
		return nil, fmt.Errorf("%w: file is schema %d, build is %d", ErrSchemaBehind, have, Version)
	}
	return s, nil
}

// Close releases the database. For a store made by OpenTemp it also removes the
// private directory, whether or not closing the database succeeded.
func (s *Store) Close() error {
	err := s.db.Close()
	if s.tempDir != "" {
		if rerr := os.RemoveAll(s.tempDir); err == nil {
			err = rerr
		}
	}
	return err
}

// TempDir is the private directory of a store made by OpenTemp, or "" for a file store.
func (s *Store) TempDir() string { return s.tempDir }

// OpenTemp opens a store in a new directory made with os.MkdirTemp (mode 0700) in the
// system temporary directory. It is the same store as any other: the caller migrates
// it and runs the same code over it. Close removes the directory; if opening fails the
// directory is removed here. The caller owns the store and must Close it on every path.
func OpenTemp(ctx context.Context) (*Store, error) {
	dir, err := os.MkdirTemp("", "jb-nostore-")
	if err != nil {
		return nil, fmt.Errorf("create temporary store dir: %w", err)
	}
	s, err := OpenContext(ctx, filepath.Join(dir, "jb.duckdb"), false, OpenOptions{})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	s.tempDir = dir
	return s, nil
}

// Path is the file backing this store.
func (s *Store) Path() string { return s.path }

// Migrate applies missing migrations, each in its own transaction, and returns the
// versions it applied. DDL is transactional in DuckDB, so a failed migration leaves
// no half-built schema. On a read-only handle the engine refuses.
func (s *Store) Migrate() ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	have, err := s.SchemaVersion()
	if err != nil {
		return nil, err
	}
	if have > Version {
		return nil, fmt.Errorf("%w: file is schema %d, build is %d", ErrSchemaAhead, have, Version)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations
		(version INTEGER NOT NULL PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	var applied []int
	for _, m := range migrations {
		if m.Version <= have {
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(m.SQL); err != nil {
			_ = tx.Rollback()
			return applied, fmt.Errorf("migration %s: %w", m.Name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations VALUES (?, now())`, m.Version); err != nil {
			_ = tx.Rollback()
			return applied, fmt.Errorf("record migration %s: %w", m.Name, err)
		}
		if err := tx.Commit(); err != nil {
			return applied, fmt.Errorf("commit migration %s: %w", m.Name, err)
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

// SchemaVersion reports the highest migration the file has; 0 for a fresh file.
func (s *Store) SchemaVersion() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM duckdb_tables() WHERE table_name = 'schema_migrations'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("inspect schema: %w", err)
	}
	if n == 0 {
		return 0, nil
	}
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return int(v.Int64), nil // 0 when the table is empty
}

// Stats summarises the store for `jb db status`.
type Stats struct {
	Path       string
	Version    int
	Runs       int64
	Events     int64
	Findings   int64
	Reputation int64
	FirstSeen  time.Time // earliest event, zero when there are none
	LastSeen   time.Time
}

// Stats reads row counts and the event time span.
func (s *Store) Stats() (Stats, error) {
	st := Stats{Path: s.path}
	v, err := s.SchemaVersion()
	if err != nil {
		return st, err
	}
	st.Version = v
	if v == 0 {
		return st, nil
	}
	for _, q := range []struct {
		sql string
		dst *int64
	}{
		{`SELECT count(*) FROM runs`, &st.Runs},
		{`SELECT count(*) FROM events`, &st.Events},
		{`SELECT count(*) FROM findings`, &st.Findings},
		{`SELECT count(*) FROM reputation`, &st.Reputation},
	} {
		if err := s.db.QueryRow(q.sql).Scan(q.dst); err != nil {
			return st, err
		}
	}
	var first, last sql.NullTime
	if err := s.db.QueryRow(`SELECT min(ts), max(ts) FROM events`).Scan(&first, &last); err != nil {
		return st, err
	}
	if first.Valid {
		st.FirstSeen = first.Time.UTC()
		st.LastSeen = last.Time.UTC()
	}
	return st, nil
}

// Digest returns the SHA-256 of the canonical JSON of v. encoding/json sorts map
// keys, so the same content gives the same digest.
func Digest(v any) string {
	canonical, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func rawDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func tsPtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := ts(t)
	return &s
}

func checkRun(run string) error {
	if run == "" {
		return errors.New("run id is empty")
	}
	return nil
}

// batchSize bounds one JSON payload.
const batchSize = 5000

type eventDoc struct {
	Seq       int64           `json:"seq"`
	TS        string          `json:"ts"`
	Source    string          `json:"source"`
	Kind      string          `json:"kind"`
	Fields    json.RawMessage `json:"fields,omitempty"`
	Raw       []byte          `json:"raw,omitempty"` // base64 in JSON
	Returners []string        `json:"returners,omitempty"`
	SHA       string          `json:"sha"`
}

// SaveEvents replaces the events of run with evs in one transaction. If the
// iterator yields an error, ctx ends, or nothing was yielded, the previous contents
// of the run are kept and an error is returned. An empty save is core.ErrNoRecords:
// replacing evidence with nothing must never look like a success.
func (s *Store) SaveEvents(ctx context.Context, run string, evs iter.Seq2[core.Event, error]) error {
	if err := checkRun(run); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	if _, err := tx.ExecContext(ctx, `INSERT INTO runs (run_id, created_at) VALUES (?, now()) ON CONFLICT DO NOTHING`, run); err != nil {
		return fmt.Errorf("record run %q: %w", run, err)
	}
	del, err := tx.ExecContext(ctx, `DELETE FROM events WHERE run_id = ?`, run)
	if err != nil {
		return fmt.Errorf("clear run %q: %w", run, err)
	}
	held, _ := del.RowsAffected() // what an empty save leaves in place; 0 when the driver cannot say

	var (
		batch []eventDoc
		total int64
	)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		payload, err := json.Marshal(batch)
		if err != nil {
			return fmt.Errorf("encode events: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO events (run_id, seq, ts, source, kind, fields, raw, doc_sha256, returners)
			SELECT ?, CAST(j->>'seq' AS BIGINT), CAST(j->>'ts' AS TIMESTAMPTZ),
			       j->>'source', j->>'kind', j->'fields', from_base64(j->>'raw'), j->>'sha', CAST(j->'returners' AS VARCHAR[])
			FROM (SELECT unnest(CAST(? AS JSON[])) AS j)`, run, string(payload))
		if err != nil {
			return fmt.Errorf("insert events: %w", err)
		}
		batch = batch[:0]
		return nil
	}

	for ev, err := range evs {
		if err != nil {
			return fmt.Errorf("event stream for run %q: %w", run, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if ev.Time.IsZero() {
			return fmt.Errorf("event %d of run %q has no time", total, run)
		}
		returners, err := lawfulReturners(ev)
		if err != nil {
			return fmt.Errorf("event %d of run %q: %w", total, run, err)
		}
		d := eventDoc{Seq: total, TS: ts(ev.Time), Source: ev.Source, Kind: ev.Kind, Raw: ev.Raw, Returners: returners}
		if ev.Fields != nil {
			if d.Fields, err = json.Marshal(ev.Fields); err != nil {
				return fmt.Errorf("event %d of run %q: fields: %w", total, run, err)
			}
		}
		if len(ev.Raw) > 0 {
			d.SHA = rawDigest(ev.Raw)
		} else {
			d.SHA = Digest(struct {
				T      string
				Source string
				Kind   string
				Fields map[string]any
			}{d.TS, ev.Source, ev.Kind, ev.Fields})
		}
		batch = append(batch, d)
		total++
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if total == 0 {
		return &core.EmptySaveError{Run: run, Kept: held}
	}
	if err := flush(); err != nil {
		return err
	}
	// The run holds events again, so a pruned_at marker from an earlier prune no longer
	// describes it. Only an events save clears it; SaveFindings leaves it alone. A hunt
	// group stores one runs row per source run, so the marker is per source run, never
	// per group: re-saving one source run does not touch its siblings.
	if _, err := tx.ExecContext(ctx, `UPDATE runs SET pruned_at = NULL WHERE run_id = ? AND pruned_at IS NOT NULL`, run); err != nil {
		return fmt.Errorf("clear pruned marker of run %q: %w", run, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit run %q: %w", run, err)
	}
	return nil
}

// lawfulReturners returns the membership list the store keeps for ev: a sorted set that
// contains the owner (ev.Source). Empty stays empty, meaning only the owner returned the
// document. An empty label is refused. A missing owner is added, not refused, so the list
// always answers "who returned this". The caller's slice is not modified.
func lawfulReturners(ev core.Event) ([]string, error) {
	if len(ev.Returners) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(ev.Returners)+1)
	for _, r := range ev.Returners {
		if r == "" {
			return nil, errors.New("returners holds an empty source label")
		}
		out = append(out, r)
	}
	out = append(out, ev.Source)
	slices.Sort(out)
	return slices.Compact(out), nil
}

type findingDoc struct {
	Seq      int64           `json:"seq"`
	Detector string          `json:"detector"`
	Tag      string          `json:"tag"`
	Severity int             `json:"severity"`
	From     *string         `json:"from,omitempty"`
	To       *string         `json:"to,omitempty"`
	BFrom    *string         `json:"bfrom,omitempty"`
	BTo      *string         `json:"bto,omitempty"`
	Summary  string          `json:"summary"`
	Detail   json.RawMessage `json:"detail,omitempty"`
}

// SaveFindings replaces the findings of run with fs in one transaction. An empty
// slice is valid (a detector can find nothing) and clears the run's findings.
func (s *Store) SaveFindings(ctx context.Context, run string, fs []core.Finding) error {
	if err := checkRun(run); err != nil {
		return err
	}
	docs := make([]findingDoc, 0, len(fs))
	for i, f := range fs {
		d := findingDoc{
			Seq: int64(i), Detector: f.Detector, Tag: f.Tag, Severity: int(f.Severity),
			From: tsPtr(f.Window.From), To: tsPtr(f.Window.To),
			BFrom: tsPtr(f.Baseline.From), BTo: tsPtr(f.Baseline.To),
			Summary: f.Summary,
		}
		if f.Detail != nil {
			b, err := json.Marshal(f.Detail)
			if err != nil {
				return fmt.Errorf("finding %d (%s): detail: %w", i, f.Tag, err)
			}
			d.Detail = b
		}
		docs = append(docs, d)
	}
	payload, err := json.Marshal(docs)
	if err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO runs (run_id, created_at) VALUES (?, now()) ON CONFLICT DO NOTHING`, run); err != nil {
		return fmt.Errorf("record run %q: %w", run, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE run_id = ?`, run); err != nil {
		return fmt.Errorf("clear findings of run %q: %w", run, err)
	}
	if len(docs) > 0 {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO findings
			SELECT ?, CAST(j->>'seq' AS BIGINT), j->>'detector', j->>'tag', CAST(j->>'severity' AS INTEGER),
			       CAST(j->>'from' AS TIMESTAMPTZ), CAST(j->>'to' AS TIMESTAMPTZ),
			       CAST(j->>'bfrom' AS TIMESTAMPTZ), CAST(j->>'bto' AS TIMESTAMPTZ),
			       j->>'summary', j->'detail'
			FROM (SELECT unnest(CAST(? AS JSON[])) AS j)`, run, string(payload))
		if err != nil {
			return fmt.Errorf("insert findings: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit findings of run %q: %w", run, err)
	}
	return nil
}

// pruneHook is a test seam: called before each DELETE of PruneRuns so a test can fail
// the prune half-way and prove the transaction rolls everything back. Nil in production.
var pruneHook func(table string) error

// PruneRuns implements core.RunPruner. A hunt is the group of run ids that share the
// part before the first "/": the findings are stored under the hunt id, each source's
// events under id/source. A group is stale when its newest runs.created_at is before
// `before`, so a cutoff that falls between a hunt's records cannot split it. The newest
// group is never stale. Everything happens in one transaction, and the counts are taken
// inside it, so they describe exactly what was removed.
//
// A hunt belongs to the prefix only when its id is exactly prefix + a UTC stamp
// (20060102T150405Z), never when more follows: "watch-a-" must not reach "watch-ab-..."
// nor "watch-a-b-...", which are other watchers', and the unnamed watcher's "watch-"
// must not reach any named watcher's runs. That is the delimiter-safe test; a bare
// prefix match could not tell them apart. "The newest group is never stale" is therefore
// per prefix: each watcher keeps its own newest run.
//
// prefix is matched with starts_with and a quoted pattern, not LIKE: a prefix holding %
// or _ is literal. On a read-only handle the engine refuses the first write.
func (s *Store) PruneRuns(ctx context.Context, prefix string, before time.Time) (core.PruneResult, error) {
	var res core.PruneResult
	if prefix == "" {
		return res, errors.New("prune: prefix is empty; refusing to match every run")
	}
	shape := regexp.QuoteMeta(prefix) + `\d{8}T\d{6}Z`
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("prune: begin: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		CREATE OR REPLACE TEMP TABLE prune_runs AS
		WITH g AS (
			SELECT split_part(run_id, '/', 1) AS base, max(created_at) AS newest
			FROM runs WHERE starts_with(run_id, ?) AND regexp_full_match(split_part(run_id, '/', 1), ?) GROUP BY 1
		), stale AS (
			SELECT base FROM g
			WHERE newest < CAST(? AS TIMESTAMPTZ)
			  AND base <> (SELECT base FROM g ORDER BY newest DESC, base DESC LIMIT 1)
		)
		SELECT run_id FROM runs
		WHERE starts_with(run_id, ?) AND regexp_full_match(split_part(run_id, '/', 1), ?)
		  AND split_part(run_id, '/', 1) IN (SELECT base FROM stale)`,
		prefix, shape, ts(before), prefix, shape); err != nil {
		return res, fmt.Errorf("prune: select stale runs: %w", err)
	}
	for _, q := range []struct {
		sql string
		dst *int64
	}{
		{`SELECT count(*) FROM prune_runs`, &res.Runs},
		{`SELECT count(*) FROM events WHERE run_id IN (SELECT run_id FROM prune_runs)`, &res.Events},
		{`SELECT count(*) FROM findings WHERE run_id IN (SELECT run_id FROM prune_runs)`, &res.Findings},
	} {
		if err := tx.QueryRowContext(ctx, q.sql).Scan(q.dst); err != nil {
			return core.PruneResult{}, fmt.Errorf("prune: count: %w", err)
		}
	}
	for _, table := range []string{"events", "findings", "runs"} {
		if pruneHook != nil {
			if err := pruneHook(table); err != nil {
				return core.PruneResult{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE run_id IN (SELECT run_id FROM prune_runs)`); err != nil {
			return core.PruneResult{}, fmt.Errorf("prune: delete from %s: %w", table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE prune_runs`); err != nil {
		return core.PruneResult{}, fmt.Errorf("prune: drop scratch table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return core.PruneResult{}, fmt.Errorf("prune: commit: %w", err)
	}
	return res, nil
}

// Findings returns the findings saved for run, in the order they were saved.
func (s *Store) Findings(ctx context.Context, run string) ([]core.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT detector, tag, severity, window_from, window_to, baseline_from, baseline_to,
		       summary, CAST(detail AS VARCHAR)
		FROM findings WHERE run_id = ? ORDER BY seq`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Finding
	for rows.Next() {
		var (
			f              core.Finding
			sev            int
			wf, wt, bf, bt sql.NullTime
			detail         sql.NullString
		)
		if err := rows.Scan(&f.Detector, &f.Tag, &sev, &wf, &wt, &bf, &bt, &f.Summary, &detail); err != nil {
			return nil, err
		}
		f.Severity = core.Severity(sev)
		f.Window = core.Window{From: nt(wf), To: nt(wt)}
		f.Baseline = core.Window{From: nt(bf), To: nt(bt)}
		if f.Detail, err = decodeObject(detail); err != nil {
			return nil, fmt.Errorf("finding %s: detail: %w", f.Tag, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func nt(n sql.NullTime) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return n.Time.UTC()
}

func decodeObject(s sql.NullString) (map[string]any, error) {
	if !s.Valid || s.String == "" || s.String == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s.String), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// pageSize bounds how many events one Events query holds the connection for.
const pageSize = 2000

// Events streams the events with Time in [w.From, w.To), each distinct event once,
// ordered by time, then run, then position in the run. It reads in keyset-paginated
// pages and releases the connection between them, so a consumer may run other
// queries while iterating. JSON numbers in Fields come back as float64.
//
// Identity. Two stored rows are the same event when they agree on
// (source, ts, kind, doc_sha256) and on their occurrence number within their own run.
//
//   - doc_sha256 is the SHA-256 of the raw document, or of the normalised event
//     (time, source, kind, fields) when there is no raw. For an event with raw it does
//     NOT cover the timestamp, so ts and source are part of the identity explicitly:
//     the same text at two different times is two events. Stored digests are left as
//     they are, so files written before this rule dedupe correctly without a backfill.
//   - Occurrence number: within one run, identical rows are numbered 1, 2, ... by seq.
//     Two identical lines in one fetch are real events and both survive; the same
//     event fetched again by an overlapping hunt under another run id has the same
//     (identity, occurrence) and collapses. If runs disagree on how many copies there
//     are, the larger count wins. ts is stored at microsecond precision, so events
//     that differ only below a microsecond are one event.
//   - Of rows with the same identity the latest run is returned: runs.created_at,
//     then run_id, descending. Re-saving a run id replaces it and keeps created_at.
//
// The dedupe is computed in SQL (a row_number() window filtered with QUALIFY, see the
// DuckDB docs on the QUALIFY clause) over the narrow key columns only; raw and fields
// are read for the page's winners. Every group shares one ts, so a page that starts at
// the previous page's last ts still sees whole groups.
func (s *Store) Events(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		if !w.From.Before(w.To) {
			return
		}
		var (
			afterTS  string
			afterRun string
			afterSeq int64
			first    = true
		)
		for {
			evs, last, err := s.eventsPage(ctx, w, first, afterTS, afterRun, afterSeq)
			if err != nil {
				yield(core.Event{}, err)
				return
			}
			for _, ev := range evs {
				if !yield(ev.Event, nil) {
					return
				}
			}
			if len(evs) < pageSize {
				return
			}
			first = false
			afterTS, afterRun, afterSeq = ts(last.Time), last.run, last.seq
		}
	}
}

type pagedEvent struct {
	core.Event
	run string
	seq int64
}

// eventsQuery returns one page of distinct events. Parameters: lower ts bound, upper
// ts bound, then the keyset cursor (ts, run_id, seq) strictly after which to read. The
// first page passes a cursor below every row.
const eventsQuery = `
WITH base AS (
	SELECT e.rowid AS rid, e.run_id, e.seq, e.ts, e.source, e.kind, e.doc_sha256, r.created_at, e.returners,
	       row_number() OVER (PARTITION BY e.run_id, e.source, e.ts, e.kind, e.doc_sha256
	                          ORDER BY e.seq) AS ord
	FROM events e LEFT JOIN runs r ON r.run_id = e.run_id
	WHERE e.ts >= CAST(? AS TIMESTAMPTZ) AND e.ts < CAST(? AS TIMESTAMPTZ)
), cand AS (
	-- who returned the document in any stored run, not only the newest one kept below
	SELECT *, list_distinct(flatten(list(coalesce(returners, []::VARCHAR[]))
	                                OVER (PARTITION BY source, ts, kind, doc_sha256, ord))) AS ret
	FROM base
), winners AS (
	SELECT * FROM cand
	QUALIFY row_number() OVER (PARTITION BY source, ts, kind, doc_sha256, ord
	                           ORDER BY created_at DESC NULLS LAST, run_id DESC) = 1
), page AS (
	SELECT rid, run_id, seq, ret FROM winners
	WHERE (ts, run_id, seq) > (CAST(? AS TIMESTAMPTZ), ?, ?)
	ORDER BY ts, run_id, seq LIMIT ` + "2000" + `
)
SELECT p.run_id, p.seq, e.ts, e.source, e.kind, CAST(e.fields AS VARCHAR), e.raw, CAST(to_json(p.ret) AS VARCHAR)
FROM page p JOIN events e ON e.rowid = p.rid
ORDER BY e.ts, p.run_id, p.seq`

func (s *Store) eventsPage(ctx context.Context, w core.Window, first bool, afterTS, afterRun string, afterSeq int64) ([]pagedEvent, pagedEvent, error) {
	lower := w.From
	cursorTS, cursorRun, cursorSeq := "0001-01-01T00:00:00Z", "", int64(-1)
	if !first {
		// Same-ts rows after the cursor still belong to this page, so read from afterTS.
		cursorTS, cursorRun, cursorSeq = afterTS, afterRun, afterSeq
		if t, err := time.Parse(time.RFC3339Nano, afterTS); err == nil && t.After(lower) {
			lower = t
		}
	}
	rows, err := s.db.QueryContext(ctx, eventsQuery, ts(lower), ts(w.To), cursorTS, cursorRun, cursorSeq)
	if err != nil {
		return nil, pagedEvent{}, fmt.Errorf("%w: %v", core.ErrSourceUnavailable, err)
	}
	defer rows.Close()
	var out []pagedEvent
	for rows.Next() {
		var (
			pe     pagedEvent
			fields sql.NullString
			ret    sql.NullString
		)
		if err := rows.Scan(&pe.run, &pe.seq, &pe.Time, &pe.Source, &pe.Kind, &fields, &pe.Raw, &ret); err != nil {
			return nil, pagedEvent{}, err
		}
		if ret.Valid && ret.String != "" && ret.String != "[]" {
			if err := json.Unmarshal([]byte(ret.String), &pe.Returners); err != nil {
				return nil, pagedEvent{}, fmt.Errorf("event returners: %w", err)
			}
			slices.Sort(pe.Returners) // list_distinct has no order
		}
		pe.Time = pe.Time.UTC()
		if pe.Fields, err = decodeObject(fields); err != nil {
			return nil, pagedEvent{}, fmt.Errorf("event fields: %w", err)
		}
		out = append(out, pe)
	}
	if err := rows.Err(); err != nil {
		return nil, pagedEvent{}, err
	}
	var last pagedEvent
	if len(out) > 0 {
		last = out[len(out)-1]
	}
	return out, last, nil
}

// AppendReputation appends observations to the time series. Nothing is updated or
// deleted: "armed on 4 Nov" only means something next to "unseen on 2 Nov".
func (s *Store) AppendReputation(ctx context.Context, rs []core.Reputation) error {
	if len(rs) == 0 {
		return nil
	}
	type doc struct {
		Indicator string `json:"indicator"`
		Verdict   string `json:"verdict"`
		Observed  string `json:"observed"`
		Source    string `json:"source"`
	}
	docs := make([]doc, len(rs))
	for i, r := range rs {
		if r.Indicator == "" || r.Observed.IsZero() {
			return fmt.Errorf("reputation %d: indicator and observation time are required", i)
		}
		docs[i] = doc{r.Indicator, r.Verdict, ts(r.Observed), r.Source}
	}
	payload, err := json.Marshal(docs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO reputation
		SELECT j->>'indicator', j->>'verdict', CAST(j->>'observed' AS TIMESTAMPTZ), j->>'source'
		FROM (SELECT unnest(CAST(? AS JSON[])) AS j)`, string(payload))
	if err != nil {
		return fmt.Errorf("append reputation: %w", err)
	}
	return nil
}

// Reputation returns every observation of indicator, oldest first.
func (s *Store) Reputation(ctx context.Context, indicator string) ([]core.Reputation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT indicator, verdict, observed_at, source FROM reputation
		WHERE indicator = ? ORDER BY observed_at, source`, indicator)
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
