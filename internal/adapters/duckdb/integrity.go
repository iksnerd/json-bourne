package duckdb

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ErrSchemaCorrupt means the file claims a schema version but its migration ledger or
// its events/runs columns do not match what this build's embedded migrations make for
// that version. Something other than jb changed the file.
var ErrSchemaCorrupt = errors.New("database schema does not match its recorded version")

// integrityTables are the tables whose column sets are checked: the two that every
// migration so far has changed.
var integrityTables = []string{"events", "runs"}

var (
	expectedOnce sync.Once
	expectedCols map[int]map[string]string // version -> "table.column" -> data type
	expectedErr  error
)

// expectedColumns derives, once per process, the events/runs columns after each
// embedded migration by applying them to a private in-memory database. Nothing is
// hard-coded, so a new migration file is covered without touching this file.
func expectedColumns() (map[int]map[string]string, error) {
	expectedOnce.Do(func() {
		db, err := sql.Open("duckdb", "")
		if err != nil {
			expectedErr = fmt.Errorf("open in-memory duckdb: %w", err)
			return
		}
		defer db.Close()
		db.SetMaxOpenConns(1) // one connection, so every migration sees the same in-memory database
		out := map[int]map[string]string{}
		for _, m := range migrations {
			if _, err := db.Exec(m.SQL); err != nil {
				expectedErr = fmt.Errorf("derive expected schema: migration %s: %w", m.Name, err)
				return
			}
			cols, err := columnsOf(db)
			if err != nil {
				expectedErr = fmt.Errorf("derive expected schema: %w", err)
				return
			}
			out[m.Version] = cols
		}
		expectedCols = out
	})
	return expectedCols, expectedErr
}

type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func columnsOf(q queryer) (map[string]string, error) {
	rows, err := q.Query(`SELECT table_name, column_name, data_type FROM information_schema.columns
		WHERE table_schema = 'main' AND table_name IN ('events', 'runs')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]string{}
	for rows.Next() {
		var t, c, typ string
		if err := rows.Scan(&t, &c, &typ); err != nil {
			return nil, err
		}
		cols[t+"."+c] = typ
	}
	return cols, rows.Err()
}

// checkIntegrity compares the file with what this build expects of schema version have:
// the ledger holds exactly 1..have (it records no checksum, so contiguity is all it can
// prove), and events and runs have exactly the expected columns. Three catalog queries.
func (s *Store) checkIntegrity(have int) error {
	if have == 0 {
		return nil
	}
	var n, lo, hi int
	if err := s.db.QueryRow(`SELECT count(*), min(version), max(version) FROM schema_migrations`).Scan(&n, &lo, &hi); err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	if lo != 1 || n != hi {
		return fmt.Errorf("%w: the migration ledger must hold versions 1..%d without gaps, but holds %d rows from %d", ErrSchemaCorrupt, hi, n, lo)
	}
	want, err := expectedColumns()
	if err != nil {
		return err
	}
	exp, ok := want[have]
	if !ok {
		return fmt.Errorf("%w: schema version %d is not one this build knows", ErrSchemaCorrupt, have)
	}
	got, err := columnsOf(s.db)
	if err != nil {
		return fmt.Errorf("inspect columns: %w", err)
	}
	var missing, extra, differ []string
	for k, typ := range exp {
		g, ok := got[k]
		switch {
		case !ok:
			missing = append(missing, k)
		case g != typ:
			differ = append(differ, fmt.Sprintf("%s is %s, want %s", k, g, typ))
		}
	}
	for k := range got {
		if _, ok := exp[k]; !ok {
			extra = append(extra, k)
		}
	}
	if len(missing)+len(extra)+len(differ) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(differ)
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		parts = append(parts, "unexpected "+strings.Join(extra, ", "))
	}
	if len(differ) > 0 {
		parts = append(parts, strings.Join(differ, "; "))
	}
	return fmt.Errorf("%w: file is schema %d but %s", ErrSchemaCorrupt, have, strings.Join(parts, "; "))
}

// refuseLegacy fails the open of a file that holds an event with no document identity:
// every event of a file written before schema 4, or a row put there by hand. The reader
// has one identity rule and no fallback, so such a file is not read at all.
func (s *Store) refuseLegacy(have int) error {
	if have == 0 {
		return nil
	}
	q := `SELECT count(*) FROM events WHERE doc_ident IS NULL`
	if have < 4 { // the column does not exist yet: every event lacks it
		q = `SELECT count(*) FROM events`
	}
	var n int64
	if err := s.db.QueryRow(q).Scan(&n); err != nil {
		return fmt.Errorf("check document identities: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("%w: %d events; delete the file and hunt again", ErrLegacyStore, n)
	}
	return nil
}
