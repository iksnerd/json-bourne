package duckdb

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// damaged migrates a fresh file, runs stmts against it, closes it and returns the path.
func damaged(t *testing.T, stmts ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.duckdb")
	s, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenRefusesAHealthyLookingFileWithADamagedLedgerOrColumns(t *testing.T) {
	cases := map[string][]string{
		"ledger gap":       {`DELETE FROM schema_migrations WHERE version = 2`},
		"ledger no start":  {`DELETE FROM schema_migrations WHERE version = 1`},
		"missing column":   {`ALTER TABLE events DROP COLUMN returners`},
		"extra column":     {`ALTER TABLE runs ADD COLUMN surprise VARCHAR`},
		"wrong column set": {`ALTER TABLE runs DROP COLUMN pruned_at`},
	}
	for name, stmts := range cases {
		for _, ro := range []bool{false, true} {
			t.Run(name, func(t *testing.T) {
				path := damaged(t, stmts...)
				s, err := Open(path, ro)
				if err == nil {
					s.Close()
					t.Fatalf("readOnly=%v: Open accepted a damaged store", ro)
				}
				if !errors.Is(err, ErrSchemaCorrupt) {
					t.Fatalf("readOnly=%v: %v does not wrap ErrSchemaCorrupt", ro, err)
				}
			})
		}
	}
}

func TestSaveFindingsRefusesASeverityOutsideTheDefinedRange(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for _, sev := range []core.Severity{-1, core.SevCritical + 1} {
		if err := s.SaveFindings(ctx, "r", []core.Finding{{Detector: "d", Tag: "t", Summary: "s", Severity: sev}}); err == nil {
			t.Errorf("severity %d was saved", sev)
		}
	}
	if err := s.SaveFindings(ctx, "r", []core.Finding{{Detector: "d", Tag: "t", Summary: "s", Severity: core.SevCritical}}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAcceptsAnIntactStoreAtEveryVersionItCanBeBehind(t *testing.T) {
	path := damaged(t)
	for _, ro := range []bool{false, true} {
		s, err := Open(path, ro)
		if err != nil {
			t.Fatalf("readOnly=%v: %v", ro, err)
		}
		s.Close()
	}
}
