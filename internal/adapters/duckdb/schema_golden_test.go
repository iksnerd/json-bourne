package duckdb

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

var updateSchema = flag.Bool("update-schema", false, "rewrite testdata/schema.golden")

// schemaDocument lists the schema version, every embedded migration with the SHA-256 of
// its SQL, and the tables and columns found after migrating an empty store.
func schemaDocument(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "schema version %d\n", Version)
	for _, m := range migrations {
		sum := sha256.Sum256([]byte(m.SQL))
		fmt.Fprintf(&b, "migration %04d %s sha256:%s\n", m.Version, m.Name, hex.EncodeToString(sum[:]))
	}

	s := openTest(t)
	rows, err := s.db.Query(`SELECT table_name, ordinal_position, column_name, data_type, is_nullable
		FROM information_schema.columns WHERE table_schema = 'main'
		ORDER BY table_name, ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, col, typ, nullable string
		var pos int
		if err := rows.Scan(&table, &pos, &col, &typ, &nullable); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "column %s.%s %s nullable=%s\n", table, col, typ, nullable)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var applied []string
	vr, err := s.db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Close()
	for vr.Next() {
		var v int
		if err := vr.Scan(&v); err != nil {
			t.Fatal(err)
		}
		applied = append(applied, fmt.Sprint(v))
	}
	fmt.Fprintf(&b, "applied after migrating an empty store: %s\n", strings.Join(applied, ","))
	return b.String()
}

// TestEvidenceSchemaIsUnchanged pins the evidence store (RFC 0018): the schema version,
// the content of each migration (an edited or removed migration changes the hash) and the
// tables and columns an empty store has after migrating. A change is a new migration
// file; regenerate with -update-schema and read the diff.
func TestEvidenceSchemaIsUnchanged(t *testing.T) {
	got := schemaDocument(t)
	const path = "testdata/schema.golden"
	if *updateSchema {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("the evidence schema differs from %s (rerun with -update-schema only for a NEW migration)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}
