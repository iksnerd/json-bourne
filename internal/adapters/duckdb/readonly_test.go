package duckdb

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// TestReadOnlyHandleRefusesWrite is the line of defence that matters: the engine must
// refuse writes, whatever SQL text arrives. Added 3 Nov 2026 after
// `SELECT 1; DROP TABLE events` slipped a prefix guard and dropped the live table.
// A text guard cannot be made safe; access_mode=READ_ONLY can.
func TestReadOnlyHandleRefusesWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.duckdb")

	rw, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := rw.SaveEvents(context.Background(), "r", seq(sample(2)...)); err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()

	for _, q := range []string{
		`SELECT 1; DROP TABLE events`,
		`DROP TABLE events`,
		`DELETE FROM events`,
		`INSERT INTO runs (run_id, created_at) VALUES ('x', now())`,
		`CREATE TABLE sneaky (a INT)`,
		`WITH d AS (SELECT 1) DELETE FROM events`,
	} {
		if _, err := ro.db.Exec(q); err == nil {
			t.Errorf("read-only handle accepted %q", q)
		}
	}

	// The Sink methods go through the same engine and must fail, not no-op.
	ctx := context.Background()
	if err := ro.SaveEvents(ctx, "r", seq(sample(1)...)); err == nil {
		t.Error("SaveEvents succeeded on a read-only handle")
	}
	if err := ro.SaveFindings(ctx, "r", []core.Finding{{Detector: "d", Tag: "t", Summary: "s"}}); err == nil {
		t.Error("SaveFindings succeeded on a read-only handle")
	}
	if err := ro.AppendReputation(ctx, []core.Reputation{{Indicator: "192.0.2.1", Observed: base}}); err == nil {
		t.Error("AppendReputation succeeded on a read-only handle")
	}
	if _, err := ro.Migrate(); err == nil {
		// Already at Version, so Migrate has nothing to write; the CREATE IF NOT EXISTS
		// on schema_migrations is a no-op the engine allows. Not a failure.
		t.Log("Migrate on an up-to-date read-only file is a no-op")
	}

	// Nothing was damaged and reads still work.
	var n int
	if err := ro.db.QueryRow(`SELECT count(*) FROM events`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("events after attempted writes: n=%d err=%v; want 2", n, err)
	}
	if got := collect(t, ro.Events(ctx, core.Window{From: base, To: base.Add(1e12)})); len(got) != 2 {
		t.Fatalf("Events on read-only handle returned %d, want 2", len(got))
	}
}
