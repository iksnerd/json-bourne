package duckdb

import (
	"encoding/json"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// insertLegacy writes events the way a build before schema 4 did: straight into the table,
// with doc_ident NULL, bypassing SaveEvents (which now refuses such events). Rows like these
// are still in real stores, and the reader's label-dependent fallback exists for them.
// The run's earlier rows are kept, so a test can stack several calls under one run id.
func insertLegacy(t *testing.T, s *Store, run string, evs ...core.Event) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO runs (run_id, created_at) VALUES (?, now()) ON CONFLICT DO NOTHING`, run); err != nil {
		t.Fatal(err)
	}
	var first int64
	if err := s.db.QueryRow(`SELECT coalesce(max(seq) + 1, 0) FROM events WHERE run_id = ?`, run).Scan(&first); err != nil {
		t.Fatal(err)
	}
	docs := make([]eventDoc, len(evs))
	for i, ev := range evs {
		d := eventDoc{Seq: first + int64(i), TS: ts(ev.Time), Source: ev.Source, Kind: ev.Kind, Raw: ev.Raw, Returners: ev.Returners}
		if ev.Fields != nil {
			var err error
			if d.Fields, err = json.Marshal(ev.Fields); err != nil {
				t.Fatal(err)
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
		docs[i] = d
	}
	payload, err := json.Marshal(docs)
	if err != nil {
		t.Fatal(err)
	}
	// No doc_ident column in the list: the row has NULL there, as a schema 3 row does.
	if _, err := s.db.Exec(`
		INSERT INTO events (run_id, seq, ts, source, kind, fields, raw, doc_sha256, returners)
		SELECT ?, CAST(j->>'seq' AS BIGINT), CAST(j->>'ts' AS TIMESTAMPTZ),
		       j->>'source', j->>'kind', j->'fields', from_base64(j->>'raw'), j->>'sha', CAST(j->'returners' AS VARCHAR[])
		FROM (SELECT unnest(CAST(? AS JSON[])) AS j)`, run, string(payload)); err != nil {
		t.Fatal(err)
	}
}
