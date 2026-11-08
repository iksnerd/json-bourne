package duckdb

import (
	"encoding/json"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// insertRows writes events straight into the table, bypassing SaveEvents. The document
// identity is a digest of the source label and the kind, so two labels hold two documents
// and a re-fetch under one label is one: what the label-keyed tests below need, without a
// DocKey. insertNoIdent writes the same rows with doc_ident NULL, as a pre-0.11 build did.
// The run's earlier rows are kept, so a test can stack several calls under one run id.
func insertRows(t *testing.T, s *Store, run string, evs ...core.Event) {
	t.Helper()
	insertWith(t, s, false, run, evs...)
}

func insertNoIdent(t *testing.T, s *Store, run string, evs ...core.Event) {
	t.Helper()
	insertWith(t, s, true, run, evs...)
}

func insertWith(t *testing.T, s *Store, noIdent bool, run string, evs ...core.Event) {
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
	ident := "sha256(j->>'source' || chr(0) || (j->>'kind'))"
	if noIdent {
		ident = "NULL"
	}
	if _, err := s.db.Exec(`
		INSERT INTO events (run_id, seq, ts, source, kind, fields, raw, doc_sha256, returners, doc_ident)
		SELECT ?, CAST(j->>'seq' AS BIGINT), CAST(j->>'ts' AS TIMESTAMPTZ),
		       j->>'source', j->>'kind', j->'fields', from_base64(j->>'raw'), j->>'sha', CAST(j->'returners' AS VARCHAR[]), `+ident+`
		FROM (SELECT unnest(CAST(? AS JSON[])) AS j)`, run, string(payload)); err != nil {
		t.Fatal(err)
	}
}
