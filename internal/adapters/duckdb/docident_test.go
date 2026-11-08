package duckdb

import (
	"context"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func identEvent(source, ident, mapped string, at time.Time) core.Event {
	return core.Event{Time: at, Source: source, Kind: "request", DocKey: ident,
		Raw: []byte(`{"synthetic":true}`), Fields: map[string]any{"mapped_by": mapped}}
}

// One shared document stored under source a in one run and under source b in a later run
// is one event, and it is the later run's copy. Events with no identity keep the
// (source, kind) rule, so the same raw text under two sources stays two events.
func TestEventsCountSharedDocumentOnceAcrossOwners(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	win := core.Window{From: at.Add(-time.Second), To: at.Add(time.Second)}
	read := func() []core.Event {
		var out []core.Event
		for e, err := range s.Events(ctx, win) {
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		return out
	}
	if err := s.SaveEvents(ctx, "r1/a", seq(identEvent("a", "ident-1", "a", at))); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "r2/b", seq(identEvent("b", "ident-1", "b", at))); err != nil {
		t.Fatal(err)
	}
	got := read()
	if len(got) != 1 || got[0].Source != "b" || got[0].Fields["mapped_by"] != "b" {
		t.Fatalf("want the later run's single copy under b, got %+v", got)
	}
	if err := s.SaveEvents(ctx, "r3/a", seq(identEvent("a", "ident-2", "a", at))); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got) != 2 {
		t.Fatalf("a second document is a second event, got %d", len(got))
	}
	// rows keyed by label (insertRows): same raw under two sources are two events
	insertRows(t, s, "r4/a", identEvent("a", "", "a", at))
	insertRows(t, s, "r5/b", identEvent("b", "", "b", at))
	if got := read(); len(got) != 4 {
		t.Fatalf("copies under two labels stay separate, got %d", len(got))
	}
}

// Rows whose identity is the label (insertRows): one event per (source, kind, ts, content), the occurrence number within a run counted, the
// latest run winning, and rows with an identity are not confused with them.
func TestRowsKeyedByLabelAreReadOnceAndDeduplicated(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	win := core.Window{From: at.Add(-time.Second), To: at.Add(time.Second)}
	// Two overlapping runs of one source carry the same document; one run carries it twice.
	insertRows(t, s, "old-1/a", identEvent("a", "", "r1", at), identEvent("a", "", "r1", at))
	insertRows(t, s, "old-2/a", identEvent("a", "", "r2", at), identEvent("a", "", "r2", at))
	got := readAll(t, s, win.From, win.To)
	if len(got) != 2 {
		t.Fatalf("rows: got %d events, want 2 (a repeated line within a run survives, a re-fetch collapses)", len(got))
	}
	for _, e := range got {
		if e.Fields["mapped_by"] != "r2" || e.Source != "a" {
			t.Fatalf("the latest run's copy must win, got %+v", e)
		}
	}
	// The same raw text under another label is another event: the label is the identity.
	insertRows(t, s, "old-3/b", identEvent("b", "", "r3", at))
	if got := readAll(t, s, win.From, win.To); len(got) != 3 {
		t.Fatalf("a second label: got %d events, want 3", len(got))
	}
	// A row with an identity next to them is its own document.
	if err := s.SaveEvents(ctx, "new-1/a", seq(identEvent("a", "ident-1", "n", at))); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, s, win.From, win.To); len(got) != 4 {
		t.Fatalf("with an identified row: got %d events, want 4", len(got))
	}
}
