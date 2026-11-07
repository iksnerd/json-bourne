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
	// keyless: same raw under two sources are two events
	if err := s.SaveEvents(ctx, "r4/a", seq(identEvent("a", "", "a", at))); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "r5/b", seq(identEvent("b", "", "b", at))); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got) != 4 {
		t.Fatalf("keyless copies under two sources stay separate, got %d", len(got))
	}
}
