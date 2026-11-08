package duckdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// The store refuses an event with no document identity. The save aborts like any stream
// error: the run keeps what it held before, and nothing of the refused save is stored.
func TestSaveEventsRefusesAnEventWithoutIdentity(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	win := core.Window{From: at.Add(-time.Second), To: at.Add(time.Second)}
	if err := s.SaveEvents(ctx, "r1/a", seq(identEvent("a", "ident-1", "first", at))); err != nil {
		t.Fatal(err)
	}
	err := s.SaveEvents(ctx, "r1/a", bareSeq(identEvent("a", "ident-2", "second", at), identEvent("a", "", "third", at)))
	if !errors.Is(err, core.ErrNoDocIdentity) {
		t.Fatalf("err = %v, want core.ErrNoDocIdentity", err)
	}
	want := `event 1 of run "r1/a" has no document identity: its source named no document scope or no document key`
	if err.Error() != want {
		t.Fatalf("err = %q, want %q", err, want)
	}
	got := readAll(t, s, win.From, win.To)
	if len(got) != 1 || got[0].Fields["mapped_by"] != "first" {
		t.Fatalf("the run must keep its previous contents, got %+v", got)
	}
	if err := s.SaveEvents(ctx, "r2/a", bareSeq(identEvent("a", "", "x", at))); !errors.Is(err, core.ErrNoDocIdentity) {
		t.Fatalf("err = %v", err)
	}
	if st, err := s.Stats(); err != nil || st.Events != 1 || st.Runs != 1 {
		t.Fatalf("stats = %+v, %v; want one event in one run", st, err)
	}
}
