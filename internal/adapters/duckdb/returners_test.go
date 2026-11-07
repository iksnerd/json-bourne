package duckdb

import (
	"context"
	"slices"
	"testing"
	"time"
)

// The sources that returned a shared document are stored with it and read back, and a
// later run that stores the same document without them does not take them away.
func TestReturnersAreKeptAcrossRuns(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := base.Add(time.Second)
	first := ev(at, 1, nil)
	first.Returners = []string{"a", "b"}
	later := ev(at, 1, nil) // the same document, stored again by a later hunt: no membership
	other := ev(at.Add(time.Second), 2, nil)
	if err := s.SaveEvents(ctx, "hunt-1", seq(first)); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, s, base, base.Add(time.Hour))
	if len(got) != 1 || !slices.Equal(got[0].Returners, []string{"a", "b"}) {
		t.Fatalf("read back %+v, want one event returned by a and b", got)
	}
	time.Sleep(5 * time.Millisecond) // runs.created_at orders the runs
	if err := s.SaveEvents(ctx, "hunt-2", seq(later, other)); err != nil {
		t.Fatal(err)
	}
	got = readAll(t, s, base, base.Add(time.Hour))
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if !slices.Equal(got[0].Returners, []string{"a", "b"}) {
		t.Errorf("the shared document lost its returners: %v", got[0].Returners)
	}
	if len(got[1].Returners) != 0 {
		t.Errorf("a document nobody shared has returners %v", got[1].Returners)
	}
}
