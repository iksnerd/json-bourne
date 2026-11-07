package duckdb

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func manyEvents(at time.Time, n int) []core.Event {
	evs := make([]core.Event, n)
	for i := range evs {
		evs[i] = core.Event{Time: at, Source: "a", Kind: "request", Raw: []byte(fmt.Sprintf(`{"synthetic_id":%d}`, i))}
	}
	return evs
}

// A read of more than one page with no write in between returns every distinct event.
func TestEventsPaginationUndisturbedReadsEverything(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if err := s.SaveEvents(ctx, "r1", seq(manyEvents(at, 2001)...)); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, err := range s.Events(ctx, core.Window{From: at.Add(-time.Second), To: at.Add(time.Second)}) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 2001 {
		t.Fatalf("read %d events, want 2001", n)
	}
}

// A save that commits between two pages changes which run wins each event, which moves
// rows across the keyset cursor. The reader must say so, never return a silently short set.
func TestEventsPaginationDetectsOverlappingSave(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	evs := manyEvents(at, 2001)
	if err := s.SaveEvents(ctx, "r1", seq(evs...)); err != nil {
		t.Fatal(err)
	}
	n := 0
	var readErr error
	for _, err := range s.Events(ctx, core.Window{From: at.Add(-time.Second), To: at.Add(time.Second)}) {
		if err != nil {
			readErr = err
			break
		}
		n++
		if n == 2000 {
			if err := s.SaveEvents(ctx, "r0", seq(evs...)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if readErr == nil {
		t.Fatalf("the window changed between pages and the reader emitted %d of 2001 with no error", n)
	}
	if !errors.Is(readErr, core.ErrEvidenceChanged) {
		t.Fatalf("error %v, want core.ErrEvidenceChanged", readErr)
	}
}
