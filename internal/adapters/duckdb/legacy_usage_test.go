package duckdb

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// `jb db usage` reports how many stored events carry no document identity: the rows the
// reader's label fallback still serves. When it reads 0 on every store, the fallback can go.
func TestStoreUsageCountsEventsWithoutDocIdentity(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	u, err := s.StoreUsage(ctx)
	if err != nil || u.LegacyEvents != 0 {
		t.Fatalf("empty store: %+v, %v", u, err)
	}
	if err := s.SaveEvents(ctx, "new-1/a", seq(identEvent("a", "ident-1", "n", at), identEvent("a", "ident-2", "n", at))); err != nil {
		t.Fatal(err)
	}
	insertLegacy(t, s, "old-1/a", identEvent("a", "", "o", at), identEvent("a", "", "o", at.Add(time.Second)), identEvent("b", "", "o", at))
	u, err = s.StoreUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if u.Events != 5 || u.LegacyEvents != 3 {
		t.Fatalf("events = %d, without identity = %d; want 5 and 3", u.Events, u.LegacyEvents)
	}
}

// Compaction copies a row without a document identity as it is: still NULL, still read the
// old way. The copier never gives a legacy row an identity and never refuses it.
func TestCompactKeepsLegacyRowsAsTheyAre(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	insertLegacy(t, s, "old-1/a", identEvent("a", "", "o", at))
	if err := s.SaveEvents(ctx, "new-1/a", seq(identEvent("a", "ident-1", "n", at))); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "copy.duckdb")
	if res, err := s.Compact(ctx, core.CompactRequest{Target: target}); err != nil || !res.Applied {
		t.Fatalf("res %+v err %v", res, err)
	}
	cp, err := Open(target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	u, err := cp.StoreUsage(ctx)
	if err != nil || u.Events != 2 || u.LegacyEvents != 1 {
		t.Fatalf("copy usage = %+v, %v; want 2 events, 1 without identity", u, err)
	}
	if got := readAll(t, cp, at.Add(-time.Second), at.Add(time.Second)); len(got) != 2 {
		t.Fatalf("copy reads %d events, want 2", len(got))
	}
}
