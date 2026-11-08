package duckdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// ev builds a synthetic event whose raw document is unique per n.
func ev(at time.Time, n int, extra map[string]any) core.Event {
	f := map[string]any{"n": float64(n)}
	for k, v := range extra {
		f[k] = v
	}
	return core.Event{
		Time: at, Source: "example.com", Kind: "request", Fields: f,
		Raw: []byte(fmt.Sprintf(`192.0.2.7 GET /item/%d`, n)),
	}
}

func readAll(t *testing.T, s *Store, from, to time.Time) []core.Event {
	t.Helper()
	return collect(t, s.Events(context.Background(), core.Window{From: from, To: to}))
}

func TestOverlappingRunsReturnEachEventOnce(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	var a, b []core.Event
	for i := 0; i < 10; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		if i <= 6 {
			a = append(a, ev(at, i, map[string]any{"run": "hunt-1"}))
		}
		if i >= 4 {
			b = append(b, ev(at, i, map[string]any{"run": "hunt-2"}))
		}
	}
	if err := s.SaveEvents(ctx, "hunt-1", seq(a...)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "hunt-2", seq(b...)); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, s, base, base.Add(time.Hour))
	if len(got) != 10 { // 7 + 6 stored rows, 3 shared
		t.Fatalf("got %d events, want 10 distinct (stored %d)", len(got), len(a)+len(b))
	}
	for i, e := range got {
		if e.Fields["n"] != float64(i) {
			t.Fatalf("event %d is n=%v; want ascending, once each", i, e.Fields["n"])
		}
		want := "hunt-1"
		if i >= 4 {
			want = "hunt-2" // the latest run wins for the shared events
		}
		if e.Fields["run"] != want {
			t.Errorf("event %d came from %v, want %s", i, e.Fields["run"], want)
		}
	}
}

func TestSameTextAtDifferentTimesAreDistinct(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	same := func(at time.Time, source string) core.Event {
		return core.Event{Time: at, Source: source, Kind: "request", Raw: []byte("192.0.2.9 GET /login")}
	}
	t1, t2 := base, base.Add(time.Second)
	if err := s.SaveEvents(ctx, "r1", seq(same(t1, "example.com"), same(t2, "example.com"), same(t1, "example.net"))); err != nil {
		t.Fatal(err)
	}
	// An overlapping hunt re-fetches the first two.
	if err := s.SaveEvents(ctx, "r2", seq(same(t1, "example.com"), same(t2, "example.com"))); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, s, base, base.Add(time.Hour))
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3: two timestamps and a second source with identical text", len(got))
	}
}

func TestIdenticalLinesWithinOneRunSurviveButRefetchCollapses(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	line := func() core.Event {
		return core.Event{Time: base, Source: "example.com", Kind: "request", Raw: []byte("192.0.2.9 GET /ping")}
	}
	if err := s.SaveEvents(ctx, "r1", seq(line(), line())); err != nil {
		t.Fatal(err)
	}
	if n := len(readAll(t, s, base, base.Add(time.Second))); n != 2 {
		t.Fatalf("one run with two identical lines: got %d, want 2 (they are real)", n)
	}
	if err := s.SaveEvents(ctx, "r2", seq(line(), line())); err != nil {
		t.Fatal(err)
	}
	if n := len(readAll(t, s, base, base.Add(time.Second))); n != 2 {
		t.Fatalf("same two lines re-fetched under another run: got %d, want 2 (not 4, not 1)", n)
	}
	if err := s.SaveEvents(ctx, "r3", seq(line(), line(), line())); err != nil {
		t.Fatal(err)
	}
	if n := len(readAll(t, s, base, base.Add(time.Second))); n != 3 {
		t.Fatalf("a run that saw three copies: got %d, want 3 (larger count wins)", n)
	}
}

func TestPagingAcrossDuplicatesIsStable(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	const perSecond = 7 // 2000 % 7 != 0, so a page boundary lands inside a timestamp
	n := pageSize*2 + 123
	mk := func(i int) core.Event { return ev(base.Add(time.Duration(i/perSecond)*time.Second), i, nil) }
	var a, b []core.Event
	for i := 0; i < n; i++ {
		a = append(a, mk(i))
	}
	for i := pageSize - 100; i < pageSize+300; i++ { // duplicates straddling the first boundary
		b = append(b, mk(i))
	}
	for i := 2*pageSize - 50; i < n; i++ { // and the second
		b = append(b, mk(i))
	}
	if err := s.SaveEvents(ctx, "hunt-1", seq(a...)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "hunt-2", seq(b...)); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, s, base, base.Add(24*time.Hour))
	if len(a) <= pageSize || len(got) != n {
		t.Fatalf("got %d events, want %d distinct (stored %d, page size %d)", len(got), n, len(a)+len(b), pageSize)
	}
	seen := make(map[float64]bool, n)
	for i, e := range got {
		k := e.Fields["n"].(float64)
		if seen[k] {
			t.Fatalf("event n=%v returned twice", k)
		}
		seen[k] = true
		if i > 0 && e.Time.Before(got[i-1].Time) {
			t.Fatalf("event %d out of time order", i)
		}
	}
	for i := 0; i < n; i++ {
		if !seen[float64(i)] {
			t.Fatalf("event n=%d skipped at a page boundary", i)
		}
	}
}

// A file written by the v1 build holds events with no document identity: it is refused at open.
func TestV1FileWithEventsIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.duckdb")
	raw, err := sql.Open("duckdb", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(migrations[0].SQL); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_migrations VALUES (1, now())`); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("192.0.2.9 GET /login"))
	sha := hex.EncodeToString(sum[:])
	for _, r := range []struct {
		run string
		at  time.Time
	}{{"old-1", base}, {"old-1", base.Add(time.Second)}, {"old-2", base}} {
		if _, err := raw.Exec(`INSERT INTO runs (run_id, created_at) VALUES (?, now()) ON CONFLICT DO NOTHING`, r.run); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO events VALUES (?, ?, CAST(? AS TIMESTAMPTZ), 'example.com', 'request', NULL, ?, ?)`,
			r.run, 0, r.at.Format(time.RFC3339Nano), []byte("192.0.2.9 GET /login"), sha); err != nil {
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	for _, ro := range []bool{false, true} {
		s, err := Open(path, ro)
		if err == nil {
			s.Close()
		}
		if !errors.Is(err, ErrLegacyStore) {
			t.Fatalf("Open(readOnly=%v) of a v1 file with events: err = %v, want ErrLegacyStore", ro, err)
		}
	}
}

// A current-schema file holding a row with no identity (put there by hand) is refused too.
func TestFileWithAnEventWithoutIdentityIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bare.duckdb")
	s, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	insertNoIdent(t, s, "old-1/a", identEvent("a", "", "o", at))
	s.Close()
	if s, err = Open(path, true); err == nil {
		s.Close()
	}
	if !errors.Is(err, ErrLegacyStore) {
		t.Fatalf("err = %v, want ErrLegacyStore", err)
	}
}

func TestResaveSameRunReplacesAndDoesNotResurrect(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mk := func(n int) []core.Event {
		var out []core.Event
		for i := 0; i < n; i++ {
			out = append(out, ev(base.Add(time.Duration(i)*time.Second), i, nil))
		}
		return out
	}
	if err := s.SaveEvents(ctx, "hunt-1", seq(mk(5)...)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "hunt-2", seq(mk(2)...)); err != nil { // overlaps hunt-1
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "hunt-1", seq(mk(3)...)); err != nil { // replaces: 5 -> 3
		t.Fatal(err)
	}
	if n := len(readAll(t, s, base, base.Add(time.Hour))); n != 3 {
		t.Fatalf("after re-save: %d events, want 3 (hunt-1 now holds 0..2, hunt-2 is a subset)", n)
	}
}

// Mimics detector use: hunts over sliding, overlapping windows, one read of the
// window under analysis. The count must be the distinct events, not the sum.
func TestDetectorWindowCountsDistinctEventsNotRows(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	const span = 100 // one event per second
	t0, t1 := base, base.Add(span*time.Second)
	half := span * time.Second / 2
	mk := func(from time.Time) []core.Event {
		var out []core.Event
		for i := 0; i < span; i++ {
			at := from.Add(time.Duration(i) * time.Second)
			out = append(out, ev(at, int(at.Sub(base)/time.Second), map[string]any{"status": float64(200 + 300*(i%2))}))
		}
		return out
	}
	if err := s.SaveEvents(ctx, "hunt-a", seq(mk(t0)...)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "hunt-b", seq(mk(t0.Add(half))...)); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Stats(); st.Events != 2*span {
		t.Fatalf("stored rows = %d, want %d", st.Events, 2*span)
	}
	got := readAll(t, s, t0, t1)
	var fail int
	for _, e := range got {
		if e.Fields["status"].(float64) >= 500 {
			fail++
		}
	}
	// Window [t0,t1): hunt-a holds 100 events, hunt-b holds the 50 that fall inside it.
	// Summing rows would give 150; the distinct count is 100, half of them failures.
	if len(got) != span || fail != span/2 {
		t.Fatalf("window holds %d events, %d failures; want %d and %d (row sum would be %d)",
			len(got), fail, span, span/2, span+span/2)
	}
	if n := len(readAll(t, s, t0, t0.Add(span*time.Second+half))); n != span+span/2 {
		t.Fatalf("full coverage: %d events, want %d distinct (stored %d)", n, span+span/2, 2*span)
	}
}
