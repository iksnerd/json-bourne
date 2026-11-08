package duckdb

import (
	"context"
	"errors"
	"iter"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var base = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.duckdb"), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// seq is the stream the tests hand to SaveEvents. The store refuses an event without a
// document identity, as the Kibana source never produces one, so seq gives a bare event the
// identity "test-doc/<kind>": the same document under any source label, which is what a real
// identity is. An event that sets its own DocKey keeps it. A test of a keyless event uses
// bareSeq; a test of a stored row with no identity uses insertNoIdent.
func seq(evs ...core.Event) iter.Seq2[core.Event, error] {
	stamped := make([]core.Event, len(evs))
	for i, e := range evs {
		stamped[i] = seqEvent(e)
	}
	return bareSeq(stamped...)
}

// seqEvent is seq's identity rule for one event.
func seqEvent(e core.Event) core.Event {
	if e.DocKey == "" {
		e.DocKey = "test-doc/" + e.Kind
	}
	return e
}

// bareSeq yields the events exactly as given, identity or not.
func bareSeq(evs ...core.Event) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		for _, e := range evs {
			if !yield(e, nil) {
				return
			}
		}
	}
}

func collect(t *testing.T, it iter.Seq2[core.Event, error]) []core.Event {
	t.Helper()
	var out []core.Event
	for e, err := range it {
		if err != nil {
			t.Fatalf("iterate: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func sample(n int) []core.Event {
	var evs []core.Event
	for i := 0; i < n; i++ {
		evs = append(evs, core.Event{
			Time:   base.Add(time.Duration(i) * time.Second),
			Source: "example.com",
			Kind:   "request",
			Fields: map[string]any{"client": "192.0.2.7", "status": float64(200 + i%3), "tags": []any{"a", "b"}},
			Raw:    []byte(`{"n":` + string(rune('0'+i%10)) + `}`),
		})
	}
	return evs
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := openTest(t)
	if v, err := s.SchemaVersion(); err != nil || v != Version {
		t.Fatalf("schema version = %d, %v; want %d", v, err, Version)
	}
	applied, err := s.Migrate()
	if err != nil || len(applied) != 0 {
		t.Fatalf("second migrate applied %v, err %v; want no-op", applied, err)
	}
}

func TestRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	want := sample(5)
	if err := s.SaveEvents(ctx, "run-1", seq(want...)); err != nil {
		t.Fatal(err)
	}
	got := collect(t, s.Events(ctx, core.Window{From: base, To: base.Add(time.Hour)}))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events differ\n got %+v\nwant %+v", got, want)
	}

	fs := []core.Finding{
		{Detector: "spray", Tag: "spray:example.com", Severity: core.SevHigh,
			Window:   core.Window{From: base, To: base.Add(time.Hour)},
			Baseline: core.Window{From: base.Add(-time.Hour), To: base},
			Summary:  "failure share moved", Detail: map[string]any{"cur": float64(90), "prev": float64(10)}},
		{Detector: "volume", Tag: "volume", Severity: core.SevInfo, Summary: "no baseline, no detail"},
	}
	if err := s.SaveFindings(ctx, "run-1", fs); err != nil {
		t.Fatal(err)
	}
	gotF, err := s.Findings(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotF, fs) {
		t.Fatalf("findings differ\n got %+v\nwant %+v", gotF, fs)
	}

	rep := []core.Reputation{
		{Indicator: "192.0.2.7", Verdict: "unseen", Observed: base.Add(-24 * time.Hour), Source: "feed-a"},
		{Indicator: "192.0.2.7", Verdict: "armed", Observed: base, Source: "feed-a"},
	}
	if err := s.AppendReputation(ctx, rep); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendReputation(ctx, rep[1:]); err != nil { // append, never overwrite
		t.Fatal(err)
	}
	gotR, err := s.Reputation(ctx, "192.0.2.7")
	if err != nil || len(gotR) != 3 || gotR[0].Verdict != "unseen" {
		t.Fatalf("reputation = %+v, %v; want 3 rows oldest first", gotR, err)
	}

	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Runs != 1 || st.Events != 5 || st.Findings != 2 || st.Reputation != 3 || !st.FirstSeen.Equal(base) {
		t.Fatalf("stats = %+v", st)
	}
}

func TestPagination(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	n := pageSize*2 + 7
	evs := make([]core.Event, n)
	for i := range evs { // identical timestamps force the tie-break on (run, seq)
		evs[i] = core.Event{Time: base, Source: "example.com", Kind: "k", Fields: map[string]any{"i": float64(i)}}
	}
	if err := s.SaveEvents(ctx, "big", seq(evs...)); err != nil {
		t.Fatal(err)
	}
	got := collect(t, s.Events(ctx, core.Window{From: base, To: base.Add(time.Second)}))
	if len(got) != n {
		t.Fatalf("got %d events, want %d", len(got), n)
	}
	for i, e := range got {
		if e.Fields["i"] != float64(i) {
			t.Fatalf("event %d out of order: %v", i, e.Fields["i"])
		}
	}
}

func TestResaveReplacesTheRun(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	w := core.Window{From: base, To: base.Add(time.Hour)}

	if err := s.SaveEvents(ctx, "a", seq(sample(5)...)); err != nil {
		t.Fatal(err)
	}
	other := sample(2) // a different source, so run b's events are not duplicates of a's
	for i := range other {
		other[i].Source = "other.example.com"
		other[i].DocKey = "other-doc"
	}
	if err := s.SaveEvents(ctx, "b", seq(other...)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "a", seq(sample(3)...)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvents(ctx, "a", seq(sample(3)...)); err != nil { // same again: no growth
		t.Fatal(err)
	}
	if got := len(collect(t, s.Events(ctx, w))); got != 5 {
		t.Fatalf("after re-save: %d events, want 3 (a) + 2 (b)", got)
	}
	if st, _ := s.Stats(); st.Runs != 2 {
		t.Fatalf("runs = %d, want 2", st.Runs)
	}

	for i := 0; i < 2; i++ {
		if err := s.SaveFindings(ctx, "a", []core.Finding{{Detector: "d", Tag: "t", Summary: "s"}}); err != nil {
			t.Fatal(err)
		}
	}
	if fs, _ := s.Findings(ctx, "a"); len(fs) != 1 {
		t.Fatalf("findings after re-save = %d, want 1", len(fs))
	}
	if err := s.SaveFindings(ctx, "a", nil); err != nil { // no findings is a valid result
		t.Fatal(err)
	}
	if fs, _ := s.Findings(ctx, "a"); len(fs) != 0 {
		t.Fatalf("findings not cleared: %d", len(fs))
	}
}

func TestFailedResaveKeepsThePreviousRun(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	w := core.Window{From: base, To: base.Add(time.Hour)}
	if err := s.SaveEvents(ctx, "a", seq(sample(4)...)); err != nil {
		t.Fatal(err)
	}

	boom := errors.New("upstream died")
	failing := func(yield func(core.Event, error) bool) {
		if !yield(seqEvent(sample(1)[0]), nil) {
			return
		}
		yield(core.Event{}, boom)
	}
	if err := s.SaveEvents(ctx, "a", failing); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if err := s.SaveEvents(ctx, "a", seq()); !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("empty save err = %v, want ErrNoRecords", err)
	}
	if err := s.SaveEvents(ctx, "", seq(sample(1)...)); err == nil {
		t.Fatal("empty run id accepted")
	}
	if got := len(collect(t, s.Events(ctx, w))); got != 4 {
		t.Fatalf("run has %d events after failed re-saves, want the original 4", got)
	}
}

func TestEmptyWindow(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SaveEvents(ctx, "a", seq(sample(3)...)); err != nil {
		t.Fatal(err)
	}
	// Half-open: To is excluded, so [base+2s, base+2s) and a window past the data are empty.
	for name, w := range map[string]core.Window{
		"zero length": {From: base.Add(2 * time.Second), To: base.Add(2 * time.Second)},
		"inverted":    {From: base.Add(time.Hour), To: base},
		"after data":  {From: base.Add(time.Hour), To: base.Add(2 * time.Hour)},
	} {
		if got := collect(t, s.Events(ctx, w)); len(got) != 0 {
			t.Errorf("%s: %d events, want 0", name, len(got))
		}
	}
	if got := collect(t, s.Events(ctx, core.Window{From: base, To: base.Add(2 * time.Second)})); len(got) != 2 {
		t.Errorf("[From,To) returned %d events, want 2", len(got))
	}
}

func TestStopEarlyAndCancel(t *testing.T) {
	s := openTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.SaveEvents(ctx, "a", seq(sample(5)...)); err != nil {
		t.Fatal(err)
	}
	w := core.Window{From: base, To: base.Add(time.Hour)}
	n := 0
	for range s.Events(ctx, w) {
		n++
		break
	}
	if n != 1 {
		t.Fatal("break did not stop the iterator")
	}
	cancel()
	var sawErr bool
	for _, err := range s.Events(ctx, w) {
		sawErr = sawErr || err != nil
	}
	if !sawErr {
		t.Fatal("cancelled context produced no error")
	}
}

func TestSchemaAheadOfBuildIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ahead.duckdb")
	s, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO schema_migrations VALUES (?, now())`, Version+1); err != nil {
		t.Fatal(err)
	}
	s.Close()

	for _, ro := range []bool{false, true} {
		h, err := Open(path, ro)
		if !errors.Is(err, ErrSchemaAhead) {
			if h != nil {
				h.Close()
			}
			t.Fatalf("readOnly=%v: err = %v, want ErrSchemaAhead", ro, err)
		}
	}
}

func TestReadOnlyRefusesUnmigratedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.duckdb")
	s, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if h, err := Open(path, true); !errors.Is(err, ErrSchemaBehind) {
		if h != nil {
			h.Close()
		}
		t.Fatalf("err = %v, want ErrSchemaBehind", err)
	}
}

func TestMigrationsAreNumberedWithoutGaps(t *testing.T) {
	for i, m := range migrations {
		if m.Version != i+1 {
			t.Errorf("migration %s at position %d", m.Name, i+1)
		}
	}
}
