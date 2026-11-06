package duckdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// docsAs builds n synthetic documents numbered from..from+n-1, one a second from base,
// stored under source. The raw text depends on the number only, so the same number under
// two labels is the same document as an index returns it twice.
func docsAs(source string, from, n int) []core.Event {
	var out []core.Event
	for i := from; i < from+n; i++ {
		out = append(out, core.Event{
			Time: base.Add(time.Duration(i) * time.Second), Source: source, Kind: "request",
			Fields: map[string]any{"n": float64(i)},
			Raw:    []byte(fmt.Sprintf(`192.0.2.7 GET /item/%d`, i)),
		})
	}
	return out
}

func save(t *testing.T, s *Store, run string, evs []core.Event) {
	t.Helper()
	if err := s.SaveEvents(context.Background(), run, seq(evs...)); err != nil {
		t.Fatalf("save %s: %v", run, err)
	}
}

var wide = core.Window{From: base.Add(-time.Hour), To: base.Add(time.Hour)}

// snapshot is every stored row's (run, seq, source, sha), sorted: what a rename may change.
func snapshot(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT run_id, seq, source, doc_sha256 FROM events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var run, src, sha string
		var n int64
		if err := rows.Scan(&run, &n, &src, &sha); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s|%d|%s|%s", run, n, src, sha))
	}
	sort.Strings(out)
	return out
}

func bySource(t *testing.T, s *Store) map[string]int {
	t.Helper()
	m := map[string]int{}
	for _, ev := range collect(t, s.Events(context.Background(), wide)) {
		m[ev.Source]++
	}
	return m
}

const defLabel = "kibana:logs-ingress-*"

// The case found live: the same 77 documents under the default label and again under an
// explicit name read as 154 events.
func TestSameDocumentsUnderTwoLabelsDoubleCountAndRenameFixesIt(t *testing.T) {
	s := openTest(t)
	save(t, s, "hunt-1/"+defLabel, docsAs(defLabel, 0, 77))
	save(t, s, "hunt-2/ingress", docsAs("ingress", 0, 77))

	if got := len(collect(t, s.Events(context.Background(), wide))); got != 154 {
		t.Fatalf("reproduction: a detector reads %d events, want the doubled 154", got)
	}
	ov, err := s.SourceOverlaps(context.Background(), wide, 10)
	if err != nil || len(ov) != 1 || ov[0].Docs != 77 || ov[0].A != "ingress" || ov[0].B != defLabel {
		t.Fatalf("overlaps = %+v, %v; want one pair sharing 77", ov, err)
	}

	res, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: defLabel, New: "ingress", Merge: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.Events != 77 || res.Overlap != 77 || res.Dropped != 77 || res.Relabelled != 0 {
		t.Fatalf("result = %+v", res)
	}
	if got := len(collect(t, s.Events(context.Background(), wide))); got != 77 {
		t.Fatalf("after the rename a detector reads %d events, want the single-label 77", got)
	}
	if ov, _ := s.SourceOverlaps(context.Background(), wide, 10); len(ov) != 0 {
		t.Fatalf("overlap persists: %+v", ov)
	}
}

func TestRenameDryRunChangesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.duckdb")
	s, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	s.Migrate()
	save(t, s, "h1/"+defLabel, docsAs(defLabel, 0, 6))
	save(t, s, "h2/ingress", docsAs("ingress", 3, 6))
	before := snapshot(t, s)
	s.Close()

	// A read-only handle: the engine, not this code, is what makes a dry run harmless.
	ro, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ro.RenameSource(context.Background(), core.RenameSourceRequest{Old: defLabel, New: "ingress", Merge: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	want := core.RenameSourceResult{Old: defLabel, New: "ingress", Applied: false, Events: 6, Runs: 1, NewEvents: 6, Overlap: 3, Dropped: 3, Relabelled: 3}
	if res != want {
		t.Fatalf("dry run counts = %+v\nwant %+v", res, want)
	}
	if after := snapshot(t, ro); !reflect.DeepEqual(before, after) {
		t.Fatalf("a dry run changed the store:\nbefore %v\nafter  %v", before, after)
	}
	// And a real rename through a read-only handle is refused by the engine.
	if _, err := ro.RenameSource(context.Background(), core.RenameSourceRequest{Old: defLabel, New: "ingress", Merge: true}); err == nil {
		t.Fatal("rename on a read-only handle succeeded")
	}
	if after := snapshot(t, ro); !reflect.DeepEqual(before, after) {
		t.Fatal("a refused write changed the store")
	}
	ro.Close()
}

func TestRenameRelabelsWithoutTouchingRunIDs(t *testing.T) {
	s := openTest(t)
	save(t, s, "h1/"+defLabel, docsAs(defLabel, 0, 5))
	if err := s.SaveFindings(context.Background(), "h1", []core.Finding{{Detector: "d", Tag: "t", Summary: "s"}}); err != nil {
		t.Fatal(err)
	}
	var runsBefore []string
	rows, _ := s.db.Query(`SELECT run_id FROM runs ORDER BY 1`)
	for rows.Next() {
		var r string
		rows.Scan(&r)
		runsBefore = append(runsBefore, r)
	}
	rows.Close()

	res, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: defLabel, New: "ingress"})
	if err != nil || !res.Applied || res.Relabelled != 5 || res.Dropped != 0 || res.Overlap != 0 || res.Runs != 1 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if got := bySource(t, s); !reflect.DeepEqual(got, map[string]int{"ingress": 5}) {
		t.Fatalf("by source = %v", got)
	}
	var runsAfter []string
	rows, _ = s.db.Query(`SELECT run_id FROM runs ORDER BY 1`)
	for rows.Next() {
		var r string
		rows.Scan(&r)
		runsAfter = append(runsAfter, r)
	}
	rows.Close()
	if !reflect.DeepEqual(runsBefore, runsAfter) {
		t.Fatalf("run ids changed: %v -> %v", runsBefore, runsAfter)
	}
	var runOfEvents string
	s.db.QueryRow(`SELECT DISTINCT run_id FROM events`).Scan(&runOfEvents)
	if runOfEvents != "h1/"+defLabel {
		t.Fatalf("event run id = %q", runOfEvents)
	}
	if fs, _ := s.Findings(context.Background(), "h1"); len(fs) != 1 {
		t.Fatalf("findings disturbed: %v", fs)
	}
}

func TestRenameRefusesOverlapWithoutMerge(t *testing.T) {
	s := openTest(t)
	save(t, s, "h1/"+defLabel, docsAs(defLabel, 0, 6))
	save(t, s, "h2/ingress", docsAs("ingress", 4, 6))
	before := snapshot(t, s)

	for _, dry := range []bool{true, false} {
		res, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: defLabel, New: "ingress", DryRun: dry})
		if !errors.Is(err, core.ErrSourceOverlap) {
			t.Fatalf("dry=%v: err = %v, want ErrSourceOverlap", dry, err)
		}
		if res.Overlap != 2 || res.Applied {
			t.Fatalf("dry=%v: res = %+v", dry, res)
		}
		if after := snapshot(t, s); !reflect.DeepEqual(before, after) {
			t.Fatalf("dry=%v: a refused rename changed the store", dry)
		}
	}
}

func TestRenameMergeCountsAndDropsCollisions(t *testing.T) {
	s := openTest(t)
	// OLD holds 0..9; NEW holds 6..15: documents 6..9 collide.
	save(t, s, "h1/old", docsAs("old", 0, 10))
	save(t, s, "h2/new", docsAs("new", 6, 10))

	res, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: "old", New: "new", Merge: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 10 || res.NewEvents != 10 || res.Overlap != 4 || res.Dropped != 4 || res.Relabelled != 6 || !res.Applied {
		t.Fatalf("res = %+v", res)
	}
	got := collect(t, s.Events(context.Background(), wide))
	if len(got) != 16 {
		t.Fatalf("%d events, want 16 distinct documents (0..15)", len(got))
	}
	for _, e := range got {
		if e.Source != "new" {
			t.Fatalf("event still labelled %q", e.Source)
		}
	}
	var stored int
	s.db.QueryRow(`SELECT count(*) FROM events`).Scan(&stored)
	if stored != 16 {
		t.Fatalf("%d rows stored, want 16: collisions must be dropped, not merely hidden", stored)
	}
}

// Identical lines inside one run are real events. OLD holds a document twice, NEW once:
// the larger count wins as Events reads it, so both OLD copies survive: dropping one
// would renumber the other and the reader would see a single event.
func TestRenameMergeKeepsRepeatedLinesBeyondTheTargetsCount(t *testing.T) {
	s := openTest(t)
	one := docsAs("old", 0, 1)[0]
	save(t, s, "h1/old", []core.Event{one, one})
	other := one
	other.Source = "new"
	save(t, s, "h2/new", []core.Event{other})
	before := len(collect(t, s.Events(context.Background(), wide)))

	res, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: "old", New: "new", Merge: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Dropped != 0 || res.Relabelled != 2 {
		t.Fatalf("res = %+v, want nothing dropped and 2 relabelled", res)
	}
	if after := len(collect(t, s.Events(context.Background(), wide))); after != 2 {
		t.Fatalf("%d events after, want 2 (before the rename the reader saw %d under two labels)", after, before)
	}
}

func TestRenameIsAtomic(t *testing.T) {
	for _, step := range []string{"drop", "relabel"} {
		s := openTest(t)
		save(t, s, "h1/old", docsAs("old", 0, 10))
		save(t, s, "h2/new", docsAs("new", 6, 10))
		before := snapshot(t, s)

		boom := errors.New("simulated failure at " + step)
		renameHook = func(at string) error {
			if at == step {
				return boom
			}
			return nil
		}
		_, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: "old", New: "new", Merge: true})
		renameHook = nil
		if !errors.Is(err, boom) {
			t.Fatalf("step %s: err = %v", step, err)
		}
		if after := snapshot(t, s); !reflect.DeepEqual(before, after) {
			t.Fatalf("step %s: a rename that failed half way left changes behind", step)
		}
		// And the store is usable afterwards: the same rename now succeeds.
		if res, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: "old", New: "new", Merge: true}); err != nil || !res.Applied {
			t.Fatalf("step %s: retry: %+v %v", step, res, err)
		}
	}
}

func TestRenameInputs(t *testing.T) {
	s := openTest(t)
	save(t, s, "h1/old", docsAs("old", 0, 3))
	ctx := context.Background()
	if _, err := s.RenameSource(ctx, core.RenameSourceRequest{Old: "absent", New: "new"}); !errors.Is(err, core.ErrNoSuchSource) {
		t.Errorf("absent label: %v", err)
	}
	if _, err := s.RenameSource(ctx, core.RenameSourceRequest{Old: "old", New: "old"}); err == nil {
		t.Error("same label accepted")
	}
	if _, err := s.RenameSource(ctx, core.RenameSourceRequest{Old: "", New: "x"}); err == nil {
		t.Error("empty label accepted")
	}
}

func TestRenameReportsEventsWithoutRaw(t *testing.T) {
	s := openTest(t)
	evs := docsAs("old", 0, 4)
	evs[0].Raw, evs[1].Raw = nil, nil
	save(t, s, "h1/old", evs)
	res, err := s.RenameSource(context.Background(), core.RenameSourceRequest{Old: "old", New: "new", DryRun: true})
	if err != nil || res.NoRaw != 2 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestSourceOverlaps(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if ov, err := s.SourceOverlaps(ctx, wide, 10); err != nil || len(ov) != 0 {
		t.Fatalf("empty store: %v %v", ov, err)
	}
	// One label: nothing to report, however many events.
	save(t, s, "h1/a", docsAs("a", 0, 20))
	if ov, _ := s.SourceOverlaps(ctx, wide, 10); len(ov) != 0 {
		t.Fatalf("one label: %v", ov)
	}
	// A second label holding different documents is a legitimate second source.
	save(t, s, "h2/b", docsAs("b", 100, 20))
	if ov, _ := s.SourceOverlaps(ctx, wide, 10); len(ov) != 0 {
		t.Fatalf("two labels, no shared document: %v", ov)
	}
	// A third shares 5 documents with a.
	save(t, s, "h3/c", docsAs("c", 15, 10))
	ov, err := s.SourceOverlaps(ctx, wide, 10)
	if err != nil || len(ov) != 1 || ov[0].A != "a" || ov[0].B != "c" || ov[0].Docs != 5 {
		t.Fatalf("overlaps = %+v, %v", ov, err)
	}
	// The window bounds it: documents 15..19 live at base+15s..base+19s.
	early := core.Window{From: base, To: base.Add(10 * time.Second)}
	if ov, _ := s.SourceOverlaps(ctx, early, 10); len(ov) != 0 {
		t.Fatalf("overlap outside the window reported: %v", ov)
	}
	if ov, _ := s.SourceOverlaps(ctx, core.Window{}, 10); len(ov) != 0 {
		t.Fatalf("empty window: %v", ov)
	}
}
