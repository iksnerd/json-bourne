package app

import (
	"context"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// scopedSource is a fakeSource that reads a store others may read too.
type scopedSource struct {
	*fakeSource
	scope string
}

func (s scopedSource) DocScope() string { return s.scope }

func docEvents(src string, ids ...string) []core.Event {
	var out []core.Event
	for i, id := range ids {
		e := ev(src, t0.Add(-time.Duration(10+i)*time.Minute))
		e.DocKey = "idx/" + id
		out = append(out, e)
	}
	return out
}

func scoped(name, scope string, ids ...string) scopedSource {
	return scopedSource{&fakeSource{name: name, events: docEvents(name, ids...)}, scope}
}

func totalStored(m *memStore, run string, names ...string) int {
	n := 0
	for _, name := range names {
		n += len(m.runs[SourceRun(run, name)])
	}
	return n
}

// Two sources on one cluster whose filters overlap both return d2. The document is counted
// once: by the first source to read it, not stored twice, and the other source reports it
// as a duplicate instead of an event.
func TestHuntCountsAnOverlappingDocumentOnce(t *testing.T) {
	m := newMem()
	a := scoped("a", "https://es.example.com", "d1", "d2")
	b := scoped("b", "https://es.example.com", "d2", "d3")
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{a, b}, Detectors: []core.Detector{fakeDetector{"d", fixed()}}, Sink: m, Reader: m,
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	got := res.Sources[0].Events + res.Sources[1].Events
	dups := res.Sources[0].Duplicates + res.Sources[1].Duplicates
	if got != 3 || dups != 1 {
		t.Fatalf("events %d duplicates %d, want 3 distinct documents and 1 duplicate: %+v", got, dups, res.Sources)
	}
	if n := totalStored(m, "r", "a", "b"); n != 3 {
		t.Fatalf("%d events stored, want 3: the shared document must not be stored twice", n)
	}
	for _, s := range res.Sources {
		if s.Status != StatusOK {
			t.Errorf("source %s: %s %v", s.Name, s.Status, s.Err)
		}
	}
}

// A source whose every document another source already returned saved nothing, and the
// sink refuses an empty save. That is an answer, not a dead source.
func TestHuntFullyOverlappedSourceIsNotNoRecords(t *testing.T) {
	m := newMem()
	// Concurrency 1 makes the order, and so who keeps the documents, fixed.
	a := scoped("a", "https://es.example.com", "d1", "d2")
	b := scoped("b", "https://es.example.com", "d1", "d2")
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{a, b}, Detectors: []core.Detector{fakeDetector{"d", fixed()}}, Sink: m, Reader: m, Concurrency: 1,
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	if res.Sources[0].Events != 2 || res.Sources[1].Events != 0 || res.Sources[1].Duplicates != 2 || res.Sources[1].Status != StatusOK {
		t.Fatalf("sources = %+v", res.Sources)
	}
	if !res.Complete() {
		t.Fatalf("hunt incomplete: %v", res.Failed())
	}
	if res.Sources[1].Outcome() != "matched (2 already returned by another source)" {
		t.Errorf("outcome = %q", res.Sources[1].Outcome())
	}
}

// Same document key on different clusters is two documents, and an event without a key
// is never a duplicate.
func TestHuntDoesNotDedupeAcrossScopesOrWithoutAKey(t *testing.T) {
	m := newMem()
	a := scoped("a", "https://one.example.com", "d1")
	b := scoped("b", "https://two.example.com", "d1")
	c := okSource("c")
	d := okSource("d") // plain sources, no DocScope
	res, err := Hunt(context.Background(), Deps{
		Sources: []core.Source{a, b, c, d}, Detectors: []core.Detector{fakeDetector{"d", fixed()}}, Sink: m, Reader: m,
	}, "r", win())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Sources {
		if s.Duplicates != 0 {
			t.Errorf("source %s dropped %d as duplicates", s.Name, s.Duplicates)
		}
	}
	if n := totalStored(m, "r", "a", "b", "c", "d"); n != 6 {
		t.Fatalf("%d stored, want 6", n)
	}
}

func TestHuntKeepsNoDocumentMemoryForAScopeWithOneSource(t *testing.T) {
	srcs := []core.Source{scoped("a", "x", "d1"), scoped("b", "y", "d1"), okSource("c")}
	if got := sharedScopes(srcs); len(got) != 0 {
		t.Fatalf("shared scopes = %d, want none: one source per cluster needs no per-document memory", len(got))
	}
	srcs = append(srcs, scoped("e", "x", "d9"))
	if got := sharedScopes(srcs); len(got) != 1 || got["x"] == nil {
		t.Fatalf("shared scopes = %v, want exactly x", got)
	}
}

func TestDetectorCountsSplitActorAndCommon(t *testing.T) {
	d := ActivityDetector{Report: core.ActivityReport{Seen: 50, Subjects: []core.ActivitySubject{
		{Subject: "a", Kind: "actor", Current: 2, Previous: 1},
		{Subject: "r", Kind: "rare", Current: 3, Previous: 0},
		{Subject: "c", Kind: "common", Current: 40, Previous: 35},
	}}}
	c := d.Counts()
	want := DetectorCounts{Read: 50, Current: 5, Previous: 1, CommonCurrent: 40, CommonPrevious: 35}
	if c != want {
		t.Fatalf("counts = %+v, want %+v", c, want)
	}
}

// A common action is activity only when the detector marks it active, and then it is
// named; its volume alone neither makes the check ACTIVE nor counts as an actor event.
func TestAssessKeepsCommonTrafficApartAndNamesAFlaggedOne(t *testing.T) {
	quiet := core.ActivityReport{Seen: 100, Subjects: []core.ActivitySubject{
		{Subject: "login", Kind: "common", Current: 90, Previous: 80},
		{Subject: "device-code", Kind: "rare", Current: 0, Previous: 0},
	}}
	res := runActivity(t, []core.Source{okSource("a")}, repDetector{name: "beh", report: quiet})
	if res.Verdict != VerdictQuiet || res.Current != 0 || res.CommonCurrent != 90 || res.CommonPrevious != 80 || len(res.Flagged) != 0 {
		t.Fatalf("quiet: %+v", res)
	}
	flagged := core.ActivityReport{Seen: 100, Subjects: []core.ActivitySubject{
		{Subject: "login", Kind: "common", Current: 90, Previous: 80, Active: true, Last: t0.Add(-time.Minute)},
	}}
	res = runActivity(t, []core.Source{okSource("a")}, repDetector{name: "beh", report: flagged})
	if res.Verdict != VerdictActive || res.Current != 0 || len(res.Flagged) != 1 || res.Flagged[0] != "beh:login" {
		t.Fatalf("flagged: %+v", res)
	}
}
