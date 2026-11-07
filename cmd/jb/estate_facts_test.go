package main

import (
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

// editBaseline loads estate/base.yaml of the case at dir, lets f change it and saves it.
func editBaseline(t *testing.T, dir string, f func(e *casefile.Estate)) {
	t.Helper()
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casefile.LoadEstateFile(c, "base.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f(e)
	if err := casefile.SaveEstateFile(c, "base.yaml", e); err != nil {
		t.Fatal(err)
	}
}

func portFact(value string) casefile.Fact {
	return casefile.Fact{Key: "port.open", Value: value, Source: "scan-cache", Method: "import of a synthetic export", Observed: "2026-11-01T10:00:00Z"}
}

func nodeByID(e *casefile.Estate, id string) *casefile.Node {
	for i := range e.Nodes {
		if e.Nodes[i].ID == id {
			return &e.Nodes[i]
		}
	}
	return nil
}

// The whole drift path with facts: refresh carries the baseline's facts and assessments,
// diff compares facts as sets and never counts an assessment, promote keeps both.
func TestEstateRefreshDiffPromoteCarryFactsAndAssessments(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns", "bgp", "crt.sh")
	w := newWorld()
	w.baseline(t, dir)
	editBaseline(t, dir, func(e *casefile.Estate) {
		n := nodeByID(e, "domain:example.com")
		n.Facts = []casefile.Fact{portFact("22"), portFact("443")}
		e.Assessments = []casefile.Assessment{{ID: "a1", Subject: "domain:example.com", Label: "watch", By: "analyst", Decided: "2026-11-01T10:00:00Z", Basis: []string{"domain:example.com#port.open"}}}
	})

	w.tick()
	if code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code != 0 {
		t.Fatalf("refresh: exit %d\n%s\n%s", code, out, errs)
	}
	// Nothing observed changed and the facts were carried: no drift at all.
	code, d, raw, errs := runDiff(t, w, dir)
	if code != 0 || len(d.Changes) != 0 || len(d.NotComparable) != 0 {
		t.Fatalf("no drift expected: exit %d\n%s\n%s", code, raw, errs)
	}
	if d.Counts["facts"].Added+d.Counts["facts"].Removed+d.Counts["facts"].Changed != 0 {
		t.Errorf("facts counts: %+v", d.Counts)
	}
	if !strings.Contains(raw, `"facts": 2`) {
		t.Errorf("each side states how many facts it holds:\n%s", raw)
	}

	// The operator learns another open port after the snapshot: the baseline has one more
	// value than the snapshot, which is a lost value from the baseline to the snapshot.
	editBaseline(t, dir, func(e *casefile.Estate) {
		n := nodeByID(e, "domain:example.com")
		n.Facts = append(n.Facts, portFact("8080"))
	})
	code, d, raw, errs = runDiff(t, w, dir)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, raw, errs)
	}
	if got := d.Counts["facts"]; got.Removed != 1 || got.Added != 0 {
		t.Errorf("one fact value is gone from the later state: %+v\n%s", d.Counts, raw)
	}
	if len(d.Findings) != 0 {
		t.Errorf("fact drift raises no finding: %+v", d.Findings)
	}
	_, tbl, _ := run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml")
	if !strings.Contains(tbl, "domain:example.com#port.open") || !strings.Contains(tbl, "value 8080") {
		t.Errorf("table lacks the fact change:\n%s", tbl)
	}

	// The baseline was edited after that snapshot, so promoting it would silently drop the
	// new port: it is refused, and the operator refreshes again, which carries the fact.
	snaps := snapshotFiles(t, dir)
	id := strings.TrimSuffix(snaps[len(snaps)-1], ".yaml")
	if code, _, errs := run(t, w.deps(), "estate", "promote", "--case", dir, "--file", "base.yaml", id); code == 0 || !strings.Contains(errs, "baseline changed since the snapshot; refresh again") {
		t.Fatalf("promote of a stale snapshot must be refused: exit %d\n%s", code, errs)
	}
	w.tick()
	if code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml"); code != 0 {
		t.Fatalf("second refresh: exit %d\n%s\n%s", code, out, errs)
	}
	snaps = snapshotFiles(t, dir)
	id = strings.TrimSuffix(snaps[len(snaps)-1], ".yaml")
	if code, out, errs := run(t, w.deps(), "estate", "promote", "--case", dir, "--file", "base.yaml", id); code != 0 {
		t.Fatalf("promote: exit %d\n%s\n%s", code, out, errs)
	}
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casefile.LoadEstateFile(c, "base.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if n := nodeByID(e, "domain:example.com"); n == nil || len(n.Facts) != 3 || len(e.Assessments) != 1 {
		t.Errorf("promotion must keep the carried facts and assessment: %+v %+v", n, e.Assessments)
	}
}
