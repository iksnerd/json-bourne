package app

import (
	"context"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

const (
	fm1 = "export of synthetic scan store A"
	fm2 = "export of synthetic scan store B"
)

func fact(key, value, method, at string) casefile.Fact {
	return casefile.Fact{Key: key, Value: value, Source: "scan-cache", Method: method, Observed: at}
}

func withFacts(e *casefile.Estate, nodeID string, fs ...casefile.Fact) *casefile.Estate {
	for i := range e.Nodes {
		if e.Nodes[i].ID == nodeID {
			e.Nodes[i].Facts = append(e.Nodes[i].Facts, fs...)
		}
	}
	return e
}

func hostEstate(at string, fs ...casefile.Fact) *casefile.Estate {
	e := newEst([]casefile.Node{dn("ip:192.0.2.10", "ip", "dns", mA, at)}, nil, nil)
	return withFacts(e, "ip:192.0.2.10", fs...)
}

func factChanges(d EstateDiff) []EstateChange {
	var out []EstateChange
	for _, c := range d.Changes {
		if c.Type == ItemFact {
			out = append(out, c)
		}
	}
	return out
}

// A port list that gains an entry is one added value, not a replaced list.
func TestDiffFactGainedValue(t *testing.T) {
	from := state("estate.yaml", hostEstate(t1, fact("port.open", "22", fm1, t1), fact("port.open", "443", fm1, t1)))
	to := state("20261106T100000Z", hostEstate(t2, fact("port.open", "22", fm1, t2), fact("port.open", "443", fm1, t2), fact("port.open", "8080", fm1, t2)))
	d := mustDiff(t, from, to)
	got := factChanges(d)
	if len(got) != 1 {
		t.Fatalf("want one added value, got %+v", d.Changes)
	}
	c := got[0]
	if c.Kind != ChangeAdded || c.Value != "8080" || c.Subject != "ip:192.0.2.10#port.open" || c.Source != "scan-cache" || c.Method != fm1 {
		t.Errorf("%+v", c)
	}
	if c.FromObserved != t1 || c.ToObserved != t2 {
		t.Errorf("both observation times are required: %+v", c)
	}
	if d.Compared != 2 { // the dns question and the one fact group
		t.Errorf("compared %d", d.Compared)
	}
	if d.Count(ChangeAdded, ItemFact) != 1 || len(d.NotComparable) != 0 {
		t.Errorf("%+v", d)
	}
}

func TestDiffFactLostValue(t *testing.T) {
	from := state("estate.yaml", hostEstate(t1, fact("port.open", "22", fm1, t1), fact("port.open", "23", fm1, t1)))
	to := state("20261106T100000Z", hostEstate(t2, fact("port.open", "22", fm1, t2)))
	d := mustDiff(t, from, to)
	got := factChanges(d)
	if len(got) != 1 || got[0].Kind != ChangeRemoved || got[0].Value != "23" || got[0].FromObserved != t1 || got[0].ToObserved != t2 {
		t.Fatalf("%+v", d.Changes)
	}
}

// A group that exists on one side only (another source note, another key, or a node's
// facts that appear for the first time) is listed, never counted as drift.
func TestDiffFactGroupOnOneSideOnlyIsListedNotDrift(t *testing.T) {
	from := state("estate.yaml", hostEstate(t1, fact("port.open", "22", fm1, t1)))
	to := state("20261106T100000Z", hostEstate(t2, fact("port.open", "22", fm2, t2), fact("os", "linux", fm1, t2)))
	d := mustDiff(t, from, to)
	if len(factChanges(d)) != 0 {
		t.Fatalf("a group on one side only is not drift: %+v", d.Changes)
	}
	var fromOnly, toOnly int
	for _, n := range d.NotComparable {
		if n.Subject == "" {
			continue
		}
		switch {
		case n.Side == "from only" && n.Subject == "ip:192.0.2.10#port.open" && n.Method == fm1 && n.Claims == 1:
			fromOnly++
		case n.Side == "to only" && n.Claims == 1 && (n.Subject == "ip:192.0.2.10#port.open" && n.Method == fm2 || n.Subject == "ip:192.0.2.10#os" && n.Method == fm1):
			toOnly++
		}
	}
	if fromOnly != 1 || toOnly != 2 {
		t.Errorf("each group must be listed once: %+v", d.NotComparable)
	}
	if fs := DriftFindings(d); len(fs) != 0 {
		t.Errorf("fact drift raises no finding: %+v", fs)
	}
}

// Observed time alone is not a change, and the order of facts does not matter.
func TestDiffFactSetIgnoresOrderAndTime(t *testing.T) {
	from := state("estate.yaml", hostEstate(t1, fact("port.open", "22", fm1, t1), fact("port.open", "443", fm1, t1)))
	to := state("20261106T100000Z", hostEstate(t2, fact("port.open", "443", fm1, t2), fact("port.open", "22", fm1, t2)))
	if got := factChanges(mustDiff(t, from, to)); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

// Assessments are opinion: adding, removing or changing one is not drift.
func TestDiffIgnoresAssessments(t *testing.T) {
	base := hostEstate(t1, fact("port.open", "22", fm1, t1))
	other := hostEstate(t1, fact("port.open", "22", fm1, t1))
	other.Assessments = []casefile.Assessment{{ID: "a1", Subject: "ip:192.0.2.10", Label: "suspicious", By: "analyst", Decided: t2, Basis: []string{"ip:192.0.2.10#port.open"}}}
	d := mustDiff(t, state("estate.yaml", base), state("20261106T100000Z", other))
	if len(d.Changes) != 0 || len(d.NotComparable) != 0 {
		t.Fatalf("an assessment change is not drift: %+v %+v", d.Changes, d.NotComparable)
	}
}

// The collectors write no facts, so a refresh carries the baseline's facts through
// unchanged (same value, source, method and observed time) and does not re-ask them.
func TestRefreshCarriesBaselineFactsAndResolvableAssessments(t *testing.T) {
	base := refreshBase()
	base = withFacts(base, "domain:example.com", fact("tech", "synthetic-cms", fm1, t1))
	base = withFacts(base, "host:ns1.example.com", fact("os", "synthetic-os", fm1, t1))
	base.Assessments = []casefile.Assessment{
		{ID: "a1", Subject: "domain:example.com", Label: "watch", By: "analyst", Decided: t1, Basis: []string{"domain:example.com#tech"}},
	}
	f, b := &fakeFwd{ns: map[string][]string{"example.com": {"ns2.example.com"}}}, &fakeBGP{} // ns1 is gone from the answer
	snap, err := RefreshEstate(context.Background(), refreshDeps(f, b, "dns"), RefreshRequest{BasedOnSHA256: testDigest, Base: base, MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	var dom, ns1 *casefile.Node
	for i := range snap.Estate.Nodes {
		switch snap.Estate.Nodes[i].ID {
		case "domain:example.com":
			dom = &snap.Estate.Nodes[i]
		case "host:ns1.example.com":
			ns1 = &snap.Estate.Nodes[i]
		}
	}
	if dom == nil || len(dom.Facts) != 1 || dom.Facts[0] != fact("tech", "synthetic-cms", fm1, t1) {
		t.Fatalf("the baseline fact must be carried unchanged: %+v", dom)
	}
	if ns1 != nil {
		t.Fatalf("test setup: ns1 should be absent from the new answer: %+v", ns1)
	}
	if len(snap.Estate.Assessments) != 1 {
		t.Errorf("an assessment that still resolves is carried: %+v", snap.Estate.Assessments)
	}
	if _, err := casefile.MarshalEstateSnapshot(snap); err != nil {
		t.Errorf("the snapshot must stay loadable: %v", err)
	}
	// An assessment whose subject is gone from the snapshot is dropped (the archive keeps it).
	base.Assessments = append(base.Assessments, casefile.Assessment{ID: "a2", Subject: "host:ns1.example.com", Label: "watch", By: "analyst", Decided: t1, Basis: []string{"host:ns1.example.com#os"}})
	snap, err = RefreshEstate(context.Background(), refreshDeps(f, b, "dns"), RefreshRequest{BasedOnSHA256: testDigest, Base: base, MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Estate.Assessments) != 1 || snap.Estate.Assessments[0].ID != "a1" {
		t.Errorf("%+v", snap.Estate.Assessments)
	}
	if _, err := casefile.MarshalEstateSnapshot(snap); err != nil {
		t.Errorf("the snapshot must stay loadable: %v", err)
	}
}

func TestDriftSideCountsFacts(t *testing.T) {
	e := hostEstate(t1, fact("port.open", "22", fm1, t1), fact("os", "linux", fm1, t1))
	d := mustDiff(t, state("a", e), state("b", e))
	if d.From.Facts != 2 || d.To.Facts != 2 {
		t.Errorf("%+v %+v", d.From, d.To)
	}
}
