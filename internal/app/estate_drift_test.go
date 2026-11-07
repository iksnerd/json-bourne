package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	t1 = "2026-11-01T10:00:00Z"
	t2 = "2026-11-06T10:00:00Z"
	mA = "NS example.com via resolver 192.0.2.53:53"
	mB = "NS example.com via resolver 198.51.100.53:53"
)

func newEst(nodes []casefile.Node, edges []casefile.Edge, abs []casefile.Absence) *casefile.Estate {
	return &casefile.Estate{APIVersion: casefile.EstateAPIVersion, ID: "estate", Caveat: casefile.DefaultEstateCaveat, Nodes: nodes, Edges: edges, Absences: abs}
}

func dn(id, kind, src, method, at string) casefile.Node {
	return casefile.Node{ID: id, Kind: kind, Label: strings.TrimPrefix(id, kind+":"), Source: src, Method: method, Observed: at}
}

func de(from, to, rel, src, method, at string) casefile.Edge {
	return casefile.Edge{From: from, To: to, Relation: rel, Source: src, Method: method, Observed: at}
}

func state(ref string, e *casefile.Estate) *casefile.EstateState {
	return &casefile.EstateState{Ref: ref, Path: "estate/" + ref, Estate: e}
}

// nsEstate is example.com's NS set under one method at one time.
func nsEstate(method, at string, ns ...string) *casefile.Estate {
	nodes := []casefile.Node{dn("domain:example.com", "domain", "dns", method, at)}
	var edges []casefile.Edge
	for _, n := range ns {
		nodes = append(nodes, dn("host:"+n, "host", "dns", method, at))
		edges = append(edges, de("domain:example.com", "host:"+n, "ns", "dns", method, at))
	}
	return newEst(nodes, edges, nil)
}

func mustDiff(t *testing.T, a, b *casefile.EstateState) EstateDiff {
	t.Helper()
	d, err := DiffEstates(a, b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The rule this feature exists for: a change of method or resolver is not a change of
// the world. Break it (group by source alone) and this test must fail.
func TestDiffComparesOnlySameSourceAndMethod(t *testing.T) {
	from := state("estate.yaml", nsEstate(mA, t1, "ns1.example.com", "ns2.example.com"))
	to := state("20261106T100000Z", nsEstate(mB, t2, "ns1.example.net")) // another resolver says something else
	d := mustDiff(t, from, to)
	if d.Count(ChangeAdded, ItemEdge)+d.Count(ChangeRemoved, ItemEdge) != 0 {
		t.Fatalf("a different resolver is not drift: %+v", d.Changes)
	}
	if len(DriftFindings(d)) != 0 {
		t.Errorf("no finding may come from a method change: %+v", DriftFindings(d))
	}
	if d.Compared != 0 {
		t.Errorf("compared %d questions, want 0", d.Compared)
	}
	var fromOnly, toOnly int
	for _, n := range d.NotComparable {
		switch {
		case n.Side == "from only" && n.Method == mA && n.Claims == 5:
			fromOnly++
		case n.Side == "to only" && n.Method == mB && n.Claims == 3:
			toOnly++
		}
	}
	if fromOnly != 1 || toOnly != 1 {
		t.Errorf("both questions must be listed as not comparable with their claim counts: %+v", d.NotComparable)
	}
}

func TestDiffReportsAddedRemovedWithBothTimestamps(t *testing.T) {
	from := state("estate.yaml", nsEstate(mA, t1, "ns1.example.com", "ns2.example.com"))
	to := state("20261106T100000Z", nsEstate(mA, t2, "ns1.example.com", "ns3.example.com"))
	d := mustDiff(t, from, to)
	if d.Compared != 1 || len(d.NotComparable) != 0 {
		t.Fatalf("compared %d, not comparable %+v", d.Compared, d.NotComparable)
	}
	var added, removed *EstateChange
	for i, c := range d.Changes {
		if c.Type == ItemEdge && c.Kind == ChangeAdded {
			added = &d.Changes[i]
		}
		if c.Type == ItemEdge && c.Kind == ChangeRemoved {
			removed = &d.Changes[i]
		}
	}
	if added == nil || removed == nil {
		t.Fatalf("want one added and one removed edge: %+v", d.Changes)
	}
	if added.To != "host:ns3.example.com" || added.FromObserved != t1 || added.ToObserved != t2 {
		t.Errorf("added: %+v (the earlier side's observation of that question was %s)", added, t1)
	}
	if removed.To != "host:ns2.example.com" || removed.FromObserved != t1 || removed.ToObserved != t2 {
		t.Errorf("removed: %+v", removed)
	}
	if d.Count(ChangeAdded, ItemNode) != 1 || d.Count(ChangeRemoved, ItemNode) != 1 {
		t.Errorf("node ns3 added and ns2 removed: %+v", d.Changes)
	}
	if d.From.Observed != t1 || d.To.Observed != t2 || d.From.Edges != 2 {
		t.Errorf("sides must state what was compared: %+v %+v", d.From, d.To)
	}
}

func TestDiffAbsenceParticipates(t *testing.T) {
	mAAAA := "AAAA example.com via resolver 192.0.2.53:53"
	absent := newEst([]casefile.Node{dn("domain:example.com", "domain", "dns", mAAAA, t1)}, nil,
		[]casefile.Absence{{Subject: "domain:example.com", Source: "dns", Method: mAAAA, Observed: t1, Answer: casefile.AbsenceAnswer}})
	present := newEst([]casefile.Node{dn("domain:example.com", "domain", "dns", mAAAA, t2), dn("ip:2001:db8::1", "ip", "dns", mAAAA, t2)},
		[]casefile.Edge{de("domain:example.com", "ip:2001:db8::1", "resolves_to", "dns", mAAAA, t2)}, nil)

	d := mustDiff(t, state("a", absent), state("b", present))
	var got *EstateChange
	for i, c := range d.Changes {
		if c.Type == ItemAbsence {
			got = &d.Changes[i]
		}
	}
	if got == nil || got.Kind != ChangeChanged || !strings.Contains(got.Detail, "was absent") || got.FromObserved != t1 || got.ToObserved != t2 {
		t.Fatalf("absent -> present must be a change with both timestamps: %+v", d.Changes)
	}
	if d.Count(ChangeAdded, ItemEdge) != 1 {
		t.Errorf("the new address is an added edge: %+v", d.Changes)
	}
	f := DriftFindings(d)
	if len(f) != 1 || f[0].Severity != core.SevActivity {
		t.Errorf("an address appearing is activity: %+v", f)
	}

	back := mustDiff(t, state("b", present), state("a", absent))
	var gone *EstateChange
	for i, c := range back.Changes {
		if c.Type == ItemAbsence {
			gone = &back.Changes[i]
		}
	}
	if gone == nil || !strings.Contains(gone.Detail, "now absent") {
		t.Fatalf("present -> absent must be a change: %+v", back.Changes)
	}
	// Absent on both sides is not a change.
	if same := mustDiff(t, state("a", absent), state("a2", absent)); len(same.Changes) != 0 {
		t.Errorf("unchanged absence reported: %+v", same.Changes)
	}
}

func TestDiffLabelChangeAndNodesRecordedByAnotherMethod(t *testing.T) {
	n1 := dn("org:ex", "org", "rdap", "GET https://rdap.example.com/ip/192.0.2.1", t1)
	n1.Label = "Example Old Name"
	n2 := n1
	n2.Label, n2.Observed = "Example New Name", t2
	e1 := newEst([]casefile.Node{n1, dn("ip:192.0.2.1", "ip", "rdap", n1.Method, t1)}, nil, nil)
	e2 := newEst([]casefile.Node{n2, dn("ip:192.0.2.1", "ip", "rdap", n1.Method, t2)}, nil, nil)
	d := mustDiff(t, state("a", e1), state("b", e2))
	if d.Count(ChangeChanged, ItemNode) != 1 || !strings.Contains(d.Changes[0].Detail, "Example New Name") {
		t.Fatalf("a label change under the same method is a change: %+v", d.Changes)
	}
	// Same id, but each side learned it through a different question: not compared, and said so.
	other := n2
	other.Source, other.Method = "bgp", "GET https://bgp.example.com/x"
	e3 := newEst([]casefile.Node{other}, nil, nil)
	d = mustDiff(t, state("a", e1), state("c", e3))
	if d.NodesNotCompared != 1 || d.Count(ChangeChanged, ItemNode) != 0 {
		t.Errorf("node recorded under another method must be counted as not compared: %+v", d)
	}
	found := false
	for _, n := range d.NotComparable {
		found = found || n.Side == "both"
	}
	if !found {
		t.Errorf("not-compared nodes must be listed: %+v", d.NotComparable)
	}
}

func TestDiffRefusesAnIncompleteSnapshot(t *testing.T) {
	inc := &casefile.EstateSnapshot{ID: "20261106T100000Z", Complete: false, Failures: []casefile.SnapshotFailure{{Target: "example.com", Lookup: "dns/MX", Reason: "timeout"}}}
	bad := &casefile.EstateState{Ref: inc.ID, Estate: nsEstate(mA, t2, "ns1.example.com"), Snapshot: inc}
	for _, pair := range [][2]*casefile.EstateState{{state("estate.yaml", nsEstate(mA, t1, "ns1.example.com")), bad}, {bad, state("estate.yaml", nsEstate(mA, t1))}} {
		if _, err := DiffEstates(pair[0], pair[1]); !errors.Is(err, ErrIncompleteSnapshot) {
			t.Errorf("an incomplete snapshot must be refused on either side, got %v", err)
		}
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	from := nsEstate(mA, t1, "ns1.example.com", "ns2.example.com", "ns4.example.com")
	to := nsEstate(mA, t2, "ns1.example.com", "ns3.example.com", "ns5.example.com")
	want := ""
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 30; i++ {
		f, g := *from, *to
		for _, e := range []*casefile.Estate{&f, &g} {
			e.Nodes = append([]casefile.Node(nil), e.Nodes...)
			e.Edges = append([]casefile.Edge(nil), e.Edges...)
			r.Shuffle(len(e.Nodes), func(a, b int) { e.Nodes[a], e.Nodes[b] = e.Nodes[b], e.Nodes[a] })
			r.Shuffle(len(e.Edges), func(a, b int) { e.Edges[a], e.Edges[b] = e.Edges[b], e.Edges[a] })
		}
		d := mustDiff(t, state("a", &f), state("b", &g))
		b, _ := json.Marshal(struct {
			D EstateDiff
			F []core.Finding
		}{d, DriftFindings(d)})
		if want == "" {
			want = string(b)
		} else if string(b) != want {
			t.Fatalf("output depends on input order:\n%s\n%s", want, b)
		}
	}
}

func TestDriftFindingSeveritiesTagsAndSummaries(t *testing.T) {
	mx := "MX example.com via r"
	ct := "GET https://ct.example.com/?q=%25.example.com"
	asn := "GET https://bgp.example.com/ip/192.0.2.10"
	build := func(at string, mxHost, origin string, ctNames ...string) *casefile.Estate {
		e := newEst([]casefile.Node{
			dn("domain:example.com", "domain", "dns", mx, at), dn("host:"+mxHost, "host", "dns", mx, at),
			dn("network:192.0.2.0/24", "network", "bgp", asn, at), dn("asn:"+origin, "asn", "bgp", asn, at),
			dn("host:placeholder.example.com", "host", "crt.sh", ct, at),
		}, []casefile.Edge{
			de("domain:example.com", "host:"+mxHost, "mx", "dns", mx, at),
			de("network:192.0.2.0/24", "asn:"+origin, "originated_by", "bgp", asn, at),
		}, nil)
		for _, n := range ctNames {
			e.Nodes = append(e.Nodes, dn("host:"+n, "host", "crt.sh", ct, at))
			e.Edges = append(e.Edges, casefile.Edge{From: "domain:example.com", To: "host:" + n, Relation: "ct_candidate", Source: "crt.sh", Method: ct, Observed: at, Confidence: "inferred", InferredFrom: "name on a certificate"})
		}
		return e
	}
	from := state("estate.yaml", build(t1, "mail.example.com", "as64500"))
	to := state("20261106T100000Z", build(t2, "mail2.example.com", "as64501", "new1.example.com", "new2.example.com"))
	d := mustDiff(t, from, to)
	got := map[string]core.Finding{}
	for _, f := range DriftFindings(d) {
		got[f.Detail["class"].(string)] = f
	}
	want := map[string]core.Severity{"mx": core.SevHigh, "origin": core.SevHigh, "ct": core.SevCheck}
	for class, sev := range want {
		f, ok := got[class]
		if !ok || f.Severity != sev || f.Detector != DriftDetector {
			t.Errorf("%s: want severity %s, got %+v", class, core.SeverityName(sev), f)
		}
		if !strings.HasPrefix(f.Tag, "estate_drift:"+class+":") {
			t.Errorf("tag %q must be detector, class, subject", f.Tag)
		}
	}
	if len(got) != 3 {
		t.Errorf("only mx, origin and ct raise findings here: %v", got)
	}
	for _, f := range got {
		for _, leak := range []string{"mail", "as6450", "new1", "new2"} {
			if strings.Contains(f.Summary, leak) {
				t.Errorf("summary %q must hold the subject and counts only, not %q", f.Summary, leak)
			}
		}
	}
	if s := got["ct"].Summary; !strings.Contains(s, "2 new candidate") || !strings.Contains(s, "not live hosts") {
		t.Errorf("ct summary: %q", s)
	}
	if s := got["mx"].Summary; !strings.Contains(s, "domain:example.com") || !strings.Contains(s, "+1") || !strings.Contains(s, "-1") {
		t.Errorf("mx summary: %q", s)
	}
	// Same drift on a later run: same tags (so dedupe holds). Another change: a new tag.
	again := mustDiff(t, from, state("20261107T100000Z", build("2026-11-07T10:00:00Z", "mail2.example.com", "as64501", "new1.example.com", "new2.example.com")))
	for _, f := range DriftFindings(again) {
		if got[f.Detail["class"].(string)].Tag != f.Tag {
			t.Errorf("tag changed between runs of the same drift: %s", f.Tag)
		}
	}
	further := mustDiff(t, from, state("20261108T100000Z", build("2026-11-08T10:00:00Z", "mail3.example.com", "as64501", "new1.example.com", "new2.example.com")))
	for _, f := range DriftFindings(further) {
		if f.Detail["class"] == "mx" && f.Tag == got["mx"].Tag {
			t.Errorf("a further change of the same subject must not reuse the old tag")
		}
	}
}

func TestDriftFindingsRemovedCTNameIsQuietAndAddressIsActivity(t *testing.T) {
	ct := "GET https://ct.example.com/?q=%25.example.com"
	a := "A example.com via r"
	with := newEst([]casefile.Node{dn("domain:example.com", "domain", "crt.sh", ct, t1), dn("host:old.example.com", "host", "crt.sh", ct, t1),
		dn("ip:192.0.2.1", "ip", "dns", a, t1)},
		[]casefile.Edge{{From: "domain:example.com", To: "host:old.example.com", Relation: "ct_candidate", Source: "crt.sh", Method: ct, Observed: t1, Confidence: "inferred", InferredFrom: "x"},
			de("domain:example.com", "ip:192.0.2.1", "resolves_to", "dns", a, t1)}, nil)
	without := newEst([]casefile.Node{dn("domain:example.com", "domain", "crt.sh", ct, t2), dn("ip:192.0.2.2", "ip", "dns", a, t2)},
		[]casefile.Edge{de("domain:example.com", "ip:192.0.2.2", "resolves_to", "dns", a, t2)}, nil)
	f := DriftFindings(mustDiff(t, state("a", with), state("b", without)))
	if len(f) != 1 || f[0].Severity != core.SevActivity || !strings.Contains(f[0].Detail["note"].(string), "CDN") {
		t.Fatalf("a removed CT name is not a finding; an address change is activity and says it is not ownership: %+v", f)
	}
}

// ---- targets, refresh, promote ----

func TestEstateTargetsReadOnlyWhatWasAsked(t *testing.T) {
	dnsM, ctM, ptrM := "A example.com via r", "GET https://ct.example.com/?q=%25.example.com", "PTR 10.2.0.192.in-addr.arpa via r"
	bipM, basnM := "GET https://bgp.example.com/ip/192.0.2.77", "GET https://bgp.example.com/AS64500"
	e := newEst([]casefile.Node{
		dn("domain:example.com", "domain", "dns", dnsM, t1), dn("domain:spf.example.net", "domain", "dns", dnsM, t1),
		dn("ip:192.0.2.10", "ip", "rdns", ptrM, t1), dn("host:ptr.example.com", "host", "rdns", ptrM, t1),
		dn("ip:192.0.2.77", "ip", "bgp", bipM, t1), dn("network:192.0.2.0/24", "network", "bgp", bipM, t1),
		dn("asn:as64500", "asn", "bgp", bipM, t1), dn("asn:as64999", "asn", "bgp", basnM, t1), dn("network:198.51.100.0/24", "network", "bgp", basnM, t1),
		dn("domain:ct.example.org", "domain", "crt.sh", ctM, t1),
	}, []casefile.Edge{
		de("domain:example.com", "domain:spf.example.net", "spf_include", "dns", dnsM, t1),
		de("domain:example.com", "ip:192.0.2.5", "resolves_to", "dns", dnsM, t1),
		de("ip:192.0.2.10", "host:ptr.example.com", "ptr", "rdns", ptrM, t1),
		de("ip:192.0.2.77", "network:192.0.2.0/24", "announced_in", "bgp", bipM, t1),
		de("network:192.0.2.0/24", "asn:as64500", "originated_by", "bgp", bipM, t1),
		de("network:198.51.100.0/24", "asn:as64999", "originated_by", "bgp", basnM, t1),
	}, nil)
	got := EstateTargets(e)
	eq := func(name string, g, w []string) {
		if strings.Join(g, ",") != strings.Join(w, ",") {
			t.Errorf("%s: got %v want %v", name, g, w)
		}
	}
	eq("dns", got.DNS, []string{"example.com"}) // the SPF include was an answer, not a question
	eq("ct", got.CT, []string{"ct.example.org"})
	eq("addresses", got.Addresses, []string{"192.0.2.10"}) // a PTR target and an A answer were not asked about
	eq("bgp ips", got.BGPIPs, []string{"192.0.2.77"})
	eq("bgp asns", got.BGPASNs, []string{"AS64999"}) // AS64500 was only the origin of an address question
}

type fakeFwd struct {
	ns     map[string][]string
	failMX bool
	asked  []string
}

func (f *fakeFwd) Lookup(_ context.Context, name string, t core.DNSType) (core.DNSAnswer, error) {
	f.asked = append(f.asked, string(t)+" "+name)
	a := core.DNSAnswer{Query: fmt.Sprintf("%s %s via fake resolver", t, name)}
	switch {
	case t == core.DNSMX && f.failMX:
		return a, fmt.Errorf("%w: SERVFAIL", core.ErrLookupFailed)
	case t == core.DNSNS:
		a.Values = f.ns[name]
		return a, nil
	}
	return a, fmt.Errorf("%w: none", core.ErrNotFound)
}

type fakeBGP struct{ asked []string }

func (f *fakeBGP) LookupASN(_ context.Context, n uint32) (core.BGPAnnouncement, error) {
	f.asked = append(f.asked, fmt.Sprint("AS", n))
	return core.BGPAnnouncement{Query: "GET https://bgp.example.com/AS", Holder: core.BGPHolder{ASN: n, Holder: "EXAMPLE-AS"}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, nil
}
func (f *fakeBGP) LookupIP(context.Context, netip.Addr) (core.BGPOrigin, error) {
	return core.BGPOrigin{}, errors.New("unused")
}

func refreshBase() *casefile.Estate {
	m := "NS example.com via fake resolver"
	b := "GET https://bgp.example.com/AS"
	return newEst([]casefile.Node{dn("domain:example.com", "domain", "dns", m, t1), dn("host:ns1.example.com", "host", "dns", m, t1),
		dn("asn:as64500", "asn", "bgp", b, t1), dn("network:192.0.2.0/24", "network", "bgp", b, t1)},
		[]casefile.Edge{de("domain:example.com", "host:ns1.example.com", "ns", "dns", m, t1), de("network:192.0.2.0/24", "asn:as64500", "originated_by", "bgp", b, t1)}, nil)
}

func refreshDeps(f *fakeFwd, b *fakeBGP, enabled ...string) RefreshDeps {
	return RefreshDeps{
		Ext:     ExternalDeps{DNS: f, BGP: b, Now: func() time.Time { return mustTime(t2) }, Sleep: func(context.Context, time.Duration) error { return nil }},
		Enabled: func(s string) bool { return slices.Contains(enabled, s) },
		Now:     func() time.Time { return mustTime(t2) },
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestRefreshSkipsDisabledServicesAndListsThem(t *testing.T) {
	f, b := &fakeFwd{ns: map[string][]string{"example.com": {"ns1.example.com"}}}, &fakeBGP{}
	snap, err := RefreshEstate(context.Background(), refreshDeps(f, b, "dns"), RefreshRequest{BasedOnSHA256: testDigest, Base: refreshBase(), BasedOn: "estate/estate.yaml", MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.asked) != 0 {
		t.Errorf("bgp is not enabled, nothing may be sent: %v", b.asked)
	}
	state := map[string]string{}
	for _, s := range snap.Services {
		state[s.Name] = s.State
	}
	if state["bgp"] != casefile.ServiceSkipped || state["dns"] != casefile.ServiceRan || state["crt.sh"] != casefile.ServiceNone || state["rdap"] != casefile.ServiceNone {
		t.Errorf("services must all be listed with what happened: %+v", snap.Services)
	}
	for _, s := range snap.Services {
		if s.State == casefile.ServiceSkipped && !strings.Contains(s.Reason, "not enabled") {
			t.Errorf("skip reason: %+v", s)
		}
	}
	if !snap.Complete {
		t.Errorf("a skipped service is not a failed lookup, but it must not be promotable: %+v", snap.Failures)
	}
	if snap.ID != "20261106T100000Z" || snap.Taken != t2 {
		t.Errorf("id/taken: %s %s", snap.ID, snap.Taken)
	}
	if _, err := casefile.MarshalEstateSnapshot(snap); err != nil {
		t.Errorf("the snapshot must be loadable: %v", err)
	}
}

func TestRefreshFailedLookupMakesTheSnapshotIncomplete(t *testing.T) {
	f, b := &fakeFwd{ns: map[string][]string{"example.com": {"ns1.example.com"}}, failMX: true}, &fakeBGP{}
	snap, err := RefreshEstate(context.Background(), refreshDeps(f, b, "dns", "bgp"), RefreshRequest{BasedOnSHA256: testDigest, Base: refreshBase(), MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Complete || len(snap.Failures) != 1 || snap.Failures[0].Lookup != "dns/MX" {
		t.Fatalf("a failed lookup must make the snapshot incomplete and be named: %+v", snap)
	}
	for _, n := range snap.Estate.Nodes {
		if strings.Contains(n.Method, "MX") {
			t.Errorf("a failed lookup stores nothing: %+v", n)
		}
	}
	if _, err := casefile.MarshalEstateSnapshot(snap); err != nil {
		t.Errorf("an incomplete snapshot must still be writable: %v", err)
	}
}

func TestRefreshRefusesTooManyTargetsAndNoTargets(t *testing.T) {
	f, b := &fakeFwd{}, &fakeBGP{}
	_, err := RefreshEstate(context.Background(), refreshDeps(f, b, "dns", "bgp"), RefreshRequest{BasedOnSHA256: testDigest, Base: refreshBase(), MaxTargets: 1})
	if !errors.Is(err, ErrTooManyTargets) || len(f.asked)+len(b.asked) != 0 {
		t.Errorf("a longer list is refused before anything is asked: %v asked %v %v", err, f.asked, b.asked)
	}
	_, err = RefreshEstate(context.Background(), refreshDeps(f, b), RefreshRequest{BasedOnSHA256: testDigest, Base: newEst([]casefile.Node{dn("host:x.example.com", "host", "dns", "m", t1)}, nil, nil), MaxTargets: 5})
	if !errors.Is(err, ErrNoTargets) {
		t.Errorf("an estate with nothing to ask again: %v", err)
	}
}

// ---- delivery ----

type driftState struct{ s core.WatchState }

func (m *driftState) Load(context.Context) (core.WatchState, error) { return m.s, nil }
func (m *driftState) Save(_ context.Context, s core.WatchState) error {
	m.s = s
	return nil
}

type driftSink struct{ got []core.Alert }

func (m *driftSink) Deliver(_ context.Context, a core.Alert) error {
	m.got = append(m.got, a)
	return nil
}

func TestDeliverDriftDedupesByTagAndRepeatsAfterTTLOrSeverityRise(t *testing.T) {
	st, sink := &driftState{}, &driftSink{}
	now := mustTime(t2)
	f := core.Finding{Detector: DriftDetector, Tag: "estate_drift:ns:domain:example.com:abcd1234", Severity: core.SevActivity, Summary: "estate drift: x"}
	deliver := func(at time.Time, fs ...core.Finding) DriftDelivery {
		t.Helper()
		r, err := DeliverDrift(context.Background(), st, sink, at, time.Hour, "run", fs)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := deliver(now, f); r.New != 1 || len(sink.got) != 1 || sink.got[0].Text != f.Summary {
		t.Fatalf("first sight alerts: %+v", r)
	}
	if r := deliver(now.Add(10*time.Minute), f); r.New != 0 || r.Suppressed != 1 || len(sink.got) != 1 {
		t.Errorf("the same drift within the ttl is held back: %+v", r)
	}
	up := f
	up.Severity = core.SevHigh
	if r := deliver(now.Add(20*time.Minute), up); r.New != 1 {
		t.Errorf("a severity rise alerts again: %+v", r)
	}
	if r := deliver(now.Add(3*time.Hour), up); r.New != 1 {
		t.Errorf("after the ttl it alerts again: %+v", r)
	}
}
