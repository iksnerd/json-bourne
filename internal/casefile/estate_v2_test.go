package casefile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The corpus under testdata/estate holds synthetic files only. A valid file must load.
// An invalid file starts with `# want: SUBSTRING`, and the error must contain it. The
// test compares the substring, not the whole message.
func TestEstateCorpus(t *testing.T) {
	for _, kind := range []string{"valid", "invalid"} {
		files, err := filepath.Glob(filepath.Join("testdata", "estate", kind, "*.yaml"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no %s estate corpus: %v", kind, err)
		}
		for _, f := range files {
			t.Run(kind+"/"+strings.TrimSuffix(filepath.Base(f), ".yaml"), func(t *testing.T) {
				b, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				_, perr := ParseEstate(b)
				if kind == "valid" {
					if perr != nil {
						t.Fatalf("valid file refused: %v", perr)
					}
					return
				}
				first, _, _ := strings.Cut(string(b), "\n")
				want, ok := strings.CutPrefix(first, "# want: ")
				if !ok || want == "" {
					t.Fatalf("invalid file must start with `# want: SUBSTRING`, starts %q", first)
				}
				if perr == nil {
					t.Fatal("accepted")
				}
				if !strings.Contains(perr.Error(), want) {
					t.Errorf("error %q does not contain %q", perr, want)
				}
			})
		}
	}
}

// The migration from v1 is one line: an example that was valid as v1 is valid as v2
// with only its apiVersion changed, and keeps its nodes and edges.
func TestV1FileWithOnlyTheVersionChangedLoadsAsV2(t *testing.T) {
	v2 := mustEstate(t, validEstate)
	v1 := strings.Replace(validEstate, "jb.estate/v2", "jb.estate/v1", 1)
	_, err := ParseEstate([]byte(v1))
	if err == nil || !strings.Contains(err.Error(), "jb.estate/v1") || !strings.Contains(err.Error(), "jb.estate/v2") || !strings.Contains(err.Error(), "rewrite") {
		t.Fatalf("a v1 file must be refused with an error naming both versions and saying to rewrite it, got %v", err)
	}
	back := strings.Replace(v1, "jb.estate/v1", "jb.estate/v2", 1)
	e := mustEstate(t, back)
	if !reflect.DeepEqual(e.Nodes, v2.Nodes) || !reflect.DeepEqual(e.Edges, v2.Edges) {
		t.Error("the migrated file changed its nodes or edges")
	}
}

func TestFactsAreTextAndKeepTheirOrder(t *testing.T) {
	e := mustEstate(t, readCorpus(t, "valid/fact-number-value-is-text"))
	if got := e.Nodes[0].Facts[0].Value; got != "22" {
		t.Errorf("value: 22 must be read as the text %q, got %q", "22", got)
	}
	e = mustEstate(t, readCorpus(t, "valid/fact-same-key-two-values"))
	if len(e.Nodes[0].Facts) != 2 {
		t.Fatalf("two facts may share a key: %+v", e.Nodes[0].Facts)
	}
}

func readCorpus(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "estate", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A fact that differs only in its observed time is still a duplicate; one that differs in
// source or method is not.
func TestFactDuplicateIgnoresObservedOnly(t *testing.T) {
	e := mustEstate(t, readCorpus(t, "valid/fact-ct-log"))
	f := e.Nodes[0].Facts[0]
	other := f
	other.Source = "dns"
	e.Nodes[0].Facts = []Fact{f, other}
	if err := e.validate(); err != nil {
		t.Errorf("a different source is a different fact: %v", err)
	}
	other = f
	other.Method = "m2"
	e.Nodes[0].Facts = []Fact{f, other}
	if err := e.validate(); err != nil {
		t.Errorf("a different method is a different fact: %v", err)
	}
	other = f
	other.Observed = "2027-01-01T00:00:00Z"
	e.Nodes[0].Facts = []Fact{f, other}
	if err := e.validate(); err == nil || !strings.Contains(err.Error(), "duplicate fact") {
		t.Errorf("same key, value, source and method must be a duplicate, got %v", err)
	}
}

// For every cap, "at most N" means entry N+1 is the error and entry N is not.
func TestEstateCapsAreExact(t *testing.T) {
	base := func() *Estate { return mustEstate(t, readCorpus(t, "valid/fact-ct-log")) }
	fact := func(i int) Fact {
		return Fact{Key: "port.open", Value: fmt.Sprint(i), Source: "ct-log", Method: "m", Observed: "2026-11-06T10:00:00Z"}
	}
	node := func(i int) Node {
		return Node{ID: fmt.Sprintf("host:h%d.example.com", i), Kind: "host", Label: "h", Source: "dns", Method: "m", Observed: "2026-11-06T10:00:00Z"}
	}
	t.Run("facts per node", func(t *testing.T) {
		e := base()
		e.Nodes[0].Facts = nil
		for i := 0; i < maxNodeFacts; i++ {
			e.Nodes[0].Facts = append(e.Nodes[0].Facts, fact(i))
		}
		if err := e.validate(); err != nil {
			t.Fatalf("%d facts refused: %v", maxNodeFacts, err)
		}
		e.Nodes[0].Facts = append(e.Nodes[0].Facts, fact(maxNodeFacts))
		if err := e.validate(); err == nil || !strings.Contains(err.Error(), "facts") {
			t.Errorf("%d facts accepted: %v", maxNodeFacts+1, err)
		}
	})
	t.Run("facts per file", func(t *testing.T) {
		e := base()
		e.Nodes[0].Facts = nil
		for len(e.Nodes) < maxEstateFacts/maxNodeFacts {
			e.Nodes = append(e.Nodes, node(len(e.Nodes)))
		}
		for ni := range e.Nodes {
			for i := 0; i < maxNodeFacts; i++ {
				e.Nodes[ni].Facts = append(e.Nodes[ni].Facts, fact(i))
			}
		}
		if err := e.validate(); err != nil {
			t.Fatalf("%d facts refused: %v", maxEstateFacts, err)
		}
		e.Nodes = append(e.Nodes, node(len(e.Nodes)))
		e.Nodes[len(e.Nodes)-1].Facts = []Fact{fact(0)}
		if err := e.validate(); err == nil || !strings.Contains(err.Error(), "facts in total") {
			t.Errorf("%d facts accepted: %v", maxEstateFacts+1, err)
		}
	})
	t.Run("assessments", func(t *testing.T) {
		e := base()
		for i := 0; i < maxEstateAssessments; i++ {
			e.Assessments = append(e.Assessments, Assessment{ID: fmt.Sprintf("a%d", i), Subject: e.Nodes[0].ID, Label: "x", By: "analyst", Decided: "2026-11-06T10:00:00Z", Basis: []string{e.Nodes[0].ID}})
		}
		if err := e.validate(); err != nil {
			t.Fatalf("%d assessments refused: %v", maxEstateAssessments, err)
		}
		e.Assessments = append(e.Assessments, Assessment{ID: "over", Subject: e.Nodes[0].ID, Label: "x", By: "analyst", Decided: "2026-11-06T10:00:00Z", Basis: []string{e.Nodes[0].ID}})
		if err := e.validate(); err == nil || !strings.Contains(err.Error(), "assessments hold at most") {
			t.Errorf("%d assessments accepted: %v", maxEstateAssessments+1, err)
		}
	})
	t.Run("basis entries", func(t *testing.T) {
		e := base()
		var basis []string
		for i := 0; i < maxBasis; i++ {
			basis = append(basis, fmt.Sprintf("ip:192.0.2.10#k%d", i))
			e.Nodes[0].Facts = append(e.Nodes[0].Facts, Fact{Key: fmt.Sprintf("k%d", i), Value: "v", Source: "ct-log", Method: "m", Observed: "2026-11-06T10:00:00Z"})
		}
		a := Assessment{ID: "a1", Subject: e.Nodes[0].ID, Label: "x", By: "analyst", Decided: "2026-11-06T10:00:00Z", Basis: basis}
		e.Assessments = []Assessment{a}
		if err := e.validate(); err != nil {
			t.Fatalf("%d references refused: %v", maxBasis, err)
		}
		e.Nodes[0].Facts = append(e.Nodes[0].Facts, Fact{Key: "kx", Value: "v", Source: "ct-log", Method: "m", Observed: "2026-11-06T10:00:00Z"})
		e.Assessments[0].Basis = append(basis, "ip:192.0.2.10#kx")
		if err := e.validate(); err == nil || !strings.Contains(err.Error(), "basis") {
			t.Errorf("%d references accepted: %v", maxBasis+1, err)
		}
	})
	t.Run("value and by lengths", func(t *testing.T) {
		e := base()
		e.Nodes[0].Facts[0].Value = strings.Repeat("v", 500)
		if err := e.validate(); err != nil {
			t.Errorf("a 500 byte value refused: %v", err)
		}
		e.Nodes[0].Facts[0].Value = strings.Repeat("v", 501)
		if err := e.validate(); err == nil || !strings.Contains(err.Error(), "500 bytes") {
			t.Errorf("a 501 byte value accepted: %v", err)
		}
		e = base()
		e.Assessments = []Assessment{{ID: "a1", Subject: e.Nodes[0].ID, Label: "x", By: strings.Repeat("b", 128), Decided: "2026-11-06T10:00:00Z", Basis: []string{e.Nodes[0].ID}}}
		if err := e.validate(); err != nil {
			t.Errorf("a 128 byte author refused: %v", err)
		}
		e.Assessments[0].By = strings.Repeat("b", 129)
		if err := e.validate(); err == nil || !strings.Contains(err.Error(), "128 bytes") {
			t.Errorf("a 129 byte author accepted: %v", err)
		}
	})
}

func TestEstateRoundTripWithFactsAndAssessments(t *testing.T) {
	e := mustEstate(t, readCorpus(t, "valid/assessment-future-time-and-note"))
	out, err := MarshalEstate(e)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := ParseEstate(out)
	if err != nil {
		t.Fatalf("own output refused: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(e, e2) {
		t.Errorf("round trip changed the estate:\n%+v\n%+v", e, e2)
	}
}

// A v1 snapshot is refused with a message that says how to get a v2 one.
func TestSnapshotV1IsRefusedWithTheRewriteMessage(t *testing.T) {
	data, err := MarshalEstateSnapshot(validSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	v1 := strings.Replace(string(data), "jb.estate-snapshot/v2", "jb.estate-snapshot/v1", 1)
	_, err = ParseEstateSnapshot([]byte(v1))
	if err == nil {
		t.Fatal("a v1 snapshot was accepted")
	}
	for _, want := range []string{"jb.estate-snapshot/v1", "jb.estate-snapshot/v2", "jb estate refresh"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// The body of a snapshot is a v2 estate, so facts and assessments survive a round trip.
func TestSnapshotCarriesFactsAndAssessments(t *testing.T) {
	s := validSnapshot(t)
	s.Estate = *mustEstate(t, readCorpus(t, "valid/assessment-fact-basis"))
	data, err := MarshalEstateSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEstateSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Estate.Nodes[0].Facts) != 1 || len(got.Estate.Assessments) != 1 {
		t.Errorf("%+v", got.Estate)
	}
}

// Merging claims into an estate keeps the facts and assessments already recorded.
func TestMergeEstateKeepsFactsAndAssessments(t *testing.T) {
	base := mustEstate(t, readCorpus(t, "valid/assessment-fact-basis"))
	add := frag([]Node{{ID: "ip:192.0.2.11", Kind: "ip", Label: "192.0.2.11", Source: "dns", Method: "m", Observed: "2026-11-06T10:00:00Z"}}, nil, nil)
	got, res := MergeEstate(base, add)
	if res.AddedNodes != 1 || len(got.Assessments) != 1 || len(got.Nodes[0].Facts) != 1 {
		t.Fatalf("%+v %+v", res, got)
	}
}
