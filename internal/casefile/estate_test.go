package casefile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// All data is synthetic: example.com and RFC 5737 / RFC 5398 documentation values.
const validEstate = `apiVersion: jb.estate/v2
id: estate-a
caveat: This map shows infrastructure ownership and relationships as public registries and DNS describe them. It does not show who typed the commands.
nodes:
  - id: ip:192.0.2.10
    kind: ip
    label: 192.0.2.10
    source: rdns
    method: "PTR 10.2.0.192.in-addr.arpa via system resolver"
    observed: 2026-11-06T10:00:00Z
  - id: host:edge.example.com
    kind: host
    label: edge.example.com
    source: rdns
    method: "PTR 10.2.0.192.in-addr.arpa via system resolver"
    observed: 2026-11-06T10:00:00Z
  - id: org:example-net
    kind: org
    label: Example Network Operator
    source: rdap
    method: "GET https://rdap.example.com/ip/192.0.2.10"
    observed: 2026-11-06T10:00:01Z
edges:
  - from: ip:192.0.2.10
    to: host:edge.example.com
    relation: ptr
    source: rdns
    method: "PTR 10.2.0.192.in-addr.arpa via system resolver"
    observed: 2026-11-06T10:00:00Z
    confidence: stated
  - from: host:edge.example.com
    to: org:example-net
    relation: operated_by
    source: rdap
    method: "GET https://rdap.example.com/ip/192.0.2.10"
    observed: 2026-11-06T10:00:01Z
    confidence: inferred
    inferred_from: "the host name sits inside the example.com zone and the covering range is registered to this organisation"
absences:
  - subject: ip:192.0.2.10
    source: rdap
    method: "GET https://rdap.example.com/ip/192.0.2.10 (second registry)"
    observed: 2026-11-06T10:00:02Z
    answer: not_found
`

func mustEstate(t *testing.T, doc string) *Estate {
	t.Helper()
	e, err := ParseEstate([]byte(doc))
	if err != nil {
		t.Fatalf("valid estate refused: %v", err)
	}
	return e
}

func TestParseEstateValid(t *testing.T) {
	e := mustEstate(t, validEstate)
	if e.ID != "estate-a" || len(e.Nodes) != 3 || len(e.Edges) != 2 || len(e.Absences) != 1 {
		t.Fatalf("%+v", e)
	}
	if e.Edges[1].Confidence != "inferred" || e.Edges[1].InferredFrom == "" {
		t.Errorf("inferred edge lost its basis: %+v", e.Edges[1])
	}
}

// mutate replaces the first occurrence of old with new in validEstate.
func mutate(t *testing.T, old, new string) string {
	t.Helper()
	if !strings.Contains(validEstate, old) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return strings.Replace(validEstate, old, new, 1)
}

func TestParseEstateRefusals(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"empty":                {"", "empty"},
		"no apiVersion":        {mutate(t, "apiVersion: jb.estate/v2\n", ""), "apiVersion is required"},
		"wrong apiVersion":     {mutate(t, "jb.estate/v2", "jb.estate/v3"), "unsupported apiVersion"},
		"v1 is refused":        {mutate(t, "jb.estate/v2", "jb.estate/v1"), "rewrite"},
		"no caveat":            {mutate(t, "caveat:", "caveat_x:"), "caveat"},
		"blank caveat":         {strings.Replace(validEstate, validEstate[strings.Index(validEstate, "caveat:"):strings.Index(validEstate, "nodes:")], "caveat: \"   \"\n", 1), "caveat"},
		"empty caveat":         {strings.Replace(validEstate, validEstate[strings.Index(validEstate, "caveat:"):strings.Index(validEstate, "nodes:")], "caveat: \"\"\n", 1), "caveat"},
		"unknown top key":      {validEstate + "extra: 1\n", "unknown key"},
		"unknown node key":     {mutate(t, "    label: 192.0.2.10\n", "    label: 192.0.2.10\n    owner: x\n"), "unknown key"},
		"two documents":        {validEstate + "---\napiVersion: jb.estate/v2\n", "more than one"},
		"node no source":       {mutate(t, "    source: rdns\n    method: \"PTR 10.2.0.192.in-addr.arpa via system resolver\"\n    observed: 2026-11-06T10:00:00Z\n  - id: host", "    method: \"x\"\n    observed: 2026-11-06T10:00:00Z\n  - id: host"), "source"},
		"node no method":       {mutate(t, "    source: rdns\n    method: \"PTR 10.2.0.192.in-addr.arpa via system resolver\"\n    observed: 2026-11-06T10:00:00Z\n  - id: host", "    source: rdns\n    observed: 2026-11-06T10:00:00Z\n  - id: host"), "method"},
		"node no observed":     {mutate(t, "    observed: 2026-11-06T10:00:01Z\nedges:", "edges:"), "observed"},
		"node blank method":    {mutate(t, "method: \"GET https://rdap.example.com/ip/192.0.2.10\"\n    observed: 2026-11-06T10:00:01Z\nedges:", "method: \"  \"\n    observed: 2026-11-06T10:00:01Z\nedges:"), "method"},
		"bad observed":         {mutate(t, "observed: 2026-11-06T10:00:01Z\nedges:", "observed: yesterday\nedges:"), "observed"},
		"observed no zone":     {mutate(t, "observed: 2026-11-06T10:00:01Z\nedges:", "observed: 2026-11-06T10:00:01\nedges:"), "observed"},
		"active source":        {mutate(t, "source: rdap\n    method: \"GET https://rdap.example.com/ip/192.0.2.10\"\n    observed: 2026-11-06T10:00:01Z\nedges:", "source: nmap\n    method: \"-sV\"\n    observed: 2026-11-06T10:00:01Z\nedges:"), "allowlist"},
		"unknown node kind":    {mutate(t, "kind: org", "kind: planet"), "kind"},
		"duplicate node id":    {mutate(t, "id: host:edge.example.com", "id: ip:192.0.2.10"), "duplicate node id"},
		"dangling from":        {mutate(t, "  - from: host:edge.example.com", "  - from: host:gone.example.com"), "dangling"},
		"dangling to":          {mutate(t, "    to: org:example-net", "    to: org:gone"), "dangling"},
		"self edge":            {mutate(t, "    to: host:edge.example.com\n    relation: ptr", "    to: ip:192.0.2.10\n    relation: ptr"), "self"},
		"edge no source":       {mutate(t, "    relation: ptr\n    source: rdns\n", "    relation: ptr\n"), "source"},
		"edge no method":       {mutate(t, "    relation: ptr\n    source: rdns\n    method: \"PTR 10.2.0.192.in-addr.arpa via system resolver\"\n", "    relation: ptr\n    source: rdns\n"), "method"},
		"edge no observed":     {mutate(t, "    observed: 2026-11-06T10:00:00Z\n    confidence: stated\n", "    confidence: stated\n"), "observed"},
		"bad confidence":       {mutate(t, "confidence: stated", "confidence: certain"), "confidence"},
		"inferred no basis":    {mutate(t, "    inferred_from: \"the host name sits inside the example.com zone and the covering range is registered to this organisation\"\n", ""), "inferred_from"},
		"stated with basis":    {mutate(t, "confidence: stated", "confidence: stated\n    inferred_from: because"), "inferred_from"},
		"basis without conf":   {mutate(t, "    confidence: stated\n", "    inferred_from: because\n"), "inferred_from"},
		"duplicate edge":       {strings.Replace(validEstate, "absences:", "  - from: ip:192.0.2.10\n    to: host:edge.example.com\n    relation: ptr\n    source: rdns\n    method: \"PTR 10.2.0.192.in-addr.arpa via system resolver\"\n    observed: 2026-11-06T10:05:00Z\nabsences:", 1), "duplicate edge"},
		"absence dangling":     {mutate(t, "subject: ip:192.0.2.10", "subject: ip:203.0.113.1"), "dangling"},
		"absence wrong answer": {mutate(t, "answer: not_found", "answer: nothing"), "answer"},
		"absence no method":    {mutate(t, "    method: \"GET https://rdap.example.com/ip/192.0.2.10 (second registry)\"\n", ""), "method"},
		"credential":           {mutate(t, "label: Example Network Operator", "label: ghp_abcdefghijklmnopqrstuvwxyz0123456789"), "credential"},
		"multi-line label":     {mutate(t, "label: Example Network Operator", "label: \"a\\nb\""), "label"},
		"uppercase node id":    {mutate(t, "id: org:example-net", "id: org:Example-Net"), "id"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseEstate([]byte(c.doc))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// A missing required key must be named, whichever object it is missing from.
func TestParseEstateMissingFieldNamesThePosition(t *testing.T) {
	doc := mutate(t, "    source: rdns\n    method: \"PTR 10.2.0.192.in-addr.arpa via system resolver\"\n    observed: 2026-11-06T10:00:00Z\n  - id: host", "    method: \"x\"\n    observed: 2026-11-06T10:00:00Z\n  - id: host")
	_, err := ParseEstate([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "nodes[0]") {
		t.Fatalf("want a nodes[0] error, got %v", err)
	}
}

func TestEstateAllowlistIsPassiveOnly(t *testing.T) {
	for _, bad := range []string{"nmap", "masscan", "zmap", "httpx", "nuclei", "tlsx", "naabu", "active", "scan", "shodan", ""} {
		if slices.Contains(EstateSources, bad) {
			t.Errorf("%q must not be an allowed estate source", bad)
		}
	}
	for _, good := range []string{"rdap", "rdns", "dns", "crt.sh"} {
		if !slices.Contains(EstateSources, good) {
			t.Errorf("%q should be allowed", good)
		}
	}
	for _, s := range EstateSources {
		doc := strings.Replace(validEstate, "source: rdap\n    method: \"GET https://rdap.example.com/ip/192.0.2.10\"\n    observed: 2026-11-06T10:00:01Z\nedges:", "source: "+s+"\n    method: \"q\"\n    observed: 2026-11-06T10:00:01Z\nedges:", 1)
		if _, err := ParseEstate([]byte(doc)); err != nil {
			t.Errorf("allowed source %q refused: %v", s, err)
		}
	}
}

// docs/POLICY.md declares the allowlist; the code and the policy must agree.
func TestEstateAllowlistMatchesPolicyDoc(t *testing.T) {
	b, err := os.ReadFile("../../docs/POLICY.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "<!-- estate-sources:begin -->")
	j := strings.Index(s, "<!-- estate-sources:end -->")
	if i < 0 || j < i {
		t.Fatal("docs/POLICY.md has no estate-sources block")
	}
	var doc []string
	for _, line := range strings.Split(s[i:j], "\n") {
		if strings.HasPrefix(line, "- `") {
			doc = append(doc, strings.Trim(strings.SplitN(line, "`", 3)[1], "`"))
		}
	}
	if !slices.Equal(sorted(doc), sorted(EstateSources)) {
		t.Errorf("POLICY.md lists %v, code allows %v", doc, EstateSources)
	}
}

func TestEstateRoundTrip(t *testing.T) {
	e := mustEstate(t, validEstate)
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

func TestMarshalEstateRefusesInvalid(t *testing.T) {
	e := mustEstate(t, validEstate)
	e.Nodes[0].Source = ""
	if _, err := MarshalEstate(e); err == nil {
		t.Fatal("an estate that would not load must not be written")
	}
}

func frag(nodes []Node, edges []Edge, abs []Absence) *Estate {
	return &Estate{Nodes: nodes, Edges: edges, Absences: abs}
}

func TestMergeEstate(t *testing.T) {
	base := mustEstate(t, validEstate)
	t.Run("same node and edge again is a no-op", func(t *testing.T) {
		add := frag([]Node{base.Nodes[0]}, []Edge{base.Edges[0]}, []Absence{base.Absences[0]})
		got, res := MergeEstate(base, add)
		if len(res.Conflicts) != 0 || res.AddedNodes != 0 || res.AddedEdges != 0 || res.AddedAbsences != 0 {
			t.Fatalf("%+v", res)
		}
		if !reflect.DeepEqual(got, base) {
			t.Error("estate changed")
		}
	})
	t.Run("new node is added and the input is not mutated", func(t *testing.T) {
		n := Node{ID: "ip:192.0.2.11", Kind: "ip", Label: "192.0.2.11", Source: "rdns", Method: "m", Observed: "2026-11-06T11:00:00Z"}
		before := len(base.Nodes)
		got, res := MergeEstate(base, frag([]Node{n}, nil, nil))
		if res.AddedNodes != 1 || len(got.Nodes) != before+1 || len(base.Nodes) != before {
			t.Fatalf("%+v %d %d", res, len(got.Nodes), len(base.Nodes))
		}
	})
	t.Run("same id with a different label is a conflict and the old node stays", func(t *testing.T) {
		n := base.Nodes[2]
		n.Label = "A Different Operator"
		got, res := MergeEstate(base, frag([]Node{n}, nil, nil))
		if len(res.Conflicts) != 1 || !strings.Contains(res.Conflicts[0], "org:example-net") {
			t.Fatalf("%+v", res)
		}
		if got.Nodes[2].Label != "Example Network Operator" {
			t.Errorf("existing node was overwritten: %+v", got.Nodes[2])
		}
	})
	t.Run("same id with a different kind is a conflict", func(t *testing.T) {
		n := base.Nodes[2]
		n.Kind = "host"
		_, res := MergeEstate(base, frag([]Node{n}, nil, nil))
		if len(res.Conflicts) != 1 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("same edge key with a different confidence is a conflict", func(t *testing.T) {
		ed := base.Edges[0]
		ed.Confidence = "inferred"
		ed.InferredFrom = "guess"
		got, res := MergeEstate(base, frag(nil, []Edge{ed}, nil))
		if len(res.Conflicts) != 1 || got.Edges[0].Confidence != "stated" {
			t.Fatalf("%+v %+v", res, got.Edges[0])
		}
	})
	t.Run("same endpoints by a different method is a second observation, not a conflict", func(t *testing.T) {
		ed := base.Edges[0]
		ed.Method = "PTR via 203.0.113.53"
		_, res := MergeEstate(base, frag(nil, []Edge{ed}, nil))
		if len(res.Conflicts) != 0 || res.AddedEdges != 1 {
			t.Fatalf("%+v", res)
		}
	})
}

// ---- files in the case ----

func writeEstate(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, "estate", name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEstateFileAndDirectory(t *testing.T) {
	c := newCase(t)
	if es, err := LoadEstates(c); err != nil || len(es) != 0 {
		t.Fatalf("no estate directory is not an error: %v %v", es, err)
	}
	writeEstate(t, c.Dir, "a.yaml", validEstate)
	if e, err := LoadEstateFile(c, "a.yaml"); err != nil || e.ID != "estate-a" {
		t.Fatalf("%v %+v", err, e)
	}
	writeEstate(t, c.Dir, "b.yml", strings.Replace(validEstate, "id: estate-a", "id: estate-a", 1))
	if _, err := LoadEstates(c); err == nil || !strings.Contains(err.Error(), "estate-a") {
		t.Fatalf("an id used by two files must be reported, got %v", err)
	}
	writeEstate(t, c.Dir, "b.yml", strings.Replace(validEstate, "id: estate-a", "id: estate-b", 1))
	writeEstate(t, c.Dir, "notes.txt", "not yaml")
	es, err := LoadEstates(c)
	if err != nil || len(es) != 2 {
		t.Fatalf("%v %v", es, err)
	}
	writeEstate(t, c.Dir, "c.yaml", "apiVersion: jb.estate/v2\n")
	if _, err := LoadEstates(c); err == nil || !strings.Contains(err.Error(), "c.yaml") {
		t.Fatalf("a broken file must be named, got %v", err)
	}
}

func TestLoadEstateFileConfinement(t *testing.T) {
	c := newCase(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.yaml"), []byte(validEstate), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(c.Dir, "estate"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "x.yaml"), filepath.Join(c.Dir, "estate", "link.yaml")); err != nil {
		t.Skip("symlinks unavailable")
	}
	for name, file := range map[string]string{"dotdot": "../x.yaml", "abs": "/etc/passwd", "ext": "a.txt", "symlink out": "link.yaml"} {
		if _, err := LoadEstateFile(c, file); err == nil {
			t.Errorf("%s: %q accepted", name, file)
		}
	}
}

func TestSaveEstateFileWritesAtomicallyAndRefusesInvalid(t *testing.T) {
	c := newCase(t)
	e := mustEstate(t, validEstate)
	if err := SaveEstateFile(c, "out.yaml", e); err != nil {
		t.Fatal(err)
	}
	got, err := LoadEstateFile(c, "out.yaml")
	if err != nil || !reflect.DeepEqual(got, e) {
		t.Fatalf("%v", err)
	}
	ents, _ := os.ReadDir(filepath.Join(c.Dir, "estate"))
	if len(ents) != 1 {
		t.Errorf("a temporary file was left behind: %v", ents)
	}
	bad := mustEstate(t, validEstate)
	bad.Caveat = ""
	if err := SaveEstateFile(c, "out.yaml", bad); err == nil {
		t.Fatal("invalid estate saved")
	}
	still, err := LoadEstateFile(c, "out.yaml")
	if err != nil || still.Caveat == "" {
		t.Errorf("the earlier file was damaged by the refused save: %v", err)
	}
}

func TestEstatePathDefaultAndDistinct(t *testing.T) {
	c := newCase(t)
	if c.Paths.Estate != "estate" {
		t.Fatalf("paths.estate default is %q", c.Paths.Estate)
	}
	dir := t.TempDir()
	body := "apiVersion: jb.case/v1\nid: t\ntitle: t\nstatus: open\nopened: 2026-11-01\npaths:\n  estate: actors\n"
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"), []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "estate") {
		t.Fatalf("paths.estate == paths.actors must be refused, got %v", err)
	}
}

// ---- schema/loader equality ----

func loadEstateSchema(t *testing.T) schemaNode {
	t.Helper()
	b, err := os.ReadFile("../../docs/schemas/estate.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s schemaNode
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEstateSchemaMatchesStruct(t *testing.T) {
	s := loadEstateSchema(t)
	var fromSchema, fromGo []string
	schemaNames(t, s, "", &fromSchema)
	goNames(reflect.TypeOf(Estate{}), "", &fromGo)
	sort.Strings(fromSchema)
	sort.Strings(fromGo)
	if !slices.Equal(fromSchema, fromGo) {
		t.Errorf("schema properties %v\nGo fields         %v", fromSchema, fromGo)
	}
}

func TestEstateSchemaMatchesLoaderRules(t *testing.T) {
	s := loadEstateSchema(t)
	if !slices.Equal(sorted(s.Required), sorted(EstateRequiredKeys)) {
		t.Errorf("required: schema %v, loader %v", s.Required, EstateRequiredKeys)
	}
	if s.Properties["apiVersion"].Const != EstateAPIVersion {
		t.Errorf("apiVersion const: schema %v, loader %s", s.Properties["apiVersion"].Const, EstateAPIVersion)
	}
	n := s.Properties["nodes"].Items
	if got := asStrings(t, n.Properties["kind"].Enum); !slices.Equal(sorted(got), sorted(NodeKinds)) {
		t.Errorf("node kind enum: schema %v, loader %v", got, NodeKinds)
	}
	if got := asStrings(t, n.Properties["source"].Enum); !slices.Equal(sorted(got), sorted(EstateSources)) {
		t.Errorf("node source enum: schema %v, loader %v", got, EstateSources)
	}
	if !slices.Equal(sorted(n.Required), sorted(NodeRequiredKeys)) {
		t.Errorf("node required: schema %v, loader %v", n.Required, NodeRequiredKeys)
	}
	ed := s.Properties["edges"].Items
	if got := asStrings(t, ed.Properties["source"].Enum); !slices.Equal(sorted(got), sorted(EstateSources)) {
		t.Errorf("edge source enum: schema %v, loader %v", got, EstateSources)
	}
	if got := asStrings(t, ed.Properties["confidence"].Enum); !slices.Equal(sorted(got), sorted(EdgeConfidences)) {
		t.Errorf("edge confidence enum: schema %v, loader %v", got, EdgeConfidences)
	}
	if !slices.Equal(sorted(ed.Required), sorted(EdgeRequiredKeys)) {
		t.Errorf("edge required: schema %v, loader %v", ed.Required, EdgeRequiredKeys)
	}
	fa := n.Properties["facts"].Items
	if got := asStrings(t, fa.Properties["source"].Enum); !slices.Equal(sorted(got), sorted(EstateSources)) {
		t.Errorf("fact source enum: schema %v, loader %v", got, EstateSources)
	}
	if !slices.Equal(sorted(fa.Required), sorted(FactRequiredKeys)) {
		t.Errorf("fact required: schema %v, loader %v", fa.Required, FactRequiredKeys)
	}
	as := s.Properties["assessments"].Items
	if !slices.Equal(sorted(as.Required), sorted(AssessmentRequiredKeys)) {
		t.Errorf("assessment required: schema %v, loader %v", as.Required, AssessmentRequiredKeys)
	}
	for name, max := range map[string]int{"nodes": maxEstateNodes, "edges": maxEstateEdges, "absences": maxEstateAbsences, "assessments": maxEstateAssessments} {
		if got := s.Properties[name].MaxItems; got != max {
			t.Errorf("%s maxItems: schema %d, loader %d", name, got, max)
		}
	}
	if got := n.Properties["facts"].MaxItems; got != maxNodeFacts {
		t.Errorf("facts maxItems: schema %d, loader %d", got, maxNodeFacts)
	}
	if got := as.Properties["basis"].MaxItems; got != maxBasis {
		t.Errorf("basis maxItems: schema %d, loader %d", got, maxBasis)
	}
	ab := s.Properties["absences"].Items
	if got := asStrings(t, ab.Properties["source"].Enum); !slices.Equal(sorted(got), sorted(EstateSources)) {
		t.Errorf("absence source enum: schema %v, loader %v", got, EstateSources)
	}
	if !slices.Equal(sorted(ab.Required), sorted(AbsenceRequiredKeys)) {
		t.Errorf("absence required: schema %v, loader %v", ab.Required, AbsenceRequiredKeys)
	}
}

// The fixture must be plain YAML a person can write: guard against the marshaller
// producing something the schema's string-typed fields would not accept.
func TestEstateFixtureIsYAMLMapping(t *testing.T) {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(validEstate), &m); err != nil {
		t.Fatal(err)
	}
}
