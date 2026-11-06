package casefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EstateAPIVersion is the only estate file format this build reads. The format is
// specified in docs/CASE-SPEC.md section 4.5 and schemas/estate.schema.json.
const EstateAPIVersion = "jb.estate/v2"

// estateV1APIVersion is refused with a message that says how to migrate. There is no
// v1 reader (docs/rfcs/0001-estate-v2.md).
const estateV1APIVersion = "jb.estate/v1"

// EstateRequiredKeys are the top-level keys that must be present.
// EstateSubjects are the allowed values of the optional top-level subject (RFC 0015).
var EstateSubjects = []string{"operated", "adversary"}

var EstateRequiredKeys = []string{"apiVersion", "id", "caveat", "nodes"}

// NodeRequiredKeys, EdgeRequiredKeys and AbsenceRequiredKeys: every claim in an
// estate file names where it came from, how, and when. A claim without all three is
// a load error, because two observations taken by different methods cannot be compared.
var (
	NodeRequiredKeys    = []string{"id", "kind", "label", "source", "method", "observed"}
	EdgeRequiredKeys    = []string{"from", "to", "relation", "source", "method", "observed"}
	AbsenceRequiredKeys = []string{"subject", "source", "method", "observed", "answer"}
	// FactRequiredKeys: a fact is an observation and carries the same provenance as any claim.
	FactRequiredKeys = []string{"key", "value", "source", "method", "observed"}
	// AssessmentRequiredKeys: an assessment is one author's judgement. It is not a claim,
	// but it must say who decided and what it rests on.
	AssessmentRequiredKeys = []string{"id", "subject", "label", "by", "decided", "basis"}
)

// NodeKinds are the allowed values of a node's kind.
var NodeKinds = []string{"ip", "host", "domain", "asn", "org", "network", "service"}

// EdgeConfidences are the allowed values of an edge's confidence.
var EdgeConfidences = []string{"stated", "inferred"}

// EstateSources is the closed list of passive sources an estate file may cite. It is
// the list declared in docs/POLICY.md (a test keeps the two equal). Every one is a
// public registry, resolver or log that answers about an address or name without
// the investigator contacting the infrastructure itself, or a store the operator
// already holds and the target observes nothing from (`scan-cache`; see "The test for a
// source"). A scanner or prober is not on it, and adding one is a policy change, not a
// code change.
var EstateSources = []string{"rdap", "rdns", "dns", "whois", "crt.sh", "ct-log", "bgp", "passive-dns", "scan-cache"}

// AbsenceAnswer is the only answer an absence can record: the source was asked and
// said it holds nothing. A failed lookup is not an absence and is never recorded.
const AbsenceAnswer = "not_found"

const (
	maxEstateSize     = 4 << 20
	maxEstateNodes    = 5000
	maxEstateEdges    = 20000
	maxEstateAbsences = 5000
	// The caps below bound what a hostile file can make the loader or the dashboard hold.
	maxNodeFacts         = 50
	maxEstateFacts       = 20000
	maxEstateAssessments = 2000
	maxBasis             = 20
	maxAssessmentBy      = 128
	maxCaveat            = 2000
	maxEstateLine        = 500
)

var (
	estateIDRE  = regexp.MustCompile(`^[a-z0-9_][a-z0-9._:/_-]{0,253}$`)
	relationRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	factKeyRE   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	assessIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	assessLabRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	errEstateNL = errors.New("must be one line")
)

// Estate is a parsed, validated jb.estate/v2 file: infrastructure relationships
// inferred from passive sources. It maps ownership and infrastructure, never the
// people who used it; Caveat says so and is required. Assessments are opinion and are
// kept apart from the claims.
type Estate struct {
	APIVersion  string       `yaml:"apiVersion"`
	ID          string       `yaml:"id"`
	Subject     string       `yaml:"subject,omitempty"`
	Caveat      string       `yaml:"caveat"`
	Nodes       []Node       `yaml:"nodes"`
	Edges       []Edge       `yaml:"edges,omitempty"`
	Absences    []Absence    `yaml:"absences,omitempty"`
	Assessments []Assessment `yaml:"assessments,omitempty"`
}

// Node is one thing: an address, a host name, a domain, an AS, an organisation, a
// network range or a third-party service. Facts are observations about the node, each
// with its own source, method and time.
type Node struct {
	ID       string `yaml:"id"`
	Kind     string `yaml:"kind"`
	Label    string `yaml:"label"`
	Source   string `yaml:"source"`
	Method   string `yaml:"method"`   // how it was obtained, e.g. the exact query
	Observed string `yaml:"observed"` // RFC 3339
	Facts    []Fact `yaml:"facts,omitempty"`
}

// Fact is one observation about a node: an open port, an operating system, a
// certificate name. It is a claim, so it carries source, method and observed. A
// judgement is not a fact; it belongs in an Assessment.
type Fact struct {
	Key      string `yaml:"key"`
	Value    string `yaml:"value"`
	Source   string `yaml:"source"`
	Method   string `yaml:"method"`
	Observed string `yaml:"observed"`
}

// Assessment is one author's judgement about one node. It is opinion and not an
// observation, so it never sits on a node. Basis lists what it rests on: node ids, or
// `<node id>#<fact key>`.
type Assessment struct {
	ID      string   `yaml:"id"`
	Subject string   `yaml:"subject"`
	Label   string   `yaml:"label"`
	By      string   `yaml:"by"`
	Decided string   `yaml:"decided"` // RFC 3339
	Basis   []string `yaml:"basis"`
	Note    string   `yaml:"note,omitempty"`
}

// key is what makes two facts of one node identical. Observed is not compared.
func (f Fact) key() string {
	return strings.Join([]string{f.Key, f.Value, f.Source, f.Method}, "\x00")
}

// Edge is a relationship between two nodes. An inferred edge says what it was
// inferred from.
type Edge struct {
	From         string `yaml:"from"`
	To           string `yaml:"to"`
	Relation     string `yaml:"relation"`
	Source       string `yaml:"source"`
	Method       string `yaml:"method"`
	Observed     string `yaml:"observed"`
	Confidence   string `yaml:"confidence,omitempty"`
	InferredFrom string `yaml:"inferred_from,omitempty"`
}

// Absence records a real "not found" answer from a source about a node (an RDAP 404,
// an NXDOMAIN). It is an answer. A timeout, a rate limit or a non-2xx is not one.
type Absence struct {
	Subject  string `yaml:"subject"`
	Source   string `yaml:"source"`
	Method   string `yaml:"method"`
	Observed string `yaml:"observed"`
	Answer   string `yaml:"answer"`
}

func (e Edge) key() string {
	return strings.Join([]string{e.From, e.To, e.Relation, e.Source, e.Method}, "\x00")
}

func (a Absence) key() string { return strings.Join([]string{a.Subject, a.Source, a.Method}, "\x00") }

// ParseEstate decodes and validates one estate file without touching the filesystem.
func ParseEstate(data []byte) (*Estate, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("file is empty")
	}
	var probe struct {
		APIVersion string `yaml:"apiVersion"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	switch probe.APIVersion {
	case EstateAPIVersion:
	case "":
		return nil, fmt.Errorf("apiVersion is required (this build reads %s)", EstateAPIVersion)
	case estateV1APIVersion:
		return nil, fmt.Errorf("unsupported apiVersion %q: this build reads only %s; rewrite the file with apiVersion: %s (that edit is the whole migration)", probe.APIVersion, EstateAPIVersion, EstateAPIVersion)
	default:
		return nil, fmt.Errorf("unsupported apiVersion %q: this build reads only %s", probe.APIVersion, EstateAPIVersion)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if err := scanCredentials(&root); err != nil {
		return nil, err
	}
	var e Estate
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		if strings.Contains(err.Error(), "not found in type") {
			return nil, fmt.Errorf("unknown key (rejected, not ignored): %w", err)
		}
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	if err := checkSubjectKey(&root, &e); err != nil {
		return nil, err
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

// errSubject names the two valid values. The subject is untrusted text, so it is not
// echoed.
func errSubject() error {
	return fmt.Errorf("subject must be %s (or left out for an unclassified file)", strings.Join(EstateSubjects, " or "))
}

// checkSubjectKey rejects a subject key that is present but empty: absent means
// unclassified, and an empty value is neither that nor a valid one.
func checkSubjectKey(root *yaml.Node, e *Estate) error {
	if e.Subject != "" || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	m := root.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		if m[i].Value == "subject" {
			return errSubject()
		}
	}
	return nil
}

func checkLine(field, v string, max int) error {
	switch {
	case strings.TrimSpace(v) == "":
		return fmt.Errorf("missing required field %q", field)
	case len(v) > max:
		return fmt.Errorf("%s is longer than %d bytes", field, max)
	case strings.ContainsAny(v, "\r\n"):
		return fmt.Errorf("%s %w", field, errEstateNL)
	}
	return nil
}

// checkProvenance enforces source, method and observed on any claim.
func checkProvenance(source, method, observed string) []error {
	var errs []error
	switch {
	case source == "":
		errs = append(errs, errors.New(`missing required field "source"`))
	case !slices.Contains(EstateSources, source):
		errs = append(errs, fmt.Errorf("source %q is not on the passive-source allowlist (%s); see docs/POLICY.md", source, strings.Join(EstateSources, ", ")))
	}
	if err := checkLine("method", method, maxEstateLine); err != nil {
		errs = append(errs, err)
	}
	switch {
	case observed == "":
		errs = append(errs, errors.New(`missing required field "observed"`))
	default:
		if _, err := time.Parse(time.RFC3339, observed); err != nil {
			errs = append(errs, fmt.Errorf("observed %q must be an RFC 3339 timestamp with a zone, e.g. 2026-11-06T10:00:00Z", observed))
		}
	}
	return errs
}

func (e *Estate) validate() error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }

	if e.APIVersion != EstateAPIVersion {
		bad("apiVersion must be %s", EstateAPIVersion)
	}
	if !idRE.MatchString(e.ID) {
		bad("id %q must match %s", e.ID, idRE)
	}
	if err := checkLine("caveat", e.Caveat, maxCaveat); err != nil {
		bad("%v: an estate file must state that it maps infrastructure ownership and relationships, not who typed the commands", err)
	}
	if e.Subject != "" && !slices.Contains(EstateSubjects, e.Subject) {
		bad("%v", errSubject())
	}
	if n := len(e.Nodes); n < 1 || n > maxEstateNodes {
		bad("nodes must hold 1 to %d entries, has %d", maxEstateNodes, n)
	}
	if len(e.Edges) > maxEstateEdges {
		bad("edges hold at most %d entries, has %d", maxEstateEdges, len(e.Edges))
	}
	if len(e.Absences) > maxEstateAbsences {
		bad("absences hold at most %d entries, has %d", maxEstateAbsences, len(e.Absences))
	}
	if len(e.Assessments) > maxEstateAssessments {
		bad("assessments hold at most %d entries, has %d", maxEstateAssessments, len(e.Assessments))
	}

	ids := map[string]bool{}
	factKeys := map[string]map[string]bool{} // node id -> fact keys present
	totalFacts := 0
	for i, n := range e.Nodes {
		if i >= maxEstateNodes {
			break
		}
		for _, err := range n.validate() {
			bad("nodes[%d]: %v", i, err)
		}
		if ids[n.ID] {
			bad("nodes[%d]: duplicate node id %q", i, n.ID)
		}
		ids[n.ID] = true
		totalFacts += len(n.Facts)
		keys := map[string]bool{}
		for _, f := range n.Facts {
			keys[f.Key] = true
		}
		factKeys[n.ID] = keys
	}
	if totalFacts > maxEstateFacts {
		bad("the file holds %d facts in total, at most %d", totalFacts, maxEstateFacts)
	}
	seenEdge := map[string]int{}
	for i, ed := range e.Edges {
		if i >= maxEstateEdges {
			break
		}
		for _, err := range ed.validate() {
			bad("edges[%d]: %v", i, err)
		}
		for _, end := range []struct{ name, id string }{{"from", ed.From}, {"to", ed.To}} {
			if end.id != "" && !ids[end.id] {
				bad("edges[%d]: dangling edge: %s %q is not a node", i, end.name, end.id)
			}
		}
		if j, dup := seenEdge[ed.key()]; dup {
			bad("edges[%d]: duplicate edge, repeats edges[%d] (same from, to, relation, source and method)", i, j)
		}
		seenEdge[ed.key()] = i
	}
	seenAbs := map[string]int{}
	for i, a := range e.Absences {
		if i >= maxEstateAbsences {
			break
		}
		for _, err := range a.validate() {
			bad("absences[%d]: %v", i, err)
		}
		if a.Subject != "" && !ids[a.Subject] {
			bad("absences[%d]: dangling absence: subject %q is not a node", i, a.Subject)
		}
		if j, dup := seenAbs[a.key()]; dup {
			bad("absences[%d]: duplicate absence, repeats absences[%d]", i, j)
		}
		seenAbs[a.key()] = i
	}
	seenAssess := map[string]int{}
	for i, a := range e.Assessments {
		if i >= maxEstateAssessments {
			break
		}
		for _, err := range a.validate(ids, factKeys) {
			bad("assessments[%d]: %v", i, err)
		}
		if j, dup := seenAssess[a.ID]; dup && a.ID != "" {
			bad("assessments[%d]: duplicate assessment id %q, repeats assessments[%d]", i, a.ID, j)
		}
		seenAssess[a.ID] = i
	}
	return errors.Join(errs...)
}

func (n Node) validate() []error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }
	if !slices.Contains(NodeKinds, n.Kind) {
		bad("kind %q must be one of %s", n.Kind, strings.Join(NodeKinds, ", "))
	}
	switch {
	case !estateIDRE.MatchString(n.ID):
		bad("id %q must match %s (lower case)", n.ID, estateIDRE)
	case n.Kind != "" && !strings.HasPrefix(n.ID, n.Kind+":"):
		bad("id %q must start with its kind and a colon (%s:)", n.ID, n.Kind)
	}
	if err := checkLine("label", n.Label, 255); err != nil {
		errs = append(errs, err)
	} else if n.Kind == "ip" && !isIP(n.Label) {
		bad("label of an ip node must be the address in canonical form")
	}
	errs = append(errs, checkProvenance(n.Source, n.Method, n.Observed)...)
	if len(n.Facts) > maxNodeFacts {
		bad("facts hold at most %d entries, has %d", maxNodeFacts, len(n.Facts))
	}
	seen := map[string]int{}
	for i, f := range n.Facts {
		if i >= maxNodeFacts {
			break
		}
		for _, err := range f.validate() {
			bad("facts[%d]: %v", i, err)
		}
		if j, dup := seen[f.key()]; dup {
			bad("facts[%d]: duplicate fact, repeats facts[%d] (same key, value, source and method)", i, j)
		}
		seen[f.key()] = i
	}
	return errs
}

func (f Fact) validate() []error {
	var errs []error
	switch {
	case f.Key == "":
		errs = append(errs, errors.New(`missing required field "key"`))
	case !factKeyRE.MatchString(f.Key):
		errs = append(errs, fmt.Errorf("key %q must match %s", f.Key, factKeyRE))
	}
	if err := checkLine("value", f.Value, maxEstateLine); err != nil {
		errs = append(errs, err)
	}
	return append(errs, checkProvenance(f.Source, f.Method, f.Observed)...)
}

// validate checks one assessment. ids holds the node ids of the file and factKeys the
// fact keys of each node, which is what a basis reference resolves against.
func (a Assessment) validate(ids map[string]bool, factKeys map[string]map[string]bool) []error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }
	if !assessIDRE.MatchString(a.ID) {
		bad("id %q must match %s", a.ID, assessIDRE)
	}
	switch {
	case a.Subject == "":
		bad(`missing required field "subject"`)
	case !ids[a.Subject]:
		bad("subject %q is not a node of this file", a.Subject)
	}
	if !assessLabRE.MatchString(a.Label) {
		bad("label %q must match %s (lower case)", a.Label, assessLabRE)
	}
	if err := checkLine("by", a.By, maxAssessmentBy); err != nil {
		errs = append(errs, err)
	}
	if a.Decided == "" {
		bad(`missing required field "decided"`)
	} else if _, err := time.Parse(time.RFC3339, a.Decided); err != nil {
		bad("decided %q must be an RFC 3339 timestamp with a zone, e.g. 2026-11-06T10:00:00Z", a.Decided)
	}
	if a.Note != "" {
		if err := checkLine("note", a.Note, maxEstateLine); err != nil {
			errs = append(errs, err)
		}
	}
	switch n := len(a.Basis); {
	case n == 0:
		bad(`missing required field "basis": an assessment must say what it rests on (1 to %d references)`, maxBasis)
	case n > maxBasis:
		bad("basis holds at most %d references, has %d", maxBasis, n)
	}
	seen := map[string]bool{}
	for i, ref := range a.Basis {
		if i >= maxBasis {
			break
		}
		if seen[ref] {
			bad("basis[%d]: duplicate reference %q", i, ref)
		}
		seen[ref] = true
		node, key, hasKey := strings.Cut(ref, "#")
		switch {
		case !ids[node]:
			bad("basis[%d]: reference %q does not resolve: %q is not a node of this file", i, ref, node)
		case hasKey && !factKeys[node][key]:
			bad("basis[%d]: reference %q does not resolve: node %q has no fact with key %q", i, ref, node, key)
		}
	}
	return errs
}

func (e Edge) validate() []error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }
	if e.From == "" || e.To == "" {
		bad(`missing required field "from" or "to"`)
	} else if e.From == e.To {
		bad("self edge on %q", e.From)
	}
	if !relationRE.MatchString(e.Relation) {
		bad("relation %q must match %s", e.Relation, relationRE)
	}
	errs = append(errs, checkProvenance(e.Source, e.Method, e.Observed)...)
	switch e.Confidence {
	case "":
		if e.InferredFrom != "" {
			bad("inferred_from needs confidence: inferred")
		}
	case "stated":
		if e.InferredFrom != "" {
			bad("inferred_from belongs to an inferred edge, not a stated one")
		}
	case "inferred":
		if err := checkLine("inferred_from", e.InferredFrom, maxEstateLine); err != nil {
			bad("an inferred edge must say what it was inferred from: %v", err)
		}
	default:
		bad("confidence %q must be one of %s", e.Confidence, strings.Join(EdgeConfidences, ", "))
	}
	return errs
}

func (a Absence) validate() []error {
	var errs []error
	if a.Subject == "" {
		errs = append(errs, errors.New(`missing required field "subject"`))
	}
	if a.Answer != AbsenceAnswer {
		errs = append(errs, fmt.Errorf("answer %q must be %q: only a real not-found answer is recorded, never a failure", a.Answer, AbsenceAnswer))
	}
	return append(errs, checkProvenance(a.Source, a.Method, a.Observed)...)
}

// MarshalEstate validates e and renders it as YAML. A file that would not load is
// never produced. Comments in a hand-edited file are not preserved.
func MarshalEstate(e *Estate) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, fmt.Errorf("refusing to write an invalid estate: %w", err)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > maxEstateSize {
		return nil, fmt.Errorf("estate would be %d bytes, over the %d byte limit: start a second estate file", buf.Len(), maxEstateSize)
	}
	// What is written must be what the loader reads back, including the credential scan,
	// which works on the YAML and not on the struct.
	if _, err := ParseEstate(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("refusing to write an estate the loader would reject: %w", err)
	}
	return buf.Bytes(), nil
}

// MergeResult counts what MergeEstate did. A conflict is reported, never resolved.
type MergeResult struct {
	AddedNodes, AddedEdges, AddedAbsences int
	Unchanged                             int      // claims already present, identical
	Conflicts                             []string // claims refused because they disagree with what is recorded
}

// MergeEstate adds the claims of add to a copy of base. It never overwrites: a node
// with the same id but a different kind or label, or an edge with the same from, to,
// relation, source and method but a different confidence or basis, is a conflict, the
// recorded claim stays, and the new one is dropped. An edge or absence that points at a
// conflicting node is dropped too, because it would attach to the wrong thing. The
// same endpoints seen by a different method are a second observation, not a conflict.
func MergeEstate(base, add *Estate) (*Estate, MergeResult) {
	out := *base
	out.Nodes = slices.Clone(base.Nodes)
	out.Edges = slices.Clone(base.Edges)
	out.Absences = slices.Clone(base.Absences)
	var res MergeResult

	nodes := map[string]Node{}
	for _, n := range out.Nodes {
		nodes[n.ID] = n
	}
	blocked := map[string]bool{}
	for _, n := range add.Nodes {
		have, ok := nodes[n.ID]
		switch {
		case !ok:
			nodes[n.ID] = n
			out.Nodes = append(out.Nodes, n)
			res.AddedNodes++
		case have.Kind == n.Kind && have.Label == n.Label:
			res.Unchanged++
		default:
			blocked[n.ID] = true
			res.Conflicts = append(res.Conflicts, fmt.Sprintf("node %s: recorded as %s %q (%s, %s), new observation says %s %q (%s, %s); kept the recorded one",
				n.ID, have.Kind, have.Label, have.Source, have.Observed, n.Kind, n.Label, n.Source, n.Observed))
		}
	}
	edges := map[string]Edge{}
	for _, ed := range out.Edges {
		edges[ed.key()] = ed
	}
	for _, ed := range add.Edges {
		if blocked[ed.From] || blocked[ed.To] {
			res.Conflicts = append(res.Conflicts, fmt.Sprintf("edge %s -[%s]-> %s: dropped, an endpoint conflicts with the recorded node", ed.From, ed.Relation, ed.To))
			continue
		}
		have, ok := edges[ed.key()]
		switch {
		case !ok:
			edges[ed.key()] = ed
			out.Edges = append(out.Edges, ed)
			res.AddedEdges++
		case have.Confidence == ed.Confidence && have.InferredFrom == ed.InferredFrom:
			res.Unchanged++
		default:
			res.Conflicts = append(res.Conflicts, fmt.Sprintf("edge %s -[%s]-> %s (%s): recorded confidence %q, new observation says %q; kept the recorded one",
				ed.From, ed.Relation, ed.To, ed.Source, have.Confidence, ed.Confidence))
		}
	}
	abs := map[string]bool{}
	for _, a := range out.Absences {
		abs[a.key()] = true
	}
	for _, a := range add.Absences {
		switch {
		case blocked[a.Subject]:
			res.Conflicts = append(res.Conflicts, fmt.Sprintf("absence for %s: dropped, the node conflicts with the recorded one", a.Subject))
		case abs[a.key()]:
			res.Unchanged++
		default:
			abs[a.key()] = true
			out.Absences = append(out.Absences, a)
			res.AddedAbsences++
		}
	}
	return &out, res
}

// estateFile reports whether a file name is read as an estate file.
func estateFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// ValidEstateName checks an estate file name before the filesystem is touched.
func ValidEstateName(name string) error {
	if err := lexical(name); err != nil {
		return fmt.Errorf("estate file %q: %w", name, err)
	}
	if !estateFile(name) {
		return fmt.Errorf("estate file %q: must end in .yaml or .yml", name)
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("estate file %q: must be directly inside the estate directory", name)
	}
	return nil
}

// estatePaths resolves the estate directory and one file inside it.
func estatePaths(c *Case, name string) (dir, file string, err error) {
	if err := ValidEstateName(name); err != nil {
		return "", "", err
	}
	if c.Dir == "" {
		return "", "", errors.New("Dir is not set: paths cannot be checked")
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return "", "", err
	}
	dir, err = resolveInside(root, c.Paths.Estate)
	if err != nil {
		return "", "", fmt.Errorf("paths.estate: %w", err)
	}
	file, err = resolveInside(root, path.Join(c.Paths.Estate, name))
	if err != nil {
		return "", "", fmt.Errorf("estate file %q: %w", name, err)
	}
	if !within(dir, file) {
		return "", "", fmt.Errorf("estate file %q resolves outside the estate directory %q", name, c.Paths.Estate)
	}
	return dir, file, nil
}

// LoadEstateFile reads one estate file from the case's estate directory (paths.estate).
// It is confined like an actor file and is at most 4 MiB.
func LoadEstateFile(c *Case, name string) (*Estate, error) {
	_, file, err := estatePaths(c, name)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(file) // #nosec G304 -- confined by estatePaths
	if err != nil {
		return nil, fmt.Errorf("estate file %q: %w", name, err)
	}
	defer fh.Close()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("estate file %q is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxEstateSize+1))
	if err != nil {
		return nil, fmt.Errorf("read estate file %q: %w", name, err)
	}
	if len(data) > maxEstateSize {
		return nil, fmt.Errorf("estate file %q is larger than %d bytes", name, maxEstateSize)
	}
	e, err := ParseEstate(data)
	if err != nil {
		return nil, fmt.Errorf("estate file %q: %w", name, err)
	}
	return e, nil
}

// LoadEstates reads every .yaml and .yml file directly inside the estate directory, in
// name order. A missing directory means no estate. Every broken file is reported, and
// so is an id used by two files.
func LoadEstates(c *Case) ([]*Estate, error) {
	if c.Dir == "" {
		return nil, errors.New("Dir is not set: paths cannot be checked")
	}
	root, err := realRoot(c.Dir)
	if err != nil {
		return nil, err
	}
	dir, err := resolveInside(root, c.Paths.Estate)
	if err != nil {
		return nil, fmt.Errorf("paths.estate: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read estate directory: %w", err)
	}
	var out []*Estate
	var errs []error
	from := map[string]string{}
	for _, en := range entries {
		if !estateFile(en.Name()) {
			continue
		}
		e, err := LoadEstateFile(c, en.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if other, dup := from[e.ID]; dup {
			errs = append(errs, fmt.Errorf("estate id %q is used by %s and %s", e.ID, other, en.Name()))
			continue
		}
		from[e.ID] = en.Name()
		out = append(out, e)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

// SaveEstateFile validates e and replaces the named file atomically (temporary file in
// the same directory, then rename), so a refused or interrupted save leaves the earlier
// file intact.
func SaveEstateFile(c *Case, name string, e *Estate) error {
	dir, file, err := estatePaths(c, name)
	if err != nil {
		return err
	}
	data, err := MarshalEstate(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create estate directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".estate-*.tmp")
	if err != nil {
		return fmt.Errorf("write estate file: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write estate file: %w", err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), file); err != nil {
		return fmt.Errorf("write estate file: %w", err)
	}
	return nil
}

// DefaultEstateCaveat is written into an estate file the collector creates. A person
// can reword it; the loader only requires that it is not empty.
const DefaultEstateCaveat = "This map shows infrastructure ownership and relationships as public registries and DNS describe them. " +
	"It does not show who typed the commands. A CDN or proxy edge address says nothing about the visitor behind it."
