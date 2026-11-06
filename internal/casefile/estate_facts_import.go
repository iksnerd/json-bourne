package casefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// FactsImportAPIVersion is the one neutral import shape `jb estate facts import` reads
// (docs/CASE-SPEC.md section 4.5.2). The operator converts an export they obtained, with
// a script they control, into this shape. jb reads no vendor format and never goes to
// the network for it.
const FactsImportAPIVersion = "jb.estate-facts/v1"

// FactsImportSource is the source role every imported fact carries: a cache of past
// observations by someone else (docs/POLICY.md, "The test for a source").
const FactsImportSource = "scan-cache"

const (
	// MaxFactsImportSize is the most bytes of an import file.
	MaxFactsImportSize = 1 << 20
	// MaxFactsImportFacts is the most facts (values) in one import file.
	MaxFactsImportFacts = 5000
)

// FactsImport is a parsed, validated import file.
type FactsImport struct {
	APIVersion string `json:"apiVersion"`
	// Method says how the data was obtained, for example the export and the script that
	// converted it. It becomes part of each fact's method, so two exports taken by
	// different means are never compared as one question.
	Method string `json:"method"`
	// SourceNote names where the data came from (the store and the date of the export).
	SourceNote string `json:"source_note"`
	// Observed is when the store observed the data. An entry may carry its own time.
	Observed string             `json:"observed"`
	Facts    []FactsImportEntry `json:"facts"`
}

// FactsImportEntry is the values one node has for one key.
type FactsImportEntry struct {
	Node     string   `json:"node"`
	Key      string   `json:"key"`
	Values   []string `json:"values"`
	Observed string   `json:"observed,omitempty"`
}

// Count returns the number of facts (values) in the import.
func (f *FactsImport) Count() int {
	n := 0
	for _, e := range f.Facts {
		n += len(e.Values)
	}
	return n
}

func (f *FactsImport) factMethod() string {
	return f.Method + " (source: " + f.SourceNote + ")"
}

// ParseFactsImport decodes and validates an import file without touching the
// filesystem or the network. An unknown key is an error at any depth.
func ParseFactsImport(data []byte) (*FactsImport, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("file is empty")
	}
	if len(data) > MaxFactsImportSize {
		return nil, fmt.Errorf("file is larger than %d bytes", MaxFactsImportSize)
	}
	var f FactsImport
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("not a valid import file (JSON object with the keys of docs/CASE-SPEC.md section 4.5.2): %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value in the file")
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *FactsImport) validate() error {
	var errs []error
	bad := func(format string, v ...any) { errs = append(errs, fmt.Errorf(format, v...)) }
	switch {
	case f.APIVersion == "":
		bad("apiVersion is required (this build reads %s)", FactsImportAPIVersion)
	case f.APIVersion != FactsImportAPIVersion:
		bad("unsupported apiVersion %q: this build reads only %s", f.APIVersion, FactsImportAPIVersion)
	}
	for _, x := range []struct{ name, v string }{{"method", f.Method}, {"source_note", f.SourceNote}} {
		if err := checkLine(x.name, x.v, maxEstateLine); err != nil {
			errs = append(errs, err)
		}
	}
	if len(f.Method)+len(" (source: )")+len(f.SourceNote) > maxEstateLine {
		bad("method and source_note together are longer than %d bytes", maxEstateLine)
	}
	if err := checkImportTime("observed", f.Observed); err != nil {
		errs = append(errs, err)
	}
	if len(f.Facts) == 0 {
		bad("facts holds no entry")
	}
	if n := f.Count(); n > MaxFactsImportFacts {
		bad("the file holds %d facts, at most %d", n, MaxFactsImportFacts)
		return errors.Join(errs...)
	}
	for _, s := range []string{f.Method, f.SourceNote} {
		if looksLikeCredential(s) {
			bad("method or source_note holds a credential-shaped value")
		}
	}
	for i, e := range f.Facts {
		if e.Node == "" {
			bad("facts[%d]: missing required field %q", i, "node")
		}
		switch {
		case e.Key == "":
			bad("facts[%d]: missing required field %q", i, "key")
		case !factKeyRE.MatchString(e.Key):
			bad("facts[%d]: key %q must match %s", i, e.Key, factKeyRE)
		}
		if e.Observed != "" {
			if err := checkImportTime("observed", e.Observed); err != nil {
				bad("facts[%d]: %v", i, err)
			}
		}
		if len(e.Values) == 0 {
			bad("facts[%d]: values holds no entry", i)
		}
		seen := map[string]bool{}
		for j, v := range e.Values {
			if err := checkLine("value", v, maxEstateLine); err != nil {
				bad("facts[%d].values[%d]: %v", i, j, err)
			}
			if looksLikeCredential(v) {
				bad("facts[%d].values[%d] holds a credential-shaped value; an import file names facts about hosts and never holds a credential", i, j)
			}
			if seen[v] {
				bad("facts[%d].values[%d]: duplicate value %q for this node and key", i, j, v)
			}
			seen[v] = true
		}
	}
	return errors.Join(errs...)
}

func checkImportTime(name, v string) error {
	if v == "" {
		return fmt.Errorf("missing required field %q", name)
	}
	if _, err := time.Parse(time.RFC3339, v); err != nil {
		return fmt.Errorf("%s %q must be an RFC 3339 timestamp with a zone, e.g. 2026-11-05T08:00:00Z", name, v)
	}
	return nil
}

// FactsImportResult counts what ApplyFactsImport did.
type FactsImportResult struct {
	Added     int // facts new to the estate
	Unchanged int // facts already recorded, identical in key, value, source and method
}

// ApplyFactsImport adds the facts of imp to a copy of base. Every fact has the source
// `scan-cache`, the import's method and note, and the observed time of its entry or of
// the file. A fact already recorded is left as it is, with its original time. The whole
// import is refused, and base is not changed, when a node it names is not in base or when
// the result would not load: more than 50 facts on one node, more than 20000 in the file,
// or anything else the loader checks.
func ApplyFactsImport(base *Estate, imp *FactsImport) (*Estate, FactsImportResult, error) {
	var res FactsImportResult
	out := *base
	out.Nodes = slices.Clone(base.Nodes)
	index := map[string]int{}
	for i := range out.Nodes {
		out.Nodes[i].Facts = slices.Clone(out.Nodes[i].Facts)
		index[out.Nodes[i].ID] = i
	}
	method := imp.factMethod()
	var missing []string
	for _, e := range imp.Facts {
		i, ok := index[e.Node]
		if !ok {
			if !slices.Contains(missing, e.Node) {
				missing = append(missing, e.Node)
			}
			continue
		}
		at := e.Observed
		if at == "" {
			at = imp.Observed
		}
		for _, v := range e.Values {
			f := Fact{Key: e.Key, Value: v, Source: FactsImportSource, Method: method, Observed: at}
			if slices.ContainsFunc(out.Nodes[i].Facts, func(have Fact) bool { return have.key() == f.key() }) {
				res.Unchanged++
				continue
			}
			out.Nodes[i].Facts = append(out.Nodes[i].Facts, f)
			res.Added++
		}
	}
	if len(missing) > 0 {
		return nil, FactsImportResult{}, fmt.Errorf("the import names node(s) that are not in the estate file, so nothing was imported: %s (a fact needs a node that was recorded first; see `jb estate`)", strings.Join(missing, ", "))
	}
	// Everything the loader checks, including the caps and the credential scan.
	if _, err := MarshalEstate(&out); err != nil {
		return nil, FactsImportResult{}, fmt.Errorf("the import would leave an estate file that does not load, so nothing was imported: %w", err)
	}
	return &out, res, nil
}
