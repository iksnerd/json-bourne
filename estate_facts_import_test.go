package jb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

const factsImportDoc = `{
  "apiVersion": "jb.estate-facts/v1",
  "method": "export of a synthetic scan store, converted by a synthetic script",
  "source_note": "synthetic store, export dated 2026-11-05",
  "observed": "2026-11-05T08:00:00Z",
  "facts": [
    {"node": "ip:192.0.2.10", "key": "os", "values": ["linux"]},
    {"node": "host:edge.example.com", "key": "tech", "values": ["nginx", "php"]}
  ]
}`

func writeImport(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func estateFacts(t *testing.T, dir, file string) int {
	t.Helper()
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casefile.LoadEstateFile(c, file)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range e.Nodes {
		n += len(x.Facts)
	}
	return n
}

// Like every mutating function, a call without Apply changes nothing and says what it
// would have done.
func TestEstateFactsImportIsADryRunUnlessApplied(t *testing.T) {
	dir := copyCase(t)
	file := "example-estate.yaml"
	before, err := os.ReadFile(filepath.Join(dir, "estate", file))
	if err != nil {
		t.Fatal(err)
	}
	have := estateFacts(t, dir, file)
	imp := writeImport(t, factsImportDoc)

	res, err := EstateFactsImport(dir, imp, EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || res.Added != 3 || res.Unchanged != 0 || res.Facts != 3 || res.Source != "scan-cache" {
		t.Fatalf("%+v", res)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "estate", file))
	if string(after) != string(before) {
		t.Fatal("a dry run changed the estate file")
	}

	res, err = EstateFactsImport(dir, imp, EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}, Apply: true})
	if err != nil || !res.Applied || res.Added != 3 {
		t.Fatalf("%v %+v", err, res)
	}
	if got := estateFacts(t, dir, file); got != have+3 {
		t.Errorf("facts %d, want %d", got, have+3)
	}
	// The same export again adds nothing and does not rewrite the file.
	again, err := EstateFactsImport(dir, imp, EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}, Apply: true})
	if err != nil || again.Added != 0 || again.Unchanged != 3 || again.Applied {
		t.Fatalf("%v %+v", err, again)
	}
	// The result prints as the CLI prints it.
	hasKeys(t, "EstateFactsImportResult", keysOf(t, res), "note", "file", "import", "source", "method", "entries", "facts", "added", "unchanged", "applied")
}

func TestEstateFactsImportRefusesCallerMistakes(t *testing.T) {
	dir := copyCase(t)
	file := "example-estate.yaml"
	opts := EstateFactsImportOptions{EstateOptions: EstateOptions{File: file}, Apply: true}
	have := estateFacts(t, dir, file)
	bad := map[string]struct {
		dir, file, doc string
	}{
		"no case":            {"", "x", ""},
		"no file":            {dir, "", ""},
		"missing file":       {dir, filepath.Join(t.TempDir(), "none.json"), ""},
		"unknown key":        {dir, "", strings.Replace(factsImportDoc, `"method"`, `"vendor": "x", "method"`, 1)},
		"unknown node":       {dir, "", strings.Replace(factsImportDoc, "ip:192.0.2.10", "ip:203.0.113.9", 1)},
		"not json":           {dir, "", "nodes: []"},
		"not a regular file": {dir, os.TempDir(), ""},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			path := c.file
			if path == "" && c.doc != "" {
				path = writeImport(t, c.doc)
			}
			_, err := EstateFactsImport(c.dir, path, opts)
			var ue *UsageError
			if !errors.As(err, &ue) {
				t.Fatalf("want a usage error, got %v", err)
			}
		})
	}
	if got := estateFacts(t, dir, file); got != have {
		t.Errorf("a refused import changed the file: %d facts, had %d", got, have)
	}
	if _, err := EstateFactsImport(dir, writeImport(t, factsImportDoc), EstateFactsImportOptions{EstateOptions: EstateOptions{File: "../x.yaml"}}); err == nil {
		t.Error("a file name with a path was accepted")
	}
	if _, err := EstateFactsImport(dir, writeImport(t, factsImportDoc), EstateFactsImportOptions{EstateOptions: EstateOptions{File: "absent.yaml"}}); err == nil {
		t.Error("an import into an estate file that does not exist was accepted")
	}
}

// An import file larger than the cap is refused without being read whole.
func TestEstateFactsImportRefusesAnOversizedFile(t *testing.T) {
	dir := copyCase(t)
	p := writeImport(t, strings.Repeat(" ", casefile.MaxFactsImportSize+10)+factsImportDoc)
	_, err := EstateFactsImport(dir, p, EstateFactsImportOptions{EstateOptions: EstateOptions{File: "example-estate.yaml"}})
	var ue *UsageError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}
