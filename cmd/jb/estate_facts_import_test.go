package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliImportDoc = `{
  "apiVersion": "jb.estate-facts/v1",
  "method": "export of a synthetic scan store, converted by a synthetic script",
  "source_note": "synthetic store, export dated 2026-11-05",
  "observed": "2026-11-05T08:00:00Z",
  "facts": [
    {"node": "ip:192.0.2.10", "key": "os", "values": ["linux"]},
    {"node": "host:edge.example.com", "key": "tech", "values": ["nginx", "php"]}
  ]
}`

func writeCLIImport(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEstateFactsImportCommand(t *testing.T) {
	dir := copyExampleCase(t, "")
	estatePath := filepath.Join(dir, "estate", "example-estate.yaml")
	before, _ := os.ReadFile(estatePath)
	imp := writeCLIImport(t, cliImportDoc)

	// Without --apply it is a dry run.
	code, out, errs := run(t, testDeps(nil), "estate", "facts", "import", "--case", dir, "--file", "example-estate.yaml", imp)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"dry run", "--apply", "+3 fact(s)", "scan-cache"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
	if after, _ := os.ReadFile(estatePath); string(after) != string(before) {
		t.Fatal("a dry run changed the estate file")
	}

	code, out, errs = run(t, testDeps(nil), "estate", "facts", "import", "--case", dir, "--file", "example-estate.yaml", "--apply", "--output", "json", imp)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantEstateKeys(t, "facts import", out, "note", "file", "import", "source", "method", "entries", "facts", "added", "unchanged", "applied")
	if !strings.Contains(out, `"applied": true`) || !strings.Contains(out, `"added": 3`) {
		t.Errorf("%s", out)
	}
	if after, _ := os.ReadFile(estatePath); !strings.Contains(string(after), "scan-cache") {
		t.Error("--apply did not write the facts")
	}
	// `jb case check` still loads the file.
	if code, out, errs = run(t, testDeps(nil), "case", "check", "--case", dir); code != 0 {
		t.Fatalf("case check after the import: exit %d\n%s\n%s", code, out, errs)
	}
}

func TestEstateFactsImportCommandUsageErrors(t *testing.T) {
	dir := copyExampleCase(t, "")
	imp := writeCLIImport(t, cliImportDoc)
	bad := writeCLIImport(t, strings.Replace(cliImportDoc, "ip:192.0.2.10", "ip:203.0.113.9", 1))
	for name, args := range map[string][]string{
		"no case":       {"estate", "facts", "import", imp},
		"no file":       {"estate", "facts", "import", "--case", dir},
		"unknown node":  {"estate", "facts", "import", "--case", dir, "--file", "example-estate.yaml", bad},
		"bad output":    {"estate", "facts", "import", "--case", dir, "--file", "example-estate.yaml", "--output", "xml", imp},
		"missing input": {"estate", "facts", "import", "--case", dir, "--file", "example-estate.yaml", filepath.Join(t.TempDir(), "none.json")},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errs := run(t, testDeps(nil), args...)
			if code != exitUsage {
				t.Errorf("exit %d, want %d\n%s\n%s", code, exitUsage, out, errs)
			}
		})
	}
}
