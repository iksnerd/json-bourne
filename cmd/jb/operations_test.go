package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/ops"
	"github.com/iksnerd/json-bourne/jb"
)

func runOps(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Execute(context.Background(), append([]string{"operations"}, args...), &out, &errb)
	return out.String(), errb.String(), code
}

func TestOperationsCommandPrintsValidDefinitions(t *testing.T) {
	out, errs, code := runOps(t)
	if code != 0 || errs != "" {
		t.Fatalf("code %d stderr %q", code, errs)
	}
	var list []ops.Operation
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		t.Fatalf("output is not a list of operations: %v\n%s", err, out)
	}
	if len(list) != len(jb.Operations()) || len(list) == 0 {
		t.Fatalf("listed %d operations", len(list))
	}
	if ps := ops.ValidateAll(list); len(ps) != 0 {
		t.Fatalf("output breaks the RFC rules: %s", ops.Describe(ps))
	}
	for _, op := range list {
		if op.CLI == nil {
			t.Errorf("%s has no cli in the full definition", op.Name)
		}
	}
}

func TestOperationsCommandJSONFlagIsTheDefault(t *testing.T) {
	a, _, _ := runOps(t)
	b, _, code := runOps(t, "--output", "json")
	if code != 0 || a != b {
		t.Fatalf("--output json differs from the default (code %d)", code)
	}
}

func TestOperationsToolPrintsMCPEntries(t *testing.T) {
	out, errs, code := runOps(t, "--tool")
	if code != 0 || errs != "" {
		t.Fatalf("code %d stderr %q", code, errs)
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != len(jb.Operations()) {
		t.Fatalf("listed %d tools", len(list))
	}
	for _, e := range list {
		if _, ok := e["cli"]; ok {
			t.Errorf("tool %v carries cli", e["name"])
		}
		if _, ok := e["annotations"]; !ok {
			t.Errorf("tool %v has no annotations", e["name"])
		}
		if _, ok := e["inputSchema"]; !ok {
			t.Errorf("tool %v has no inputSchema", e["name"])
		}
	}
}

func TestOperationsTableNamesEveryOperation(t *testing.T) {
	out, _, code := runOps(t, "--output", "table")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, op := range jb.Operations() {
		if !strings.Contains(out, op.Name) {
			t.Errorf("table lacks %s:\n%s", op.Name, out)
		}
	}
}

func TestOperationsUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"--output", "xml"}, {"extra"}, {"--tool", "--output", "table"}} {
		_, errs, code := runOps(t, args...)
		if code != 2 {
			t.Errorf("%v: code %d stderr %q, want 2", args, code, errs)
		}
	}
}

// docs/operations.json is the committed copy of `jb operations`. Regenerate it with
// `go run ./cmd/jb operations > docs/operations.json` after changing an operation.
func TestOperationsGoldenFile(t *testing.T) {
	want, err := os.ReadFile("../../docs/operations.json")
	if err != nil {
		t.Fatal(err)
	}
	got, _, code := runOps(t)
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if got != string(want) {
		t.Fatalf("docs/operations.json is out of date; regenerate it with: go run ./cmd/jb operations > docs/operations.json")
	}
}
