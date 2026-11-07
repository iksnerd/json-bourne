package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	jb "github.com/iksnerd/json-bourne"
)

type opDoc struct {
	Name        string `json:"name"`
	ReadOnly    bool   `json:"readOnly"`
	InputSchema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	} `json:"inputSchema"`
}

// committed reads docs/operations.json, the copy of `jb operations` that the repository
// keeps. This module only asserts that what jb.Operations() returns to an outside
// program agrees with it; the repository's own test keeps the file current.
func committed(t *testing.T) []opDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "docs", "operations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []opDoc
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOperationsAgreeWithTheCommittedList(t *testing.T) {
	want := committed(t)
	got := jb.Operations()
	if len(got) != len(want) {
		t.Fatalf("%d operations, docs/operations.json lists %d", len(got), len(want))
	}
	if len(got) != 22 {
		t.Errorf("%d operations; the README says 22 (everything but watch and serve)", len(got))
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.Name || g.ReadOnly != w.ReadOnly {
			t.Errorf("operation %d: got %s readOnly=%v, committed %s readOnly=%v", i, g.Name, g.ReadOnly, w.Name, w.ReadOnly)
		}
		var props []string
		for p := range g.InputSchema.Properties {
			props = append(props, p)
		}
		var wantProps []string
		for p := range w.InputSchema.Properties {
			wantProps = append(wantProps, p)
		}
		sort.Strings(props)
		sort.Strings(wantProps)
		if strings.Join(props, ",") != strings.Join(wantProps, ",") {
			t.Errorf("%s: properties %v, committed %v", g.Name, props, wantProps)
		}
		if strings.Join(g.InputSchema.Required, ",") != strings.Join(w.InputSchema.Required, ",") {
			t.Errorf("%s: required %v, committed %v", g.Name, g.InputSchema.Required, w.InputSchema.Required)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Name >= got[i].Name {
			t.Errorf("operations are not sorted by name at %s", got[i].Name)
		}
	}
}

// Operations returns a copy: a caller that edits it changes nothing for the next caller.
func TestOperationsReturnsACopy(t *testing.T) {
	a := jb.Operations()
	a[0].Name, a[0].ReadOnly = "tampered", !a[0].ReadOnly
	b := jb.Operations()
	if b[0].Name == "tampered" {
		t.Error("an edit of the returned list reached the next caller")
	}
}

// dryRunArgs gives, for each operation that takes apply, arguments that would change
// something if apply were true.
func dryRunArgs(dir string) map[string]map[string]any {
	return map[string]map[string]any{
		"db_prune":            {"case": dir, "kind": "hunt", "older_than": "1m", "keep_latest": 0},
		"db_compact":          {"case": dir, "to": filepath.Join(dir, "evidence", "copy.duckdb")},
		"db_rename_source":    {"case": dir, "old": "kibana:logs-http-*", "new": "renamed"},
		"estate_facts_import": {"case": dir, "file": "example-estate.yaml", "import_file": ""},
	}
}

func TestAMutatingOperationWithoutApplyChangesNothing(t *testing.T) {
	dir, _ := pinned(t)
	imp := filepath.Join(t.TempDir(), "export.json")
	body := `{"apiVersion":"jb.estate-facts/v1","method":"synthetic export","source_note":"synthetic","observed":"2026-11-05T08:00:00Z",
"facts":[{"node":"ip:192.0.2.10","key":"os","values":["linux"]}]}`
	if err := os.WriteFile(imp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	table := dryRunArgs(dir)
	table["estate_facts_import"]["import_file"] = imp

	// Every mutating operation that takes apply has a row; a new one needs a row too.
	have := map[string]bool{}
	for _, op := range jb.Operations() {
		if _, ok := op.InputSchema.Properties["apply"]; ok {
			have[op.Name] = true
			if op.ReadOnly {
				t.Errorf("%s takes apply but is marked read only", op.Name)
			}
			if _, ok := table[op.Name]; !ok {
				t.Errorf("%s takes apply and has no row in this test", op.Name)
			}
		}
	}
	for name := range table {
		if !have[name] {
			t.Errorf("row %s: the operation no longer takes apply", name)
		}
	}

	before := treeDigest(t, dir)
	for name, args := range table {
		for _, variant := range []string{"omitted", "false"} {
			a := map[string]any{}
			for k, v := range args {
				a[k] = v
			}
			if variant == "false" {
				a["apply"] = false
			}
			if _, err := jb.Call(t.Context(), name, a, env); err != nil {
				t.Errorf("%s (apply %s): %v", name, variant, err)
			}
			sameTree(t, name+" with apply "+variant, before, treeDigest(t, dir))
		}
	}
	// With apply: true the first one does change the store, so the check has teeth.
	if _, err := jb.Call(t.Context(), "db_rename_source", map[string]any{"case": dir, "old": "kibana:logs-http-*", "new": "renamed", "apply": true}, env); err != nil {
		t.Fatal(err)
	}
	changed := false
	for p, h := range treeDigest(t, dir) {
		changed = changed || before[p] != h
	}
	if !changed {
		t.Error("apply: true changed nothing, so the dry-run check above proves nothing")
	}
}

// An external estate service is off until the case lists it: refused as a usage error
// and nothing leaves the machine or the case.
func TestEstateExternalOperationsAreOffUntilTheCaseEnablesThem(t *testing.T) {
	dir := exampleCase(t, nil)
	before := treeDigest(t, dir)
	for name, target := range map[string]string{"estate_asn": "64496", "estate_dns": "example.com", "estate_ct": "example.com"} {
		_, err := jb.Call(t.Context(), name, map[string]any{"case": dir, "targets": []any{target}}, env)
		if !jb.IsUsage(err) || !strings.Contains(err.Error(), "not enabled, so nothing was sent") {
			t.Errorf("%s: want a usage error saying nothing was sent, got %v", name, err)
		}
		noPrefix(t, name, err)
	}
	sameTree(t, "a refused estate call", before, treeDigest(t, dir))
}

func TestCallRunsHuntAndActivityStoredUnlessToldOtherwise(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	store := filepath.Join(dir, "evidence", "jb.duckdb")
	args := func(extra map[string]any) map[string]any {
		a := map[string]any{"case": dir, "config": fpConfig, "window": "1h"}
		for k, v := range extra {
			a[k] = v
		}
		return a
	}

	out, err := jb.Call(t.Context(), "hunt", args(map[string]any{"store": false}), env)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := out.(*jb.Result); !ok || res.Stored {
		t.Errorf("store false: %T %+v", out, out)
	}
	if _, err := os.Stat(store); err == nil {
		t.Fatal("store false left an evidence database")
	}

	// An MCP tool call never stores: the property is not offered, and is refused.
	if _, err := jb.CallTool(t.Context(), "hunt", args(map[string]any{"store": true}), env); !jb.IsUsage(err) {
		t.Errorf("CallTool accepted store: %v", err)
	}
	if _, err := jb.CallTool(t.Context(), "hunt", args(nil), env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store); err == nil {
		t.Fatal("a tool call left an evidence database")
	}

	// Call stores by default, as the command line does.
	if _, err := jb.Call(t.Context(), "activity", args(nil), env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store); err != nil {
		t.Errorf("Call with store omitted must store: %v", err)
	}
}

// Call returns the value of the typed function: the same type, not a map.
func TestCallReturnsTheTypedResult(t *testing.T) {
	dir := exampleCase(t, nil)
	out, err := jb.Call(t.Context(), "case_check", map[string]any{"case": dir}, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.(*jb.CaseCheckResult); !ok {
		t.Errorf("case_check returned %T", out)
	}
	out, err = jb.Call(t.Context(), "case_show", map[string]any{"case": dir, "config": "config/hunt.yaml"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.(*jb.CaseShowResult); !ok {
		t.Errorf("case_show returned %T", out)
	}
}
