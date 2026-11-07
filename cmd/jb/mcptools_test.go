package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/ops"
)

var updateMCPTools = flag.Bool("update-mcp-tools", false, "rewrite testdata/mcp-tools.golden")

// withoutDescriptions removes the prose from a schema so the golden pins the contract
// (names, types, required, enums, defaults, bounds) and not the wording.
func withoutDescriptions(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if k == "description" || k == "title" {
				if _, isSchema := e.(map[string]any); !isSchema {
					continue
				}
			}
			out[k] = withoutDescriptions(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = withoutDescriptions(e)
		}
		return out
	}
	return v
}

type listedTool struct {
	Name        string `json:"name"`
	Annotations struct {
		ReadOnlyHint bool `json:"readOnlyHint"`
	} `json:"annotations"`
	InputSchema any `json:"inputSchema"`
}

// listTools asks the real `jb mcp` server for tools/list, with the given --allow flags.
func listTools(t *testing.T, allow ...string) []listedTool {
	t.Helper()
	var args []string
	for _, a := range allow {
		args = append(args, "--allow", a)
	}
	msgs, stderr, code := runMCP(t, mcpInit+`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n", args...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, m := range msgs {
		if m["id"] != float64(1) {
			continue
		}
		raw, err := json.Marshal(m["result"].(map[string]any)["tools"])
		if err != nil {
			t.Fatal(err)
		}
		var tools []listedTool
		if err := json.Unmarshal(raw, &tools); err != nil {
			t.Fatal(err)
		}
		return tools
	}
	t.Fatal("no tools/list response")
	return nil
}

func toolLine(tl listedTool) string {
	schema, err := json.Marshal(withoutDescriptions(tl.InputSchema))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s readOnlyHint=%v %s\n", tl.Name, tl.Annotations.ReadOnlyHint, schema)
}

func mcpToolsDocument(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	base := listTools(t)
	b.WriteString("## jb mcp (default)\n")
	var baseNames []string
	for _, tl := range base {
		b.WriteString(toolLine(tl))
		baseNames = append(baseNames, tl.Name)
	}
	var mutating []string
	for _, op := range newMCPRegistry().ops {
		if !op.ReadOnly {
			mutating = append(mutating, op.Name)
		}
	}
	slices.Sort(mutating)
	for _, name := range mutating {
		b.WriteString("## jb mcp --allow " + name + " (adds)\n")
		for _, tl := range listTools(t, name) {
			if !slices.Contains(baseNames, tl.Name) {
				b.WriteString(toolLine(tl))
			}
		}
	}
	return b.String()
}

// TestMCPToolListIsUnchanged pins what `jb mcp` lists by default and with each --allow:
// tool names, readOnlyHint and input schema (RFC 0018). Rewrite the golden with
// -update-mcp-tools after reading the diff; docs/operations.json changes with it.
func TestMCPToolListIsUnchanged(t *testing.T) {
	got := mcpToolsDocument(t)
	const path = "testdata/mcp-tools.golden"
	if *updateMCPTools {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("the MCP tool list differs from %s (rerun with -update-mcp-tools if the change is deliberate)\n%s", path, firstDiff(string(want), got))
	}
}

// The tool list agrees with docs/operations.json: every operation in it is a tool named
// the same, read-only ones are listed by default, and the hint equals the readOnly flag.
func TestMCPToolListAgreesWithOperationsJSON(t *testing.T) {
	data, err := os.ReadFile("../../docs/operations.json")
	if err != nil {
		t.Fatal(err)
	}
	var committed []ops.Operation
	if err := json.Unmarshal(data, &committed); err != nil {
		t.Fatal(err)
	}
	var mutating []string
	byDefault := map[string]bool{}
	for _, tl := range listTools(t) {
		byDefault[tl.Name] = tl.Annotations.ReadOnlyHint
	}
	for _, op := range committed {
		hint, listed := byDefault[op.Name]
		switch {
		case op.ReadOnly && !(listed && hint):
			t.Errorf("read-only operation %s is not listed by default as readOnlyHint=true", op.Name)
		case !op.ReadOnly && listed:
			t.Errorf("mutating operation %s is listed by default", op.Name)
		}
		if !op.ReadOnly {
			mutating = append(mutating, op.Name)
		}
	}
	if len(byDefault) != len(committed)-len(mutating) {
		t.Errorf("%d tools listed by default, operations.json has %d read-only operations", len(byDefault), len(committed)-len(mutating))
	}
	for _, name := range mutating {
		var found bool
		for _, tl := range listTools(t, name) {
			if tl.Name == name {
				found = true
				if tl.Annotations.ReadOnlyHint {
					t.Errorf("%s is mutating but listed with readOnlyHint=true", name)
				}
			}
		}
		if !found {
			t.Errorf("--allow %s does not list it", name)
		}
	}
}
