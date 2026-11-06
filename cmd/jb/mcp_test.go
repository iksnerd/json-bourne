package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/mcp"
	"github.com/iksnerd/json-bourne/internal/ops"
)

const mcpInit = `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n" +
	`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"

// runMCP runs `jb mcp args...` with the lines as standard input and returns the decoded
// responses in order. Standard input ends after the lines, which stops the server.
func runMCP(t *testing.T, lines string, args ...string) (msgs []map[string]any, stderr string, code int) {
	t.Helper()
	root := newRootCmdWith(testDeps(nil))
	var out, errb bytes.Buffer
	root.SetIn(strings.NewReader(lines))
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(append([]string{"mcp"}, args...))
	if err := root.ExecuteContext(context.Background()); err != nil {
		code = exitUsage
		errb.WriteString(err.Error())
	}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stdout carries a non-protocol line: %q", l)
		}
		msgs = append(msgs, m)
	}
	return msgs, errb.String(), code
}

func TestMCPEndToEndOnTheRealRegistry(t *testing.T) {
	lines := mcpInit +
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"case_check","arguments":{"case":"../../examples/case"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"case_check","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"case_show","arguments":{"case":"../../examples/case","bogus":1}}}` + "\n" +
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"not_an_operation"}}` + "\n"
	msgs, stderr, code := runMCP(t, lines)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	byID := map[float64]map[string]any{}
	for _, m := range msgs {
		byID[m["id"].(float64)] = m
	}
	if v := byID[0]["result"].(map[string]any)["serverInfo"].(map[string]any); v["name"] != "jb" || v["version"] == "" {
		t.Errorf("serverInfo = %v", v)
	}
	var listed []string
	for _, x := range byID[1]["result"].(map[string]any)["tools"].([]any) {
		tool := x.(map[string]any)
		listed = append(listed, tool["name"].(string))
		if tool["annotations"].(map[string]any)["readOnlyHint"] != true {
			t.Errorf("%v is listed by default and is not read-only", tool["name"])
		}
	}
	for _, want := range []string{"case_check", "case_show"} {
		if !contains(listed, want) {
			t.Errorf("%s is not listed: %v", want, listed)
		}
	}
	r := byID[2]["result"].(map[string]any)
	if r["isError"] != false {
		t.Fatalf("case_check on examples/case: %v", r)
	}
	if sc := r["structuredContent"].(map[string]any); sc["ok"] != true {
		t.Errorf("case_check result = %v", sc)
	}
	for _, id := range []float64{3, 4} {
		r := byID[id]["result"].(map[string]any)
		text := r["content"].([]any)[0].(map[string]any)["text"].(string)
		if r["isError"] != true || !strings.Contains(text, "argument-") {
			t.Errorf("call %v should be a tool execution error listing the problem: %v", id, r)
		}
	}
	if e, ok := byID[5]["error"].(map[string]any); !ok || e["code"] != float64(-32602) {
		t.Errorf("unknown tool = %v", byID[5])
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestMCPAllowOfAnUnknownOperationIsAUsageError(t *testing.T) {
	_, stderr, code := runMCP(t, "", "--allow", "no_such_operation")
	if code != exitUsage || !strings.Contains(stderr, "no_such_operation") {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
	if _, _, code := runMCP(t, "", "--allow", "case_check"); code != 0 {
		t.Errorf("allowing a known operation exited %d", code)
	}
}

func TestMCPWritesNothingToStdoutBeforeAMessage(t *testing.T) {
	msgs, _, code := runMCP(t, "")
	if code != 0 || len(msgs) != 0 {
		t.Errorf("code %d, messages %v", code, msgs)
	}
}

// pruneRegistry is the registry with a stand-in db_prune whose handler is the library
// function with the same option mapping the real handler uses: apply is the only thing
// that deletes.
func pruneRegistry(config string) *mcpRegistry {
	schema := ops.Schema{Type: "object", Properties: map[string]ops.Property{
		"run":   {Type: "string"},
		"apply": {Type: "boolean"},
	}, Required: []string{}}
	return &mcpRegistry{
		ops: []ops.Operation{
			{Name: "case_check", Description: "Checks.", InputSchema: ops.Schema{Type: "object", Properties: map[string]ops.Property{}, Required: []string{}}, ReadOnly: true},
			{Name: "db_prune", Description: "Prunes.", InputSchema: schema, ReadOnly: false},
		},
		call: func(ctx context.Context, name string, args map[string]any) (any, error) {
			apply, _ := args["apply"].(bool)
			return jb.DBPrune(ctx, "", jb.DBPruneOptions{Config: config, RunIDs: []string{args["run"].(string)}, Apply: apply})
		},
	}
}

func TestMCPMutatingToolIsHiddenUntilAllowedAndNeedsApply(t *testing.T) {
	cfg, store := seedMaint(t, runIDHunts)
	reg := pruneRegistry(cfg)

	if got := reg.Tools(nil); len(got) != 1 || got[0].Name != "case_check" {
		t.Fatalf("default tools = %v", got)
	}
	if got := reg.Tools([]string{"db_prune"}); len(got) != 2 || got[1].Annotations.ReadOnlyHint {
		t.Fatalf("allowed tools = %v", got)
	}

	var in, out bytes.Buffer
	in.WriteString(mcpInit)
	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db_prune","arguments":{"run":"hunt-20261001T000000Z"}}}` + "\n")
	if err := mcp.Serve(context.Background(), &in, &out, &bytes.Buffer{}, mcp.Config{Version: "t", Registry: reg}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "-32602") {
		t.Errorf("an unallowed mutating tool was callable: %s", out.String())
	}
	before := eventsOf(t, store)

	run := func(allow []string, args string) {
		t.Helper()
		var in, out bytes.Buffer
		in.WriteString(mcpInit)
		in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db_prune","arguments":` + args + `}}` + "\n")
		if err := mcp.Serve(context.Background(), &in, &out, &bytes.Buffer{}, mcp.Config{Version: "t", Allow: allow, Registry: reg}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), `"isError":false`) {
			t.Fatalf("call failed: %s", out.String())
		}
	}
	run([]string{"db_prune"}, `{"run":"hunt-20261001T000000Z"}`)
	if got := eventsOf(t, store); !sameCounts(got, before) {
		t.Errorf("a call without apply changed the store: %v -> %v", before, got)
	}
	run([]string{"db_prune"}, `{"run":"hunt-20261001T000000Z","apply":true}`)
	if got := eventsOf(t, store); sameCounts(got, before) {
		t.Errorf("apply=true deleted nothing: %v", got)
	}
}

func sameCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestMCPHuntAndActivityNeverStoreAndHideTheStoreProperty(t *testing.T) {
	schema := ops.Schema{Type: "object", Properties: map[string]ops.Property{"store": {Type: "boolean"}, "case": {Type: "string"}}, Required: []string{}}
	var seen map[string]any
	reg := &mcpRegistry{
		ops: []ops.Operation{
			{Name: "hunt", Description: "Hunts.", InputSchema: schema, ReadOnly: false},
			{Name: "case_show", Description: "Shows.", InputSchema: schema, ReadOnly: true, CLI: &ops.CLI{Command: []string{"case", "show"}, Only: []string{"case"}}},
		},
		call: func(_ context.Context, _ string, args map[string]any) (any, error) {
			seen = args
			return map[string]any{}, nil
		},
	}
	tools := reg.Tools(nil)
	if len(tools) != 2 || tools[0].Name != "hunt" || !tools[0].Annotations.ReadOnlyHint {
		t.Fatalf("hunt is not a default read-only tool: %+v", tools)
	}
	if _, ok := tools[0].InputSchema.Properties["store"]; ok {
		t.Error("the store property is still offered")
	}
	if _, err := reg.Call(context.Background(), "hunt", map[string]any{"case": "x"}); err != nil {
		t.Fatal(err)
	}
	if seen["store"] != false || seen["case"] != "x" {
		t.Errorf("handler saw %v", seen)
	}
	if _, err := reg.Call(context.Background(), "hunt", map[string]any{"store": true}); err == nil || !jb.IsUsage(err) {
		t.Errorf("a supplied store was accepted: %v", err)
	}
	// A property that only the command line accepts is refused as unknown.
	if _, err := reg.Call(context.Background(), "case_show", map[string]any{"case": "x"}); err == nil || !strings.Contains(err.Error(), "not an argument") {
		t.Errorf("cli.only property accepted: %v", err)
	}
}
