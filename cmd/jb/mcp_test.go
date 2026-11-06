package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
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

func toolNames(ts []ops.ToolEntry) []string {
	var n []string
	for _, t := range ts {
		n = append(n, t.Name)
	}
	return n
}

// The real db_prune is a mutating operation: hidden from tools/list and refused as an
// unknown tool until the operator names it, and even then a call without apply=true
// changes nothing.
func TestMCPMutatingToolIsHiddenUntilAllowedAndNeedsApply(t *testing.T) {
	cfg, store := seedMaint(t, runIDHunts)
	reg := newMCPRegistry()

	if slices.Contains(toolNames(reg.Tools(nil)), "db_prune") {
		t.Fatalf("db_prune is listed by default: %v", toolNames(reg.Tools(nil)))
	}
	var allowed *ops.ToolEntry
	for _, tl := range reg.Tools([]string{"db_prune"}) {
		if tl.Name == "db_prune" {
			tl := tl
			allowed = &tl
		}
	}
	if allowed == nil || allowed.Annotations.ReadOnlyHint {
		t.Fatalf("db_prune with --allow = %+v", allowed)
	}

	call := func(allow []string, args string) string {
		t.Helper()
		var in, out bytes.Buffer
		in.WriteString(mcpInit)
		in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db_prune","arguments":` + args + `}}` + "\n")
		if err := mcp.Serve(context.Background(), &in, &out, &bytes.Buffer{}, mcp.Config{Version: "t", Allow: allow, Registry: reg}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	args := `{"config":` + strconv.Quote(cfg) + `,"run":["hunt-20261001T000000Z"]`
	before := eventsOf(t, store)

	if got := call(nil, args+`}`); !strings.Contains(got, "-32602") {
		t.Errorf("an unallowed mutating tool was callable: %s", got)
	}
	if got := call([]string{"db_prune"}, args+`}`); !strings.Contains(got, `"isError":false`) {
		t.Fatalf("allowed call failed: %s", got)
	}
	if got := eventsOf(t, store); !sameCounts(got, before) {
		t.Errorf("a call without apply changed the store: %v -> %v", before, got)
	}
	if got := call([]string{"db_prune"}, args+`,"apply":true}`); !strings.Contains(got, `"isError":false`) {
		t.Fatalf("apply call failed: %s", got)
	}
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

// hunt and activity write a run unless store is false. As tools they are read-only: the
// property is not offered, a call that supplies it is refused, and a call leaves no
// evidence database behind. A property only the command line accepts is refused too.
func TestMCPHuntAndActivityNeverStoreAndHideTheStoreProperty(t *testing.T) {
	reg := newMCPRegistry()
	byName := map[string]ops.ToolEntry{}
	for _, tl := range reg.Tools(nil) {
		byName[tl.Name] = tl
	}
	for _, name := range []string{"hunt", "activity"} {
		tl, ok := byName[name]
		if !ok || !tl.Annotations.ReadOnlyHint {
			t.Fatalf("%s is not a default read-only tool: %+v", name, tl)
		}
		if _, has := tl.InputSchema.Properties["store"]; has {
			t.Errorf("%s still offers the store property", name)
		}
		if tl.Fixed["store"] != false {
			t.Errorf("%s does not fix store=false: %v", name, tl.Fixed)
		}
	}

	t.Setenv("JB_KIBANA_API_KEY", secretKey)
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	if _, err := reg.Call(context.Background(), "hunt", map[string]any{"case": dir, "config": "config/hunt.yaml"}); err != nil && jb.IsUsage(err) {
		t.Fatalf("hunt through the tool path: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "evidence", "*.duckdb")); len(left) != 0 {
		t.Errorf("a tool call to hunt stored evidence: %v", left)
	}
	if _, err := reg.Call(context.Background(), "hunt", map[string]any{"case": dir, "store": true}); err == nil || !jb.IsUsage(err) {
		t.Errorf("a supplied store was accepted: %v", err)
	}
	if _, err := reg.Call(context.Background(), "estate_diff", map[string]any{"case": dir, "alert": true}); err == nil || !jb.IsUsage(err) {
		t.Errorf("a command-line-only property was accepted: %v", err)
	}
}
