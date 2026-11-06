package ops

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixedOp(t *testing.T) Operation {
	t.Helper()
	op := sampleOp(t, true)
	op.InputSchema.Properties["store"] = Property{Type: "boolean", Default: true}
	op.ToolFixed = map[string]any{"store": false}
	return op
}

func TestToolFixesAndRemovesAToolFixedProperty(t *testing.T) {
	op := fixedOp(t)
	tool := Tool(op)
	if _, ok := tool.InputSchema.Properties["store"]; ok {
		t.Fatal("the tool still offers a property it fixes")
	}
	for _, r := range tool.InputSchema.Required {
		if r == "store" {
			t.Fatal("required names a fixed property")
		}
	}
	if got := tool.Fixed["store"]; got != false {
		t.Fatalf("fixed = %v", tool.Fixed)
	}
	if _, ok := op.InputSchema.Properties["store"]; !ok {
		t.Fatal("the projection changed the operation")
	}
	b, _ := json.Marshal(op)
	if !strings.Contains(string(b), `"toolFixed":{"store":false}`) {
		t.Fatalf("the operation does not print toolFixed: %s", b)
	}
	tb, _ := json.Marshal(tool)
	if strings.Contains(string(tb), "toolFixed") || strings.Contains(string(tb), `"store"`) || strings.Contains(string(tb), `"Fixed"`) {
		t.Fatalf("the MCP entry shows the fixed property: %s", tb)
	}
}

func TestValidateToolFixed(t *testing.T) {
	op := fixedOp(t)
	if ps := Validate(op); len(ps) != 0 {
		t.Fatal(ps)
	}
	op.ToolFixed = map[string]any{"nope": false}
	if ps := Validate(op); len(ps) != 1 || ps[0].Code != "tool-fixed-unknown" {
		t.Fatalf("unknown property: %v", ps)
	}
	op.ToolFixed = map[string]any{"store": "no"}
	if ps := Validate(op); len(ps) != 1 || ps[0].Code != "tool-fixed-type" {
		t.Fatalf("wrong type: %v", ps)
	}
}
