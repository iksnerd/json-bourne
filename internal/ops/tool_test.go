package ops

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleOp(t *testing.T, readOnly bool) Operation {
	t.Helper()
	s, only, ps := Reflect(goodOptions{})
	if len(ps) != 0 {
		t.Fatal(ps)
	}
	return Operation{
		Name: "sample_op", Title: "Sample", Description: "Does a sample thing.",
		InputSchema: s, ReadOnly: readOnly,
		CLI: &CLI{Command: []string{"sample", "op"}, Positional: []string{"case"}, Only: only},
	}
}

func TestToolProjection(t *testing.T) {
	op := sampleOp(t, true)
	tool := Tool(op)
	b, _ := json.Marshal(tool)
	if strings.Contains(string(b), `"cli"`) || strings.Contains(string(b), `"out"`) {
		t.Fatalf("tool carries cli or a cli.only property: %s", b)
	}
	if _, ok := tool.InputSchema.Properties["out"]; ok {
		t.Fatal("cli.only property kept")
	}
	if _, ok := op.InputSchema.Properties["out"]; !ok {
		t.Fatal("the projection changed the operation")
	}
	if tool.Name != op.Name || tool.Description != op.Description || tool.Title != op.Title {
		t.Fatalf("%+v", tool)
	}
	if !strings.Contains(string(b), `"annotations":{"readOnlyHint":true,"destructiveHint":false}`) {
		t.Fatalf("annotations: %s", b)
	}
	if strings.Contains(string(b), "outputSchema") {
		t.Fatalf("outputSchema in this cut: %s", b)
	}
}

func TestToolAnnotationsFollowReadOnly(t *testing.T) {
	b, _ := json.Marshal(Tool(sampleOp(t, false)))
	if !strings.Contains(string(b), `"annotations":{"readOnlyHint":false,"destructiveHint":true}`) {
		t.Fatalf("%s", b)
	}
}

func TestToolDropsACliOnlyRequiredProperty(t *testing.T) {
	op := sampleOp(t, true)
	op.InputSchema.Required = append(append([]string{}, op.InputSchema.Required...), "out")
	tool := Tool(op)
	for _, r := range tool.InputSchema.Required {
		if r == "out" {
			t.Fatal("required names a property the tool does not have")
		}
	}
	if len(op.InputSchema.Required) != 2 {
		t.Fatal("the projection changed the operation")
	}
}

func TestToolDoesNotAliasTheOperation(t *testing.T) {
	op := sampleOp(t, true)
	tool := Tool(op)
	p := tool.InputSchema.Properties["mode"]
	p.Enum[0] = "mutated"
	if op.InputSchema.Properties["mode"].Enum[0] == "mutated" {
		t.Fatal("the tool shares the enum slice")
	}
	delete(tool.InputSchema.Properties, "days")
	if _, ok := op.InputSchema.Properties["days"]; !ok {
		t.Fatal("the tool shares the properties map")
	}
}
