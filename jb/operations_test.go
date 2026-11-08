package jb_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/ops"
	"github.com/iksnerd/json-bourne/jb"
)

func opByName(t *testing.T, name string) jb.Operation {
	t.Helper()
	for _, op := range jb.Operations() {
		if op.Name == name {
			return op
		}
	}
	t.Fatalf("no operation %q", name)
	return jb.Operation{}
}

func TestOperationsAreValidAndUnique(t *testing.T) {
	list := jb.Operations()
	if ps := ops.ValidateAll(list); len(ps) != 0 {
		t.Fatalf("registry breaks the RFC rules: %s", ops.Describe(ps))
	}
}

func TestOperationsReturnsCopies(t *testing.T) {
	a := jb.Operations()
	a[0].Name = "mutated"
	delete(a[0].InputSchema.Properties, "case")
	b := jb.Operations()
	if b[0].Name == "mutated" || len(b[0].InputSchema.Properties) == 0 {
		t.Fatal("Operations shares state between calls")
	}
}

func TestOperationReadOnlyFlagsAndCommands(t *testing.T) {
	for _, c := range []struct {
		name string
		cmd  []string
	}{{"case_show", []string{"case", "show"}}, {"case_check", []string{"case", "check"}}} {
		op := opByName(t, c.name)
		if !op.ReadOnly {
			t.Errorf("%s must be read-only", c.name)
		}
		if op.CLI == nil || strings.Join(op.CLI.Command, " ") != strings.Join(c.cmd, " ") {
			t.Errorf("%s cli = %+v", c.name, op.CLI)
		}
		if op.Description == "" {
			t.Errorf("%s has no description", c.name)
		}
	}
}

func TestCaseShowSchemaCarriesTheCaseAndTheConfig(t *testing.T) {
	op := opByName(t, "case_show")
	if p, ok := op.InputSchema.Properties["case"]; !ok || p.Type != "string" {
		t.Fatalf("properties = %+v", op.InputSchema.Properties)
	}
	if p, ok := op.InputSchema.Properties["config"]; !ok || p.Type != "string" {
		t.Fatalf("properties = %+v", op.InputSchema.Properties)
	}
	if len(op.InputSchema.Required) != 1 || op.InputSchema.Required[0] != "case" {
		t.Fatalf("required = %v", op.InputSchema.Required)
	}
}

func TestToolProjectionOfTheRegistry(t *testing.T) {
	for _, op := range jb.Operations() {
		b, _ := json.Marshal(ops.Tool(op))
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["cli"]; ok {
			t.Errorf("%s: tool carries cli", op.Name)
		}
		ann := m["annotations"].(map[string]any)
		if ann["readOnlyHint"] != op.ReadOnly || ann["destructiveHint"] != !op.ReadOnly {
			t.Errorf("%s: annotations %v", op.Name, ann)
		}
		if op.CLI != nil {
			for _, o := range op.CLI.Only {
				if strings.Contains(string(b), `"`+o+`"`) {
					t.Errorf("%s: tool still has cli.only property %s", op.Name, o)
				}
			}
		}
	}
}

func TestCallCaseShowRunsTheTypedFunction(t *testing.T) {
	got, err := jb.Call(context.Background(), "case_show", map[string]any{"case": "../examples/case", "config": "config/hunt.yaml"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := jb.CaseShow("../examples/case", jb.CaseShowOptions{Config: "config/hunt.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("Call differs from CaseShow:\n%s\n%s", g, w)
	}
	if _, ok := got.(*jb.CaseShowResult); !ok {
		t.Fatalf("result is %T", got)
	}
}

func TestCallCaseCheckRunsTheTypedFunction(t *testing.T) {
	got, err := jb.Call(context.Background(), "case_check", map[string]any{"case": "../examples/case"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := got.(*jb.CaseCheckResult)
	if !ok || !r.OK || r.ID != "example-login-spray" {
		t.Fatalf("result = %#v", got)
	}
}

func TestCallReportsAProblemInTheCaseAsAResultNotAnError(t *testing.T) {
	got, err := jb.Call(context.Background(), "case_check", map[string]any{"case": t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("a bad case is a result, got %v", err)
	}
	if r := got.(*jb.CaseCheckResult); r.OK {
		t.Fatal("an empty directory passed case check")
	}
}

func TestCallAcceptsJSONDecodedArguments(t *testing.T) {
	var args map[string]any
	if err := json.Unmarshal([]byte(`{"case":"../examples/case"}`), &args); err != nil {
		t.Fatal(err)
	}
	if _, err := jb.Call(context.Background(), "case_check", args, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCallRefusesBadArgumentsAsUsageErrorsWithEveryProblem(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want []string
	}{
		{"case_show", nil, []string{"argument-missing case"}},
		{"case_show", map[string]any{}, []string{"argument-missing case"}},
		{"case_show", map[string]any{"case": "x", "zzz": 1}, []string{"argument-unknown zzz"}},
		{"case_show", map[string]any{"case": 5}, []string{"argument-type case"}},
		{"case_check", map[string]any{"case": true, "config": "x"}, []string{"argument-type case", "argument-unknown config"}},
		{"case_show", map[string]any{"config": 1, "extra": "x"}, []string{"argument-missing case", "argument-type config", "argument-unknown extra"}},
	}
	for _, c := range cases {
		_, err := jb.Call(context.Background(), c.name, c.args, nil)
		if !jb.IsUsage(err) {
			t.Errorf("%s %v: err = %v, want a usage error", c.name, c.args, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s %v: %q lacks %q", c.name, c.args, err, w)
			}
		}
		if strings.HasPrefix(err.Error(), "jb: ") {
			t.Errorf("library errors carry no jb: prefix: %q", err)
		}
	}
}

func TestCallRefusesAnUnknownOperation(t *testing.T) {
	_, err := jb.Call(context.Background(), "nope", nil, nil)
	if !jb.IsUsage(err) || !strings.Contains(err.Error(), `"nope"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestCallDoesNotFillDefaultsOrRunOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := jb.Call(ctx, "case_check", map[string]any{"case": "../examples/case"}, nil); err == nil {
		t.Fatal("a cancelled context still ran the handler")
	}
}

func TestCallErrorsOfTheHandlerPassThrough(t *testing.T) {
	_, err := jb.Call(context.Background(), "case_show", map[string]any{"case": "../examples/case", "config": "nope.yaml"}, nil)
	if err == nil || jb.IsUsage(err) && !strings.Contains(err.Error(), "nope.yaml") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "nope.yaml") {
		t.Fatalf("err = %v", err)
	}
}
