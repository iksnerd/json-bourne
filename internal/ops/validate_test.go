package ops

import "testing"

func TestValidateAcceptsAReflectedOperation(t *testing.T) {
	if ps := Validate(sampleOp(t, true)); len(ps) != 0 {
		t.Fatal(ps)
	}
}

func TestValidateRefusals(t *testing.T) {
	i := func(n int64) *int64 { return &n }
	mut := map[string]struct {
		f    func(*Operation)
		code string
	}{
		"bad name": {func(o *Operation) { o.Name = "Bad-Name" }, "operation-name"},
		"long name": {func(o *Operation) {
			o.Name = "a" + string(make([]byte, 0)) + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "operation-name"},
		"no description":  {func(o *Operation) { o.Description = " " }, "operation-description"},
		"schema type":     {func(o *Operation) { o.InputSchema.Type = "array" }, "schema-type"},
		"additional":      {func(o *Operation) { o.InputSchema.AdditionalProperties = true }, "schema-additional"},
		"null required":   {func(o *Operation) { o.InputSchema.Required = nil }, "schema-shape"},
		"property name":   {func(o *Operation) { o.InputSchema.Properties["no_x"] = Property{Type: "boolean"} }, "property-name"},
		"property help":   {func(o *Operation) { o.InputSchema.Properties["help"] = Property{Type: "boolean"} }, "property-name"},
		"property type":   {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "number"} }, "property-type"},
		"enum on integer": {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "integer", Enum: []string{"a"}} }, "property-keyword"},
		"min on string":   {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "string", Minimum: i(1)} }, "property-keyword"},
		"keyword on bool": {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "boolean", Minimum: i(1)} }, "property-keyword"},
		"enum dup":        {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "string", Enum: []string{"a", "a"}} }, "enum-duplicate"},
		"enum empty":      {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "string", Enum: []string{}} }, "enum-empty"},
		"range": {func(o *Operation) {
			o.InputSchema.Properties["x"] = Property{Type: "integer", Minimum: i(3), Maximum: i(1)}
		}, "range-invalid"},
		"items missing": {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "array"} }, "array-items"},
		"items not string": {func(o *Operation) {
			o.InputSchema.Properties["x"] = Property{Type: "array", Items: &Items{Type: "integer"}}
		}, "array-items"},
		"default type": {func(o *Operation) { o.InputSchema.Properties["x"] = Property{Type: "integer", Default: "one"} }, "default-type"},
		"default range": {func(o *Operation) {
			o.InputSchema.Properties["x"] = Property{Type: "integer", Maximum: i(1), Default: 5}
		}, "default-type"},
		"required unknown": {func(o *Operation) { o.InputSchema.Required = append(o.InputSchema.Required, "ghost") }, "required-unknown"},
		"positional":       {func(o *Operation) { o.CLI.Positional = []string{"ghost"} }, "cli-positional-unknown"},
		"array not last":   {func(o *Operation) { o.CLI.Positional = []string{"ips", "case"} }, "cli-positional-array"},
		"only unknown":     {func(o *Operation) { o.CLI.Only = []string{"ghost"} }, "cli-only-unknown"},
		"no command":       {func(o *Operation) { o.CLI.Command = nil }, "cli-command"},
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			op := sampleOp(t, true)
			// own copies, so a mutation never leaks into another case
			props := map[string]Property{}
			for k, v := range op.InputSchema.Properties {
				props[k] = v
			}
			op.InputSchema.Properties = props
			c := *op.CLI
			op.CLI = &c
			m.f(&op)
			if ps := Validate(op); !hasCode(ps, m.code, "") {
				t.Fatalf("want %s, got %v", m.code, ps)
			}
		})
	}
}

func TestValidateAllFindsDuplicates(t *testing.T) {
	op := sampleOp(t, true)
	if ps := ValidateAll([]Operation{op, op}); !hasCode(ps, "operation-duplicate", "sample_op") {
		t.Fatal(ps)
	}
}
