package casefile

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

type schemaNode struct {
	Const                any                   `json:"const"`
	Enum                 []any                 `json:"enum"`
	Required             []string              `json:"required"`
	Properties           map[string]schemaNode `json:"properties"`
	AdditionalProperties json.RawMessage       `json:"additionalProperties"`
	Items                *schemaNode           `json:"items"`
}

func loadSchema(t *testing.T) schemaNode {
	t.Helper()
	b, err := os.ReadFile("../../schemas/case.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s schemaNode
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// schemaNames lists dotted property paths. Arrays add no path segment.
func schemaNames(t *testing.T, n schemaNode, prefix string, out *[]string) {
	t.Helper()
	if n.Properties != nil && string(n.AdditionalProperties) != "false" {
		t.Errorf("%q: an object with properties must set additionalProperties: false", prefix)
	}
	for k, v := range n.Properties {
		p := prefix + k
		*out = append(*out, p)
		schemaNames(t, v, p+".", out)
	}
	if n.Items != nil {
		schemaNames(t, *n.Items, prefix, out)
	}
}

func goNames(rt reflect.Type, prefix string, out *[]string) {
	for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "-" || tag == "" {
			continue
		}
		*out = append(*out, prefix+tag)
		goNames(f.Type, prefix+tag+".", out)
	}
}

func TestSchemaMatchesStruct(t *testing.T) {
	s := loadSchema(t)
	var fromSchema, fromGo []string
	schemaNames(t, s, "", &fromSchema)
	goNames(reflect.TypeOf(Case{}), "", &fromGo)
	sort.Strings(fromSchema)
	sort.Strings(fromGo)
	for _, n := range fromGo {
		if !slices.Contains(fromSchema, n) {
			t.Errorf("Go field %q is not in the schema", n)
		}
	}
	for _, n := range fromSchema {
		if !slices.Contains(fromGo, n) {
			t.Errorf("schema property %q has no Go field", n)
		}
	}
}

func asStrings(t *testing.T, in []any) []string {
	t.Helper()
	var out []string
	for _, v := range in {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("non-string enum value %v", v)
		}
		out = append(out, s)
	}
	return out
}

func sorted(s []string) []string { c := slices.Clone(s); sort.Strings(c); return c }

func TestSchemaMatchesLoaderRules(t *testing.T) {
	s := loadSchema(t)
	if !slices.Equal(sorted(s.Required), sorted(RequiredKeys)) {
		t.Errorf("required: schema %v, loader %v", s.Required, RequiredKeys)
	}
	if s.Properties["apiVersion"].Const != APIVersion {
		t.Errorf("apiVersion const: schema %v, loader %s", s.Properties["apiVersion"].Const, APIVersion)
	}
	if got := asStrings(t, s.Properties["status"].Enum); !slices.Equal(sorted(got), sorted(Statuses)) {
		t.Errorf("status enum: schema %v, loader %v", got, Statuses)
	}
	redact := s.Properties["handling"].Properties["redact_in_reports"].Items.Enum
	if got := asStrings(t, redact); !slices.Equal(sorted(got), sorted(RedactKinds)) {
		t.Errorf("redact enum: schema %v, loader %v", got, RedactKinds)
	}
	if s.Properties["handling"].Properties["passive_only"].Const != true {
		t.Error("passive_only must be const true in the schema")
	}
}
