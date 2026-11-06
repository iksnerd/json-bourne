package ops

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// field is one struct field that became a property.
type field struct {
	index    []int
	name     string
	prop     Property
	required bool
	cliOnly  bool
}

// Reflect reads a Go option struct (or a pointer to one) and returns its input schema
// and the names of the properties tagged cli:"only". It reports every problem it
// finds, so one run lists them all. The tags, in the style of encoding/json:
//
//	jb:"window"      the property name (required on every exported field); jb:"-" skips the field
//	desc:"..."       the description
//	default:"1h"     the default, documentation only: the check never fills it in
//	enum:"a,b"       the allowed strings of a string property
//	min:"1" max:"31" the range of an integer property
//	required:"true"  the property must be present
//	cli:"only"       the command line accepts it and a tool call does not
//
// A struct embedded without a tag contributes its fields. Only string, int, int64,
// bool and []string (unnamed types) map to a shape; any other type is refused.
func Reflect(v any) (Schema, []string, []Problem) {
	t := reflect.TypeOf(v)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	s := Schema{Type: "object", Properties: map[string]Property{}, Required: []string{}}
	if t == nil || t.Kind() != reflect.Struct {
		return s, nil, []Problem{{Code: "type-not-struct", Ref: fmt.Sprintf("%T", v), Message: "an operation's options must be a struct"}}
	}
	fields, ps := walk(t)
	var only []string
	for _, f := range fields {
		s.Properties[f.name] = f.prop
		if f.required {
			s.Required = append(s.Required, f.name)
		}
		if f.cliOnly {
			only = append(only, f.name)
		}
	}
	return s, only, ps
}

func walk(t reflect.Type) ([]field, []Problem) {
	var out []field
	var ps []Problem
	seen := map[string]string{}
	walkInto(t, nil, t.Name(), &out, &ps, seen)
	return out, ps
}

func walkInto(t reflect.Type, prefix []int, owner string, out *[]field, ps *[]Problem, seen map[string]string) {
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		ref := owner + "." + sf.Name
		tag, tagged := sf.Tag.Lookup("jb")
		if tag == "-" {
			continue
		}
		index := append(append([]int{}, prefix...), i)
		if sf.Anonymous && !tagged && sf.Type.Kind() == reflect.Struct {
			walkInto(sf.Type, index, sf.Type.Name(), out, ps, seen)
			continue
		}
		if !sf.IsExported() {
			continue
		}
		bad := func(code, format string, a ...any) {
			*ps = append(*ps, Problem{Code: code, Ref: ref, Message: fmt.Sprintf(format, a...)})
		}
		if !tagged {
			bad("field-untagged", "exported field has no jb tag; tag it or write jb:\"-\"")
			continue
		}
		n := len(*ps)
		if !validPropertyName(tag) {
			bad("name-invalid", "name %q must be lower case words joined by _, not start with no_ and not be help", tag)
		} else if prev, dup := seen[tag]; dup {
			bad("name-duplicate", "name %q is also the name of %s", tag, prev)
		} else {
			seen[tag] = ref
		}
		f := field{index: index, name: tag}
		shape, ok := shapeOf(sf.Type)
		if !ok {
			bad("field-type", "type %s is not string, int, int64, bool or []string", sf.Type)
		} else {
			f.prop = Property{Type: shape, Description: sf.Tag.Get("desc")}
			if shape == "array" {
				f.prop.Items = &Items{Type: "string"}
			}
			applyTags(sf, shape, &f, bad)
		}
		if len(*ps) == n {
			*out = append(*out, f)
		}
	}
}

func shapeOf(t reflect.Type) (string, bool) {
	if t.PkgPath() != "" { // a named type such as time.Duration is not a plain shape
		return "", false
	}
	switch t.Kind() {
	case reflect.String:
		return "string", true
	case reflect.Int, reflect.Int64:
		return "integer", true
	case reflect.Bool:
		return "boolean", true
	case reflect.Slice:
		if t.Elem().Kind() == reflect.String && t.Elem().PkgPath() == "" {
			return "array", true
		}
	}
	return "", false
}

func applyTags(sf reflect.StructField, shape string, f *field, bad func(code, format string, a ...any)) {
	tag := sf.Tag
	if v, ok := tag.Lookup("enum"); ok {
		if shape != "string" {
			bad("tag-invalid", "enum applies to a string property, not %s", shape)
		} else {
			parts := strings.Split(v, ",")
			seen := map[string]bool{}
			for _, e := range parts {
				switch {
				case e == "":
					bad("tag-invalid", "enum %q has an empty entry", v)
				case seen[e]:
					bad("enum-duplicate", "enum value %q is repeated", e)
				}
				seen[e] = true
			}
			f.prop.Enum = parts
		}
	}
	for _, k := range []string{"min", "max"} {
		v, ok := tag.Lookup(k)
		if !ok {
			continue
		}
		if shape != "integer" {
			bad("tag-invalid", "%s applies to an integer property, not %s", k, shape)
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			bad("tag-invalid", "%s %q is not an integer", k, v)
			continue
		}
		if k == "min" {
			f.prop.Minimum = &n
		} else {
			f.prop.Maximum = &n
		}
	}
	if f.prop.Minimum != nil && f.prop.Maximum != nil && *f.prop.Minimum > *f.prop.Maximum {
		bad("range-invalid", "min %d is above max %d", *f.prop.Minimum, *f.prop.Maximum)
	}
	if v, ok := tag.Lookup("default"); ok {
		d, err := parseDefault(shape, v)
		if err != nil {
			bad("default-invalid", "default %q: %v", v, err)
		} else {
			f.prop.Default = d
			if !defaultFits(f.prop) {
				bad("default-invalid", "default %q is outside the enum or range", v)
			}
		}
	}
	if v, ok := tag.Lookup("required"); ok {
		switch v {
		case "true":
			f.required = true
		case "false":
		default:
			bad("tag-invalid", "required must be true or false, got %q", v)
		}
	}
	if v, ok := tag.Lookup("cli"); ok {
		if v != "only" {
			bad("tag-invalid", "cli must be \"only\", got %q", v)
		}
		f.cliOnly = v == "only"
	}
}

func parseDefault(shape, v string) (any, error) {
	switch shape {
	case "string":
		return v, nil
	case "integer":
		return strconv.ParseInt(v, 10, 64)
	case "boolean":
		return strconv.ParseBool(v)
	default:
		if v == "" {
			return []string{}, nil
		}
		return strings.Split(v, ","), nil
	}
}
