package ops

import (
	"fmt"
	"reflect"
	"sort"
)

// Check is the one check of an arguments object against a schema, run on the parsed
// command line and on the JSON of a tool call alike. It returns every problem, ordered
// by reference. It never changes the arguments and never fills a default: the handler
// applies those, so the surfaces cannot disagree about one.
//
// A nil arguments value is an empty object. Codes: arguments-type, argument-unknown,
// argument-missing, argument-type, argument-enum, argument-range.
func Check(s Schema, arguments any) []Problem {
	var args map[string]any
	switch a := arguments.(type) {
	case nil:
	case map[string]any:
		args = a
	default:
		return []Problem{{Code: "arguments-type", Ref: "arguments", Message: fmt.Sprintf("arguments must be an object, got %s", describeType(a))}}
	}
	var ps []Problem
	add := func(code, ref, format string, a ...any) {
		ps = append(ps, Problem{Code: code, Ref: ref, Message: fmt.Sprintf(format, a...)})
	}
	for _, r := range s.Required {
		if _, ok := args[r]; !ok {
			add("argument-missing", r, "%s is required", r)
		}
	}
	for _, name := range sortedKeys(args) {
		p, ok := s.Properties[name]
		if !ok {
			add("argument-unknown", name, "%s is not an argument of this operation", name)
			continue
		}
		checkValue(name, p, args[name], add)
	}
	sort.SliceStable(ps, func(i, j int) bool { return baseRef(ps[i].Ref) < baseRef(ps[j].Ref) })
	return ps
}

// baseRef strips an array index so "ips[1]" sorts with "ips".
func baseRef(ref string) string {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '[' {
			return ref[:i]
		}
	}
	return ref
}

func checkValue(name string, p Property, v any, add func(code, ref, format string, a ...any)) {
	switch p.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			add("argument-type", name, "%s must be a string, got %s", name, describeType(v))
			return
		}
		if p.Enum != nil && !contains(p.Enum, s) {
			add("argument-enum", name, "%s must be one of %v, got %q", name, p.Enum, s)
		}
	case "integer":
		n, ok := asInt(v)
		if !ok {
			add("argument-type", name, "%s must be an integer, got %s", name, describeType(v))
			return
		}
		if p.Minimum != nil && n < *p.Minimum {
			add("argument-range", name, "%s must be at least %d, got %d", name, *p.Minimum, n)
		}
		if p.Maximum != nil && n > *p.Maximum {
			add("argument-range", name, "%s must be at most %d, got %d", name, *p.Maximum, n)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			add("argument-type", name, "%s must be a boolean, got %s", name, describeType(v))
		}
	case "array":
		switch a := v.(type) {
		case []string:
		case []any:
			for i, e := range a {
				if _, ok := e.(string); !ok {
					add("argument-type", fmt.Sprintf("%s[%d]", name, i), "%s[%d] must be a string, got %s", name, i, describeType(e))
				}
			}
		default:
			add("argument-type", name, "%s must be an array of strings, got %s", name, describeType(v))
		}
	}
}

func describeType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case map[string]any:
		return "an object"
	case []any, []string:
		return "an array"
	}
	if _, ok := asInt(v); ok {
		return "an integer"
	}
	switch reflect.TypeOf(v).Kind() {
	case reflect.Float32, reflect.Float64:
		return "a number"
	}
	return fmt.Sprintf("%T", v)
}
