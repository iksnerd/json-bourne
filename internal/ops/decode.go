package ops

import (
	"fmt"
	"reflect"
)

// Decode copies a checked arguments object into the struct dst points to, so a handler
// gets typed options. It sets only the fields whose property is present and leaves the
// rest as they are, so the handler's own defaults apply. It returns an error for a
// key or value the check would have refused, and never panics on one.
func Decode(arguments map[string]any, dst any) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("decode: destination must be a non-nil pointer to a struct, got %T", dst)
	}
	fields, ps := walk(rv.Elem().Type())
	if len(ps) != 0 {
		return fmt.Errorf("decode: %s", Describe(ps))
	}
	byName := map[string]field{}
	for _, f := range fields {
		byName[f.name] = f
	}
	for _, name := range sortedKeys(arguments) {
		f, ok := byName[name]
		if !ok {
			return fmt.Errorf("decode: %s is not an argument", name)
		}
		fv := rv.Elem().FieldByIndex(f.index)
		v := arguments[name]
		switch f.prop.Type {
		case "string":
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("decode: %s is not a string", name)
			}
			fv.SetString(s)
		case "integer":
			n, ok := asInt(v)
			if !ok {
				return fmt.Errorf("decode: %s is not an integer", name)
			}
			if fv.OverflowInt(n) {
				return fmt.Errorf("decode: %s does not fit the field", name)
			}
			fv.SetInt(n)
		case "boolean":
			b, ok := v.(bool)
			if !ok {
				return fmt.Errorf("decode: %s is not a boolean", name)
			}
			fv.SetBool(b)
		case "array":
			a, ok := asStrings(v)
			if !ok {
				return fmt.Errorf("decode: %s is not an array of strings", name)
			}
			fv.Set(reflect.ValueOf(append([]string{}, a...)))
		}
	}
	return nil
}
