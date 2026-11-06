package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Limits every example enforces. They are constants, not config, except where a
// config key says otherwise, so a bad config cannot switch the protection off.
const (
	DefaultMaxLineBytes = 8 << 10
	HardMaxLineBytes    = 64 << 10
	MaxFields           = 64
	MaxConfigBytes      = 64 << 10
	MaxPathSegments     = 8
	DefaultMaxDocBytes  = 1 << 20
)

var fieldName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// FieldSpec says how one source value becomes one event field.
type FieldSpec struct {
	From     string   `json:"from"`     // key, group name or JSON path, depending on the plugin
	Type     string   `json:"type"`     // string (default), int, bool, time, ip
	Layout   string   `json:"layout"`   // time only: rfc3339, rfc3339nano, unix, unix_ms or a Go layout
	Omit     []string `json:"omit"`     // source values treated as absent, such as "-"
	Required bool     `json:"required"` // absent means the document is unparsable
}

// TimeSpec says where the event time comes from.
type TimeSpec struct {
	// DocField is a path in the document (default "@timestamp"). A value that is not
	// a valid time is a fault in the document set and fails the request, as the
	// built-in mappers do.
	DocField string `json:"doc_field"`
	// From takes the time from the parsed text instead (a key, group or path). A value
	// that is not a valid time makes that one document unparsable.
	From   string `json:"from"`
	Layout string `json:"layout"`
}

// Common is the configuration shared by the examples.
type Common struct {
	Fields map[string]FieldSpec `json:"fields"`
	Time   *TimeSpec            `json:"time"`
	// Required lists source names that must be present (and non-empty).
	Required []string `json:"required"`
}

// Validate checks the shared part of a config.
func (c *Common) Validate() error {
	if len(c.Fields) == 0 {
		return fmt.Errorf("fields: map at least one source value to an event field (nothing is emitted that is not mapped)")
	}
	if len(c.Fields) > MaxFields {
		return fmt.Errorf("fields: %d entries, at most %d", len(c.Fields), MaxFields)
	}
	for name, f := range c.Fields {
		if !fieldName.MatchString(name) {
			return fmt.Errorf("fields.%s: event field names are lower_snake_case, 1-64 characters", name)
		}
		if f.From == "" {
			return fmt.Errorf("fields.%s: from is required", name)
		}
		switch f.Type {
		case "", "string", "int", "bool", "time", "ip":
		default:
			return fmt.Errorf("fields.%s: unknown type %q (string, int, bool, time, ip)", name, f.Type)
		}
		if f.Layout != "" && f.Type != "time" {
			return fmt.Errorf("fields.%s: layout is only for type time", name)
		}
		if len(f.Omit) > 16 {
			return fmt.Errorf("fields.%s: omit has more than 16 entries", name)
		}
	}
	if c.Time != nil {
		if c.Time.DocField != "" && c.Time.From != "" {
			return fmt.Errorf("time: doc_field and from are alternatives, not both")
		}
	}
	if len(c.Required) > MaxFields {
		return fmt.Errorf("required: more than %d entries", MaxFields)
	}
	return nil
}

// DecodeStrict decodes config into dst, refusing unknown keys, and bounds its size.
func DecodeStrict(config json.RawMessage, dst any) error {
	if len(config) > MaxConfigBytes {
		return fmt.Errorf("config is %d bytes, at most %d", len(config), MaxConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(config))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}

// Lookup finds a dotted path in a decoded JSON value. At an object it first tries the
// longest remaining run of segments as a literal key (so a flattened "log.level" key
// is found) and then shorter ones; a numeric segment indexes an array.
func Lookup(v any, path string) (any, bool) {
	segs := strings.Split(path, ".")
	if len(segs) > MaxPathSegments+4 {
		return nil, false
	}
	return lookup(v, segs, 0)
}

func lookup(v any, segs []string, depth int) (any, bool) {
	if len(segs) == 0 {
		return v, true
	}
	if depth > MaxPathSegments {
		return nil, false
	}
	switch x := v.(type) {
	case map[string]any:
		for n := len(segs); n >= 1; n-- {
			if child, ok := x[strings.Join(segs[:n], ".")]; ok {
				if r, ok := lookup(child, segs[n:], depth+1); ok {
					return r, true
				}
			}
		}
	case []any:
		if i, err := strconv.Atoi(segs[0]); err == nil && i >= 0 && i < len(x) {
			return lookup(x[i], segs[1:], depth+1)
		}
	}
	return nil, false
}

// Build applies the field specs to a source of values. get returns the raw value for
// a from-name. The returned fields contain only what the config maps.
func (c *Common) Build(get func(name string) (any, bool)) (map[string]any, error) {
	for _, r := range c.Required {
		v, ok := get(r)
		if !ok || isEmpty(v) {
			return nil, fmt.Errorf("%w: required %q is missing", ErrUnparsable, r)
		}
	}
	names := make([]string, 0, len(c.Fields))
	for n := range c.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make(map[string]any, len(names))
	for _, n := range names {
		f := c.Fields[n]
		raw, ok := get(f.From)
		if ok && omitted(raw, f.Omit) {
			ok = false
		}
		if !ok || isEmpty(raw) {
			if f.Required {
				return nil, fmt.Errorf("%w: required field %q is missing", ErrUnparsable, n)
			}
			continue
		}
		v, err := Coerce(raw, f.Type, f.Layout)
		if err != nil {
			return nil, fmt.Errorf("%w: field %q: %v", ErrUnparsable, n, err)
		}
		out[n] = v
	}
	return out, nil
}

func isEmpty(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && s == ""
}

func omitted(v any, omit []string) bool {
	if len(omit) == 0 {
		return false
	}
	s := asString(v)
	for _, o := range omit {
		if s == o {
			return true
		}
	}
	return false
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// Coerce converts a raw value to the configured type. Objects and arrays are never
// scalars: they are an error, not a stringified blob.
func Coerce(v any, typ, layout string) (any, error) {
	switch v.(type) {
	case map[string]any, []any:
		return nil, fmt.Errorf("value is an object or array, not a scalar")
	}
	switch typ {
	case "", "string":
		return asString(v), nil
	case "int":
		switch x := v.(type) {
		case json.Number:
			i, err := x.Int64()
			if err != nil {
				return nil, fmt.Errorf("not an integer")
			}
			return i, nil
		case string:
			i, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("not an integer")
			}
			return i, nil
		}
		return nil, fmt.Errorf("not an integer")
	case "bool":
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			b, err := strconv.ParseBool(strings.TrimSpace(x))
			if err != nil {
				return nil, fmt.Errorf("not a boolean")
			}
			return b, nil
		}
		return nil, fmt.Errorf("not a boolean")
	case "ip":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("not an IP address")
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("not an IP address")
		}
		return a.String(), nil
	case "time":
		t, err := ParseTime(v, layout)
		if err != nil {
			return nil, err
		}
		return t.UTC().Format(time.RFC3339Nano), nil
	}
	return nil, fmt.Errorf("unknown type %q", typ)
}

// ParseTime reads a time from a string or number by layout. Layout names: rfc3339
// (default), rfc3339nano, unix (seconds), unix_ms; anything else is a Go layout.
func ParseTime(v any, layout string) (time.Time, error) {
	switch strings.ToLower(layout) {
	case "unix", "unix_ms":
		var n int64
		switch x := v.(type) {
		case json.Number:
			i, err := x.Int64()
			if err != nil {
				return time.Time{}, fmt.Errorf("not a unix time")
			}
			n = i
		case string:
			i, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("not a unix time")
			}
			n = i
		default:
			return time.Time{}, fmt.Errorf("not a unix time")
		}
		if strings.ToLower(layout) == "unix_ms" {
			return time.UnixMilli(n), nil
		}
		return time.Unix(n, 0), nil
	}
	s, ok := v.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("not a time")
	}
	l := layout
	switch strings.ToLower(layout) {
	case "", "rfc3339", "rfc3339nano":
		l = time.RFC3339Nano
	}
	t, err := time.Parse(l, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("not a time in layout %q", layoutName(layout))
	}
	return t, nil
}

func layoutName(l string) string {
	if l == "" {
		return "rfc3339"
	}
	return l
}

// EventTime resolves the event time. text is the lookup over the parsed text (the same
// one Build uses); doc is the whole document.
func (c *Common) EventTime(doc map[string]any, text func(string) (any, bool)) (time.Time, error) {
	ts := c.Time
	if ts != nil && ts.From != "" {
		raw, ok := text(ts.From)
		if !ok || isEmpty(raw) {
			return time.Time{}, fmt.Errorf("%w: no time value %q", ErrUnparsable, ts.From)
		}
		t, err := ParseTime(raw, ts.Layout)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: time: %v", ErrUnparsable, err)
		}
		return t, nil
	}
	field, layout := "@timestamp", ""
	if ts != nil {
		if ts.DocField != "" {
			field = ts.DocField
		}
		layout = ts.Layout
	}
	raw, ok := Lookup(doc, field)
	if !ok {
		return time.Time{}, fmt.Errorf("bad or missing %s in the document", field)
	}
	t, err := ParseTime(raw, layout)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad or missing %s in the document", field)
	}
	return t, nil
}
