// Command kvlines is an example jb mapper plugin for key=value log lines.
//
// It knows no product. The operator's mapper_config says which document field holds
// the line, which keys become which event fields, their types, which key (or document
// field) is the time, and which keys must be present. See README.md.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/iksnerd/json-bourne/sdk"
)

const (
	maxPairs  = 128
	maxKeyLen = 64
)

type config struct {
	sdk.Common
	LineField    string `json:"line_field"`     // document path holding the line (default "message")
	MaxLineBytes int    `json:"max_line_bytes"` // longer lines are unparsable (default 8192, at most 65536)
	// Separators are extra characters that end an unquoted value besides whitespace, such
	// as "," for "a=1, b=2". They are also skipped between pairs.
	Separators string `json:"separators"`
}

type mapper struct {
	cfg config
}

func newMapper(raw json.RawMessage) (sdk.Mapper, error) {
	var c config
	if err := sdk.DecodeStrict(raw, &c); err != nil {
		return nil, err
	}
	if err := c.Common.Validate(); err != nil {
		return nil, err
	}
	if c.LineField == "" {
		c.LineField = "message"
	}
	if c.MaxLineBytes == 0 {
		c.MaxLineBytes = sdk.DefaultMaxLineBytes
	}
	if c.MaxLineBytes < 0 || c.MaxLineBytes > sdk.HardMaxLineBytes {
		return nil, fmt.Errorf("max_line_bytes must be 1..%d", sdk.HardMaxLineBytes)
	}
	if len(c.Separators) > 8 {
		return nil, fmt.Errorf("separators: at most 8 characters")
	}
	return &mapper{cfg: c}, nil
}

func (m *mapper) Map(doc map[string]any, _ int) (sdk.Event, error) {
	v, _ := sdk.Lookup(doc, m.cfg.LineField)
	line, ok := v.(string)
	if !ok {
		return sdk.Event{}, fmt.Errorf("%w: no text field %q", sdk.ErrUnparsable, m.cfg.LineField)
	}
	if len(line) > m.cfg.MaxLineBytes {
		// An oversize line is never parsed at all.
		return sdk.Event{}, fmt.Errorf("%w: line longer than %d bytes", sdk.ErrUnparsable, m.cfg.MaxLineBytes)
	}
	pairs, perr := parse(line, m.cfg.Separators)
	get := func(name string) (any, bool) {
		v, ok := pairs[name]
		return v, ok
	}
	// The document time is judged before the line, as the built-in mappers do: a bad
	// timestamp is a fault in the document set, which fails the run, not an odd line.
	t, err := m.cfg.EventTime(doc, get)
	if err != nil && !(perr != nil && errors.Is(err, sdk.ErrUnparsable)) {
		return sdk.Event{}, err
	}
	if perr != nil {
		return sdk.Event{}, perr
	}
	fields, err := m.cfg.Build(get)
	if err != nil {
		return sdk.Event{}, err
	}
	return sdk.Event{Time: t, Fields: fields}, nil
}

// parse reads key=value pairs. Rules, all of them about not trusting the line:
// a key is 1-64 characters of letters, digits and _ . : @ / -; a value is either a
// double-quoted string (backslash escapes \" and \\ only) or runs to whitespace or a
// separator; a duplicate key makes the line unparsable, because a value that carries
// another "key=" inside it would otherwise let log content impersonate a field; a
// token that is not key=value is skipped; at most 128 pairs.
func parse(line, seps string) (map[string]string, error) {
	out := map[string]string{}
	isSep := func(c byte) bool { return c == ' ' || c == '\t' || strings.IndexByte(seps, c) >= 0 }
	i, n := 0, len(line)
	for i < n {
		for i < n && isSep(line[i]) {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && line[i] != '=' && !isSep(line[i]) {
			i++
		}
		if i >= n || line[i] != '=' {
			continue // a bare word, not a pair
		}
		key := line[start:i]
		i++ // '='
		if !validKey(key) {
			// Skip this token's value and carry on: free text with an '=' in it.
			for i < n && !isSep(line[i]) {
				i++
			}
			continue
		}
		var val string
		if i < n && line[i] == '"' {
			i++
			var b strings.Builder
			closed := false
			for i < n {
				c := line[i]
				if c == '\\' && i+1 < n && (line[i+1] == '"' || line[i+1] == '\\') {
					b.WriteByte(line[i+1])
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(c)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated quoted value", sdk.ErrUnparsable)
			}
			val = b.String()
		} else {
			vs := i
			for i < n && !isSep(line[i]) {
				i++
			}
			val = line[vs:i]
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%w: duplicate key", sdk.ErrUnparsable)
		}
		if len(out) >= maxPairs {
			return nil, fmt.Errorf("%w: more than %d pairs", sdk.ErrUnparsable, maxPairs)
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no key=value pairs", sdk.ErrUnparsable)
	}
	return out, nil
}

func validKey(k string) bool {
	if k == "" || len(k) > maxKeyLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("_.:@/-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func main() {
	err := sdk.Serve(os.Stdin, os.Stdout, sdk.Plugin{
		Name:         "kvlines",
		Version:      "0.1.0",
		ConfigSchema: "line_field, max_line_bytes, separators, time{doc_field|from,layout}, required[], fields{name:{from,type,layout,omit,required}}; see examples/plugins/kvlines/README.md",
		New:          newMapper,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "kvlines:", err)
		os.Exit(1)
	}
}
