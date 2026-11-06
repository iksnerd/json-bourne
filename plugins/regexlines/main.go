// Command regexlines is an example jb mapper plugin for log lines matched by a regular
// expression with named groups.
//
// It knows no product. The operator's mapper_config carries the pattern (Go's RE2
// syntax, which cannot backtrack catastrophically) and says which group becomes which
// event field. See README.md.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/iksnerd/json-bourne/sdk"
)

const maxPatternBytes = 4 << 10

type config struct {
	sdk.Common
	LineField    string `json:"line_field"`     // document path holding the line (default "message")
	MaxLineBytes int    `json:"max_line_bytes"` // longer lines are unparsable (default 8192, at most 65536)
	Pattern      string `json:"pattern"`        // RE2, at least one named group
}

type mapper struct {
	cfg   config
	re    *regexp.Regexp
	index map[string]int // group name -> submatch index
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
	if c.Pattern == "" || len(c.Pattern) > maxPatternBytes {
		return nil, fmt.Errorf("pattern is required and at most %d bytes", maxPatternBytes)
	}
	re, err := regexp.Compile(c.Pattern) // RE2: linear time in the line, no backtracking
	if err != nil {
		return nil, fmt.Errorf("pattern: %v", err)
	}
	idx := map[string]int{}
	for i, n := range re.SubexpNames() {
		if n != "" {
			idx[n] = i
		}
	}
	if len(idx) == 0 {
		return nil, errors.New("pattern: needs at least one named group (?P<name>...)")
	}
	for name, f := range c.Fields {
		if _, ok := idx[f.From]; !ok {
			return nil, fmt.Errorf("fields.%s: from %q is not a named group in the pattern", name, f.From)
		}
	}
	return &mapper{cfg: c, re: re, index: idx}, nil
}

func (m *mapper) Map(doc map[string]any, _ int) (sdk.Event, error) {
	v, _ := sdk.Lookup(doc, m.cfg.LineField)
	line, ok := v.(string)
	if !ok {
		return sdk.Event{}, fmt.Errorf("%w: no text field %q", sdk.ErrUnparsable, m.cfg.LineField)
	}
	if len(line) > m.cfg.MaxLineBytes {
		return sdk.Event{}, fmt.Errorf("%w: line longer than %d bytes", sdk.ErrUnparsable, m.cfg.MaxLineBytes)
	}
	sub := m.re.FindStringSubmatch(line)
	get := func(name string) (any, bool) {
		i, ok := m.index[name]
		if !ok || sub == nil {
			return nil, false
		}
		return sub[i], true
	}
	t, err := m.cfg.EventTime(doc, get)
	if err != nil && !(sub == nil && errors.Is(err, sdk.ErrUnparsable)) {
		return sdk.Event{}, err
	}
	if sub == nil {
		return sdk.Event{}, fmt.Errorf("%w: line does not match the pattern", sdk.ErrUnparsable)
	}
	fields, err := m.cfg.Build(get)
	if err != nil {
		return sdk.Event{}, err
	}
	return sdk.Event{Time: t, Fields: fields}, nil
}

func main() {
	err := sdk.Serve(os.Stdin, os.Stdout, sdk.Plugin{
		Name:         "regexlines",
		Version:      "0.1.0",
		ConfigSchema: "pattern (RE2, named groups), line_field, max_line_bytes, time{doc_field|from,layout}, required[], fields{name:{from,type,layout,omit,required}}; see plugins/regexlines/README.md",
		New:          newMapper,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "regexlines:", err)
		os.Exit(1)
	}
}
