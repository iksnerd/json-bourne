// Command jsondoc is an example jb mapper plugin for documents that are already JSON.
//
// It knows no product. The operator's mapper_config maps JSON paths in the document to
// event fields, with types and a time. See README.md.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/iksnerd/json-bourne/sdk"
)

type config struct {
	sdk.Common
	MaxDocBytes int `json:"max_doc_bytes"` // larger documents are unparsable (default 1 MiB)
}

type mapper struct{ cfg config }

func newMapper(raw json.RawMessage) (sdk.Mapper, error) {
	var c config
	if err := sdk.DecodeStrict(raw, &c); err != nil {
		return nil, err
	}
	if err := c.Common.Validate(); err != nil {
		return nil, err
	}
	if c.MaxDocBytes == 0 {
		c.MaxDocBytes = sdk.DefaultMaxDocBytes
	}
	if c.MaxDocBytes < 0 || c.MaxDocBytes > 8<<20 {
		return nil, fmt.Errorf("max_doc_bytes must be 1..%d", 8<<20)
	}
	for name, f := range c.Fields {
		if n := len(strings.Split(f.From, ".")); n > sdk.MaxPathSegments {
			return nil, fmt.Errorf("fields.%s: path has %d segments, at most %d", name, n, sdk.MaxPathSegments)
		}
	}
	return &mapper{cfg: c}, nil
}

func (m *mapper) Map(doc map[string]any, size int) (sdk.Event, error) {
	if size > m.cfg.MaxDocBytes {
		return sdk.Event{}, fmt.Errorf("%w: document larger than %d bytes", sdk.ErrUnparsable, m.cfg.MaxDocBytes)
	}
	get := func(path string) (any, bool) { return sdk.Lookup(doc, path) }
	t, err := m.cfg.EventTime(doc, get)
	if err != nil {
		return sdk.Event{}, err
	}
	fields, err := m.cfg.Build(get)
	if err != nil {
		return sdk.Event{}, err
	}
	return sdk.Event{Time: t, Fields: fields}, nil
}

func main() {
	err := sdk.Serve(os.Stdin, os.Stdout, sdk.Plugin{
		Name:         "jsondoc",
		Version:      "0.1.0",
		ConfigSchema: "max_doc_bytes, time{doc_field|from,layout}, required[], fields{name:{from(json path),type,layout,omit,required}}; see plugins/jsondoc/README.md",
		New:          newMapper,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "jsondoc:", err)
		os.Exit(1)
	}
}
