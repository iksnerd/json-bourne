package contract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/sdk"
)

// The public surface of sdk, as a program outside the module sees it.
var (
	_ func(in io.Reader, out io.Writer, p sdk.Plugin) error               = sdk.Serve
	_ func(config json.RawMessage, dst any) error                         = sdk.DecodeStrict
	_ func(v any, path string) (any, bool)                                = sdk.Lookup
	_ func(v any, typ, layout string) (any, error)                        = sdk.Coerce
	_ func(v any, layout string) (time.Time, error)                       = sdk.ParseTime
	_ func(br *bufio.Reader, max int) ([]byte, error)                     = sdk.ReadLine
	_ sdk.Mapper                                                          = (*exampleMapper)(nil)
	_ func(*sdk.Common) error                                             = (*sdk.Common).Validate
	_ func(*sdk.Common, func(string) (any, bool)) (map[string]any, error) = (*sdk.Common).Build
)

// exampleMapper is the plugin docs/PLUGINS.md describes: it reads "ip status" lines
// from the document field "line" and emits canonical event fields. It uses only what
// the sdk package exports.
type exampleMapper struct{ cfg exampleConfig }

type exampleConfig struct {
	sdk.Common
	LineField string `json:"line_field"`
}

func newExampleMapper(raw json.RawMessage) (sdk.Mapper, error) {
	var c exampleConfig
	if err := sdk.DecodeStrict(raw, &c); err != nil {
		return nil, err
	}
	if c.LineField == "" {
		c.LineField = "line"
	}
	return &exampleMapper{cfg: c}, nil
}

func (m *exampleMapper) Map(doc map[string]any, _ int) (sdk.Event, error) {
	v, _ := sdk.Lookup(doc, m.cfg.LineField)
	line, ok := v.(string)
	if !ok {
		return sdk.Event{}, fmt.Errorf("%w: no text field %q", sdk.ErrUnparsable, m.cfg.LineField)
	}
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return sdk.Event{}, fmt.Errorf("%w: want \"ip status\"", sdk.ErrUnparsable)
	}
	status, err := sdk.Coerce(parts[1], "int", "")
	if err != nil {
		return sdk.Event{}, fmt.Errorf("%w: %v", sdk.ErrUnparsable, err)
	}
	ts, err := sdk.ParseTime(doc["@timestamp"], "rfc3339")
	if err != nil {
		return sdk.Event{}, err // a fault in the document set, not one odd line
	}
	return sdk.Event{Time: ts, Fields: map[string]any{"client_ip": parts[0], "status": status}}, nil
}

// TestSDKMessageRoundTrip compiles the example plugin against the public sdk and runs
// one request through Serve: manifest first, then one response with one slot per
// document, and a null slot listed in "unparsable" for the line the mapper refused.
func TestSDKMessageRoundTrip(t *testing.T) {
	p := sdk.Plugin{Name: "contract-example", Version: "0.0.1", ConfigSchema: "line_field: the document field holding the line", New: newExampleMapper}
	req := `{"v":1,"id":7,"config":{"line_field":"line"},"docs":[` +
		`{"@timestamp":"2026-11-05T12:00:00Z","line":"192.0.2.1 401"},` +
		`{"@timestamp":"2026-11-05T12:00:01Z","line":"not a pair of fields at all"}]}` + "\n"
	var out bytes.Buffer
	if err := sdk.Serve(strings.NewReader(req), &out, p); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want a manifest and one response, got %d lines:\n%s", len(lines), out.String())
	}

	var manifest struct {
		V       int    `json:"v"`
		Role    string `json:"role"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.V != sdk.ProtocolVersion || manifest.Role != "mapper" || manifest.Name != "contract-example" || manifest.Version != "0.0.1" {
		t.Errorf("manifest = %+v", manifest)
	}

	var resp struct {
		ID     int `json:"id"`
		Events []*struct {
			TS     string         `json:"ts"`
			Fields map[string]any `json:"fields"`
		} `json:"events"`
		Unparsable []int  `json:"unparsable"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != 7 || resp.Error != "" || len(resp.Events) != 2 {
		t.Fatalf("response = %s", lines[1])
	}
	e := resp.Events[0]
	if e == nil || e.TS != "2026-11-05T12:00:00Z" || e.Fields["client_ip"] != "192.0.2.1" || e.Fields["status"] != float64(401) {
		t.Errorf("event 0 = %+v", e)
	}
	if resp.Events[1] != nil || len(resp.Unparsable) != 1 || resp.Unparsable[0] != 1 {
		t.Errorf("slot 1 = %+v, unparsable = %v: a refused line is a null slot listed by index", resp.Events[1], resp.Unparsable)
	}
}

func TestSDKBadConfigFailsTheRequestNotThePlugin(t *testing.T) {
	p := sdk.Plugin{Name: "contract-example", Version: "0.0.1", New: newExampleMapper}
	req := `{"v":1,"id":1,"config":{"surprise":true},"docs":[{"line":"192.0.2.1 200"}]}` + "\n"
	var out bytes.Buffer
	if err := sdk.Serve(strings.NewReader(req), &out, p); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var resp struct {
		ID    int    `json:"id"`
		Error string `json:"error"`
	}
	if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &resp) != nil || resp.ID != 1 || resp.Error == "" {
		t.Errorf("an unknown config key must come back as an error response:\n%s", out.String())
	}
}

func TestSDKErrUnparsableIsMatchableAndLimitsAreFixed(t *testing.T) {
	err := fmt.Errorf("%w: x", sdk.ErrUnparsable)
	if !errors.Is(err, sdk.ErrUnparsable) {
		t.Error("errors.Is does not see ErrUnparsable through a wrap")
	}
	if sdk.ProtocolVersion != 1 || sdk.DefaultMaxLineBytes != 8<<10 || sdk.HardMaxLineBytes != 64<<10 || sdk.MaxRequestLine != 16<<20 {
		t.Error("a documented sdk limit changed")
	}
	// ReadLine refuses an endless line after max bytes.
	_, rerr := sdk.ReadLine(bufio.NewReader(strings.NewReader(strings.Repeat("a", 100)+"\n")), 10)
	if rerr == nil {
		t.Error("ReadLine accepted a line over the limit")
	}
}
