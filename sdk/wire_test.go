package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var updateWire = flag.Bool("update-wire", false, "rewrite testdata/wire-v1.golden")

func structLines(b *strings.Builder, name string, v any) {
	t := reflect.TypeOf(v)
	fmt.Fprintf(b, "struct %s\n", name)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fmt.Fprintf(b, "  %s %s %s\n", f.Name, f.Type, f.Tag)
	}
}

type wireMapper struct{}

func (wireMapper) Map(doc map[string]any, _ int) (Event, error) {
	switch {
	case doc["bad"] == true:
		return Event{}, fmt.Errorf("not mine: %w", ErrUnparsable)
	case doc["panic"] == true:
		panic("mapper bug")
	case doc["fault"] == true:
		return Event{}, errors.New("fault in the document set")
	}
	return Event{Time: time.Date(2026, 1, 2, 3, 4, 5, 6000, time.FixedZone("x", 3600)), Fields: map[string]any{"status": 401, "k": doc["k"]}}, nil
}

// wireV1 describes the plugin side of protocol v1 (docs/PLUGINS.md): the constants, the
// shapes Serve reads and writes, and a transcript of Serve over every kind of request.
func wireV1(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "const ProtocolVersion = %d\nconst MaxRequestLine = %d\n", ProtocolVersion, MaxRequestLine)
	structLines(&b, "request", request{})
	structLines(&b, "response", response{})
	structLines(&b, "wireEvent", wireEvent{})

	requests := []string{
		`{"v":1,"id":1,"config":{"mode":"a"},"docs":[{"k":"x"},{"bad":true},"not an object",null]}`,
		`{"v":1,"id":2,"config":{"mode":"a"},"docs":[]}`,
		`{"v":1,"id":3,"config":{"mode":"fail"},"docs":[{"k":1}]}`,
		`{"v":2,"id":4,"config":{},"docs":[]}`,
		`{"v":1,"id":5,"config":{"mode":"a"},"docs":[{"panic":true}]}`,
		`{"v":1,"id":6,"config":{"mode":"a"},"docs":[{"fault":true}]}`,
		`{"v":1,"id":7,"config":{"mode":"a"},"docs":[{"k":"y"}],"future":{"a":1}}`,
	}
	var out bytes.Buffer
	p := Plugin{Name: "wire", Version: "1.2.3", ConfigSchema: "free text", New: func(c json.RawMessage) (Mapper, error) {
		if strings.Contains(string(c), "fail") {
			return nil, errors.New("bad mode")
		}
		return wireMapper{}, nil
	}}
	if err := Serve(strings.NewReader(strings.Join(requests, "\n")+"\n"), &out, p); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	b.WriteString("< " + lines[0] + "\n")
	for i, r := range requests {
		b.WriteString("> " + r + "\n< " + lines[i+1] + "\n")
	}
	if len(lines) != len(requests)+1 {
		t.Fatalf("%d output lines for %d requests", len(lines), len(requests))
	}

	// A plugin without a config schema leaves the key out of the manifest.
	out.Reset()
	if err := Serve(strings.NewReader(""), &out, Plugin{Name: "n", Version: "v", New: p.New}); err != nil {
		t.Fatal(err)
	}
	b.WriteString("< " + strings.TrimRight(out.String(), "\n") + "\n")
	return b.String()
}

// TestPluginWireProtocolV1PluginSideIsUnchanged pins what Serve reads and writes
// (RFC 0018). A changed field, tag, constant or answer fails it. Rewrite the golden
// with -update-wire after reading the diff; a breaking change needs a new `v`.
func TestPluginWireProtocolV1PluginSideIsUnchanged(t *testing.T) {
	got := wireV1(t)
	const path = "testdata/wire-v1.golden"
	if *updateWire {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("the plugin side of the wire protocol differs from %s (rerun with -update-wire if the change is deliberate)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}
