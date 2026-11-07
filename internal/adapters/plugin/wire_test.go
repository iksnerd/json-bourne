package plugin

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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

// wireV1 describes the host side of protocol v1 (docs/PLUGINS.md): the constants and
// limits, the shapes the host decodes, and the exact request line it writes.
func wireV1(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "const ProtocolVersion = %d\nconst RoleMapper = %q\n", ProtocolVersion, RoleMapper)
	fmt.Fprintf(&b, "limit DefaultMaxDocs = %d\nlimit DefaultDeadline = %s\nlimit DefaultMaxResponseBytes = %d\nlimit DefaultMaxRequestBytes = %d\n", DefaultMaxDocs, DefaultDeadline, DefaultMaxResponseBytes, DefaultMaxRequestBytes)
	fmt.Fprintf(&b, "limit DefaultStderrBytes = %d\nlimit DefaultMaxBreaks = %d\nlimit maxConfigBytes = %d\nlimit maxManifestBytes = %d\nlimit shutdownGrace = %s\n", DefaultStderrBytes, DefaultMaxBreaks, maxConfigBytes, maxManifestBytes, shutdownGrace)
	structLines(&b, "Manifest", Manifest{})
	structLines(&b, "response", response{})
	structLines(&b, "rawEvent", rawEvent{})

	e := install(t, "logrequest")
	h := newHost(t, e, Limits{}, map[string]any{"k": "v", "n": 2})
	if _, err := h.MapBatch(context.Background(), []map[string]any{{"x": 0, "a": "z"}, {"bad": true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.MapBatch(context.Background(), []map[string]any{{"x": 1}}); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(readFile(filepath.Dir(e.Path), "requests")), "\n") {
		b.WriteString("request " + l + "\n")
	}
	return b.String()
}

// TestPluginWireProtocolV1HostSideIsUnchanged pins what the host sends and decodes
// (RFC 0018). A changed field, tag, limit or request shape fails it. Rewrite the golden
// with -update-wire after reading the diff; a breaking change needs a new `v`.
func TestPluginWireProtocolV1HostSideIsUnchanged(t *testing.T) {
	got := wireV1(t)
	const path = "testdata/wire-v1.golden"
	if *updateWire {
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
		t.Errorf("the host side of the wire protocol differs from %s (rerun with -update-wire if the change is deliberate)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}
