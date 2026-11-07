package config

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var updateKeySet = flag.Bool("update-config-keys", false, "rewrite testdata/config-keys.golden")

// specTypes maps each registered `type:` to the Go type its options decode into. The
// registries are checked against these names, so a new type fails the test until it is
// listed here and the golden is regenerated.
var specTypes = map[string]map[string]reflect.Type{
	"source": {"kibana": reflect.TypeOf(kibanaSpec{})},
	"detector": {
		"authspike":   reflect.TypeOf(authspikeSpec{}),
		"behaviour":   reflect.TypeOf(behaviourSpec{}),
		"fingerprint": reflect.TypeOf(fingerprintSpec{}),
		"newkey":      reflect.TypeOf(newkeySpec{}),
		"signature":   reflect.TypeOf(signatureSpec{}),
		"signup":      reflect.TypeOf(signupSpec{}),
	},
	"feed": {
		"dnsbl":     reflect.TypeOf(dnsblSpec{}),
		"greynoise": reflect.TypeOf(greynoiseSpec{}),
		"sans-isc":  reflect.TypeOf(sansiscSpec{}),
	},
	"alert": {"webhook": reflect.TypeOf(webhookSpec{})},
}

// keyLines lists, for a struct type, every yaml key path with the Go type of its value.
// A struct field with no yaml tag is skipped, except a field named cfg, which holds the
// detector's own Config and is entered.
func keyLines(t reflect.Type, prefix string, out *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("yaml")
		key, _, _ := strings.Cut(tag, ",")
		switch {
		case ok && key == "-":
			continue
		case !ok && f.Name == "cfg":
			keyLines(f.Type, prefix, out)
			continue
		case !ok || key == "":
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		path := prefix + key
		elem, suffix := ft, ""
		for elem.Kind() == reflect.Slice {
			elem, suffix = elem.Elem(), suffix+"[]"
		}
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct && elem.PkgPath() != "time" {
			*out = append(*out, fmt.Sprintf("%s\tstruct%s", path, suffix))
			keyLines(elem, path+suffix+".", out)
			continue
		}
		*out = append(*out, fmt.Sprintf("%s\t%s", path, ft.String()))
	}
}

func configKeySet(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	section := func(title string, typ reflect.Type) {
		var lines []string
		keyLines(typ, "", &lines)
		sort.Strings(lines)
		b.WriteString("## " + title + "\n")
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	section("file", reflect.TypeOf(File{}))
	section("store", reflect.TypeOf(Store{}))
	section("intel", reflect.TypeOf(IntelConfig{}))
	section("estate", reflect.TypeOf(EstateConfig{}))

	registries := map[string][]string{}
	for k := range sourceTypes() {
		registries["source"] = append(registries["source"], k)
	}
	for k := range detectorTypes() {
		registries["detector"] = append(registries["detector"], k)
	}
	for k := range feedTypes() {
		registries["feed"] = append(registries["feed"], k)
	}
	for k := range alertTypes() {
		registries["alert"] = append(registries["alert"], k)
	}
	for _, kind := range []string{"source", "detector", "feed", "alert"} {
		known := registries[kind]
		sort.Strings(known)
		var listed []string
		for k := range specTypes[kind] {
			listed = append(listed, k)
		}
		sort.Strings(listed)
		if strings.Join(known, ",") != strings.Join(listed, ",") {
			t.Fatalf("registered %s types %v differ from the types this test lists %v", kind, known, listed)
		}
		for _, name := range known {
			section(kind+" type: "+name, specTypes[kind][name])
		}
	}

	// Keys the entry wrappers take out before the type's own decoding.
	b.WriteString("## source and detector entries (taken out before the type sees the mapping)\nenabled\tbool\ntype\tstring\n")
	b.WriteString("## detector entries only\nsources\t[]string\n")

	// Defaults that are declared in code and visible without building anything.
	o := (&File{}).IntelOptions()
	b.WriteString("## defaults\n")
	fmt.Fprintf(&b, "intel.ip_fields\t%v\nintel.max_indicators\t%d\n", o.IPFields, o.MaxIndicators)
	return b.String()
}

// TestConfigKeySetIsUnchanged pins every key the loader accepts and the Go type it
// decodes into (RFC 0018). A key added, removed, renamed or retyped fails it. Rewrite the
// golden with: go test ./internal/config -run TestConfigKeySetIsUnchanged -update-config-keys
func TestConfigKeySetIsUnchanged(t *testing.T) {
	got := configKeySet(t)
	const path = "testdata/config-keys.golden"
	if *updateKeySet {
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
		t.Errorf("config key set differs from %s (rerun with -update-config-keys if the change is deliberate)\n%s", path, firstLineDiff(string(want), got))
	}
}

func firstLineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return fmt.Sprintf("line %d\n  want: %s\n  got:  %s", i+1, a, b)
		}
	}
	return ""
}

// Every key of the golden is named in docs/CONFIG.md, so a key cannot be added without
// being documented. The reverse (a documented key that no longer exists) is not checked.
func TestEveryConfigKeyIsDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/CONFIG.md")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(configKeySet(t), "\n") {
		if line == "" || strings.HasPrefix(line, "##") {
			continue
		}
		path, _, _ := strings.Cut(line, "\t")
		key := path[strings.LastIndex(path, ".")+1:]
		key = strings.TrimSuffix(key, "[]")
		if seen[key] {
			continue
		}
		seen[key] = true
		if !strings.Contains(string(doc), key) {
			t.Errorf("docs/CONFIG.md never mentions the key %q", key)
		}
	}
}
