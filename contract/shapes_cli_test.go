package contract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// cliGolden returns the stdout of a recorded `jb hunt|activity --output json` run
// (cmd/jb/testdata/golden/hunt-activity), compacted. The library value must marshal to
// the same bytes, key order included: the CLI prints the library's value.
func cliGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "cmd", "jb", "testdata", "golden", "hunt-activity", name+".golden"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "exit 0\n--- stdout\n") {
		t.Fatalf("%s: unexpected golden layout", name)
	}
	s = strings.TrimPrefix(s, "exit 0\n--- stdout\n")
	i := strings.Index(s, "--- stderr\n")
	if i < 0 {
		t.Fatalf("%s: no stderr section", name)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s[:i])); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return buf.String()
}

func sameAsCLI(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if want := cliGolden(t, name); string(raw) != want {
		t.Errorf("the library value differs from the CLI golden %s\n--- got\n%s\n--- want\n%s", name, raw, want)
	}
}

func huntOpts() jb.CaseHuntOptions {
	return jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Window: time.Hour, Env: env, Now: fixedNow}}
}

func TestHuntJSONIsTheCLIGolden(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	res, err := jb.HuntCase(t.Context(), dir, huntOpts())
	if err != nil {
		t.Fatal(err)
	}
	sameAsCLI(t, "hunt-json", res)
}

func TestHuntNoStoreJSONIsTheCLIGolden(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	o := huntOpts()
	o.NoStore = true
	res, err := jb.HuntCase(t.Context(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	sameAsCLI(t, "hunt-no-store-json", res)
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); err == nil {
		t.Error("NoStore left an evidence database")
	}
}

func TestHuntSearchJSONIsTheCLIGolden(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	o := huntOpts()
	o.Search, o.SearchField = []string{"needle-token"}, "message"
	res, err := jb.HuntCase(t.Context(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	sameAsCLI(t, "hunt-search-json", res)
}

func TestActivityJSONIsTheCLIGolden(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	res, err := jb.Activity(t.Context(), dir, jb.ActivityOptions{Config: fpConfig, Window: time.Hour, Env: env, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	sameAsCLI(t, "activity-json", res)
}
