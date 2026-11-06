package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	jb "github.com/iksnerd/json-bourne"
)

// The keys of `case check`, `doctor` and `actor status` `--output json` as they were
// before the commands called the library (RFC 0013). A key renamed or dropped fails here.

var caseCheckKeys = []string{
	"configs[].ok", "configs[].path", "dir", "estate.ids[]", "estate.ok", "evidence", "guard.ok", "guard.result",
	"id", "ok", "opened", "actors.ids[]", "actors.ok", "status", "title",
}

var caseCheckFailKeys = []string{"configs", "dir", "error", "ok"}

var doctorKeys = []string{
	"checks[].detail", "checks[].group", "checks[].name", "checks[].status", "ok",
	"services[].config", "services[].env_vars[]", "services[].kind", "services[].leaves", "services[].name", "services[].state", "services[].type",
}

var actorKeys = []string{
	"actors[].actor", "actors[].examined", "actors[].ignored", "actors[].label", "actors[].last_genuine", "actors[].noise",
	"actors[].unparsable", "actors[].user_agent", "store", "store_events", "store_from", "store_to",
}

// keyPaths lists every key path of a decoded JSON value, arrays as "[]", sorted. An empty
// array or object is listed as its own path.
func keyPaths(v any) []string {
	set := map[string]bool{}
	var walk func(v any, p string)
	walk = func(v any, p string) {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				set[p] = true
			}
			for k, e := range x {
				walk(e, join(p, k))
			}
		case []any:
			if len(x) == 0 {
				set[p] = true
			}
			for _, e := range x {
				walk(e, p+"[]")
			}
		default:
			set[p] = true
		}
	}
	walk(v, "")
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, strings.TrimPrefix(k, "."))
	}
	sort.Strings(out)
	return out
}

func join(p, k string) string { return p + "." + k }

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return v
}

func asJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, string(b))
}

func sorted(s []string) []string { c := append([]string(nil), s...); sort.Strings(c); return c }

func wantKeys(t *testing.T, what string, got []string, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, sorted(want)) {
		t.Errorf("%s keys changed:\n got %v\nwant %v", what, got, sorted(want))
	}
}

func TestCaseCheckJSONKeysAndLibraryParity(t *testing.T) {
	_, out, _ := run(t, testDeps(nil), "case", "check", "--case", exampleCase, "--output", "json")
	wantKeys(t, "case check", keyPaths(decode(t, out)), caseCheckKeys)
	lib, err := jb.CaseCheck(exampleCase)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decode(t, out), asJSON(t, lib)) {
		t.Errorf("CLI and library differ:\n%s\n%v", out, asJSON(t, lib))
	}

	bad := copyExampleCase(t, "")
	editFile(t, filepath.Join(bad, "case.yaml"), "passive_only: true", "passive_only: false")
	_, out, _ = run(t, testDeps(nil), "case", "check", "--case", bad, "--output", "json")
	wantKeys(t, "case check (failing)", keyPaths(decode(t, out)), caseCheckFailKeys)
	lib, _ = jb.CaseCheck(bad)
	if !reflect.DeepEqual(decode(t, out), asJSON(t, lib)) {
		t.Errorf("CLI and library differ on a failing case:\n%s", out)
	}
}

func TestDoctorJSONKeysAndLibraryParity(t *testing.T) {
	dir, _ := readyCase(t)
	d := doctorDeps(nil)
	_, out, _ := run(t, d, "doctor", "--case", dir, "--output", "json")
	got := keyPaths(decode(t, out))
	// A disabled estate service has no env_vars; the case has no check that fails here.
	wantKeys(t, "doctor", got, doctorKeys)
	lib, err := jb.Doctor(context.Background(), jb.DoctorOptions{Case: dir, Env: d.env, Now: d.now})
	if err != nil {
		t.Fatal(err)
	}
	cli := decode(t, out).(map[string]any)
	libm := asJSON(t, lib).(map[string]any)
	// The build line holds link-time information the test process does not share.
	for _, m := range []map[string]any{cli, libm} {
		var keep []any
		for _, c := range m["checks"].([]any) {
			if c.(map[string]any)["group"] != "build" {
				keep = append(keep, c)
			}
		}
		m["checks"] = keep
	}
	if !reflect.DeepEqual(cli, libm) {
		t.Errorf("CLI and library differ:\n%v\n%v", cli, libm)
	}
}

func TestActorStatusJSONKeysAndLibraryParity(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(5), exampleUA, "/login", 200, "203.0.113.11", "x"),
		webDoc(cur(20), exampleUA, "/wp-login.php", 200, "203.0.113.11", "x"),
	})
	dir := searchCase(t, idx)
	if code, _, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel); code != 0 {
		t.Fatalf("hunt exit %d: %s", code, stderr)
	}
	code, out, stderr := run(t, testDeps(nil), "actor", "status", "--output", "json", "--case", dir, "--config", fpConfigRel)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wantKeys(t, "actor status", keyPaths(decode(t, out)), actorKeys)
	lib, err := jb.ActorStatus(context.Background(), dir, jb.ActorStatusOptions{Config: fpConfigRel})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decode(t, out), asJSON(t, lib)) {
		t.Errorf("CLI and library differ:\n%s\n%v", out, asJSON(t, lib))
	}
}
