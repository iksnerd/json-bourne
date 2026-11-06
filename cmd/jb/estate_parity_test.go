package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// jsonKeys returns the sorted keys of the JSON object in raw.
func jsonKeys(t *testing.T, raw string) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, raw)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// wantKeys fails unless the object has exactly these keys. It pins the `--output json`
// shape of a command: a key renamed, added or dropped fails here.
func wantEstateKeys(t *testing.T, what, raw string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := jsonKeys(t, raw); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s keys\n got %v\nwant %v", what, got, want)
	}
}

// firstOf returns the first element of the array at key, as raw JSON.
func firstOf(t *testing.T, raw, key string) string {
	t.Helper()
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(subObject(t, raw, key)), &arr); err != nil {
		t.Fatalf("%s: %v\n%s", key, err, raw)
	}
	if len(arr) == 0 {
		t.Fatalf("%s is empty in\n%s", key, raw)
	}
	return string(arr[0])
}

func subObject(t *testing.T, raw, key string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return string(m[key])
}

func TestEstateIPJSONKeysAreUnchanged(t *testing.T) {
	dir := copyExampleCase(t, "")
	r := &stubRDAP{errs: map[string]error{"192.0.2.10": fmt.Errorf("%w: HTTP 503", core.ErrLookupFailed)}}
	_, out, _ := run(t, estateDeps(okPTR(), r), "estate", "--case", dir, "--output", "json", "192.0.2.10")
	wantEstateKeys(t, "estate", out, "note", "file", "complete", "wrote", "addresses", "added", "unchanged", "failures", "conflicts")
	wantEstateKeys(t, "estate added", subObject(t, out, "added"), "nodes", "edges", "absences")
	wantEstateKeys(t, "estate failure", firstOf(t, out, "failures"), "ip", "lookup", "error")
}

func TestEstateExternalJSONKeysAreUnchanged(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "crt.sh")
	st := newExtStubs()
	st.ct.truncated = true
	_, out, _ := run(t, st.deps(), "estate", "ct", "--case", dir, "--output", "json", "example.com")
	wantEstateKeys(t, "estate ct", out, "note", "notes", "service", "asked", "file", "complete", "wrote", "targets", "added", "unchanged", "failures", "conflicts")
	wantEstateKeys(t, "estate ct added", subObject(t, out, "added"), "nodes", "edges", "absences")
	wantEstateKeys(t, "estate ct failure", firstOf(t, out, "failures"), "target", "lookup", "error")
}

func TestEstateDriftJSONKeysAreUnchanged(t *testing.T) {
	dir := copyExampleCase(t, "")
	enableExt(t, dir, "dns")
	w := newWorld()
	w.baseline2(t, dir)
	w.tick()
	w.ns = []string{"ns1.example.com", "ns7.example.com"}
	w.failMX = true
	code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml", "--output", "json")
	if code != exitFailure {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	wantEstateKeys(t, "refresh", out, "note", "snapshot", "file", "based_on", "complete", "nodes", "edges", "absences", "services", "failures")
	svc := firstOf(t, out, "services")
	failure := firstOf(t, out, "failures")
	// A complete snapshot to diff and promote.
	w.failMX = false
	w.tick()
	if code, out, errs := run(t, w.deps(), "estate", "refresh", "--case", dir, "--file", "base.yaml", "--output", "json"); code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	wantEstateKeys(t, "refresh service", svc, "Name", "State", "Targets", "Reason")
	wantEstateKeys(t, "refresh failure", failure, "Target", "Lookup", "Reason")
	diffKeys := []string{"note", "from", "to", "questions_compared", "changes", "not_comparable", "nodes_not_compared", "counts", "findings"}
	_, out, _ = run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml", "--output", "json")
	wantEstateKeys(t, "diff", out, diffKeys...)
	wantEstateKeys(t, "diff side", subObject(t, out, "from"), "ref", "path", "latest_observed", "nodes", "edges", "absences")
	wantEstateKeys(t, "diff counts", subObject(t, out, "counts"), "all", "nodes", "edges", "absences")
	wantEstateKeys(t, "diff counts all", subObject(t, subObject(t, out, "counts"), "all"), "added", "removed", "changed")
	wantEstateKeys(t, "diff finding", firstOf(t, out, "findings"), "detector", "tag", "severity", "summary", "detail")
	wantEstateKeys(t, "diff change", firstOf(t, out, "changes"), "kind", "type", "subject", "from", "to", "relation", "source", "method", "from_observed", "to_observed")
	_, out, _ = run(t, w.deps(), "estate", "diff", "--case", dir, "--file", "base.yaml", "--output", "json", "--alert")
	wantEstateKeys(t, "diff --alert", out, append(diffKeys, "alerts")...)
	wantEstateKeys(t, "diff alerts", subObject(t, out, "alerts"), "New", "Suppressed", "OptionalFailed")

	snaps := snapshotFiles(t, dir)
	id := strings.TrimSuffix(snaps[len(snaps)-1], ".yaml")
	code, out, errs = run(t, w.deps(), "estate", "promote", "--case", dir, "--file", "base.yaml", "--output", "json", id)
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	wantEstateKeys(t, "promote", out, "promoted", "baseline", "archived")
	if _, err := os.Stat(filepath.Join(dir, "estate", "archive")); err != nil {
		t.Error(err)
	}
}

func TestIntelJSONKeysAreUnchanged(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	dir := intelCase(t, gn, "")
	_, out, _ := run(t, intelDeps(), "intel", "--case", dir, "--output", "json", "192.0.2.7", "192.0.2.50")
	wantEstateKeys(t, "intel", out, "note", "complete", "results", "failures")
	wantEstateKeys(t, "intel row", firstOf(t, out, "results"), "indicator", "feed", "verdict", "observed")
	wantEstateKeys(t, "intel failure", firstOf(t, out, "failures"), "indicator", "feed", "error")
}
