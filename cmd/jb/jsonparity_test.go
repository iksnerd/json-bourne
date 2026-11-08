package main

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// RFC 0013: `hunt --output json` and `activity --output json` print the library value, so
// json.Marshal(result) is the CLI document. The keys are pinned to what the CLI printed
// before the encoding moved into the library.

type docScenario struct {
	name string
	cli  []string                                // arguments after the command, with --case already in
	lib  func(t *testing.T, d deps) (any, error) // the same question asked of the library
}

func unionKeys(t *testing.T, docs []string) []string {
	t.Helper()
	set := map[string]bool{}
	for _, s := range docs {
		for _, k := range keyPaths(decode(t, s)) {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func huntLib(dir, cfg string, o jb.HuntOptions) func(t *testing.T, d deps) (any, error) {
	return func(t *testing.T, d deps) (any, error) {
		o.Window, o.Env, o.Now = time.Hour, d.env, d.now
		r, err := jb.HuntCase(context.Background(), dir, jb.CaseHuntOptions{HuntOptions: o, Config: cfg})
		if r == nil {
			t.Fatalf("no result: %v", err)
		}
		return r, err
	}
}

func activityLib(dir, cfg string, o jb.ActivityOptions) func(t *testing.T, d deps) (any, error) {
	return func(t *testing.T, d deps) (any, error) {
		o.Config, o.Window, o.Env, o.Now = cfg, time.Hour, d.env, d.now
		r, err := jb.Activity(context.Background(), dir, o)
		if r == nil {
			t.Fatalf("no result: %v", err)
		}
		return r, err
	}
}

func runScenarios(t *testing.T, command string, want []string, scs []docScenario) {
	t.Helper()
	d := testDeps(huntEnv)
	var docs []string
	for _, sc := range scs {
		_, out, stderr := run(t, d, append([]string{command, "--output", "json"}, sc.cli...)...)
		if out == "" {
			t.Fatalf("%s: no output\n%s", sc.name, stderr)
		}
		docs = append(docs, out)
		lib, _ := sc.lib(t, d)
		if cli, got := decode(t, out), asJSON(t, lib); !reflect.DeepEqual(cli, got) {
			t.Errorf("%s: the CLI document and json.Marshal of the library value differ:\n%s\n%v", sc.name, out, got)
		}
	}
	wantKeys(t, command, unionKeys(t, docs), want)
}

func TestHuntJSONKeysAndLibraryParity(t *testing.T) {
	dir := searchCase(t, newFakeIndex(t, searchDocs()))
	pc := partialCase(t)
	empty := searchCase(t, newFakeIndex(t, nil))
	until := time.Date(2026, 11, 5, 11, 30, 0, 0, time.UTC)
	runScenarios(t, "hunt", huntJSONKeys, []docScenario{
		{"plain", []string{"--case", dir, "--config", fpConfigRel}, huntLib(dir, fpConfigRel, jb.HuntOptions{})},
		{"search, not stored", []string{"--case", dir, "--config", fpConfigRel, "--search", "needle-token", "--no-store"},
			huntLib(dir, fpConfigRel, jb.HuntOptions{Search: []string{"needle-token"}, NoStore: true})},
		{"search absent, historical", []string{"--case", dir, "--config", fpConfigRel, "--search", "no-such-term", "--until", "2026-11-05T11:30:00Z"},
			huntLib(dir, fpConfigRel, jb.HuntOptions{Search: []string{"no-such-term"}, Until: until})},
		{"finding and an incomplete detector", []string{"--case", pc, "--config", "config/behaviour.yaml", "--window", "1h"},
			huntLib(pc, "config/behaviour.yaml", jb.HuntOptions{})},
		{"search on an empty index", []string{"--case", empty, "--config", fpConfigRel, "--search", "x"},
			huntLib(empty, fpConfigRel, jb.HuntOptions{Search: []string{"x"}})},
	})
}

func TestActivityJSONKeysAndLibraryParity(t *testing.T) {
	active := searchCase(t, newFakeIndex(t, searchDocs()))
	pc := partialCase(t)
	quiet := searchCase(t, newFakeIndex(t, []doc{webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x")}))
	empty := searchCase(t, newFakeIndex(t, nil))
	until := time.Date(2026, 11, 5, 11, 30, 0, 0, time.UTC)
	hour := []string{"--window", "1h"}
	runScenarios(t, "activity", activityJSONKeys, []docScenario{
		{"active", append([]string{"--case", active, "--config", fpConfigRel}, hour...), activityLib(active, fpConfigRel, jb.ActivityOptions{})},
		{"active and incomplete", append([]string{"--case", pc, "--config", "config/behaviour.yaml"}, hour...), activityLib(pc, "config/behaviour.yaml", jb.ActivityOptions{})},
		{"quiet", append([]string{"--case", quiet, "--config", fpConfigRel}, hour...), activityLib(quiet, fpConfigRel, jb.ActivityOptions{})},
		{"incomplete, historical, not stored", append([]string{"--case", empty, "--config", fpConfigRel, "--until", "2026-11-05T11:30:00Z", "--no-store"}, hour...),
			activityLib(empty, fpConfigRel, jb.ActivityOptions{Until: until, NoStore: true})},
	})
}

// The MCP path serializes what jb.Call returns, so the document over MCP has the CLI keys.
func TestCallHuntAndActivityResultsHaveTheCLIKeys(t *testing.T) {
	d := testDeps(huntEnv)
	dir := searchCase(t, newFakeIndex(t, searchDocs()))
	for _, tc := range []struct {
		op   string
		want []string
	}{{"hunt", huntJSONKeys}, {"activity", activityJSONKeys}} {
		res, err := jb.Call(context.Background(), tc.op, map[string]any{"case": dir, "config": fpConfigRel, "window": "1h"}, d.env)
		if res == nil {
			t.Fatalf("%s: %v", tc.op, err)
		}
		got := keyPaths(asJSON(t, res))
		// A key the CLI scenarios reach only on a run with a search, an --until or a finding
		// may be absent here; none may be a Go field name or a key the CLI never printed.
		for _, k := range got {
			if !contains(tc.want, k) {
				t.Errorf("%s: key %q over jb.Call is not a key of the CLI document", tc.op, k)
			}
		}
		for _, must := range []string{"run", "complete", "window[]", "baseline[]", "sources[].name", "detectors[].name", "stored"} {
			if !contains(got, must) {
				t.Errorf("%s: jb.Call document lacks %q: %v", tc.op, must, got)
			}
		}
	}
}
