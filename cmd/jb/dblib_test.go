package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// caseStorePath is the evidence database of a case, as the db commands resolve it.
func caseStorePath(dir, cfg string) (string, error) {
	s, err := jb.DBStatus(context.Background(), dir, jb.DBOptions{Config: cfg})
	if err != nil {
		return "", err
	}
	return s.Path, nil
}

// The CLI prints the library's value: for each db command the JSON on stdout equals the
// JSON of the value the Go function returns for the same store and options. The key
// sets of those values are pinned in package jb (jb/db_test.go) against the shape the
// commands printed before they called the library.
func TestDBCommandsPrintTheLibraryValue(t *testing.T) {
	cfg, _ := seedMaint(t, append(standardHunts, maintHunt{"hunt-20261106T000000Z", 2, 1, "other"}))
	target := filepath.Join(filepath.Dir(cfg), "c.duckdb")
	ctx := t.Context()
	now := func() time.Time { return fixedNow }

	status, err := jb.DBStatus(ctx, "", jb.DBOptions{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	usage, err := jb.DBUsage(ctx, "", jb.DBOptions{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	prune, err := jb.DBPrune(ctx, "", jb.DBPruneOptions{Config: cfg, Kinds: []jb.RunKind{jb.RunKindHunt, jb.RunKindActivity}, OlderThan: 7 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	pruneRun, err := jb.DBPrune(ctx, "", jb.DBPruneOptions{Config: cfg, RunIDs: []string{"hunt-20261001T000000Z"}})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jb.DBCompact(ctx, "", jb.DBCompactOptions{Config: cfg, To: target})
	if err != nil {
		t.Fatal(err)
	}
	rename, err := jb.DBRenameSource(ctx, "", jb.DBRenameSourceOptions{Config: cfg, Old: "ingress", New: "renamed"})
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name string
		args []string
		want any
	}{
		{"status", []string{"db", "status", "--config", cfg}, status},
		{"usage", []string{"db", "usage", "--config", cfg}, usage},
		{"prune", []string{"db", "prune", "--config", cfg, "--kind", "hunt,activity", "--older-than", "7d"}, prune},
		{"prune --run", []string{"db", "prune", "--config", cfg, "--run", "hunt-20261001T000000Z"}, pruneRun},
		{"compact", []string{"db", "compact", "--config", cfg, "--to", target}, compact},
		{"rename-source", []string{"db", "rename-source", "--config", cfg, "ingress", "renamed"}, rename},
	}
	for _, tc := range rows {
		code, out, errs := run(t, testDeps(nil), append(tc.args, "--output", "json")...)
		if code != 0 {
			t.Errorf("%s: exit %d\n%s", tc.name, code, errs)
			continue
		}
		var got, want any
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Errorf("%s: %v\n%s", tc.name, err, out)
			continue
		}
		b, _ := json.Marshal(tc.want)
		_ = json.Unmarshal(b, &want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: the CLI printed something other than the library value\ncli: %s\nlib: %s", tc.name, out, b)
		}
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("a dry run wrote the compact target")
	}
}

// One path: each db command calls its library function and holds no second
// implementation. The table is command file to the function it must call and the store
// calls it must not make itself.
func TestDBCommandsHaveNoSecondImplementation(t *testing.T) {
	banned := []string{"duckdb.Open", "PruneRunEvents(", ".Compact(", ".RenameSource(", ".StoreUsage(", "config.Load("}
	for file, calls := range map[string][]string{
		"db.go":       {"jb.DBStatus("},
		"dbmaint.go":  {"jb.DBUsage(", "jb.DBPrune(", "jb.DBCompact("},
		"dbrename.go": {"jb.DBRenameSource("},
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, c := range calls {
			if !strings.Contains(src, c) {
				t.Errorf("%s does not call %s", file, c)
			}
		}
		for _, x := range banned {
			if strings.Contains(src, x) {
				t.Errorf("%s contains %q: a second implementation of what the library does", file, x)
			}
		}
	}
}
