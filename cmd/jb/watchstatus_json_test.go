//go:build unix

package main

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	jb "github.com/iksnerd/json-bourne"
)

// RFC 0013: `watch status --output json` prints json.Marshal of jb.WatchStatus, and the
// keys are the ones the CLI printed before the encoding moved into the library.
func TestWatchStatusJSONKeysAndLibraryParity(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	run(t, d, "watch", "--case", dir, "--once", "--name", "edge")
	run(t, d, "watch", "--case", dir, "--once")

	_, out, stderr := run(t, d, "watch", "status", "--case", dir, "--output", "json")
	if out == "" {
		t.Fatalf("no output\n%s", stderr)
	}
	wantKeys(t, "watch status", keyPaths(decode(t, out)), watchStatusJSONKeys)

	lib, err := jb.WatchStatus(dir, jb.WatchStatusOptions{Now: d.now})
	if err != nil {
		t.Fatal(err)
	}
	if len(lib.Watchers) != 2 {
		t.Fatalf("watchers = %+v", lib.Watchers)
	}
	if cli, got := decode(t, out), asJSON(t, lib); !reflect.DeepEqual(cli, got) {
		t.Errorf("CLI and library differ:\n%s\n%v", out, got)
	}

	// An empty case still has both keys, with [] and not null.
	empty, _ := watchCase(t, http.StatusOK)
	_, out, _ = run(t, d, "watch", "status", "--case", empty, "--output", "json")
	if got := keyPaths(decode(t, out)); !reflect.DeepEqual(got, []string{"checked", "watchers"}) {
		t.Errorf("empty case keys = %v, want [checked watchers]: %s", got, out)
	}
}

// The MCP path serializes what jb.Call returns.
func TestCallWatchStatusHasTheCLIKeys(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	run(t, d, "watch", "--case", dir, "--once")
	res, err := jb.Call(context.Background(), "watch_status", map[string]any{"case": dir}, d.env)
	if err != nil {
		t.Fatal(err)
	}
	got := keyPaths(asJSON(t, res))
	for _, k := range got {
		if !contains(watchStatusJSONKeys, k) {
			t.Errorf("key %q over jb.Call is not a key of the CLI document", k)
		}
	}
	for _, must := range []string{"checked", "watchers[].name", "watchers[].state", "watchers[].lockHeld"} {
		if !contains(got, must) {
			t.Errorf("jb.Call document lacks %q: %v", must, got)
		}
	}
}
