package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type actorStatusJSON struct {
	Events int64 `json:"store_events"`
	Actors []struct {
		Actor       string     `json:"actor"`
		UserAgent   string     `json:"user_agent"`
		LastGenuine *time.Time `json:"last_genuine"`
		Examined    int        `json:"examined"`
		Noise       int        `json:"noise"`
		Ignored     int        `json:"ignored"`
	} `json:"actors"`
}

func TestActorStatusReportsTheLastGenuineMatchFromTheStore(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(5), exampleUA, "/login", 200, "203.0.113.11", "x"),
		webDoc(cur(20), exampleUA, "/wp-login.php", 200, "203.0.113.11", "x"), // newer, but noise
		webDoc(cur(30), exampleUA, "/login", 200, gatewayAddr, "x"),           // newer, but our gateway
	})
	dir := searchCase(t, idx)
	// A second user agent the store has never seen.
	editFile(t, filepath.Join(dir, "actors", "example-actor.yaml"),
		"  # An address is an observation",
		"  - kind: user_agent\n    value: NeverSeen/1.0\n    first_seen: 2026-10-30\n  # An address is an observation")
	if code, _, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel); code != 0 {
		t.Fatalf("hunt exit %d: %s", code, stderr)
	}

	code, stdout, stderr := run(t, testDeps(nil), "actor", "status", "--output", "json", "--case", dir, "--config", fpConfigRel)
	var out actorStatusJSON
	if err := json.Unmarshal([]byte(stdout), &out); err != nil || code != 0 {
		t.Fatalf("exit %d: %v\n%s\n%s", code, err, stdout, stderr)
	}
	byUA := map[string]int{}
	for i, a := range out.Actors {
		byUA[a.UserAgent] = i
	}
	seen, never := out.Actors[byUA[exampleUA]], out.Actors[byUA["NeverSeen/1.0"]]
	if seen.LastGenuine == nil || !seen.LastGenuine.Equal(cur(5)) || seen.Noise != 1 || seen.Ignored != 1 {
		t.Fatalf("seen = %+v, want last genuine %v past 1 noise and 1 infrastructure event", seen, cur(5))
	}
	if never.LastGenuine != nil || never.Examined != 0 {
		t.Fatalf("never = %+v", never)
	}

	code, tbl, _ := run(t, testDeps(nil), "actor", "status", "--case", dir, "--config", fpConfigRel)
	if code != 0 || !strings.Contains(tbl, "2026-11-05T11:05:00Z") || !strings.Contains(tbl, "no stored event carries this user agent") || !strings.Contains(tbl, "never") {
		t.Fatalf("exit %d\n%s", code, tbl)
	}
}

// status needs no credential and writes nothing: the environment is empty and the store
// file is byte for byte what it was.
func TestActorStatusNeedsNoCredentialAndWritesNothing(t *testing.T) {
	idx := newFakeIndex(t, []doc{webDoc(cur(5), exampleUA, "/login", 200, "203.0.113.11", "x")})
	dir := searchCase(t, idx)
	if code, _, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel); code != 0 {
		t.Fatalf("hunt exit %d: %s", code, stderr)
	}
	store := filepath.Join(dir, "evidence", "jb.duckdb")
	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	n := len(idx.requests())
	code, stdout, stderr := run(t, testDeps(map[string]string{}), "actor", "status", "--case", dir, "--config", fpConfigRel)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	after, _ := os.ReadFile(store)
	if string(before) != string(after) {
		t.Fatal("actor status changed the store file")
	}
	if len(idx.requests()) != n {
		t.Fatal("actor status went to the network")
	}
}

func TestActorStatusOnAnEmptyStoreIsAnErrorNotNever(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	code, stdout, stderr := run(t, testDeps(nil), "actor", "status", "--case", dir, "--config", fpConfigRel)
	if code != exitFailure || strings.Contains(stdout, "never") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestActorStatusNeedsAnActorKeepingDetector(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	if code, _, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel); code != 0 {
		t.Fatalf("hunt exit %d: %s", code, stderr)
	}
	code, _, stderr := run(t, testDeps(nil), "actor", "status", "--case", dir, "--config", "config/hunt.yaml")
	if code != exitFailure || !strings.Contains(stderr, "no detector that keeps actors") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestActorStatusUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no case":    {"actor", "status"},
		"bad output": {"actor", "status", "--case", ".", "--output", "xml"},
	} {
		if code, _, _ := run(t, testDeps(nil), args...); code != exitUsage {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}
