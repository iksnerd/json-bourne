package main

import (
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// treeState is every path under dir with its mode and content hash, so a test can
// prove a directory is byte-for-byte unchanged.
func treeState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := e.Info()
		if err != nil {
			return err
		}
		if e.IsDir() {
			out[rel] = "dir " + info.Mode().String()
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = info.Mode().String() + " " + string(sha256.New().Sum(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// scratchRoot points TMPDIR at a fresh empty directory and returns it, so a test can see
// whether a temporary store was left behind.
func scratchRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	return root
}

func requireEmptyDir(t *testing.T, dir string) {
	t.Helper()
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		names := []string{}
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Fatalf("temporary store left behind: %v", names)
	}
}

type storedJSON struct {
	Run    string `json:"run"`
	Stored *bool  `json:"stored"`
}

func TestHuntNoStoreLeavesTheEvidenceDirectoryUntouchedAndSaysSo(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	tmp := scratchRoot(t)
	before := treeState(t, dir)

	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--output", "json", "--case", dir, "--config", fpConfigRel, "--no-store")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var out storedJSON
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if out.Stored == nil || *out.Stored {
		t.Errorf("stored = %v, want false", out.Stored)
	}
	if after := treeState(t, dir); !reflect.DeepEqual(before, after) {
		t.Errorf("the case directory changed under --no-store:\nbefore %v\nafter  %v", before, after)
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); !os.IsNotExist(err) {
		t.Errorf("a store was created in the evidence directory: %v", err)
	}
	requireEmptyDir(t, tmp)
}

func TestHuntStoredSaysStoredTrue(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--output", "json", "--case", dir, "--config", fpConfigRel)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var out storedJSON
	_ = json.Unmarshal([]byte(stdout), &out)
	if out.Stored == nil || !*out.Stored {
		t.Errorf("stored = %v, want true", out.Stored)
	}
	code, stdout, _ = run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel)
	if code != 0 || strings.Contains(stdout, "not stored") {
		t.Errorf("a stored table says it is not stored (exit %d):\n%s", code, stdout)
	}
}

func TestHuntNoStoreTablePrintsTheNotStoredLine(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	scratchRoot(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel, "--no-store")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "not stored: this run left no evidence\n") {
		t.Errorf("missing the line:\n%s", stdout)
	}
}

func TestHuntNoStoreWorksWithSearchAndUntil(t *testing.T) {
	dir, _ := untilCase(t, pastDocs(), 0)
	tmp := scratchRoot(t)
	before := treeState(t, dir)
	d := depsAt(untilEnd.Add(24 * 60 * 60 * 1e9))
	code, stdout, stderr := run(t, d, "hunt", "--output", "json", "--case", dir, "--config", fpConfigRel,
		"--no-store", "--search", "login", "--until", untilEnd.Format("2006-01-02T15:04:05Z"))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var out struct {
		storedJSON
		Search *struct{} `json:"search"`
		Until  *string   `json:"until"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Stored == nil || *out.Stored || out.Search == nil || out.Until == nil {
		t.Errorf("stored/search/until = %v/%v/%v", out.Stored, out.Search, out.Until)
	}
	if after := treeState(t, dir); !reflect.DeepEqual(before, after) {
		t.Error("the case directory changed")
	}
	requireEmptyDir(t, tmp)
}

// The error path: the source is down, the hunt fails, and the temporary store is gone.
func TestHuntNoStoreRemovesTheTemporaryStoreWhenTheHuntFails(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	idx.srv.Close()
	tmp := scratchRoot(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel, "--no-store")
	if code == 0 {
		t.Fatalf("a dead source hunted clean\n%s\n%s", stdout, stderr)
	}
	requireEmptyDir(t, tmp)
}

// TMPDIR inside the case would put the scratch store in the evidence tree: refused, and
// nothing is left there.
func TestHuntNoStoreRefusesATempDirInsideTheCase(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	inside := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", inside)
	before := treeState(t, dir)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", fpConfigRel, "--no-store")
	if code == 0 {
		t.Fatalf("want a refusal\n%s", stdout)
	}
	if !strings.Contains(stderr, "--no-store") {
		t.Errorf("stderr = %q", stderr)
	}
	if after := treeState(t, dir); !reflect.DeepEqual(before, after) {
		t.Error("the case directory changed")
	}
}

func TestActivityNoStoreLeavesTheEvidenceDirectoryUntouched(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(2), exampleUA, "/login", 200, "203.0.113.11", "x"),
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
	})
	dir := searchCase(t, idx)
	tmp := scratchRoot(t)
	before := treeState(t, dir)
	code, out, stdout, stderr := runActivityCmd(t, dir, "--no-store")
	if out.Verdict == "" {
		t.Fatalf("not JSON (exit %d)\n%s\n%s", code, stdout, stderr)
	}
	var s storedJSON
	_ = json.Unmarshal([]byte(stdout), &s)
	if s.Stored == nil || *s.Stored {
		t.Errorf("stored = %v, want false", s.Stored)
	}
	if after := treeState(t, dir); !reflect.DeepEqual(before, after) {
		t.Error("the case directory changed under --no-store")
	}
	requireEmptyDir(t, tmp)

	code, stdout, _ = run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h", "--no-store")
	if !strings.Contains(stdout, "not stored: this run left no evidence") {
		t.Errorf("table lacks the line (exit %d):\n%s", code, stdout)
	}
	requireEmptyDir(t, tmp)

	_, stdout, _ = run(t, testDeps(huntEnv), "activity", "--output", "json", "--case", dir, "--config", fpConfigRel, "--window", "1h")
	_ = json.Unmarshal([]byte(stdout), &s)
	if s.Stored == nil || !*s.Stored {
		t.Errorf("a stored activity run says stored = %v", s.Stored)
	}
}

func TestHuntNoStoreWithoutACaseNeverOpensTheConfiguredStore(t *testing.T) {
	srv := fakeKibana(t, 200)
	cfgFile := writeConfig(t, srv.URL)
	db := filepath.Join(filepath.Dir(cfgFile), "jb.duckdb")
	scratchRoot(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--config", cfgFile, "--no-store")
	if code != 0 && code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "not stored") {
		t.Errorf("no not-stored line:\n%s", stdout)
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Errorf("the configured store was created: %v", err)
	}
}
