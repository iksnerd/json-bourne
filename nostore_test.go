package jb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNoStoreLeavesNoStoreAndSaysSo(t *testing.T) {
	env := func(string) (string, bool) { return "k", true }
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	dir := copyCase(t)
	res, _ := HuntCase(t.Context(), dir, CaseHuntOptions{HuntOptions: HuntOptions{Env: env, NoStore: true}})
	if res == nil || res.Stored {
		t.Fatalf("hunt result = %+v, want Stored false", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); !os.IsNotExist(err) {
		t.Errorf("hunt with NoStore created the store: %v", err)
	}

	ares, _ := Activity(t.Context(), dir, ActivityOptions{Config: filepath.Join(dir, "config", "fingerprint.yaml"), Env: env, NoStore: true})
	if ares == nil || ares.Stored {
		t.Fatalf("activity result = %+v, want Stored false", ares)
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); !os.IsNotExist(err) {
		t.Errorf("activity with NoStore created the store: %v", err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("%d temporary entries left behind", len(left))
	}

	res, _ = HuntCase(t.Context(), dir, CaseHuntOptions{HuntOptions: HuntOptions{Env: env}})
	if res == nil || !res.Stored {
		t.Errorf("a stored hunt result = %+v, want Stored true", res)
	}
}
