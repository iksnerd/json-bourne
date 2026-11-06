package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenRunStoreNoStoreNeverTouchesTheConfiguredPath(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	evidence := filepath.Join(root, "case", "evidence")
	cfg := &File{}
	cfg.Store.Path = filepath.Join(evidence, "jb.duckdb")

	st, err := OpenRunStore(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if st.TempDir() == "" {
		t.Fatal("not a temporary store")
	}
	if _, err := os.Stat(evidence); !os.IsNotExist(err) {
		t.Fatalf("the evidence directory was created: %v", err)
	}
	dir := st.TempDir()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temp dir survived Close: %v", err)
	}
}

func TestOpenRunStoreStoredUsesTheConfiguredPath(t *testing.T) {
	cfg := &File{}
	cfg.Store.Path = filepath.Join(t.TempDir(), "sub", "jb.duckdb")
	st, err := OpenRunStore(context.Background(), cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.TempDir() != "" || st.Path() != cfg.Store.Path {
		t.Fatalf("path = %q temp = %q", st.Path(), st.TempDir())
	}
}

// A temporary directory that would land inside a directory the run must not write to
// is refused, and the directory it made is removed on that error path.
func TestOpenRunStoreRefusesATempDirInsideAProtectedDirAndRemovesIt(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "evidence")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", protected)
	cfg := &File{}
	cfg.Store.Path = filepath.Join(protected, "jb.duckdb")
	st, err := OpenRunStore(context.Background(), cfg, true, protected)
	if err == nil {
		st.Close()
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "--no-store") {
		t.Errorf("error = %v", err)
	}
	left, _ := os.ReadDir(protected)
	if len(left) != 0 {
		t.Fatalf("the refused run left %d entries in the protected directory", len(left))
	}
}
