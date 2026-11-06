package duckdb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenTempIsPrivateMigratableAndRemovedOnClose(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	s, err := OpenTemp(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := s.TempDir()
	if dir == "" || filepath.Dir(dir) != root {
		t.Fatalf("TempDir = %q, want a directory made under %s", dir, root)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("temp dir = %v, %v; want mode 0700", fi, err)
	}
	if _, err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temp dir still exists after Close: %v", err)
	}
}

func TestStoreTempDirIsEmptyForAFileStore(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.duckdb"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.TempDir() != "" {
		t.Fatalf("TempDir = %q for a file store", s.TempDir())
	}
}
