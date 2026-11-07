//go:build unix

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// within fails the test if fn blocks; the bound is a 60s backstop, not a measure.
func within(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("blocked")
	}
}

func TestReadAllNormalAndMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := ReadAll(p, 10)
	if err != nil || string(b) != "hello" {
		t.Fatalf("got %q, %v", b, err)
	}
	if _, err := ReadAll(p+".none", 10); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

func TestReadAllRefusesOversize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, make([]byte, 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAll(p, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestReadAllRefusesDirectoryAndFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no mkfifo: %v", err)
	}
	for _, p := range []string{dir, fifo} {
		within(t, func() {
			if _, err := ReadAll(p, 10); !errors.Is(err, ErrNotRegular) {
				t.Errorf("%s: got %v", p, err)
			}
		})
	}
}
