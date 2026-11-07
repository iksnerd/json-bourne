//go:build unix

package watchstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func within(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second): // backstop, not a measure
		t.Fatal("blocked")
	}
}

func TestLoadAndPeekRefuseFIFOAndDirectoryWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	for _, p := range []string{fifo, dir} {
		within(t, func() {
			if _, err := (Store{Path: p}).Load(context.Background()); !errors.Is(err, core.ErrStateCorrupt) {
				t.Errorf("Load %s: %v", p, err)
			}
			if _, err := (Store{Path: p}).Peek(context.Background()); !errors.Is(err, core.ErrStateCorrupt) {
				t.Errorf("Peek %s: %v", p, err)
			}
		})
	}
	if _, err := os.Lstat(fifo); err != nil {
		t.Errorf("the FIFO must be left where it is: %v", err)
	}
}

func TestLoadRefusesHugeFileAndKeepsItAsCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch-state.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxPeekBytes + 1); err != nil { // sparse
		t.Fatal(err)
	}
	f.Close()
	_, err = Store{Path: p}.Load(context.Background())
	if !errors.Is(err, core.ErrStateCorrupt) {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(p + ".corrupt"); serr != nil {
		t.Errorf("huge file not kept as .corrupt: %v", serr)
	}
}
