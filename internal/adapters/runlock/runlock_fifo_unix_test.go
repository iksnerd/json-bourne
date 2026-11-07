//go:build unix

package runlock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/safefile"
)

// within runs f and fails the test if it has not returned in 60 seconds (a FIFO open
// that blocks would otherwise hang the suite until the go test timeout).
func within(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("blocked: a FIFO at the lock path must not hang the command")
	}
}

func fifoAt(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "run.lock")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	return p
}

func TestFIFOAtLockPathIsRefusedByProbeAndAcquire(t *testing.T) {
	p := fifoAt(t)
	within(t, func() {
		if _, err := Probe(p); !errors.Is(err, safefile.ErrNotRegular) {
			t.Errorf("Probe on a FIFO: err = %v, want ErrNotRegular", err)
		}
		if l, err := Acquire(p); !errors.Is(err, safefile.ErrNotRegular) {
			t.Errorf("Acquire on a FIFO: lock %v err = %v, want ErrNotRegular", l, err)
		}
	})
}

func TestDirectoryAtLockPathIsRefused(t *testing.T) {
	p := t.TempDir()
	within(t, func() {
		if _, err := Probe(p); err == nil {
			t.Error("Probe on a directory succeeded")
		}
		if _, err := Acquire(p); err == nil {
			t.Error("Acquire on a directory succeeded")
		}
	})
}

func TestReadPIDDoesNotBlockOnFIFOAndIsCapped(t *testing.T) {
	p := fifoAt(t)
	within(t, func() {
		if got := readPID(p); got != 0 {
			t.Errorf("readPID(FIFO) = %d, want 0", got)
		}
	})
	big := filepath.Join(t.TempDir(), "big.lock")
	if err := os.WriteFile(big, []byte(strings.Repeat("1", 1<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPID(big); got != 0 {
		t.Errorf("readPID(huge file) = %d, want 0", got)
	}
	ok := filepath.Join(t.TempDir(), "ok.lock")
	if err := os.WriteFile(ok, []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPID(ok); got != 4242 {
		t.Errorf("readPID(normal) = %d, want 4242", got)
	}
}
