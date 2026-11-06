//go:build unix

package runlock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProbeSeesAHeldLockWithoutTakingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	l, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()

	h, err := Probe(path)
	if err != nil || !h.Held || h.PID != os.Getpid() {
		t.Fatalf("Probe = %+v, %v; want held by our PID %d", h, err, os.Getpid())
	}
	if h2, _ := Probe(path); !h2.Held {
		t.Error("second probe lost the lock")
	}
}

func TestProbeOfAFreeLockLeavesItFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	l, _ := Acquire(path)
	l.Release()

	h, err := Probe(path)
	if err != nil || h.Held {
		t.Fatalf("Probe = %+v, %v; want free", h, err)
	}
	// The probe left nothing behind that blocks the real holder.
	l2, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire after Probe: %v", err)
	}
	l2.Release()
}

func TestProbeOfAMissingFileIsFreeAndCreatesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	h, err := Probe(path)
	if err != nil || h.Held {
		t.Fatalf("Probe = %+v, %v; want free", h, err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("Probe created the lock file")
	}
}

// A killed holder leaves its PID in the file; the kernel dropped the lock, so it is free.
func TestProbeOfAKilledHolderIsFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	cmd, _ := holder(t, path)
	h, err := Probe(path)
	if err != nil || !h.Held || h.PID != cmd.Process.Pid {
		t.Fatalf("Probe while held = %+v, %v; want held by %d", h, err, cmd.Process.Pid)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if h, err = Probe(path); err != nil || h.Held {
		t.Fatalf("Probe after kill = %+v, %v; want free", h, err)
	}
}

func TestProbeOfAnUnreadableLockFileIsAnErrorNotFree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	path := filepath.Join(t.TempDir(), "watch.lock")
	if err := os.WriteFile(path, []byte("1\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if h, err := Probe(path); err == nil {
		t.Errorf("Probe of an unreadable file = %+v, nil; want an error, never a free lock", h)
	}
}

// A probe holds a shared lock for an instant. A real Acquire racing it must not be
// refused for that: Acquire retries a refusal briefly.
func TestAcquireSurvivesAConcurrentProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				Probe(path)
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 200; i++ {
		l, err := Acquire(path)
		if err != nil {
			t.Fatalf("Acquire %d refused while only probes ran: %v", i, err)
		}
		l.Release()
	}
}
