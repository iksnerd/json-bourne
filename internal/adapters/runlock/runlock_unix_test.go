//go:build unix

package runlock

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMain doubles as the second process: with RUNLOCK_HOLD set, the test binary takes
// the lock, says so on stdout and waits for stdin to close (or to be killed).
func TestMain(m *testing.M) {
	if path := os.Getenv("RUNLOCK_HOLD"); path != "" {
		l, err := Acquire(path)
		if err != nil {
			os.Stdout.WriteString("error " + err.Error() + "\n")
			os.Exit(3)
		}
		os.Stdout.WriteString("held\n")
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		l.Release()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// holder starts a real second process that holds path and returns it once it says so.
func holder(t *testing.T, path string) (*exec.Cmd, func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=NONE")
	cmd.Env = append(os.Environ(), "RUNLOCK_HOLD="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "held" {
		cmd.Process.Kill()
		t.Fatalf("holder said %q, %v", line, err)
	}
	stop := func() { stdin.Close(); cmd.Wait() }
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, stop
}

func TestSecondProcessIsRefusedAndNamesTheHolderPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	cmd, stop := holder(t, path)

	l, err := Acquire(path)
	if err == nil {
		l.Release()
		t.Fatal("a lock held by another process was granted")
	}
	var he *HeldError
	if !errors.As(err, &he) || !errors.Is(err, ErrHeld) {
		t.Fatalf("err = %v, want a *HeldError matching ErrHeld", err)
	}
	if he.PID != cmd.Process.Pid {
		t.Errorf("HeldError.PID = %d, want the holder's %d", he.PID, cmd.Process.Pid)
	}
	if !strings.Contains(err.Error(), "PID "+strconv.Itoa(cmd.Process.Pid)) {
		t.Errorf("message %q does not name the holder", err)
	}

	stop() // the holder exits normally
	l, err = Acquire(path)
	if err != nil {
		t.Fatalf("the lock was not free after the holder exited: %v", err)
	}
	l.Release()
}

// A holder that is killed (no chance to release) leaves its PID in the file. That is a
// stale file, not a held lock: the kernel dropped the lock with the process.
func TestLockOfAKilledHolderIsStaleAndTakenOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	cmd, _ := holder(t, path)
	dead := cmd.Process.Pid
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != strconv.Itoa(dead) {
		t.Fatalf("precondition: file holds %q, want the dead PID %d", b, dead)
	}
	l, err := Acquire(path)
	if err != nil {
		t.Fatalf("a stale lock (dead PID %d) was not taken over: %v", dead, err)
	}
	defer l.Release()
	if got := readPID(path); got != os.Getpid() {
		t.Errorf("file holds PID %d, want ours %d", got, os.Getpid())
	}
}

func TestSameProcessCannotTakeTheSameLockTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.lock")
	l, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrHeld) {
		t.Fatalf("second Acquire = %v, want ErrHeld", err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Errorf("second Release = %v, want nil", err)
	}
	l2, err := Acquire(path)
	if err != nil {
		t.Fatalf("not free after Release: %v", err)
	}
	l2.Release()
	if b, _ := os.ReadFile(path); len(b) != 0 {
		t.Errorf("a released lock file still holds %q", b)
	}
}

func TestDistinctPathsDoNotBlockEachOther(t *testing.T) {
	dir := t.TempDir()
	a, err := Acquire(filepath.Join(dir, "watch.a.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := Acquire(filepath.Join(dir, "watch.b.lock"))
	if err != nil {
		t.Fatalf("watchers with different names block each other: %v", err)
	}
	b.Release()
}
