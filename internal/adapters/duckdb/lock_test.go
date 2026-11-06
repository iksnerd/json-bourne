package duckdb

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A lock error as DuckDB words it (synthetic path and PID).
const fakeLockMsg = `IO Error: Could not set lock on file "/data/jb.duckdb": Conflicting lock is held in /usr/local/bin/jb (PID 4242) by user someone. See also https://duckdb.org/docs/connect/concurrency`

type lockScript struct {
	fails  int // lock errors to return before succeeding (-1: forever)
	other  error
	opens  atomic.Int32
	sleeps []time.Duration
}

func (l *lockScript) opts(budget time.Duration) OpenOptions {
	return OpenOptions{
		LockWait: budget,
		sleep: func(ctx context.Context, d time.Duration) error {
			l.sleeps = append(l.sleeps, d)
			return ctx.Err()
		},
		jitter: func(d time.Duration) time.Duration { return d },
		open: func(path string, ro bool) (*sql.DB, error) {
			n := int(l.opens.Add(1))
			if l.other != nil {
				return nil, l.other
			}
			if l.fails < 0 || n <= l.fails {
				return nil, errors.New(fakeLockMsg)
			}
			return rawOpen(path, ro)
		},
	}
}

func total(ds []time.Duration) (t time.Duration) {
	for _, d := range ds {
		t += d
	}
	return
}

func TestLockRetrySucceedsWhenLockFrees(t *testing.T) {
	for _, ro := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "a.duckdb")
		if !ro {
			// nothing to prepare; read-write creates the file
		} else {
			s, err := Open(path, false)
			if err != nil {
				t.Fatal(err)
			}
			s.Migrate()
			s.Close()
		}
		l := &lockScript{fails: 3}
		s, err := OpenContext(context.Background(), path, ro, l.opts(15*time.Second))
		if err != nil {
			t.Fatalf("readOnly=%v: %v", ro, err)
		}
		s.Close()
		if got := l.opens.Load(); got != 4 {
			t.Errorf("readOnly=%v: %d open attempts, want 4", ro, got)
		}
		want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}
		if fmt.Sprint(l.sleeps) != fmt.Sprint(want) {
			t.Errorf("sleeps = %v, want %v", l.sleeps, want)
		}
	}
}

func TestLockRetryGivesUpWithActionableError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.duckdb")
	l := &lockScript{fails: -1}
	_, err := OpenContext(context.Background(), path, true, l.opts(3*time.Second))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	var le *LockedError
	if !errors.As(err, &le) || le.PID != 4242 || le.Holder != "jb" {
		t.Fatalf("holder = %+v", le)
	}
	msg := err.Error()
	for _, want := range []string{path, "another process (jb, PID 4242)", "Wait for it", "stop that process", EnvLockWait} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "someone") || strings.Contains(msg, "/usr/local/bin") {
		t.Errorf("message leaks more of DuckDB's text than the holder name and PID:\n%s", msg)
	}
	if got := total(l.sleeps); got != 3*time.Second {
		t.Errorf("waited %v in total, want exactly the 3s budget", got)
	}
}

func TestLockRetryDisabled(t *testing.T) {
	l := &lockScript{fails: -1}
	_, err := OpenContext(context.Background(), filepath.Join(t.TempDir(), "a.duckdb"), false, l.opts(NoLockWait))
	if !errors.Is(err, ErrLocked) || l.opens.Load() != 1 || len(l.sleeps) != 0 {
		t.Fatalf("err=%v opens=%d sleeps=%v", err, l.opens.Load(), l.sleeps)
	}
	if !strings.Contains(err.Error(), "retry is off") {
		t.Errorf("message does not say the retry is off: %v", err)
	}
}

func TestLockRetryOnlyRetriesTheLockError(t *testing.T) {
	for _, msg := range []string{
		`IO Error: Trying to read a database file with version number 64, but we can only read version 67`,
		`IO Error: Could not open file "/x": Permission denied`,
		`Invalid Input Error: file is not a database`,
	} {
		l := &lockScript{other: errors.New(msg)}
		_, err := OpenContext(context.Background(), filepath.Join(t.TempDir(), "a.duckdb"), false, l.opts(15*time.Second))
		if err == nil || errors.Is(err, ErrLocked) || err.Error() != msg {
			t.Errorf("%q: err = %v, want it unchanged and not ErrLocked", msg, err)
		}
		if l.opens.Load() != 1 || len(l.sleeps) != 0 {
			t.Errorf("%q: retried (%d opens, %d sleeps)", msg, l.opens.Load(), len(l.sleeps))
		}
	}
}

func TestLockRetryCancellationStopsTheWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &lockScript{fails: -1}
	o := l.opts(2 * time.Minute)
	o.sleep = func(ctx context.Context, d time.Duration) error {
		l.sleeps = append(l.sleeps, d)
		cancel() // SIGINT arrives during the first wait
		return sleepCtx(ctx, time.Hour)
	}
	start := time.Now()
	_, err := OpenContext(ctx, filepath.Join(t.TempDir(), "a.duckdb"), false, o)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrLocked) || l.opens.Load() != 1 || time.Since(start) > 2*time.Second {
		t.Fatalf("did not stop at once: opens=%d err=%v", l.opens.Load(), err)
	}
	// Already-cancelled context: not even a first attempt.
	l2 := &lockScript{fails: -1}
	if _, err := OpenContext(ctx, filepath.Join(t.TempDir(), "b.duckdb"), false, l2.opts(time.Second)); !errors.Is(err, context.Canceled) || l2.opens.Load() != 0 {
		t.Fatalf("pre-cancelled: err=%v opens=%d", err, l2.opens.Load())
	}
}

func TestLockBackoffIsBounded(t *testing.T) {
	l := &lockScript{fails: -1}
	_, _ = OpenContext(context.Background(), filepath.Join(t.TempDir(), "a.duckdb"), false, l.opts(MaxLockWait))
	for i, d := range l.sleeps {
		if d > lockBackoffCap {
			t.Errorf("sleep %d = %v exceeds the %v cap", i, d, lockBackoffCap)
		}
		if i > 0 && d < l.sleeps[i-1] && i != len(l.sleeps)-1 {
			t.Errorf("sleep %d = %v shrank from %v", i, d, l.sleeps[i-1])
		}
	}
	if l.sleeps[0] != lockBackoffStart {
		t.Errorf("first sleep = %v", l.sleeps[0])
	}
	if got := total(l.sleeps); got != MaxLockWait {
		t.Errorf("total wait %v, want %v", got, MaxLockWait)
	}
	// 100+200+400+800 then 1s steps: well under 200 attempts for two minutes.
	if len(l.sleeps) > 130 {
		t.Errorf("%d attempts for a 2m budget", len(l.sleeps))
	}
	// Real jitter stays within half to full of the step.
	for range 200 {
		if j := halfJitter(time.Second); j < 500*time.Millisecond || j > time.Second {
			t.Fatalf("jitter %v out of range", j)
		}
	}
}

func TestResolveLockWait(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	for _, c := range []struct {
		opt  time.Duration
		env  string
		want time.Duration
		bad  bool
	}{
		{0, "", DefaultLockWait, false},
		{0, "30s", 30 * time.Second, false},
		{0, "0", 0, false},
		{0, "2m", MaxLockWait, false},
		{0, "3m", 0, true},
		{0, "-1s", 0, true},
		{0, "soon", 0, true},
		{5 * time.Second, "0", 5 * time.Second, false}, // the option beats the environment
		{NoLockWait, "30s", 0, false},
		{3 * time.Minute, "", 0, true},
	} {
		got, err := ResolveLockWait(c.opt, env(c.env))
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("opt=%v env=%q: got %v, %v", c.opt, c.env, got, err)
		}
	}
}

// TestLockHolderProcess is the child half of the real-process tests: it opens the file
// read-write, says so on stdout, then holds it until stdin closes.
func TestLockHolderProcess(t *testing.T) {
	path := os.Getenv("JB_TEST_HOLD")
	if path == "" {
		t.Skip("child helper")
	}
	s, err := Open(path, false)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	if _, err := s.Migrate(); err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	fmt.Println("HELD")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	s.Close()
	os.Exit(0)
}

func startHolder(t *testing.T, path string) (release func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHolderProcess$")
	cmd.Env = append(os.Environ(), "JB_TEST_HOLD="+path)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "HELD" {
		t.Fatalf("holder said %q", line)
	}
	var once atomic.Bool
	release = func() {
		if once.CompareAndSwap(false, true) {
			in.Close()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(release)
	return release
}

func TestRealProcessHoldsThenReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.duckdb")
	release := startHolder(t, path)
	go func() { time.Sleep(700 * time.Millisecond); release() }()

	for _, ro := range []bool{true, false} {
		start := time.Now()
		s, err := OpenContext(context.Background(), path, ro, OpenOptions{LockWait: 20 * time.Second})
		if err != nil {
			t.Fatalf("readOnly=%v: %v", ro, err)
		}
		s.Close()
		if ro && time.Since(start) < 300*time.Millisecond {
			t.Errorf("read-only open returned in %v: the holder was not holding", time.Since(start))
		}
	}
}

func TestRealProcessGiveUpNamesTheHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.duckdb")
	startHolder(t, path)
	for _, ro := range []bool{true, false} {
		start := time.Now()
		_, err := OpenContext(context.Background(), path, ro, OpenOptions{LockWait: 600 * time.Millisecond})
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("readOnly=%v: err = %v", ro, err)
		}
		var le *LockedError
		errors.As(err, &le)
		if le.PID <= 0 || le.Holder == "" {
			t.Errorf("readOnly=%v: holder not named: %+v", ro, le)
		}
		if el := time.Since(start); el < 500*time.Millisecond || el > 5*time.Second {
			t.Errorf("readOnly=%v: gave up after %v for a 600ms budget", ro, el)
		}
	}
}
