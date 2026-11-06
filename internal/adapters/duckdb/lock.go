package duckdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Cross-process locking. DuckDB admits one process that opens the file read-write OR
// any number that open it read-only, never both; the loser fails at open with
// "Could not set lock on file ... Conflicting lock is held in ... (PID n)". A running
// `jb watch` holds the file for the write phase of each cycle only, so a command that
// collides with it can usually just wait a moment. Open therefore retries that one
// error, and only that one, with a bounded, jittered backoff.
const (
	// EnvLockWait overrides the retry budget: a Go duration ("30s", "1m"), "0" to
	// disable the retry. Anything above MaxLockWait is refused, not clamped.
	EnvLockWait = "JB_DB_LOCK_WAIT"
	// DefaultLockWait is the total time Open waits for a lock held by another process.
	DefaultLockWait = 15 * time.Second
	// MaxLockWait is the longest budget accepted.
	MaxLockWait = 2 * time.Minute
	// NoLockWait in OpenOptions.LockWait fails at the first lock error, as before.
	NoLockWait time.Duration = -1

	lockBackoffStart = 100 * time.Millisecond
	lockBackoffCap   = time.Second
)

// ErrLocked is matched (errors.Is) by the error Open returns when another process holds
// the database file and the wait budget ran out.
var ErrLocked = errors.New("database is locked by another process")

// LockedError says which file is held, by whom (when DuckDB names the holder) and how
// long Open waited. Only the holder's executable name and PID are taken from DuckDB's
// message; nothing else in it is kept.
type LockedError struct {
	Path     string
	PID      int    // 0 when DuckDB did not name one
	Holder   string // base name of the holder's executable, "" when not named
	Waited   time.Duration
	Budget   time.Duration // 0 when the retry was disabled
	ReadOnly bool
	Err      error // the engine's error
}

func (e *LockedError) Error() string {
	who := "another process"
	switch {
	case e.Holder != "" && e.PID > 0:
		who = fmt.Sprintf("another process (%s, PID %d)", e.Holder, e.PID)
	case e.PID > 0:
		who = fmt.Sprintf("another process (PID %d)", e.PID)
	case e.Holder != "":
		who = fmt.Sprintf("another process (%s)", e.Holder)
	}
	mode := "read-write"
	if e.ReadOnly {
		mode = "read-only"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "evidence database %s is held by %s and could not be opened %s", e.Path, who, mode)
	if e.Budget > 0 {
		fmt.Fprintf(&b, " after waiting %s", e.Waited.Round(time.Millisecond))
	} else {
		fmt.Fprintf(&b, " (lock retry is off, %s=0)", EnvLockWait)
	}
	fmt.Fprintf(&b, ". DuckDB allows one read-write process or many read-only ones, never both. Wait for it to finish (a running `jb watch` holds the file for a few seconds per cycle) or stop that process, then retry; %s raises the wait, up to %s", EnvLockWait, MaxLockWait)
	return b.String()
}

func (e *LockedError) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrLocked) true.
func (e *LockedError) Is(target error) bool { return target == ErrLocked }

// OpenOptions tunes Open. The zero value is the production behaviour.
type OpenOptions struct {
	// LockWait is the total time to wait for a lock held by another process. 0 means
	// the default (EnvLockWait, else DefaultLockWait); NoLockWait disables the retry.
	LockWait time.Duration

	// Test seams.
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
	open   func(path string, readOnly bool) (*sql.DB, error)
}

// ResolveLockWait turns the option and the environment into the budget in force:
// 0 means retry disabled. It refuses a malformed, negative or oversized value.
func ResolveLockWait(opt time.Duration, getenv func(string) string) (time.Duration, error) {
	switch {
	case opt == NoLockWait:
		return 0, nil
	case opt > MaxLockWait:
		return 0, fmt.Errorf("lock wait %s is above the maximum %s", opt, MaxLockWait)
	case opt > 0:
		return opt, nil
	case opt < 0:
		return 0, fmt.Errorf("lock wait %s is negative", opt)
	}
	raw := ""
	if getenv != nil {
		raw = strings.TrimSpace(getenv(EnvLockWait))
	}
	if raw == "" {
		return DefaultLockWait, nil
	}
	if raw == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: not a duration like 30s or 1m (0 disables the retry)", EnvLockWait, raw)
	}
	if d < 0 || d > MaxLockWait {
		return 0, fmt.Errorf("%s=%s: must be between 0 and %s", EnvLockWait, d, MaxLockWait)
	}
	return d, nil
}

var (
	lockMarker = "Could not set lock on file"
	holderRE   = regexp.MustCompile(`Conflicting lock is held in (.+?) \(PID (\d+)\)`)
)

// isLockError reports whether err is DuckDB's "another process holds the file" error.
// Nothing else is retried: a corrupt file, a permission error or a storage-version
// mismatch fails at once.
func isLockError(err error) bool {
	return err != nil && strings.Contains(err.Error(), lockMarker)
}

// holderOf extracts the holder's executable name and PID, and nothing more.
func holderOf(err error) (name string, pid int) {
	m := holderRE.FindStringSubmatch(err.Error())
	if m == nil {
		return "", 0
	}
	pid, _ = strconv.Atoi(m[2])
	return filepath.Base(m[1]), pid
}

func rawOpen(path string, readOnly bool) (*sql.DB, error) {
	mode := "READ_WRITE"
	if readOnly {
		mode = "READ_ONLY"
	}
	db, err := sql.Open("duckdb", path+"?access_mode="+mode)
	if err != nil {
		return nil, fmt.Errorf("open duckdb %s: %w", path, err)
	}
	// One connection: DuckDB is in-process and a second writer would block anyway.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping duckdb: %w", err)
	}
	return db, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func halfJitter(d time.Duration) time.Duration {
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// openRetry opens the file, retrying only the cross-process lock error within budget.
// Delays start at 100ms and double up to 1s, each cut to half-to-full by jitter and
// to what is left of the budget, so the sleeps never add up to more than the budget.
func openRetry(ctx context.Context, path string, readOnly bool, o OpenOptions, getenv func(string) string) (*sql.DB, error) {
	budget, err := ResolveLockWait(o.LockWait, getenv)
	if err != nil {
		return nil, err
	}
	open, sleep, jitter := o.open, o.sleep, o.jitter
	if open == nil {
		open = rawOpen
	}
	if sleep == nil {
		sleep = sleepCtx
	}
	if jitter == nil {
		jitter = halfJitter
	}
	var (
		waited time.Duration
		delay  = lockBackoffStart
	)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("interrupted before opening %s: %w", path, err)
		}
		db, err := open(path, readOnly)
		if err == nil {
			return db, nil
		}
		if !isLockError(err) {
			return nil, err
		}
		holder, pid := holderOf(err)
		locked := &LockedError{Path: path, PID: pid, Holder: holder, Waited: waited, Budget: budget, ReadOnly: readOnly, Err: err}
		left := budget - waited
		if left <= 0 {
			return nil, locked
		}
		d := min(jitter(delay), left)
		if err := sleep(ctx, d); err != nil {
			return nil, fmt.Errorf("interrupted while waiting for the lock on %s held by %s: %w", path, holderLabel(holder, pid), err)
		}
		waited += d
		delay = min(delay*2, lockBackoffCap)
	}
}

func holderLabel(name string, pid int) string {
	switch {
	case name != "" && pid > 0:
		return fmt.Sprintf("%s (PID %d)", name, pid)
	case pid > 0:
		return fmt.Sprintf("PID %d", pid)
	case name != "":
		return name
	}
	return "another process"
}
