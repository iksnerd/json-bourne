// Package runlock keeps two copies of one long-running command from running together:
// an exclusive lock on a file, with the holder's PID written in it so that the loser can
// say who has it. It depends on the standard library only and sends nothing anywhere.
//
// On Unix the lock is flock(2) on the open file, so the kernel drops it when the holder
// exits for any reason, a crash and kill -9 included: a leftover file with a dead PID in
// it is not a held lock, and nothing has to guess whether a PID is alive. The file is
// never removed (removing a lock file another process has just opened would let two
// holders each lock a different inode). Elsewhere see lock_other.go.
package runlock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrHeld is matched (errors.Is) by the error Acquire returns when another process
// holds the lock.
var ErrHeld = errors.New("lock is held by another process")

// HeldError says which lock is held and by whom. PID is 0 when the holder's file could
// not be read (it is mid-write, or the holder predates the PID line).
type HeldError struct {
	Path string
	PID  int
}

func (e *HeldError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("%s is held by PID %d", e.Path, e.PID)
	}
	return fmt.Sprintf("%s is held by another process (its PID could not be read)", e.Path)
}

func (e *HeldError) Is(target error) bool { return target == ErrHeld }

// Lock is a held lock. Release it when the command ends; the OS also releases it if the
// process dies first.
type Lock struct {
	f    *os.File
	path string
}

// Path is the lock file.
func (l *Lock) Path() string { return l.path }

// Acquire takes the exclusive lock on path, creating the file (mode 0600) if needed, and
// records this process's PID in it. It never waits: a lock held by another process is an
// immediate *HeldError. The same process taking the same path twice is refused too.
func Acquire(path string) (*Lock, error) {
	return acquire(path, os.Getpid())
}

func readPID(path string) int {
	b, err := os.ReadFile(path) // #nosec G304 -- the lock path is built by the command from the case's evidence directory
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
