//go:build unix

package runlock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/iksnerd/json-bourne/internal/safefile"
)

// A probe (Probe) holds a shared lock for an instant, which refuses an exclusive request
// made in that instant. Acquire asks again a few times before it calls the lock held.
const (
	acquireTries = 4
	acquireWait  = 10 * time.Millisecond
)

func probe(path string) (Holder, error) {
	// safefile.Open opens with O_NONBLOCK and refuses anything but a regular file, so a
	// FIFO at the path cannot block the open. flock works on its read-only descriptor.
	f, _, err := safefile.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Holder{}, nil
	}
	if err != nil {
		return Holder{}, fmt.Errorf("open lock file: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return Holder{Held: true, PID: readPID(path)}, nil
		}
		return Holder{}, fmt.Errorf("probe %s: %w", path, err)
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return Holder{}, nil
}

func acquire(path string, pid int) (*Lock, error) {
	// The lock needs a read-write descriptor (the PID is written through it) and may
	// create the file, which safefile.Open (read-only, never creates) cannot do. So it
	// does the same two things itself: O_NONBLOCK, so opening a FIFO cannot block, and an
	// fstat of the opened descriptor, so the lock is only ever taken on a regular file.
	// O_NONBLOCK does nothing to a regular file's later reads, writes or flock.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NONBLOCK, 0o600) // #nosec G304 -- see readPID
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if st, err := f.Stat(); err != nil {
		f.Close()
		return nil, fmt.Errorf("open lock file: %w", err)
	} else if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("open lock file: %s: %w (%s)", path, safefile.ErrNotRegular, st.Mode().Type())
	}
	var err2 error
	for try := 0; try < acquireTries; try++ {
		if err2 = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err2 != syscall.EWOULDBLOCK {
			break
		}
		time.Sleep(acquireWait)
	}
	if err := err2; err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &HeldError{Path: path, PID: readPID(path)}
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	// Ours now. Replace whatever PID a previous holder left.
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, fmt.Errorf("write lock file: %w", err)
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(pid)+"\n"), 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("write lock file: %w", err)
	}
	return &Lock{f: f, path: path}, nil
}

// Release drops the lock and empties the file, so a later reader does not see a PID
// that no longer holds anything. It is safe to call twice.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	terr := f.Truncate(0) // while still locked, so no new holder's PID is erased
	return errors.Join(terr, f.Close())
}
