//go:build unix

package runlock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func acquire(path string, pid int) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- see readPID
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
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
