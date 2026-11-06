//go:build !unix

package runlock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Without flock the lock is the file itself: created exclusively (O_EXCL) with the PID
// in it, and removed on Release. A crash leaves the file behind, and the next Acquire
// cannot tell a dead holder from a live one on this platform, so it refuses and names
// the PID; the operator removes the file once they have checked that process is gone.
// This is the weaker half of the contract and is not exercised by the Unix tests.
func acquire(path string, pid int) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- see readPID
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, &HeldError{Path: path, PID: readPID(path)}
		}
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if _, err := f.WriteString(strconv.Itoa(pid) + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write lock file: %w", err)
	}
	return &Lock{f: f, path: path}, nil
}

// Release closes and removes the lock file. It is safe to call twice.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	return errors.Join(f.Close(), os.Remove(l.path))
}

// probe cannot tell a dead holder from a live one here: a lock file that exists is held.
func probe(path string) (Holder, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return Holder{}, nil
	} else if err != nil {
		return Holder{}, fmt.Errorf("stat lock file: %w", err)
	}
	return Holder{Held: true, PID: readPID(path)}, nil
}
