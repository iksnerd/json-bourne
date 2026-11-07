// Package safefile reads operator-writable local files (watch state, watch status,
// the alert log) without trusting what the path points at. It opens with O_NONBLOCK
// so a FIFO or device cannot block the open, checks the opened descriptor is a
// regular file, and never reads more than a cap. Standard library only.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ErrNotRegular is wrapped when the path is a directory, FIFO, device or socket.
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge is wrapped when a file is over the caller's cap.
var ErrTooLarge = errors.New("file too large")

// Open opens path for reading and returns it with its fstat. The check is made on the
// descriptor, so the file cannot be swapped between check and use. The error from a
// missing file is the os error unchanged, so errors.Is(err, fs.ErrNotExist) works.
func Open(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- the caller owns the path; this package exists to distrust what it names
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: %w (%s)", path, ErrNotRegular, st.Mode().Type())
	}
	return f, st, nil
}

// ReadAll reads the regular file at path, failing with ErrTooLarge when it holds more
// than max bytes. It reads at most max+1 bytes whatever the size fstat claimed.
func ReadAll(path string, max int64) ([]byte, error) {
	f, st, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size() > max {
		return nil, fmt.Errorf("%s: %w: over %d bytes", path, ErrTooLarge, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: %w: over %d bytes", path, ErrTooLarge, max)
	}
	return b, nil
}
