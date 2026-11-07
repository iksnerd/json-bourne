package alertlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
)

// MaxTailBytes bounds how much of the end of the log one read takes.
const MaxTailBytes = 256 << 10

const maxTailBytes = MaxTailBytes

// Tailer reads the end of the alert log for a viewer. It only reads.
type Tailer struct{ Path string }

var _ core.LogTailer = Tailer{}

// Tail returns the last n lines, oldest first, reading at most maxTailBytes from the
// end of the file. A line cut by that bound is dropped, not shown half. Lines are
// returned as written (the writer escapes control characters); they are still log
// content and the caller must escape them for its medium.
func (t Tailer) Tail(ctx context.Context, n int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(t.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no alert log at %s", core.ErrAbsent, t.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("alert log: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("alert log: %w", err)
	}
	off := int64(0)
	if st.Size() > maxTailBytes {
		off = st.Size() - maxTailBytes
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("alert log: %w", err)
	}
	if off > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			buf = nil
		}
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// ReadTail returns the lines of the last max bytes of the file at path, oldest first,
// and whether the file was larger than that (cut: earlier lines exist and are not
// returned). A line cut by the bound is dropped, not shown half. Only a regular file
// is read. ErrAbsent (wrapped) when there is no file. Lines are log content and the
// caller must treat them as untrusted.
func ReadTail(ctx context.Context, path string, max int64) (lines []string, cut bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("%w: no alert log at %s", core.ErrAbsent, path)
	}
	if err != nil {
		return nil, false, fmt.Errorf("alert log: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("alert log: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("alert log %s is not a regular file", path)
	}
	off := int64(0)
	if st.Size() > max {
		off, cut = st.Size()-max, true
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("alert log: %w", err)
	}
	if cut {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			buf = nil
		}
	}
	if len(buf) == 0 {
		return nil, cut, nil
	}
	return strings.Split(strings.TrimRight(string(buf), "\n"), "\n"), cut, nil
}
