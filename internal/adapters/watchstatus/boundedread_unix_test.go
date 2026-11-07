//go:build unix

package watchstatus

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/safefile"
)

func TestReadRefusesFIFOHugeFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	huge := filepath.Join(dir, "huge")
	f, err := os.Create(huge)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxRecordBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := Read(fifo); !errors.Is(err, safefile.ErrNotRegular) {
			t.Errorf("fifo: %v", err)
		}
		if _, err := Read(dir); !errors.Is(err, safefile.ErrNotRegular) {
			t.Errorf("dir: %v", err)
		}
		if _, err := Read(huge); !errors.Is(err, safefile.ErrTooLarge) {
			t.Errorf("huge: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("blocked")
	}
}
