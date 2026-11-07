//go:build unix

package alertlog

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTailAndReadTailRefuseFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := (Tailer{Path: fifo}).Tail(context.Background(), 5); err == nil {
			t.Error("Tail read a FIFO")
		}
		if _, _, err := ReadTail(context.Background(), fifo, 1024); err == nil {
			t.Error("ReadTail read a FIFO")
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("blocked")
	}
}
