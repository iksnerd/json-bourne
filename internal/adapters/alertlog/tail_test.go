package alertlog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func TestTailReturnsLastLinesAndNeverMoreThanAsked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch.log")
	var b strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	os.WriteFile(p, []byte(b.String()), 0o600)
	got, err := Tailer{Path: p}.Tail(context.Background(), 3)
	if err != nil || strings.Join(got, "|") != "line 7|line 8|line 9" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestTailReadsOnlyTheEndOfAHugeFileAndDropsThePartialLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch.log")
	big := strings.Repeat("x", 3*maxTailBytes) + "\nlast one\n"
	os.WriteFile(p, []byte(big), 0o600)
	got, err := Tailer{Path: p}.Tail(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range got {
		if len(l) > maxTailBytes {
			t.Errorf("returned a %d byte line from a bounded read", len(l))
		}
	}
	if got[len(got)-1] != "last one" {
		t.Errorf("got %v", got)
	}
}

func TestTailMissingIsAbsentEmptyIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := (Tailer{Path: filepath.Join(dir, "none")}).Tail(context.Background(), 5); !errors.Is(err, core.ErrAbsent) {
		t.Errorf("err = %v, want ErrAbsent", err)
	}
	p := filepath.Join(dir, "empty")
	os.WriteFile(p, nil, 0o600)
	got, err := Tailer{Path: p}.Tail(context.Background(), 5)
	if err != nil || len(got) != 0 {
		t.Errorf("empty file: %v, %v", got, err)
	}
}
