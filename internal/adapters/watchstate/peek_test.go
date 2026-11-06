package watchstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

func TestPeekReadsWithoutTouchingTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch-state.json")
	s := Store{Path: p}
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if err := s.Save(context.Background(), core.WatchState{
		Seen:   map[string]core.SeenTag{"spray:192.0.2.7": {At: at, Severity: core.SevHigh}},
		Health: map[string]core.HealthSeen{"kibana:logs": {At: at, Fingerprint: "f"}},
	}); err != nil {
		t.Fatal(err)
	}
	st, err := s.Peek(context.Background())
	if err != nil || st.Seen["spray:192.0.2.7"].Severity != core.SevHigh || st.Health["kibana:logs"].Fingerprint != "f" {
		t.Fatalf("%+v, %v", st, err)
	}
}

// Load moves a corrupt file aside, which is the writer's job. A viewer that did the
// same would destroy the evidence of what went wrong.
func TestPeekOfACorruptFileReportsItAndLeavesItInPlace(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch-state.json")
	os.WriteFile(p, []byte(`{"version":1,"seen":{"":{}}} junk`), 0o600)
	_, err := Store{Path: p}.Peek(context.Background())
	if !errors.Is(err, core.ErrStateCorrupt) {
		t.Fatalf("err = %v, want ErrStateCorrupt", err)
	}
	if _, serr := os.Stat(p); serr != nil {
		t.Errorf("Peek moved or removed the file: %v", serr)
	}
	if _, serr := os.Stat(p + ".corrupt"); serr == nil {
		t.Error("Peek wrote a .corrupt file")
	}
}

func TestPeekMissingIsAbsent(t *testing.T) {
	_, err := Store{Path: filepath.Join(t.TempDir(), "none.json")}.Peek(context.Background())
	if !errors.Is(err, core.ErrAbsent) {
		t.Fatalf("err = %v, want ErrAbsent", err)
	}
}
