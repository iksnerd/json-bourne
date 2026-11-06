package watchstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

var at = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func sample() core.WatchState {
	return core.WatchState{Seen: map[string]core.SeenTag{
		"spray:192.0.2.7": {At: at, Severity: core.SevHigh},
		"sustained":       {At: at.Add(-time.Hour), Severity: core.SevCheck},
	}}
}

func TestRoundTrip(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "watch-state.json")}
	if err := s.Save(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Seen) != 2 || got.Seen["spray:192.0.2.7"] != (core.SeenTag{At: at, Severity: core.SevHigh}) {
		t.Errorf("got %+v", got)
	}
}

func TestMissingFileIsAColdStart(t *testing.T) {
	got, err := Store{Path: filepath.Join(t.TempDir(), "none.json")}.Load(context.Background())
	if err != nil || got.Seen == nil || len(got.Seen) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestStrictLoaderRejects(t *testing.T) {
	good := `{"version":1,"seen":{"t":{"at":"2026-11-05T12:00:00Z","severity":"high"}}}`
	cases := map[string]string{
		"unknown top field":   `{"version":1,"seen":{},"extra":1}`,
		"unknown entry field": `{"version":1,"seen":{"t":{"at":"2026-11-05T12:00:00Z","severity":"high","x":1}}}`,
		"trailing data":       good + `{"version":1,"seen":{}}`,
		"trailing garbage":    good + "\ngarbage",
		"wrong version":       `{"version":2,"seen":{}}`,
		"no version":          `{"seen":{}}`,
		"unknown severity":    `{"version":1,"seen":{"t":{"at":"2026-11-05T12:00:00Z","severity":"urgent"}}}`,
		"no time":             `{"version":1,"seen":{"t":{"severity":"high"}}}`,
		"empty tag":           `{"version":1,"seen":{"":{"at":"2026-11-05T12:00:00Z","severity":"high"}}}`,
		"not json":            `nope`,
		"empty file":          ``,
		"truncated":           good[:len(good)-10],
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "watch-state.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Store{Path: p}.Load(context.Background())
			if !errors.Is(err, core.ErrStateCorrupt) {
				t.Fatalf("err = %v, want ErrStateCorrupt", err)
			}
			// The bad file is kept for inspection, and is no longer in the way.
			if _, serr := os.Stat(p + ".corrupt"); serr != nil {
				t.Errorf("corrupt file not kept: %v", serr)
			}
		})
	}
	// And the control: the good document loads.
	p := filepath.Join(t.TempDir(), "s.json")
	_ = os.WriteFile(p, []byte(good), 0o600)
	if _, err := (Store{Path: p}).Load(context.Background()); err != nil {
		t.Fatalf("control document rejected: %v", err)
	}
}

// A reader running while saves happen must never see a half-written file.
func TestSaveIsAtomic(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "watch-state.json")}
	big := core.WatchState{Seen: map[string]core.SeenTag{}}
	for i := range 2000 {
		big.Seen[strings.Repeat("t", 40)+string(rune('a'+i%26))+time.Duration(i).String()] = core.SeenTag{At: at, Severity: core.SevHigh}
	}
	if err := s.Save(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := s.Save(context.Background(), big); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	for range 300 {
		if _, err := s.Load(context.Background()); err != nil {
			t.Errorf("reader saw a torn file: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
	entries, _ := os.ReadDir(filepath.Dir(s.Path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSaveFailureIsAnError(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "missing-dir", "watch-state.json")}
	if err := s.Save(context.Background(), sample()); err == nil {
		t.Fatal("Save into a missing directory reported success")
	}
}

func TestHealthRoundTripAndOldFilesLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watch-state.json")
	s := Store{Path: p}
	st := sample()
	st.Health = map[string]core.HealthSeen{"watch-incomplete|source x": {At: at, Fingerprint: "boom"}}
	if err := s.Save(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h := got.Health["watch-incomplete|source x"]; h.At != at || h.Fingerprint != "boom" {
		t.Errorf("health = %+v", got.Health)
	}
	// No open outage: the section is omitted, so the file is what an older build wrote.
	st.Health = nil
	if err := s.Save(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); strings.Contains(string(b), "health") {
		t.Errorf("empty health section written:\n%s", b)
	}
	// A file from before the section existed loads with no outages.
	old := `{"version":1,"seen":{"t":{"at":"2026-11-05T12:00:00Z","severity":"high"}}}`
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err = s.Load(context.Background()); err != nil || len(got.Health) != 0 || len(got.Seen) != 1 {
		t.Fatalf("old file: %+v, %v", got, err)
	}
	for name, bad := range map[string]string{
		"health no time":   `{"version":1,"seen":{},"health":{"k":{"fingerprint":"x"}}}`,
		"health empty key": `{"version":1,"seen":{},"health":{"":{"at":"2026-11-05T12:00:00Z","fingerprint":"x"}}}`,
	} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(context.Background()); !errors.Is(err, core.ErrStateCorrupt) {
			t.Errorf("%s: err = %v, want ErrStateCorrupt", name, err)
		}
	}
}
