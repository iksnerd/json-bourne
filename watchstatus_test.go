//go:build unix

package jb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/watchstatus"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

func TestWatchStatusReadsTheRecordAndTheLockOfACase(t *testing.T) {
	dir := copyCase(t)
	evidence := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	end := now.Add(-2 * time.Minute)
	w := watchstatus.Writer{Path: filepath.Join(evidence, watchrun.File(watchrun.StatusFile, "edge")), Name: "edge", PID: os.Getpid(), Started: now.Add(-time.Hour), Config: "config/hunt.yaml"}
	err := w.Save(t.Context(), core.WatchStatus{Every: 5 * time.Minute, Window: time.Hour, TTL: time.Hour, Keep: 48 * time.Hour, Repeat: time.Hour, Updated: end,
		Last: &core.WatchCycleSummary{Run: "watch-edge-x", Verdict: "INCOMPLETE", Ended: end, Failed: []string{"source kibana:logs"}}})
	if err != nil {
		t.Fatal(err)
	}
	opts := WatchStatusOptions{Now: func() time.Time { return now }}

	got, err := WatchStatus(dir, opts)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if s := got[0]; s.Name != "edge" || s.State != WatcherStopped || s.Last == nil || s.Last.Verdict != "INCOMPLETE" {
		t.Errorf("no lock: %+v", s)
	}

	l, err := watchrun.Acquire(evidence, "edge")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	got, _ = WatchStatus(dir, opts)
	if got[0].State != WatcherRunning || got[0].PID != os.Getpid() || got[0].Last.Failed[0] != "source kibana:logs" {
		t.Errorf("lock held: %+v", got[0])
	}

	opts.Now = func() time.Time { return now.Add(time.Hour) }
	if got, _ = WatchStatus(dir, opts); got[0].State != WatcherStale {
		t.Errorf("an hour on: %+v", got[0])
	}

	if _, err := WatchStatus(filepath.Join(dir, "missing"), opts); err == nil {
		t.Error("a missing case was accepted")
	}
	if _, err := WatchStatus(dir, WatchStatusOptions{Config: "config/none.yaml"}); err == nil {
		t.Error("a config that is not the case's was accepted")
	}
}
