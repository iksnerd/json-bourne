//go:build unix

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/watchstatus"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

type statusOut struct {
	Watchers []struct {
		Name         string `json:"name"`
		State        string `json:"state"`
		Reason       string `json:"reason"`
		LockHeld     bool   `json:"lockHeld"`
		PID          int    `json:"pid"`
		Config       string `json:"config"`
		EverySeconds int64  `json:"everySeconds"`
		LastCycle    *struct {
			Verdict string `json:"verdict"`
			Run     string `json:"run"`
		} `json:"lastCycle"`
		NextDue string `json:"nextDue"`
	} `json:"watchers"`
}

func statusJSON(t *testing.T, d deps, dir string, extra ...string) statusOut {
	t.Helper()
	args := append([]string{"watch", "status", "--case", dir, "--output", "json"}, extra...)
	code, stdout, stderr := run(t, d, args...)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var out statusOut
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	return out
}

// A real cycle against the fake Kibana writes the record, and `status` reads it back.
func TestWatchOnceWritesTheStatusRecordAndStatusReadsIt(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	if code, stdout, stderr := run(t, d, "watch", "--case", dir, "--once", "--name", "edge"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	rec, err := watchstatus.Read(filepath.Join(dir, "evidence", "watch-status.edge.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "edge" || rec.PID != os.Getpid() || rec.Config != "config/hunt.yaml" || rec.EverySeconds != 300 ||
		rec.LastCycle == nil || rec.LastCycle.Verdict != "FINDINGS" || rec.LastCycle.New != 1 || !rec.LastCycle.Ended.Equal(fixedNow) {
		t.Fatalf("record = %+v", rec)
	}
	if !rec.NextDue.IsZero() {
		t.Errorf("a --once run has no next cycle, got %v", rec.NextDue)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "evidence", "watch-status.edge.json")); strings.Contains(string(b), secretKey) {
		t.Error("credential in the record")
	}

	// The process has ended: a record and no lock is stopped.
	out := statusJSON(t, d, dir)
	if len(out.Watchers) != 1 {
		t.Fatalf("watchers = %+v", out.Watchers)
	}
	w := out.Watchers[0]
	if w.Name != "edge" || w.State != "stopped" || w.LockHeld || w.LastCycle == nil || w.LastCycle.Verdict != "FINDINGS" || w.Config != "config/hunt.yaml" {
		t.Errorf("watcher = %+v", w)
	}

	// An incomplete cycle is said so in the record, not hidden.
	dir2, _ := watchCase(t, http.StatusBadGateway)
	run(t, d, "watch", "--case", dir2, "--once")
	out = statusJSON(t, d, dir2, "--name", "")
	if len(out.Watchers) != 1 || out.Watchers[0].LastCycle == nil || out.Watchers[0].LastCycle.Verdict != "INCOMPLETE" {
		t.Errorf("incomplete cycle: %+v", out.Watchers)
	}
}

func TestWatchStatusReportsRunningStaleAndUnknownTogether(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	evidence := filepath.Join(dir, "evidence")
	os.MkdirAll(evidence, 0o700)
	d := testDeps(huntEnv)
	save := func(name string, endedAgo time.Duration) {
		w := watchstatus.Writer{Path: filepath.Join(evidence, watchrun.File(watchrun.StatusFile, name)), Name: name, PID: os.Getpid(), Started: fixedNow.Add(-24 * time.Hour), Config: "config/hunt.yaml"}
		end := fixedNow.Add(-endedAgo)
		err := w.Save(context.Background(), core.WatchStatus{Every: 5 * time.Minute, Window: time.Hour, TTL: time.Hour, Keep: 48 * time.Hour, Repeat: time.Hour,
			Updated: end, NextDue: end.Add(5 * time.Minute),
			Last: &core.WatchCycleSummary{Run: "watch-" + name, Verdict: "QUIET", Ended: end}})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"live", "hung"} {
		l, err := watchrun.Acquire(evidence, name)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Release()
	}
	save("live", time.Minute)
	save("hung", time.Hour)
	l, _ := watchrun.Acquire(evidence, "old") // a build without records: lock only
	defer l.Release()

	got := map[string]string{}
	for _, w := range statusJSON(t, d, dir).Watchers {
		got[w.Name] = w.State
	}
	want := map[string]string{"live": "running", "hung": "stale", "old": "unknown"}
	for n, s := range want {
		if got[n] != s {
			t.Errorf("%s = %q, want %q (all: %v)", n, got[n], s, got)
		}
	}

	code, stdout, stderr := run(t, d, "watch", "status", "--case", dir)
	if code != 0 {
		t.Fatalf("table: exit %d: %s", code, stderr)
	}
	for _, s := range []string{"NAME", "STATE", "running", "stale", "unknown", "live", "hung", "old", "QUIET"} {
		if !strings.Contains(stdout, s) {
			t.Errorf("table lacks %q:\n%s", s, stdout)
		}
	}
	if only := statusJSON(t, d, dir, "--name", "live"); len(only.Watchers) != 1 || only.Watchers[0].Name != "live" {
		t.Errorf("--name live: %+v", only.Watchers)
	}
	if none := statusJSON(t, d, dir, "--config", "config/hunt.yaml", "--name", "old"); len(none.Watchers) != 0 {
		t.Errorf("--config filtered in a watcher with no record: %+v", none.Watchers)
	}
}

func TestWatchStatusNeverDisturbsARunningWatcher(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	evidence := filepath.Join(dir, "evidence")
	os.MkdirAll(evidence, 0o700)
	l, err := watchrun.Acquire(evidence, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	statusJSON(t, testDeps(huntEnv), dir)
	if _, err := watchrun.Acquire(evidence, "a"); err == nil {
		t.Error("status released the lock")
	}
}

func TestWatchStatusUsageErrors(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	for name, args := range map[string][]string{
		"no case":        {"watch", "status"},
		"bad output":     {"watch", "status", "--case", dir, "--output", "xml"},
		"bad name":       {"watch", "status", "--case", dir, "--name", "../x"},
		"unknown config": {"watch", "status", "--case", dir, "--config", "config/none.yaml"},
		"an argument":    {"watch", "status", "--case", dir, "extra"},
	} {
		if code, _, stderr := run(t, d, args...); code != exitUsage {
			t.Errorf("%s: exit %d, want %d (%s)", name, code, exitUsage, stderr)
		}
	}
	if code, _, _ := run(t, d, "watch", "status", "--case", filepath.Join(dir, "missing")); code == 0 {
		t.Error("a missing case succeeded")
	}
}

func TestWatchStatusOfACaseWithNoWatcherSaysSo(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	code, stdout, _ := run(t, d, "watch", "status", "--case", dir)
	if code != 0 || !strings.Contains(stdout, "no watcher") {
		t.Errorf("exit %d: %q", code, stdout)
	}
	if out := statusJSON(t, d, dir); out.Watchers == nil || len(out.Watchers) != 0 {
		t.Errorf("json watchers = %#v, want an empty array", out.Watchers)
	}
}
