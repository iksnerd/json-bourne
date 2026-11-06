//go:build unix

package watchrun

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/runlock"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstatus"
	"github.com/iksnerd/json-bourne/internal/core"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// record writes a status record for the watcher called name whose last cycle ended
// endedAgo before now, every 5 minutes.
func record(t *testing.T, dir, name string, endedAgo time.Duration, pid int) {
	t.Helper()
	w := watchstatus.Writer{Path: filepath.Join(dir, File(StatusFile, name)), Name: name, PID: pid, Started: now.Add(-24 * time.Hour), Config: "config/hunt.yaml"}
	st := core.WatchStatus{Every: 5 * time.Minute, Window: time.Hour, TTL: 3 * time.Hour, Keep: 48 * time.Hour, Repeat: 30 * time.Minute, Updated: now.Add(-endedAgo)}
	if endedAgo >= 0 {
		st.Last = &core.WatchCycleSummary{Run: "watch-x", Verdict: "QUIET", Ended: now.Add(-endedAgo), Window: core.Window{From: now.Add(-endedAgo - time.Hour), To: now.Add(-endedAgo)}}
		st.NextDue = now.Add(-endedAgo + 5*time.Minute)
	}
	if err := w.Save(context.Background(), st); err != nil {
		t.Fatal(err)
	}
}

func hold(t *testing.T, dir, name string) {
	t.Helper()
	l, err := Acquire(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Release() })
}

func one(t *testing.T, dir string, name string) WatcherStatus {
	t.Helper()
	got, err := Status(dir, StatusOptions{Names: []string{name}, Now: now})
	if err != nil || len(got) != 1 {
		t.Fatalf("Status = %+v, %v", got, err)
	}
	return got[0]
}

func TestRunningIsLockHeldAndARecentCycle(t *testing.T) {
	dir := t.TempDir()
	hold(t, dir, "a") // held by this test process
	record(t, dir, "a", 2*time.Minute, os.Getpid())
	s := one(t, dir, "a")
	if s.State != StateRunning || !s.LockHeld || s.PID != os.Getpid() {
		t.Fatalf("status = %+v", s)
	}
	if s.Every != 5*time.Minute || s.Window != time.Hour || s.TTL != 3*time.Hour || s.Keep != 48*time.Hour || s.Repeat != 30*time.Minute || s.Config != "config/hunt.yaml" {
		t.Errorf("options = %+v", s)
	}
	if s.Last == nil || s.Last.Verdict != "QUIET" || !s.NextDue.Equal(now.Add(3*time.Minute)) {
		t.Errorf("cycle = %+v due %v", s.Last, s.NextDue)
	}
}

func TestStaleIsLockHeldButNoRecentCycle(t *testing.T) {
	dir := t.TempDir()
	hold(t, dir, "a")
	record(t, dir, "a", 16*time.Minute, os.Getpid()) // limit is 3 x 5m = 15m
	s := one(t, dir, "a")
	if s.State != StateStale || !strings.Contains(s.Reason, "15m0s") {
		t.Fatalf("status = %+v", s)
	}
	record(t, dir, "a", 15*time.Minute, os.Getpid()) // exactly at the limit is still alive
	if s := one(t, dir, "a"); s.State != StateRunning {
		t.Errorf("at the limit: %+v", s)
	}
}

func TestStaleBeforeTheFirstCycleCountsFromStart(t *testing.T) {
	dir := t.TempDir()
	hold(t, dir, "a")
	record(t, dir, "a", -1, os.Getpid()) // no cycle yet; started 24h ago
	if s := one(t, dir, "a"); s.State != StateStale {
		t.Errorf("status = %+v", s)
	}
}

func TestStoppedIsARecordAndNoLock(t *testing.T) {
	dir := t.TempDir()
	record(t, dir, "a", time.Minute, 999999)
	s := one(t, dir, "a")
	if s.State != StateStopped || s.LockHeld || s.PID != 999999 {
		t.Fatalf("status = %+v", s)
	}
	// A lock file left by a normal exit or by a kill is free, not held.
	l, _ := Acquire(dir, "a")
	l.Release()
	if s := one(t, dir, "a"); s.State != StateStopped {
		t.Errorf("after a released lock: %+v", s)
	}
}

func TestUnknownIsNoRecord(t *testing.T) {
	dir := t.TempDir()
	if s := one(t, dir, "a"); s.State != StateUnknown || s.LockHeld {
		t.Fatalf("nothing at all: %+v", s)
	}
	hold(t, dir, "b") // a watcher from a build without records holds only its lock
	s := one(t, dir, "b")
	if s.State != StateUnknown || !s.LockHeld || s.PID != os.Getpid() || !strings.Contains(s.Reason, "no status record") {
		t.Fatalf("lock without record: %+v", s)
	}
}

func TestAnUnreadableOrForeignRecordIsUnknownWithTheReason(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, File(StatusFile, "a")), []byte(`{"apiVersion":"jb.watch-status/v0"}`), 0o600)
	if s := one(t, dir, "a"); s.State != StateUnknown || !strings.Contains(s.Reason, "jb.watch-status/v0") {
		t.Errorf("old version: %+v", s)
	}
	// A record copied under another name is not that watcher's.
	record(t, dir, "b", time.Minute, 5)
	if err := os.Rename(filepath.Join(dir, File(StatusFile, "b")), filepath.Join(dir, File(StatusFile, "c"))); err != nil {
		t.Fatal(err)
	}
	if s := one(t, dir, "c"); s.State != StateUnknown || !strings.Contains(s.Reason, `"b"`) {
		t.Errorf("name mismatch: %+v", s)
	}
}

func TestStatusNeverTakesOrHoldsTheLock(t *testing.T) {
	dir := t.TempDir()
	record(t, dir, "a", time.Minute, 5)
	l, _ := Acquire(dir, "a")
	l.Release()
	if _, err := Status(dir, StatusOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	l, err := Acquire(dir, "a")
	if err != nil {
		t.Fatalf("a watcher could not start after status: %v", err)
	}
	l.Release()

	hold(t, dir, "b")
	if _, err := Status(dir, StatusOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir, "b"); err == nil {
		t.Error("the lock was granted twice")
	}
	if h, _ := runlock.Probe(filepath.Join(dir, File(LockFile, "b"))); !h.Held || h.PID != os.Getpid() {
		t.Errorf("status disturbed the holder: %+v", h)
	}
}

func TestStatusFindsEveryWatcherSortedAndSkipsOtherFiles(t *testing.T) {
	dir := t.TempDir()
	record(t, dir, "", time.Minute, 1)
	record(t, dir, "zeta", time.Minute, 2)
	hold(t, dir, "alpha")
	for _, f := range []string{"watch-state.json", "watch.log", "watch.Bad.lock", "watch-status.x.json.tmp-1", "watch..lock", "jb.duckdb"} {
		os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o600)
	}
	got, err := Status(dir, StatusOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range got {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != ",alpha,zeta" {
		t.Errorf("names = %q, want the unnamed watcher, then alpha, then zeta", names)
	}
}

func TestStatusOfAMissingEvidenceDirIsEmptyNotAnError(t *testing.T) {
	got, err := Status(filepath.Join(t.TempDir(), "none"), StatusOptions{Now: now})
	if err != nil || len(got) != 0 {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestConfigFilterKeepsOnlyWatchersOfThatConfig(t *testing.T) {
	dir := t.TempDir()
	record(t, dir, "a", time.Minute, 1)
	got, _ := Status(dir, StatusOptions{Now: now, Config: "config/other.yaml"})
	if len(got) != 0 {
		t.Errorf("filter kept %+v", got)
	}
	got, _ = Status(dir, StatusOptions{Now: now, Config: "config/hunt.yaml"})
	if len(got) != 1 {
		t.Errorf("filter dropped the match: %+v", got)
	}
}

func TestStatusRejectsAnInvalidName(t *testing.T) {
	if _, err := Status(t.TempDir(), StatusOptions{Names: []string{"../x"}}); err == nil {
		t.Error("a path as a name was accepted")
	}
}

func TestRelConfig(t *testing.T) {
	for _, c := range []struct{ dir, cfg, want string }{
		{"/case", "/case/config/hunt.yaml", "config/hunt.yaml"},
		{"/case", "/case/hunt.yaml", "hunt.yaml"},
		{"/case", "/elsewhere/hunt.yaml", ""},
		{"/case", "/case/../x.yaml", ""},
		{"", "/case/hunt.yaml", ""},
		{"/case", "", ""},
	} {
		if got := RelConfig(c.dir, c.cfg); got != c.want {
			t.Errorf("RelConfig(%q, %q) = %q, want %q", c.dir, c.cfg, got, c.want)
		}
	}
}

func TestNameFromIsTheInverseOfFile(t *testing.T) {
	for _, name := range []string{"", "a", "x_y-1"} {
		for _, unnamed := range []string{StateFile, LogFile, LockFile, StatusFile} {
			got, ok := NameFrom(unnamed, File(unnamed, name))
			if !ok || got != name {
				t.Errorf("NameFrom(%q, %q) = %q, %v", unnamed, File(unnamed, name), got, ok)
			}
		}
	}
	for _, bad := range []string{"watch.lock.bak", "watch..lock", "watch.A.lock", "other.a.lock", "watch.lock.tmp"} {
		if n, ok := NameFrom(LockFile, bad); ok {
			t.Errorf("NameFrom accepted %q as %q", bad, n)
		}
	}
}
