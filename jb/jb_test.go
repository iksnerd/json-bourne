package jb

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/watchrun"
)

func TestPlan(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 500, time.UTC)

	w, run, err := plan(now, HuntOptions{Window: time.Hour}, "hunt")
	if err != nil || run != "hunt-20261002T120000Z" || w.Duration() != time.Hour || !w.To.Equal(now.Truncate(time.Second)) {
		t.Fatalf("live: %v %q %v", w, run, err)
	}

	until := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	w, run, err = plan(now, HuntOptions{Window: 2 * time.Hour, Until: until}, "hunt")
	if err != nil || run != "hunt-until-20261001T000000Z-w7200s" || !w.To.Equal(until) {
		t.Fatalf("past: %v %q %v", w, run, err)
	}

	// Run ids (moved from cmd/jb when the planning became the library's only): a past
	// run cannot collide with a live one of the same second, windows of different
	// length ending together differ, and none can be reaped by watch retention.
	_, live, _ := plan(until, HuntOptions{Window: time.Hour}, "hunt")
	_, past1h, _ := plan(until.Add(time.Hour), HuntOptions{Window: time.Hour, Until: until}, "hunt")
	_, past24h, _ := plan(until.Add(time.Hour), HuntOptions{Window: 24 * time.Hour, Until: until}, "hunt")
	if live == past1h || past1h == past24h {
		t.Errorf("run ids collide: %q %q %q", live, past1h, past24h)
	}
	for _, p := range []string{"hunt", "search", "activity"} {
		_, id, _ := plan(until, HuntOptions{Window: time.Hour, Until: until}, p)
		if strings.HasPrefix(id, "watch-") {
			t.Errorf("%s run id would be reaped by watch retention", p)
		}
	}

	for name, o := range map[string]HuntOptions{
		"future":     {Window: time.Hour, Until: now.Add(time.Hour).Truncate(time.Second)},
		"fractional": {Window: time.Hour, Until: until.Add(time.Nanosecond)},
		"too long":   {Window: MaxHistoricalWindow + time.Second, Until: until},
	} {
		if _, _, err := plan(now, o, "hunt"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestHuntRefusesNilConfig(t *testing.T) {
	if _, err := Hunt(t.Context(), nil, HuntOptions{}); err == nil || !strings.Contains(err.Error(), "nil config") {
		t.Fatalf("got %v", err)
	}
}

// copyCase copies examples/case to a temp dir. It is not in a git work tree, which the
// evidence guard accepts (and notes), so no git is needed.
func copyCase(t *testing.T) string {
	t.Helper()
	src := "../examples/case"
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if e.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestHuntCaseStoresEvidenceInTheCaseAndIsNeverCleanWhenTheSourceIsDown(t *testing.T) {
	dir := copyCase(t)
	env := func(string) (string, bool) { return "k", true }
	res, err := HuntCase(t.Context(), dir, CaseHuntOptions{HuntOptions: HuntOptions{Env: env}})
	if res == nil {
		t.Fatalf("no result, err = %v", err)
	}
	if res.Complete() {
		t.Fatal("kibana.example.com does not exist: the hunt cannot be complete")
	}
	if _, serr := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); serr != nil {
		t.Errorf("the store is not under the case's evidence directory: %v", serr)
	}
}

func TestHuntCaseRefusesWhatTheCLIRefuses(t *testing.T) {
	if _, err := HuntCase(t.Context(), filepath.Join(t.TempDir(), "none"), CaseHuntOptions{}); err == nil {
		t.Error("a missing case was accepted")
	}
	dir := copyCase(t)
	if _, err := HuntCase(t.Context(), dir, CaseHuntOptions{Config: "../outside.yaml"}); err == nil || !strings.Contains(err.Error(), "config") {
		t.Errorf("a config outside the case: err = %v", err)
	}
}

func TestWatchOnceIsIncompleteNotQuietWhenTheSourceIsDown(t *testing.T) {
	dir := copyCase(t)
	var out strings.Builder
	rep, err := Watch(t.Context(), dir, WatchOptions{Once: true, Name: "t1", Out: &out,
		Env: func(string) (string, bool) { return "k", true }})
	if rep == nil {
		t.Fatalf("no report, err = %v", err)
	}
	if rep.Status.Healthy() || rep.Status == CycleQuiet {
		t.Fatalf("status = %s: a dead source must not read as quiet", rep.Status)
	}
	for _, f := range []string{"watch-state.t1.json", "watch.t1.log"} {
		if _, serr := os.Stat(filepath.Join(dir, "evidence", f)); serr != nil {
			t.Errorf("%s was not written in the evidence directory: %v", f, serr)
		}
	}
}

func TestWatchRefusesBadNamesAndTooShortWindows(t *testing.T) {
	dir := copyCase(t)
	if _, err := Watch(t.Context(), dir, WatchOptions{Name: "Bad Name!", Once: true}); err == nil {
		t.Error("a bad watcher name was accepted")
	}
	if _, err := Watch(t.Context(), dir, WatchOptions{Every: time.Hour, Window: time.Minute, Once: true}); err == nil {
		t.Error("a window shorter than the interval was accepted")
	}
}

func TestWatchRefusesASecondWatcherOfTheSameName(t *testing.T) {
	dir := copyCase(t)
	lock, err := watchrun.Acquire(filepath.Join(dir, "evidence"), "dup")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	_, err = Watch(t.Context(), dir, WatchOptions{Once: true, Name: "dup", Env: func(string) (string, bool) { return "k", true }})
	if !errors.Is(err, ErrWatcherRunning) {
		t.Fatalf("err = %v, want ErrWatcherRunning", err)
	}
}

func TestActivityIsIncompleteNotQuietWhenTheSourceIsDown(t *testing.T) {
	dir := copyCase(t)
	res, err := Activity(t.Context(), dir, ActivityOptions{Config: filepath.Join(dir, "config", "fingerprint.yaml"), Env: func(string) (string, bool) { return "k", true }})
	if res == nil {
		t.Fatalf("no result, err = %v", err)
	}
	if res.Verdict == VerdictQuiet {
		t.Fatal("a dead source must not read as QUIET")
	}
	if !strings.HasPrefix(res.Run, "activity-") {
		t.Errorf("run = %q", res.Run)
	}
}
