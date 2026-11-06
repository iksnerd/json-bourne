package jb

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlan(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 500, time.UTC)

	w, run, err := plan(now, HuntOptions{Window: time.Hour})
	if err != nil || run != "hunt-20261002T120000Z" || w.Duration() != time.Hour || !w.To.Equal(now.Truncate(time.Second)) {
		t.Fatalf("live: %v %q %v", w, run, err)
	}

	until := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	w, run, err = plan(now, HuntOptions{Window: 2 * time.Hour, Until: until})
	if err != nil || run != "hunt-until-20261001T000000Z-w7200s" || !w.To.Equal(until) {
		t.Fatalf("past: %v %q %v", w, run, err)
	}

	for name, o := range map[string]HuntOptions{
		"future":     {Window: time.Hour, Until: now.Add(time.Hour).Truncate(time.Second)},
		"fractional": {Window: time.Hour, Until: until.Add(time.Nanosecond)},
		"too long":   {Window: MaxHistoricalWindow + time.Second, Until: until},
	} {
		if _, _, err := plan(now, o); err == nil {
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
	src := "examples/case"
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
