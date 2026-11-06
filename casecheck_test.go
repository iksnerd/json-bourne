package jb

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitInit(t *testing.T, dir string) {
	t.Helper()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git init: %v: %s", err, out)
	}
}

func TestCaseCheckPassesTheExampleCase(t *testing.T) {
	r, err := CaseCheck("examples/case")
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.ID != "example-login-spray" || r.Guard == nil || !r.Guard.OK {
		t.Fatalf("result = %+v", r)
	}
	if r.Actors == nil || !r.Actors.OK || len(r.Actors.IDs) != 1 || r.Estate == nil || !r.Estate.OK {
		t.Errorf("actors %+v estate %+v", r.Actors, r.Estate)
	}
	if len(r.Configs) != 2 || r.Configs[0].Path != "config/hunt.yaml" || !r.Configs[0].OK {
		t.Errorf("configs = %+v", r.Configs)
	}
}

func TestCaseCheckPutsAProblemInTheResultNotInTheError(t *testing.T) {
	dir := copyCase(t)
	p := filepath.Join(dir, "case.yaml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "passive_only: true", "passive_only: false", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := CaseCheck(dir)
	if err != nil {
		t.Fatalf("a bad case is a result, got error %v", err)
	}
	if r.OK || !strings.Contains(r.Error, "passive_only") || r.FirstProblem() != r.Error || r.Complete() {
		t.Errorf("result = %+v", r)
	}
	out, _ := json.Marshal(r)
	if !strings.Contains(string(out), `"configs":[]`) {
		t.Errorf("configs must marshal as [], got %s", out)
	}
}

func TestCaseCheckRefusesAnEmptyDirectoryAsAUsageError(t *testing.T) {
	if _, err := CaseCheck(""); !IsUsage(err) {
		t.Errorf("err = %v, want a usage error", err)
	}
}

// The evidence git guard: ignored passes and is complete; exposed fails; outside git passes
// but is not complete, because it says nothing about later.
func TestCaseCheckRunsTheEvidenceGitGuard(t *testing.T) {
	dir := copyCase(t)
	r, err := CaseCheck(dir)
	if err != nil || !r.OK || r.Guard.Result != "not a git work tree" || r.Complete() {
		t.Fatalf("outside git: %+v, %v", r, err)
	}
	gitInit(t, dir)
	if r, _ = CaseCheck(dir); !r.OK || r.Guard.Result != "ignored" || !r.Complete() {
		t.Fatalf("ignored: %+v", r)
	}
	if err := os.Remove(filepath.Join(dir, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	r, _ = CaseCheck(dir)
	if r.OK || r.Guard.OK || r.Guard.Error == "" || r.FirstProblem() != r.Guard.Error {
		t.Fatalf("exposed: %+v", r)
	}
}
