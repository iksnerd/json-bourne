package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// chooseFixture copies examples/case into <root>/case and returns the loaded case and
// <root>, which is outside the case. config/fingerprint.yaml exists but is not listed.
func chooseFixture(t *testing.T) (c *casefile.Case, root string) {
	t.Helper()
	src := filepath.Join("..", "..", "examples", "case")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "case")
	err = filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
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
	if c, err = casefile.Load(dst); err != nil {
		t.Fatal(err)
	}
	return c, root
}

func writeFile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("sources: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChooseCaseConfigRelativeToTheCase(t *testing.T) {
	c, root := chooseFixture(t)
	draft := filepath.Join(c.Dir, "config", "drafts", "x.yaml")
	writeFile(t, draft)
	// A working directory that is not the case and has no such file.
	t.Chdir(root)

	for _, flag := range []string{"config/drafts/x.yaml", "./config/drafts/x.yaml", "config/../config/drafts/x.yaml", draft} {
		got, err := ChooseCaseConfig(c, flag, "hunt")
		if err != nil || got != draft {
			t.Errorf("--config %q = %q, %v; want %q", flag, got, err, draft)
		}
	}
	// A listed entry still works from anywhere, and an unlisted file next to it too.
	if got, err := ChooseCaseConfig(c, "config/hunt.yaml", "hunt"); err != nil || got != filepath.Join(c.Dir, "config", "hunt.yaml") {
		t.Errorf("listed entry = %q, %v", got, err)
	}
	if got, err := ChooseCaseConfig(c, "config/fingerprint.yaml", "hunt"); err != nil || got != filepath.Join(c.Dir, "config", "fingerprint.yaml") {
		t.Errorf("unlisted file = %q, %v", got, err)
	}
}

func TestChooseCaseConfigFallsBackToTheWorkingDirectory(t *testing.T) {
	c, _ := chooseFixture(t)
	draft := filepath.Join(c.Dir, "config", "drafts", "x.yaml")
	writeFile(t, draft)
	t.Chdir(filepath.Join(c.Dir, "config", "drafts"))

	// Not at <case>/x.yaml, but at ./x.yaml, which is inside the case.
	got, err := ChooseCaseConfig(c, "x.yaml", "hunt")
	if err != nil || got != draft {
		t.Errorf("--config x.yaml = %q, %v; want %q", got, err, draft)
	}
	// The case directory wins when both exist.
	writeFile(t, filepath.Join(c.Dir, "x.yaml"))
	if got, err = ChooseCaseConfig(c, "x.yaml", "hunt"); err != nil || got != filepath.Join(c.Dir, "x.yaml") {
		t.Errorf("both exist: --config x.yaml = %q, %v; want the case's", got, err)
	}
}

func TestChooseCaseConfigRefusesWhatLeavesTheCase(t *testing.T) {
	c, root := chooseFixture(t)
	outside := filepath.Join(root, "outside.yaml")
	writeFile(t, outside)
	writeFile(t, filepath.Join(root, "elsewhere", "only-here.yaml"))
	if err := os.Symlink(outside, filepath.Join(c.Dir, "config", "link.yaml")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	tests := []struct{ name, cwd, flag string }{
		{"dotdot out of the case", root, "../outside.yaml"},
		{"dotdot out of the case from inside it", c.Dir, "config/../../outside.yaml"},
		{"absolute outside", root, outside},
		{"symlink inside the case to a file outside", root, "config/link.yaml"},
		{"working-directory file outside the case", filepath.Join(root, "elsewhere"), "only-here.yaml"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(tc.cwd)
			got, err := ChooseCaseConfig(c, tc.flag, "hunt")
			if !core.IsUsage(err) || !strings.Contains(err.Error(), "outside the case directory") {
				t.Errorf("--config %q = %q, %v; want the outside-the-case usage error", tc.flag, got, err)
			}
		})
	}
}

func TestChooseCaseConfigNotFoundNamesBothPlaces(t *testing.T) {
	c, root := chooseFixture(t)
	t.Chdir(root)
	_, err := ChooseCaseConfig(c, "config/nope.yaml", "hunt")
	if !core.IsUsage(err) {
		t.Fatalf("err = %v, want a usage error", err)
	}
	for _, want := range []string{"not one of the case's configs", c.Dir, root} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestPlanCaseAcceptsARelativeConfigInsideTheCase(t *testing.T) {
	c, root := chooseFixture(t)
	writeFile(t, filepath.Join(c.Dir, "config", "drafts", "x.yaml"))
	t.Chdir(root)
	p, err := PlanCase(c.Dir, "config/drafts/x.yaml", "hunt", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(c.Dir, "config", "drafts", "x.yaml"); p.ConfigPath != want {
		t.Errorf("ConfigPath = %q, want %q", p.ConfigPath, want)
	}
}
