package casefile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GuardStatus is the non-error answer of Guard. The zero value is not an answer.
type GuardStatus int

const (
	// GuardIgnored: the directory is inside a git work tree and git ignores it.
	GuardIgnored GuardStatus = iota + 1
	// GuardNotWorkTree: the directory is not inside a git work tree, so nothing can
	// be committed from it by accident. This is not the same as "ignored": the case
	// directory may later be put under git, and the guard must run again.
	GuardNotWorkTree
)

func (s GuardStatus) String() string {
	switch s {
	case GuardIgnored:
		return "ignored"
	case GuardNotWorkTree:
		return "not a git work tree"
	}
	return "unknown"
}

const probeName = ".jb-guard-probe"

// Guard answers whether dir (the evidence directory, which need not exist yet) is
// safe from `git add`. Inside a work tree, it is safe when git ignores it and tracks
// nothing in it except a .gitkeep. A directory git does not ignore is an error. An
// answer that cannot be read (git failed, git is missing but a .git exists above,
// output not understood) is an error, never a pass.
func Guard(dir string) (GuardStatus, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return 0, err
	}
	base := abs
	for {
		if st, err := os.Stat(base); err == nil && st.IsDir() {
			break
		}
		parent := filepath.Dir(base)
		if parent == base {
			return 0, fmt.Errorf("guard: no existing ancestor of %s", dir)
		}
		base = parent
	}
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return 0, fmt.Errorf("guard: %w", err)
	}
	rest, err := filepath.Rel(base, abs)
	if err != nil {
		return 0, err
	}
	target := filepath.Join(realBase, rest)

	if _, err := exec.LookPath("git"); err != nil {
		if hasDotGitAbove(realBase) {
			return 0, errors.New("guard: git is not installed but a .git exists above the evidence directory, so ignore rules cannot be checked")
		}
		return GuardNotWorkTree, nil
	}

	out, errOut, code, err := git(realBase, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return 0, err
	}
	switch {
	case code == 0 && out == "true":
	case code == 0:
		return 0, fmt.Errorf("guard: %s is inside a git directory, not a work tree", dir)
	case strings.Contains(errOut, "not a git repository"):
		return GuardNotWorkTree, nil
	default:
		return 0, fmt.Errorf("guard: git rev-parse failed (exit %d): %s", code, errOut)
	}

	_, errOut, code, err = git(realBase, "check-ignore", "-q", "--", filepath.Join(target, probeName))
	if err != nil {
		return 0, err
	}
	switch code {
	case 0:
	case 1:
		return 0, fmt.Errorf("guard: %s is not ignored by git; add it to .gitignore before any evidence goes there", dir)
	default:
		return 0, fmt.Errorf("guard: git check-ignore failed (exit %d): %s", code, errOut)
	}

	out, errOut, code, err = git(realBase, "ls-files", "-z", "--", target)
	if err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, fmt.Errorf("guard: git ls-files failed (exit %d): %s", code, errOut)
	}
	for _, f := range strings.Split(out, "\x00") {
		if f != "" && filepath.Base(f) != ".gitkeep" {
			return 0, fmt.Errorf("guard: git already tracks a file under %s; remove it from the index (git rm --cached)", dir)
		}
	}
	return GuardIgnored, nil
}

// git runs one git command in dir. An exit code is returned, not raised, so the
// caller decides what each code means; err is for failing to run git at all.
func git(dir string, args ...string) (stdout, stderr string, code int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...) // #nosec G204 -- fixed binary, fixed subcommands
	cmd.Env = append(cleanEnv(os.Environ()), "LC_ALL=C")
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	runErr := cmd.Run()
	stdout, stderr = strings.TrimSpace(o.String()), strings.TrimSpace(e.String())
	if len(stderr) > 300 {
		stderr = stderr[:300]
	}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
		return stdout, stderr, 0, nil
	case errors.As(runErr, &ee):
		return o.String(), stderr, ee.ExitCode(), nil
	default:
		return "", "", 0, fmt.Errorf("guard: run git: %w", runErr)
	}
}

// cleanEnv drops variables that would point git at some other repository.
func cleanEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		switch {
		case strings.HasPrefix(kv, "GIT_DIR="), strings.HasPrefix(kv, "GIT_WORK_TREE="), strings.HasPrefix(kv, "GIT_INDEX_FILE="):
		default:
			out = append(out, kv)
		}
	}
	return out
}

func hasDotGitAbove(dir string) bool {
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
