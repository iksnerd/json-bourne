package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

// UsageError marks an error caused by how a case was asked for (no config named, a
// config outside the case) rather than by what was found. The CLI exits 2 on it.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func usagef(format string, a ...any) error { return &UsageError{Msg: fmt.Sprintf(format, a...)} }

// CasePlan is what a hunt takes from a case once it has passed the checks.
type CasePlan struct {
	Case       *casefile.Case
	ConfigPath string        // absolute path of the chosen hunt config
	Window     time.Duration // zero: the case gave none, keep the caller's value
	// Notes are advice lines for the operator, in order. The CLI prints them to stderr;
	// the library returns them to the caller that asked.
	Notes []string
}

// PlanCase loads the case, refuses when the evidence guard fails, and chooses the
// config and the default window. Nothing here reads the environment or evidence/.
// windowSet says the caller already has a window, so the case's default is not used.
func PlanCase(dir, cfgFlag string, windowSet bool) (*CasePlan, error) {
	c, err := casefile.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("case %s: %w", dir, err)
	}
	st, err := casefile.Guard(c.EvidenceDir())
	if err != nil {
		return nil, fmt.Errorf("refusing to hunt case %s: %s", c.ID, err.Error())
	}
	p := &CasePlan{Case: c}
	if st.String() == casefile.GuardNotWorkTree.String() {
		p.Notes = append(p.Notes, fmt.Sprintf("note: case %s is not in a git work tree, so evidence cannot be committed by accident yet; run `jb case check` again if it is put under git", c.ID))
	}
	if p.ConfigPath, err = ChooseCaseConfig(c, cfgFlag); err != nil {
		return nil, err
	}
	if !windowSet {
		w, ok, err := CaseWindow(c, casefile.DefaultWindowName)
		if err != nil {
			return nil, err
		}
		if ok {
			p.Window = w
			p.Notes = append(p.Notes, fmt.Sprintf("window %s from the case (windows.%s)", c.Windows[casefile.DefaultWindowName], casefile.DefaultWindowName))
		}
	}
	return p, nil
}

// CaseWindow returns the named window of the case, parsed. ok is false when the case
// does not define it.
func CaseWindow(c *casefile.Case, name string) (time.Duration, bool, error) {
	v, ok := c.Windows[name]
	if !ok {
		return 0, false, nil
	}
	d, err := ParseWindow(v)
	if err != nil {
		return 0, false, fmt.Errorf("windows.%s: %w", name, err)
	}
	return d, true, nil
}

// ParseWindow parses a Go duration, or whole days written like "7d".
func ParseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("window is empty")
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("window %q: days must be a whole number of at least 1", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("window %q: %w", s, err)
	}
	return d, nil
}

// ChooseCaseConfig returns the absolute path of the hunt config to use. flag names one
// of the case's configs, or a file inside the case; empty means the case's only config.
// A relative flag that is not a listed entry is looked for in the case directory, then
// in the working directory; the real path (symlinks followed) must be inside the case.
func ChooseCaseConfig(c *casefile.Case, flag string) (string, error) {
	abs := func(rel string) string { return filepath.Join(c.Dir, filepath.FromSlash(rel)) }
	if flag == "" {
		switch len(c.Config) {
		case 0:
			return "", usagef("case %s lists no config: pass --config FILE (a file inside the case)", c.ID)
		case 1:
			return abs(c.Config[0]), nil
		}
		return "", usagef("case %s lists %d configs, pass --config with one of: %s", c.ID, len(c.Config), strings.Join(c.Config, ", "))
	}
	clean := path.Clean(filepath.ToSlash(flag))
	for _, rel := range c.Config {
		if path.Clean(rel) == clean {
			return abs(rel), nil
		}
	}
	// Not a listed entry: accept a file that resolves inside the case directory. A
	// relative path is tried against the case directory first, then the working
	// directory; either way the resolved real path must be inside the case.
	candidates := []string{flag}
	where := "the path as given"
	if !filepath.IsAbs(flag) {
		candidates = []string{filepath.Join(c.Dir, flag), flag}
		where = fmt.Sprintf("the case directory %s and the working directory", c.Dir)
		if wd, err := os.Getwd(); err == nil {
			where += " " + wd
		}
	}
	var real string
	var err error
	for _, cand := range candidates {
		if cand, err = filepath.Abs(cand); err != nil {
			continue
		}
		if real, err = filepath.EvalSymlinks(cand); err == nil {
			break
		}
	}
	if err != nil {
		return "", usagef("--config %q is not one of the case's configs (%s) and is not a readable file (looked in %s)", flag, strings.Join(c.Config, ", "), where)
	}
	root, err := filepath.EvalSymlinks(c.Dir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", usagef("--config %q is outside the case directory: a case hunts with its own configs only", flag)
	}
	return real, nil
}

// PlaceCaseStore decides where the evidence database goes. An empty store.path means
// <case>/<paths.evidence>/jb.duckdb, which the guard has just shown to be ignored by
// git; JB_DB is not consulted, because a case keeps its evidence with itself. A
// relative path is relative to the case directory. It returns a note when the store
// ends up outside the evidence directory, where the git ignore check does not reach.
func PlaceCaseStore(c *casefile.Case, cfg *File) (note string) {
	evidence := c.EvidenceDir()
	switch sp := cfg.Store.Path; {
	case sp == "":
		cfg.Store.Path = filepath.Join(evidence, "jb.duckdb")
	case strings.HasPrefix(sp, "~/") || filepath.IsAbs(sp):
	default:
		cfg.Store.Path = filepath.Join(c.Dir, sp)
	}
	if got := cfg.StorePath(); !InsideDir(evidence, got) {
		return fmt.Sprintf("note: the store %s is outside the case's evidence directory, so git ignore rules for it are not checked", got)
	}
	return ""
}

// InsideDir reports whether p is inside dir, following symlinks in the directories.
func InsideDir(dir, p string) bool {
	if d, err := filepath.EvalSymlinks(dir); err == nil {
		dir = d
	}
	if d, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		p = filepath.Join(d, filepath.Base(p))
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
