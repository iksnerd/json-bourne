package main

import (
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
)

// casePlan is what `jb hunt --case` takes from a case once it has passed the checks.
type casePlan struct {
	c          *casefile.Case
	configPath string        // absolute path of the chosen hunt config
	window     time.Duration // zero: the case gave none, keep the flag's value
}

// planCase loads the case, refuses when the evidence guard fails, and chooses the
// config and the default window. Nothing here reads the environment or evidence/.
func planCase(stderr io.Writer, dir, cfgFlag string, windowSet bool) (*casePlan, error) {
	c, g, err := inspectCase(dir)
	if err != nil {
		return nil, fmt.Errorf("case %s: %w", dir, err)
	}
	if !g.OK {
		return nil, fmt.Errorf("refusing to hunt case %s: %s", c.ID, g.Error)
	}
	if g.Result == casefile.GuardNotWorkTree.String() {
		fmt.Fprintf(stderr, "note: case %s is not in a git work tree, so evidence cannot be committed by accident yet; run `jb case check` again if it is put under git\n", c.ID)
	}
	cfg, err := chooseCaseConfig(c, cfgFlag)
	if err != nil {
		return nil, err
	}
	p := &casePlan{c: c, configPath: cfg}
	if !windowSet {
		w, ok, err := caseWindow(c, casefile.DefaultWindowName)
		if err != nil {
			return nil, err
		}
		if ok {
			p.window = w
			fmt.Fprintf(stderr, "window %s from the case (windows.%s)\n", c.Windows[casefile.DefaultWindowName], casefile.DefaultWindowName)
		}
	}
	return p, nil
}

// chooseCaseConfig returns the absolute path of the hunt config to use.
func chooseCaseConfig(c *casefile.Case, flag string) (string, error) {
	abs := func(rel string) string { return filepath.Join(c.Dir, filepath.FromSlash(rel)) }
	if flag == "" {
		switch len(c.Config) {
		case 0:
			return "", usageErrorf("case %s lists no config: pass --config FILE (a file inside the case)", c.ID)
		case 1:
			return abs(c.Config[0]), nil
		}
		return "", usageErrorf("case %s lists %d configs, pass --config with one of: %s", c.ID, len(c.Config), strings.Join(c.Config, ", "))
	}
	clean := path.Clean(filepath.ToSlash(flag))
	for _, rel := range c.Config {
		if path.Clean(rel) == clean {
			return abs(rel), nil
		}
	}
	// Not a listed entry: accept a file that resolves inside the case directory.
	real, err := filepath.EvalSymlinks(flag)
	if err != nil {
		return "", usageErrorf("--config %q is not one of the case's configs (%s) and is not a readable file", flag, strings.Join(c.Config, ", "))
	}
	root, err := filepath.EvalSymlinks(c.Dir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", usageErrorf("--config %q is outside the case directory: a case hunts with its own configs only", flag)
	}
	return real, nil
}

// placeStore decides where the evidence database goes. An empty store.path means
// <case>/<paths.evidence>/jb.duckdb, which the guard has just shown to be ignored
// by git; JB_DB is not consulted, because a case keeps its evidence with itself. A
// relative path is relative to the case directory.
func (p *casePlan) placeStore(stderr io.Writer, cfg *config.File) {
	evidence := p.c.EvidenceDir()
	switch sp := cfg.Store.Path; {
	case sp == "":
		cfg.Store.Path = filepath.Join(evidence, "jb.duckdb")
	case strings.HasPrefix(sp, "~/") || filepath.IsAbs(sp):
	default:
		cfg.Store.Path = filepath.Join(p.c.Dir, sp)
	}
	if got := cfg.StorePath(); !insideDir(evidence, got) {
		fmt.Fprintf(stderr, "note: the store %s is outside the case's evidence directory, so git ignore rules for it are not checked\n", got)
	}
}

func insideDir(dir, p string) bool {
	if d, err := filepath.EvalSymlinks(dir); err == nil {
		dir = d
	}
	if d, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		p = filepath.Join(d, filepath.Base(p))
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
