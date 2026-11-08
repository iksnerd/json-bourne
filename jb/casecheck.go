package jb

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
)

// CaseCheckResult is what [CaseCheck] found in one case. It is the document
// `jb case check --output json` prints. Nothing in it can hold a credential value: it
// carries ids, paths and error text from loaders that never echo a value.
type CaseCheckResult struct {
	// OK is true only when case.yaml, the evidence guard, every actor and estate file and
	// every listed config passed.
	OK       bool              `json:"ok"`
	Dir      string            `json:"dir"`
	ID       string            `json:"id,omitempty"`
	Title    string            `json:"title,omitempty"`
	Status   string            `json:"status,omitempty"`
	Opened   string            `json:"opened,omitempty"`
	Error    string            `json:"error,omitempty"` // case.yaml did not load
	Evidence string            `json:"evidence,omitempty"`
	Guard    *CaseGuard        `json:"guard,omitempty"`
	Actors   *CaseFilesCheck   `json:"actors,omitempty"`
	Estate   *CaseFilesCheck   `json:"estate,omitempty"`
	Configs  []CaseConfigCheck `json:"configs"`
}

// CaseGuard is the evidence git guard: whether git ignores the evidence directory.
type CaseGuard struct {
	OK     bool   `json:"ok"`
	Result string `json:"result,omitempty"` // "ignored" or "not a git work tree"
	Error  string `json:"error,omitempty"`
}

// CaseFilesCheck is the result of loading every actor file, or every estate file, of a case.
type CaseFilesCheck struct {
	OK    bool     `json:"ok"`
	IDs   []string `json:"ids"`
	Error string   `json:"error,omitempty"` // names every file that did not load
}

// CaseConfigCheck is the result of loading one config the case lists.
type CaseConfigCheck struct {
	Path  string `json:"path"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Notes are things worth knowing that do not fail the check: today, the sources
	// and detectors the config switched off with `enabled: false`.
	Notes []string `json:"notes,omitempty"`
}

// guardNotWorkTree is the guard result of a case outside any git work tree.
var guardNotWorkTree = casefile.GuardNotWorkTree.String()

// CaseCheck validates a case as `jb case check --case DIR` does: it loads case.yaml,
// asks git whether the evidence directory is ignored, loads every actor and estate file,
// and loads each config the case lists with the hunt loader, building its detectors. It
// reads no environment variable, makes no connection and never reads the evidence
// directory.
//
// A problem in the case is not an error: it is in the result, with OK false. The error
// is a [UsageError] for an empty caseDir. Read [CaseCheckResult.OK] before relying on a
// case, and [CaseCheckResult.Complete] before treating it as safe for later.
func CaseCheck(caseDir string) (*CaseCheckResult, error) {
	if caseDir == "" {
		return nil, usagef("case directory is required")
	}
	rep, _ := checkCase(caseDir)
	return &rep, nil
}

// FirstProblem names the first thing that failed, for a one-line message. It is empty
// when OK is true.
func (r *CaseCheckResult) FirstProblem() string {
	if r.OK {
		return ""
	}
	switch {
	case r.Error != "":
		return r.Error
	case r.Guard != nil && !r.Guard.OK:
		return r.Guard.Error
	case r.Actors != nil && !r.Actors.OK:
		return r.Actors.Error
	case r.Estate != nil && !r.Estate.OK:
		return r.Estate.Error
	}
	for _, c := range r.Configs {
		if !c.OK {
			return c.Path + ": " + c.Error
		}
	}
	return "unknown problem"
}

// Complete is true when OK is true and git positively said the evidence directory is
// ignored. A case outside any git work tree passes (OK is true) but nothing is guarding
// its evidence yet, so it is not complete: check again once the case is under git.
func (r *CaseCheckResult) Complete() bool {
	return r.OK && r.Guard != nil && r.Guard.OK && r.Guard.Result != guardNotWorkTree
}

// checkCase never returns an error: every problem is in the result. The case is nil when
// case.yaml did not load.
func checkCase(dir string) (CaseCheckResult, *casefile.Case) {
	rep := CaseCheckResult{Dir: dir, Configs: []CaseConfigCheck{}}
	c, err := casefile.Load(dir)
	if err != nil {
		rep.Error = err.Error()
		return rep, nil
	}
	g := &CaseGuard{}
	if st, err := casefile.Guard(c.EvidenceDir()); err != nil {
		g.Error = err.Error()
	} else {
		g.OK, g.Result = true, st.String()
	}
	rep.ID, rep.Title, rep.Status, rep.Opened = c.ID, c.Title, c.Status, c.Opened
	rep.Evidence, rep.Guard = c.Paths.Evidence, g
	rep.OK = g.OK
	rep.Actors = &CaseFilesCheck{OK: true, IDs: []string{}}
	actors, err := casefile.LoadActors(c)
	if err != nil {
		rep.Actors.OK, rep.Actors.Error = false, err.Error()
		rep.OK = false
	}
	for _, a := range actors {
		rep.Actors.IDs = append(rep.Actors.IDs, a.ID)
	}
	rep.Estate = &CaseFilesCheck{OK: true, IDs: []string{}}
	estates, err := casefile.LoadEstates(c)
	if err != nil {
		rep.Estate.OK, rep.Estate.Error = false, err.Error()
		rep.OK = false
	}
	for _, e := range estates {
		rep.Estate.IDs = append(rep.Estate.IDs, e.ID)
	}
	for _, rel := range c.Config {
		cr := CaseConfigCheck{Path: rel, OK: true}
		// Load and BuildDetectors, not Build: the file is validated, the case files its
		// detectors name are read, and no environment variable is.
		f, err := config.Load(filepath.Join(c.Dir, filepath.FromSlash(rel)))
		if err == nil {
			f.UseCase(c)
			_, err = f.BuildDetectors()
		}
		if err != nil {
			cr.OK, cr.Error = false, err.Error()
			rep.OK = false
		}
		if f != nil {
			for _, n := range f.DisabledSources() {
				cr.Notes = append(cr.Notes, "DISABLED: source "+n+" (enabled: false; not built, not read)")
			}
			for _, n := range f.DisabledDetectors() {
				cr.Notes = append(cr.Notes, "DISABLED: detector "+n+" (enabled: false; not built, not run)")
			}
		}
		rep.Configs = append(rep.Configs, cr)
	}
	noteAmbiguousCommands(c, rep.Configs)
	return rep, c
}

// noteAmbiguousCommands adds a note to each config that declares a command another
// config of the case also declares. `jb <command> --case` then cannot choose between
// them and asks for --config. It is a note, not a failure: the case is valid, and a
// caller who always passes --config is not affected. A config that cannot be read is
// skipped here: its own check already failed.
func noteAmbiguousCommands(c *casefile.Case, configs []CaseConfigCheck) {
	declares := map[string][]int{}
	for i := range configs {
		if !configs[i].OK {
			continue
		}
		cmds, err := config.LoadCommands(filepath.Join(c.Dir, filepath.FromSlash(configs[i].Path)))
		if err != nil {
			continue
		}
		for _, cmd := range cmds {
			declares[cmd] = append(declares[cmd], i)
		}
	}
	cmds := make([]string, 0, len(declares))
	for cmd := range declares {
		cmds = append(cmds, cmd)
	}
	sort.Strings(cmds)
	for _, cmd := range cmds {
		idx := declares[cmd]
		if len(idx) < 2 {
			continue
		}
		names := make([]string, len(idx))
		for k, i := range idx {
			names[k] = configs[i].Path
		}
		for _, i := range idx {
			configs[i].Notes = append(configs[i].Notes, "AMBIGUOUS: command "+cmd+" is declared by "+strings.Join(names, ", ")+"; `jb "+cmd+" --case` will ask for --config")
		}
	}
}

// oneLine joins the lines of s with single spaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
