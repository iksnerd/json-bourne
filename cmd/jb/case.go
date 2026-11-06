package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
)

func newCaseCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "case",
		Short: "Work with a case directory (docs/CASE-SPEC.md)",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(newCaseCheckCmd())
	return c
}

func newCaseCheckCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "check DIR",
		Short: "Validate a case: case.yaml, the evidence git guard and every listed config",
		Long: "check loads DIR/case.yaml, asks git whether the evidence directory is ignored, and\n" +
			"loads each file listed under `config:` with the hunt config loader. Loading a config\n" +
			"never reads an API key from the environment. check never reads the evidence directory.\n" +
			"It exits 0 only when everything passes and 1 otherwise.",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return usageErrorf("%v", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			rep := checkCase(args[0])
			var err error
			if output == "json" {
				err = writeCaseJSON(cmd.OutOrStdout(), rep)
			} else {
				err = writeCaseTable(cmd.OutOrStdout(), rep)
			}
			if err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			if !rep.OK {
				return fmt.Errorf("case check failed: %s", rep.firstProblem())
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

// caseReport is the result of checking one case. Nothing in it can hold a credential
// value: it carries ids, paths and error text from loaders that never echo a value.
type caseReport struct {
	OK       bool           `json:"ok"`
	Dir      string         `json:"dir"`
	ID       string         `json:"id,omitempty"`
	Title    string         `json:"title,omitempty"`
	Status   string         `json:"status,omitempty"`
	Opened   string         `json:"opened,omitempty"`
	Error    string         `json:"error,omitempty"` // case.yaml did not load
	Evidence string         `json:"evidence,omitempty"`
	Guard    *guardReport   `json:"guard,omitempty"`
	Actors   *actorsReport  `json:"actors,omitempty"`
	Estate   *estateReport  `json:"estate,omitempty"`
	Configs  []configReport `json:"configs"`
}

// actorsReport is the result of loading every actor file in the case's actors directory.
type actorsReport struct {
	OK    bool     `json:"ok"`
	IDs   []string `json:"ids"`
	Error string   `json:"error,omitempty"` // names every file that did not load
}

// estateReport is the result of loading every estate file in the case's estate directory.
type estateReport struct {
	OK    bool     `json:"ok"`
	IDs   []string `json:"ids"`
	Error string   `json:"error,omitempty"` // names every file that did not load
}

type guardReport struct {
	OK     bool   `json:"ok"`
	Result string `json:"result,omitempty"` // "ignored" or "not a git work tree"
	Error  string `json:"error,omitempty"`
}

type configReport struct {
	Path  string `json:"path"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Notes are things worth knowing that do not fail the check: today, the sources
	// and detectors the config switched off with `enabled: false`.
	Notes []string `json:"notes,omitempty"`
}

func (r caseReport) firstProblem() string {
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

// inspectCase loads the case and runs the evidence guard. It is the part of the
// check that `jb hunt --case` repeats before touching anything.
func inspectCase(dir string) (*casefile.Case, *guardReport, error) {
	c, err := casefile.Load(dir)
	if err != nil {
		return nil, nil, err
	}
	g := &guardReport{}
	st, err := casefile.Guard(c.EvidenceDir())
	if err != nil {
		g.Error = err.Error()
		return c, g, nil
	}
	g.OK, g.Result = true, st.String()
	return c, g, nil
}

// checkCase never returns an error: every problem is in the report.
func checkCase(dir string) caseReport {
	rep := caseReport{Dir: dir, Configs: []configReport{}}
	c, g, err := inspectCase(dir)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	rep.ID, rep.Title, rep.Status, rep.Opened = c.ID, c.Title, c.Status, c.Opened
	rep.Evidence, rep.Guard = c.Paths.Evidence, g
	rep.OK = g.OK
	rep.Actors = &actorsReport{OK: true, IDs: []string{}}
	actors, err := casefile.LoadActors(c)
	if err != nil {
		rep.Actors.OK, rep.Actors.Error = false, err.Error()
		rep.OK = false
	}
	for _, a := range actors {
		rep.Actors.IDs = append(rep.Actors.IDs, a.ID)
	}
	rep.Estate = &estateReport{OK: true, IDs: []string{}}
	estates, err := casefile.LoadEstates(c)
	if err != nil {
		rep.Estate.OK, rep.Estate.Error = false, err.Error()
		rep.OK = false
	}
	for _, e := range estates {
		rep.Estate.IDs = append(rep.Estate.IDs, e.ID)
	}
	for _, rel := range c.Config {
		cr := configReport{Path: rel, OK: true}
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
	return rep
}

func writeCaseJSON(w io.Writer, r caseReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeCaseTable(w io.Writer, r caseReport) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if r.Error != "" {
		fmt.Fprintf(tw, "case\t%s\n", r.Dir)
		fmt.Fprintf(tw, "case.yaml\tFAIL: %s\n", oneLine(r.Error))
		return tw.Flush()
	}
	fmt.Fprintf(tw, "id\t%s\n", r.ID)
	fmt.Fprintf(tw, "title\t%s\n", r.Title)
	fmt.Fprintf(tw, "status\t%s\n", r.Status)
	fmt.Fprintf(tw, "opened\t%s\n", r.Opened)
	if r.Guard.OK {
		fmt.Fprintf(tw, "evidence\t%s: OK (%s)\n", r.Evidence, r.Guard.Result)
		if r.Guard.Result == casefile.GuardNotWorkTree.String() {
			fmt.Fprintf(tw, "\tnot a pass for later: run check again once the case is under git\n")
		}
	} else {
		fmt.Fprintf(tw, "evidence\t%s: FAIL: %s\n", r.Evidence, oneLine(r.Guard.Error))
	}
	switch {
	case r.Actors == nil:
	case !r.Actors.OK:
		fmt.Fprintf(tw, "actors\tFAIL: %s\n", oneLine(r.Actors.Error))
	case len(r.Actors.IDs) == 0:
		fmt.Fprintf(tw, "actors\tnone found\n")
	default:
		fmt.Fprintf(tw, "actors\tOK (%d: %s)\n", len(r.Actors.IDs), strings.Join(r.Actors.IDs, ", "))
	}
	switch {
	case r.Estate == nil:
	case !r.Estate.OK:
		fmt.Fprintf(tw, "estate\tFAIL: %s\n", oneLine(r.Estate.Error))
	case len(r.Estate.IDs) == 0:
		fmt.Fprintf(tw, "estate\tnone found\n")
	default:
		fmt.Fprintf(tw, "estate\tOK (%d: %s)\n", len(r.Estate.IDs), strings.Join(r.Estate.IDs, ", "))
	}
	for _, c := range r.Configs {
		if c.OK {
			fmt.Fprintf(tw, "config\t%s: OK\n", c.Path)
		} else {
			fmt.Fprintf(tw, "config\t%s: FAIL: %s\n", c.Path, oneLine(c.Error))
		}
		for _, n := range c.Notes {
			fmt.Fprintf(tw, "\tnote: %s\n", n)
		}
	}
	if len(r.Configs) == 0 {
		fmt.Fprintf(tw, "config\tnone listed\n")
	}
	if r.OK {
		fmt.Fprintf(tw, "result\tOK\n")
	} else {
		fmt.Fprintf(tw, "result\tFAIL\n")
	}
	return tw.Flush()
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
