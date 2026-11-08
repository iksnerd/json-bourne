package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/jb"
)

func newCaseCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "case",
		Short: "Work with a case directory (docs/CASE-SPEC.md)",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(newCaseCheckCmd())
	c.AddCommand(newCaseShowCmd())
	return c
}

func newCaseCheckCmd() *cobra.Command {
	var output string
	var fl *opFlags
	cmd := &cobra.Command{
		Use:   "check --case DIR [--output table|json]",
		Short: "Validate a case: case.yaml, the evidence git guard and every listed config",
		Long: "check loads DIR/case.yaml (the --case directory), asks git whether the evidence directory is ignored, and\n" +
			"loads each file listed under `config:` with the hunt config loader. Loading a config\n" +
			"never reads an API key from the environment. check never reads the evidence directory.\n" +
			"It exits 0 only when everything passes and 1 otherwise.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caseDir := fl.String("case")
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			rep, err := jb.CaseCheck(caseDir)
			if err != nil {
				return err
			}
			if output == "json" {
				err = writeCaseJSON(cmd.OutOrStdout(), rep)
			} else {
				err = writeCaseTable(cmd.OutOrStdout(), rep)
			}
			if err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			if !rep.OK {
				return fmt.Errorf("case check failed: %s", rep.FirstProblem())
			}
			return nil
		},
	}
	fl = addOperationFlags(cmd, "case_check")
	cmd.Flags().StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeCaseJSON(w io.Writer, r *jb.CaseCheckResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeCaseTable(w io.Writer, r *jb.CaseCheckResult) error {
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
