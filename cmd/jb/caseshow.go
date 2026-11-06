package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/config"
)

func newCaseShowCmd() *cobra.Command {
	var caseDir, cfgName, output string
	cmd := &cobra.Command{
		Use:   "show --case DIR [--config NAME] [--output table|json]",
		Short: "Print what one config of a case would run, without running it",
		Long: "show prints the effective configuration of one config of the case: each source (type, URL\n" +
			"without any query, index, and the NAME of its credential variable), each detector (type, name,\n" +
			"every option the file sets, its sources: scope and whether it is enabled), the store path as it\n" +
			"resolves inside the case, and the alert sinks. It reads no environment variable, runs no git\n" +
			"command, makes no connection and opens no store, so it prints no credential and needs none.\n" +
			"A webhook's address is the value of its variable, so only the variable's name is shown.\n" +
			"Options not listed take the detector's own default. The config is chosen as for `jb hunt --case`:\n" +
			"--config names one of the case's configs, or the case's only config is used.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			r, err := config.ShowCase(caseDir, cfgName)
			if err != nil {
				return err
			}
			if output == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				err = enc.Encode(r)
			} else {
				err = writeShowTable(cmd.OutOrStdout(), r)
			}
			if err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md); required")
	f.StringVar(&cfgName, "config", "", "one of the case's configs, or a file inside the case (default: the only one)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeShowTable(w io.Writer, r *config.CaseShow) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "case\t%s\n", r.Case)
	fmt.Fprintf(tw, "config\t%s\n", r.Config)
	for _, s := range r.Sources {
		fmt.Fprintf(tw, "source\t%s%s\t%s %s\n", s.Name, offTag(s.Enabled), s.Type, s.URL)
		fmt.Fprintf(tw, "\t  index\t%s\n", s.Index)
		fmt.Fprintf(tw, "\t  credential variable\t%s\n", s.CredentialEnv)
		writeOptions(tw, s.Options)
	}
	for _, d := range r.Detectors {
		fmt.Fprintf(tw, "detector\t%s%s\t%s\n", d.Name, offTag(d.Enabled), d.Type)
		if d.Sources != nil {
			fmt.Fprintf(tw, "\t  sources\t%s\n", strings.Join(d.Sources, ", "))
		}
		if d.Enabled {
			fmt.Fprintf(tw, "\t  reads\t%s\n", strings.Join(d.Reads, ", "))
		}
		writeOptions(tw, d.Options)
	}
	if r.Store.Default {
		fmt.Fprintf(tw, "store\t$JB_DB, then ~/.jb/jb.duckdb\n")
	} else {
		fmt.Fprintf(tw, "store\t%s\n", r.Store.Path)
	}
	for _, a := range r.Alerts {
		fmt.Fprintf(tw, "alert\t%s\n", a.Type)
		fmt.Fprintf(tw, "\t  credential variable\t%s (holds the address; not shown)\n", a.CredentialEnv)
		writeOptions(tw, a.Options)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(tw, "note\t%s\n", n)
	}
	return tw.Flush()
}

func offTag(enabled bool) string {
	if enabled {
		return ""
	}
	return " (disabled)"
}

func writeOptions(w io.Writer, opts map[string]any) {
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, _ := json.Marshal(opts[k])
		fmt.Fprintf(w, "\t  %s\t%s\n", k, b)
	}
}
