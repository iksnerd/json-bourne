package main

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
)

func newDBCmdWith(d deps) *cobra.Command {
	db := &cobra.Command{
		Use:   "db",
		Short: "Inspect the evidence database",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	db.AddCommand(newDBStatusCmd(), newDBRenameSourceCmd(), newDBUsageCmd(), newDBPruneCmd(d), newDBCompactCmd())
	return db
}

func newDBStatusCmd() *cobra.Command {
	var cfgPath, output string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the database path, schema version and row counts (read-only)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfgPath == "" {
				return usageErrorf("--config is required")
			}
			if err := checkOutput(output); err != nil {
				return err
			}
			// The library loads the config only: status needs the store path, never a
			// credential. Read-only is enforced by the engine, not by this code.
			s, err := jb.DBStatus(cmd.Context(), "", jb.DBOptions{Config: cfgPath})
			if err != nil {
				return err
			}
			printNotes(cmd.ErrOrStderr(), s.Notes)
			if output == "json" {
				return writeIndentedJSON(cmd.OutOrStdout(), s)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "path\t%s\n", s.Path)
			fmt.Fprintf(tw, "schema\t%d (this build: %d)\n", s.Schema, s.BuildSchema)
			fmt.Fprintf(tw, "runs\t%d\n", s.Runs)
			fmt.Fprintf(tw, "events\t%d\n", s.Events)
			fmt.Fprintf(tw, "findings\t%d\n", s.Findings)
			fmt.Fprintf(tw, "reputation\t%d\n", s.Reputation)
			if s.FirstSeen == nil || s.LastSeen == nil {
				fmt.Fprintf(tw, "event span\tnone\n")
			} else {
				fmt.Fprintf(tw, "event span\t%s to %s\n", s.FirstSeen.Format(time.RFC3339), s.LastSeen.Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to the YAML config (required)")
	cmd.Flags().StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

// printNotes writes the advice a library call returned (a store outside the evidence
// directory, a case outside git) to w, one line each.
func printNotes(w io.Writer, notes []string) {
	for _, n := range notes {
		fmt.Fprintln(w, n)
	}
}
