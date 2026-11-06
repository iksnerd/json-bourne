package main

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/config"
)

func newDBCmdWith(d deps) *cobra.Command {
	db := &cobra.Command{
		Use:   "db",
		Short: "Inspect the evidence database",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	db.AddCommand(newDBStatusCmd(), newDBRenameSourceCmd(), newDBUsageCmd(), newDBPruneCmd(d), newDBCompactCmd(), newDBReputationCmd())
	return db
}

func newDBStatusCmd() *cobra.Command {
	var output string
	var fl *opFlags
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the database path, schema version and row counts (read-only)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caseDir, cfgPath := fl.String("case"), fl.String("config")
			if cfgPath == "" && caseDir == "" {
				return usageErrorf("--config or --case is required")
			}
			if err := checkOutput(output); err != nil {
				return err
			}
			// The library loads the config only: status needs the store path, never a
			// credential. Read-only is enforced by the engine, not by this code.
			s, err := jb.DBStatus(cmd.Context(), caseDir, jb.DBOptions{Config: cfgPath})
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
	cmd.Flags().StringVar(&output, "output", "table", "output format: table or json")
	fl = addOperationFlags(cmd, "db_status")
	return cmd
}

// printNotes writes the advice a library call returned (a store outside the evidence
// directory, a case outside git) to w, one line each.
func printNotes(w io.Writer, notes []string) {
	for _, n := range notes {
		fmt.Fprintln(w, n)
	}
}

func newDBReputationCmd() *cobra.Command {
	var output string
	var fl *opFlags
	cmd := &cobra.Command{
		Use:   "reputation (--config FILE | --case DIR) [--indicator IP ...] [--source NAME] [--since TIME] [--until TIME] [--limit N] [--latest] [--output table|json]",
		Short: "List the reputation rows `jb intel` stored (read-only)",
		Long: "reputation reads the `reputation` table: indicator, verdict, observed time and source (the feed),\n" +
			"ordered by indicator and then newest first. The store is opened read-only and never created.\n" +
			"--latest keeps the newest row of each indicator from each source. --since (inclusive) and --until\n" +
			"(exclusive) take an RFC 3339 time or a date (UTC). At most " + fmt.Sprint(jb.MaxReputationRows) + " rows come back (default " + fmt.Sprint(jb.DefaultReputationRows) +
			"); a result cut at the cap says so and exits 1.\n\n" + jb.IntelNote,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caseDir, cfgPath, source, since, until, indicators, limit, latest := fl.String("case"), fl.String("config"), fl.String("source"), fl.String("since"), fl.String("until"), fl.Strings("indicator"), fl.Int("limit"), fl.Bool("latest")
			if cfgPath == "" && caseDir == "" {
				return usageErrorf("--config or --case is required")
			}
			if err := checkOutput(output); err != nil {
				return err
			}
			opts := jb.ReputationOptions{Config: cfgPath, Indicators: indicators, Source: source, Limit: limit, Latest: latest}
			var err error
			if opts.Since, err = parseWhen("--since", since); err != nil {
				return err
			}
			if opts.Until, err = parseWhen("--until", until); err != nil {
				return err
			}
			res, err := jb.Reputation(cmd.Context(), caseDir, opts)
			if err != nil {
				return err
			}
			printNotes(cmd.ErrOrStderr(), res.Notes)
			if output == "json" {
				err = writeIndentedJSON(cmd.OutOrStdout(), res)
			} else {
				err = writeReputation(cmd.OutOrStdout(), res)
			}
			if err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			if !res.Complete() {
				return fmt.Errorf("INCOMPLETE: more than %d rows matched; narrow the filters or raise --limit (at most %d)", res.Limit, jb.MaxReputationRows)
			}
			return nil
		},
	}
	fl = addOperationFlags(cmd, "db_reputation")
	f := cmd.Flags()
	f.StringVar(&output, "output", "table", "table or json")
	return cmd
}

// parseWhen reads an RFC 3339 time or a YYYY-MM-DD date (UTC); empty is the zero time.
func parseWhen(flag, v string) (time.Time, error) {
	t, err := config.ParseWhen(flag, v)
	if err != nil {
		return time.Time{}, usageErrorf("%v", err)
	}
	return t, nil
}

func writeReputation(w io.Writer, r *jb.ReputationResult) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INDICATOR\tVERDICT\tSOURCE\tOBSERVED")
	for _, x := range r.Rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", x.Indicator, x.Verdict, x.Source, x.Observed)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "%d row(s). %s\n", len(r.Rows), r.Note)
	return nil
}
