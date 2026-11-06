package main

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/config"
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
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the database path, schema version and row counts (read-only)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfgPath == "" {
				return usageErrorf("--config is required")
			}
			// Load only: status needs the store path, never a credential.
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			// Read-only is enforced by the engine (access_mode=READ_ONLY), not by this code.
			st, err := duckdb.OpenContext(cmd.Context(), cfg.StorePath(), true, duckdb.OpenOptions{})
			if err != nil {
				return fmt.Errorf("open database read-only: %w", err)
			}
			defer st.Close()
			s, err := st.Stats()
			if err != nil {
				return fmt.Errorf("read database stats: %w", err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "path\t%s\n", s.Path)
			fmt.Fprintf(tw, "schema\t%d (this build: %d)\n", s.Version, duckdb.Version)
			fmt.Fprintf(tw, "runs\t%d\n", s.Runs)
			fmt.Fprintf(tw, "events\t%d\n", s.Events)
			fmt.Fprintf(tw, "findings\t%d\n", s.Findings)
			fmt.Fprintf(tw, "reputation\t%d\n", s.Reputation)
			if s.FirstSeen.IsZero() {
				fmt.Fprintf(tw, "event span\tnone\n")
			} else {
				fmt.Fprintf(tw, "event span\t%s to %s\n", s.FirstSeen.Format(time.RFC3339), s.LastSeen.Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to the YAML config (required)")
	return cmd
}
