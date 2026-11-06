package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

func newWatchStatusCmd(d deps) *cobra.Command {
	var output string
	var fl *opFlags
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Say whether a case's watchers are alive and what they run",
		Long: "status reads the status record every `jb watch` keeps in <case>/<evidence>/ (watch-status.json, or\n" +
			"watch-status.NAME.json for a named watcher) and probes the watcher's lock without taking it, then\n" +
			"reports each watcher found as one of:\n\n" +
			"  running  the lock is held and a cycle ended within 3 intervals (--every) of now\n" +
			"  stale    the lock is held, but no cycle ended in that time: the process is there and not cycling\n" +
			"  stopped  there is a record and no process holds the lock\n" +
			"  unknown  there is no readable record (a watcher from an older build, or one that never started)\n\n" +
			"It writes nothing and never holds the lock, so it is safe while a watcher runs. --name NAME reports\n" +
			"one watcher (--name \"\" the unnamed one); --config keeps the watchers that run that config. The\n" +
			"record holds names, counts and times, never a credential. Exit 0 whatever the states; read them.\n" +
			"The format is in docs/CASE-SPEC.md section 3.1.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caseDir, cfgPath, name := fl.String("case"), fl.String("config"), fl.String("name")
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			if err := app.ValidWatchName(name); err != nil {
				return usageErrorf("--name: %v", err)
			}
			o := jb.WatchStatusOptions{Config: cfgPath, Now: d.now}
			if cmd.Flags().Changed("name") {
				o.Names = []string{name}
			}
			got, err := jb.WatchStatus(caseDir, o)
			if err != nil {
				return err
			}
			if output == "json" {
				return writeJSON(cmd.OutOrStdout(), got)
			}
			return writeWatchStatusTable(cmd.OutOrStdout(), got.Watchers, got.Checked)
		},
	}
	fl = addOperationFlags(cmd, "watch_status")
	f := cmd.Flags()
	f.StringVar(&output, "output", "table", "table or json")
	return cmd
}

func writeWatchStatusTable(w io.Writer, got []watchrun.WatcherStatus, now time.Time) error {
	if len(got) == 0 {
		_, err := fmt.Fprintln(w, "no watcher found in the case's evidence directory")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tPID\tLAST CYCLE\tENDED\tNEXT DUE\tEVERY\tCONFIG")
	for _, s := range got {
		name := s.Name
		if name == "" {
			name = "(unnamed)"
		}
		verdict, ended := "-", "-"
		if c := s.Last; c != nil {
			verdict, ended = c.Verdict, ago(now, c.Ended)
		}
		due := "-"
		if !s.NextDue.IsZero() {
			due = s.NextDue.UTC().Format(time.RFC3339)
		}
		every, cfg, pid := "-", "-", "-"
		if s.Every > 0 {
			every = s.Every.String()
		}
		if s.Config != "" {
			cfg = s.Config
		}
		if s.PID > 0 {
			pid = fmt.Sprint(s.PID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, s.State, pid, verdict, ended, due, every, cfg)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, s := range got {
		if s.Reason != "" {
			n := s.Name
			if n == "" {
				n = "(unnamed)"
			}
			fmt.Fprintf(w, "%s: %s\n", n, strings.TrimSpace(s.Reason))
		}
	}
	return nil
}

func ago(now, t time.Time) string {
	d := now.Sub(t).Round(time.Second)
	if d < 0 {
		return "just now"
	}
	return d.String() + " ago"
}
