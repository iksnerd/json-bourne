package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
)

func newDoctorCmdWith(d deps) *cobra.Command {
	var (
		cfgPath string
		caseDir string
		output  string
		online  bool
	)
	cmd := &cobra.Command{
		Use:   "doctor [--case DIR | --config FILE] [--online]",
		Short: "Check the environment and the config before a run (read-only)",
		Long: "doctor answers \"will the next hunt, watch or intel run work, and what would it send?\" without\n" +
			"running any of them. It is read-only and sends nothing by default. It checks that the config loads\n" +
			"strictly; that each environment variable the config names is set (reported as set or unset, never\n" +
			"its value or length); that the case passes `jb case check` and its evidence directory is ignored by\n" +
			"git; that the store path is writable by this user, owned by this user and opens; the jb build and\n" +
			"the DuckDB driver and engine versions; the plugin allowlist ($JB_PLUGINS_FILE or ~/.jb/plugins.yaml):\n" +
			"each plugin's path, pin state and file mode checks, without launching any; and, for every outbound\n" +
			"service, whether it is enabled and what would leave the machine.\n\n" +
			"--online adds one TCP connect per distinct service host, bounded to " + jb.DoctorReachTimeout.String() + ". The connection sends no\n" +
			"bytes: no request, no credential, no webhook URL path. A host that is reached through a DNS\n" +
			"resolver (dnsbl, estate dns) is listed but not probed.\n\n" +
			"Exit 0 only if no check failed. A thing that is not configured or not asked for is `skipped`, which\n" +
			"is not a pass. doctor does not inventory external binaries; the only programs jb starts are the allowlisted plugins listed above and git.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			v, c, dt := buildInfo()
			rep, err := jb.Doctor(cmd.Context(), jb.DoctorOptions{
				Case: caseDir, Config: cfgPath, Online: online, Env: d.env, Now: d.now,
				Version: v, Commit: c, Date: dt,
			})
			if err != nil {
				return err
			}
			if output == "json" {
				err = writeDoctorJSON(cmd.OutOrStdout(), rep)
			} else {
				err = writeDoctorTable(cmd.OutOrStdout(), rep)
			}
			if err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			if !rep.OK() {
				return fmt.Errorf("doctor: %d check(s) failed", rep.Failed())
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfgPath, "config", "", "path to the YAML config (with --case, one of the case's configs; default: all of them)")
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md)")
	f.BoolVar(&online, "online", false, "also make one TCP connect per service host (sends nothing)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeDoctorJSON(w io.Writer, r *jb.DoctorResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeDoctorTable(w io.Writer, r *jb.DoctorResult) error {
	var group []jb.DoctorCheck
	flush := func() error {
		if len(group) == 0 {
			return nil
		}
		fmt.Fprintf(w, "\n%s\n", strings.ToUpper(group[0].Group))
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, c := range group {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", strings.ToUpper(string(c.Status)), c.Name, c.Detail)
		}
		group = nil
		return tw.Flush()
	}
	for _, c := range r.Checks {
		if len(group) > 0 && group[0].Group != c.Group {
			if err := flush(); err != nil {
				return err
			}
		}
		group = append(group, c)
	}
	if err := flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nSERVICES (what would leave this machine if the command that uses it ran)\n")
	if len(r.Services) == 0 {
		fmt.Fprintf(w, "  none: no config was loaded\n")
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, s := range r.Services {
		who := s.Kind + " " + s.Name
		if s.Config != "" {
			who += " (" + s.Config + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", strings.ToUpper(s.State), who, s.Leaves)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if r.OK() {
		fmt.Fprintf(w, "\nRESULT  OK. SKIPPED is not a pass: read those lines for what was not checked.\n")
	} else {
		fmt.Fprintf(w, "\nRESULT  FAIL: %d check(s) failed.\n", r.Failed())
	}
	return nil
}
