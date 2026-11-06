package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
)

func newActorCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "actor",
		Short: "Work with the actors a case names",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	c.AddCommand(newActorStatusCmd())
	return c
}

func newActorStatusCmd() *cobra.Command {
	var (
		cfgPath string
		caseDir string
		output  string
	)
	cmd := &cobra.Command{
		Use:   "status --case DIR",
		Short: "When each actor's user agent last matched in the evidence store (read-only)",
		Long: "status lists, for every actor the case's fingerprint detector names, each exact user agent\n" +
			"and the time of its last genuine match in the evidence store. Scanner noise and traffic\n" +
			"relayed by the config's ignore_ips are set aside by the same rules `jb hunt` applies, so a\n" +
			"scanner reusing the user agent never moves the date.\n\n" +
			"It reads only what earlier hunts stored. It opens the store read-only (the engine refuses\n" +
			"writes), runs one fixed parameterised query per user agent, takes no SQL from the user and\n" +
			"never reads an API key or the network. Other indicators (addresses, ASNs, domains, probe\n" +
			"fingerprints) are not matched against events and are not listed. A user agent never\n" +
			"matched is reported as such, and an empty store is an error, not \"never matched\".",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			res, err := jb.ActorStatus(cmd.Context(), caseDir, jb.ActorStatusOptions{Config: cfgPath})
			if res != nil {
				for _, n := range res.Notes {
					fmt.Fprintln(cmd.ErrOrStderr(), n)
				}
			}
			if err != nil {
				return err
			}
			var werr error
			if output == "json" {
				werr = writeActorJSON(cmd.OutOrStdout(), res)
			} else {
				werr = writeActorTable(cmd.OutOrStdout(), res)
			}
			if werr != nil {
				return fmt.Errorf("write output: %w", werr)
			}
			for _, h := range res.Actors {
				if h.Capped {
					return fmt.Errorf("actor %q: the scan stopped at its cap before a genuine match, so no date can be given", h.Actor)
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md); required")
	f.StringVar(&cfgPath, "config", "", "one of the case's configs (default: the config whose `commands:` lists this command, else the case's only config)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func actorNote(h jb.ActorMatch) string {
	var parts []string
	switch {
	case h.Capped:
		parts = append(parts, "INCOMPLETE: scan stopped at its cap")
	case h.LastGenuine == nil && h.Examined == 0:
		parts = append(parts, "no stored event carries this user agent")
	case h.LastGenuine == nil:
		parts = append(parts, "matched only as noise or infrastructure")
	}
	if h.Noise > 0 {
		parts = append(parts, fmt.Sprintf("%d newer noise", h.Noise))
	}
	if h.Ignored > 0 {
		parts = append(parts, fmt.Sprintf("%d newer from ignored infrastructure", h.Ignored))
	}
	if h.Unparsable > 0 {
		parts = append(parts, fmt.Sprintf("%d could not be judged", h.Unparsable))
	}
	return strings.Join(parts, "; ")
}

func writeActorTable(w io.Writer, r *jb.ActorStatusResult) error {
	var from, to time.Time
	if r.From != nil {
		from = *r.From
	}
	if r.To != nil {
		to = *r.To
	}
	fmt.Fprintf(w, "store  %s: %d events, %s to %s\n\n", r.Store, r.Events, stamp(from), stamp(to))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ACTOR\tUSER AGENT\tLAST GENUINE MATCH\tNOTE")
	for _, h := range r.Actors {
		last := "never"
		if h.LastGenuine != nil {
			last = stamp(*h.LastGenuine)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.Actor, clip(h.UserAgent, 60), last, actorNote(h))
	}
	return tw.Flush()
}

func writeActorJSON(w io.Writer, r *jb.ActorStatusResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
