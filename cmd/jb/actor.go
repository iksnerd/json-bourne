package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
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
			plan, err := planCase(cmd.ErrOrStderr(), caseDir, cfgPath, "actor", true)
			if err != nil {
				return err
			}
			cfg, err := loadCaseConfig(cmd.ErrOrStderr(), plan)
			if err != nil {
				return err
			}
			dets, err := cfg.BuildDetectors()
			if err != nil {
				return err
			}
			st, err := duckdb.OpenContext(cmd.Context(), cfg.StorePath(), true, duckdb.OpenOptions{})
			if err != nil {
				return fmt.Errorf("open database read-only: %w", err)
			}
			defer st.Close()
			stats, err := st.Stats()
			if err != nil {
				return fmt.Errorf("read database stats: %w", err)
			}
			if stats.Events == 0 {
				return fmt.Errorf("the evidence store %s holds no events, so \"never matched\" cannot be said; run `jb hunt --case` first", stats.Path)
			}
			hist, err := app.ActorStatus(cmd.Context(), app.ActorStatusDeps{Detectors: dets, Finder: st})
			if err != nil {
				return err
			}
			var werr error
			if output == "json" {
				werr = writeActorJSON(cmd.OutOrStdout(), stats, hist)
			} else {
				werr = writeActorTable(cmd.OutOrStdout(), stats, hist)
			}
			if werr != nil {
				return fmt.Errorf("write output: %w", werr)
			}
			for _, h := range hist {
				if h.Capped {
					return fmt.Errorf("actor %q: the scan stopped at its cap before a genuine match, so no date can be given", h.Actor)
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md); required")
	f.StringVar(&cfgPath, "config", "", "one of the case's configs (default: the case's only config)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func actorNote(h core.ActorHistory) string {
	var parts []string
	switch {
	case h.Capped:
		parts = append(parts, "INCOMPLETE: scan stopped at its cap")
	case h.LastGenuine.IsZero() && h.Scanned == 0:
		parts = append(parts, "no stored event carries this user agent")
	case h.LastGenuine.IsZero():
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

func writeActorTable(w io.Writer, s duckdb.Stats, hist []core.ActorHistory) error {
	fmt.Fprintf(w, "store  %s: %d events, %s to %s\n\n", s.Path, s.Events, stamp(s.FirstSeen), stamp(s.LastSeen))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ACTOR\tUSER AGENT\tLAST GENUINE MATCH\tNOTE")
	for _, h := range hist {
		last := "never"
		if !h.LastGenuine.IsZero() {
			last = stamp(h.LastGenuine)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.Actor, clip(h.Indicator, 60), last, actorNote(h))
	}
	return tw.Flush()
}

type jsonActorRow struct {
	Actor       string     `json:"actor"`
	Label       string     `json:"label,omitempty"`
	UserAgent   string     `json:"user_agent"`
	LastGenuine *time.Time `json:"last_genuine,omitempty"`
	Examined    int        `json:"examined"`
	Noise       int        `json:"noise"`
	Ignored     int        `json:"ignored"`
	Unparsable  int        `json:"unparsable"`
	Capped      bool       `json:"capped,omitempty"`
}

func writeActorJSON(w io.Writer, s duckdb.Stats, hist []core.ActorHistory) error {
	out := struct {
		Store  string         `json:"store"`
		Events int64          `json:"store_events"`
		From   *time.Time     `json:"store_from,omitempty"`
		To     *time.Time     `json:"store_to,omitempty"`
		Actors []jsonActorRow `json:"actors"`
	}{Store: s.Path, Events: s.Events, From: tptr(s.FirstSeen), To: tptr(s.LastSeen), Actors: []jsonActorRow{}}
	for _, h := range hist {
		out.Actors = append(out.Actors, jsonActorRow{
			Actor: h.Actor, Label: h.Label, UserAgent: h.Indicator, LastGenuine: tptr(h.LastGenuine),
			Examined: h.Scanned, Noise: h.Noise, Ignored: h.Ignored, Unparsable: h.Unparsable, Capped: h.Capped,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
