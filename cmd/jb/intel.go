package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
)

// intelNote is printed with every result, in every format. It is the reading rule for
// a reputation snapshot, kept next to the data so it travels with a pasted table.
const intelNote = "A reputation snapshot is context, not attribution. It describes an address as a third-party " +
	"feed saw it; a CDN or proxy edge address says nothing about the visitor behind it. " +
	"It never changes a finding or a severity."

// maxFailuresShown bounds the failure rows printed in the table; JSON lists them all.
const maxFailuresShown = 25

func newIntelCmdWith(d deps) *cobra.Command {
	var (
		cfgPath string
		caseDir string
		output  string
	)
	cmd := &cobra.Command{
		Use:   "intel [IP ...]",
		Short: "Look addresses up in a reputation feed and store the snapshots",
		Long: "intel asks the configured reputation feeds (config `feeds:`: greynoise, sans-isc, dnsbl) about\n" +
			"addresses and appends each answer, with the time and the feed, to the `reputation` table. Addresses are the arguments, or\n" +
			"when there are none the distinct values of `intel.ip_fields` (default client_ip) in the latest\n" +
			"stored hunt, most frequent first.\n\n" +
			"It is passive: requests go to the feed's API only (for a dnsbl feed, a DNS question under the\n" +
			"zone), never to the address. Each address x feed is its own answer: one feed failing makes the\n" +
			"run INCOMPLETE and keeps the other feeds' answers. A dnsbl feed sends the address to a resolver\n" +
			"and the zone's operator, so it is asked only with `enabled: true`. A key comes from the\n" +
			"environment variable the feed names. Requests are capped (`max_lookups`, `intel.max_indicators`),\n" +
			"spaced (`min_interval`), timed out and size-limited.\n\n" +
			"A lookup that failed, timed out, was rate limited or was not made because a cap was reached is\n" +
			"never an answer: it is listed, the run ends with INCOMPLETE and exit status 1, and nothing is\n" +
			"stored for it. \"not_found\" is a real answer from the feed (HTTP 404) and is stored.\n\n" +
			intelNote,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgPath == "" && caseDir == "" {
				return usageErrorf("--config or --case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			for _, a := range args {
				if _, err := netip.ParseAddr(strings.TrimSpace(a)); err != nil {
					return usageErrorf("%q is not an IP address", a)
				}
			}

			var plan *casePlan
			if caseDir != "" {
				var err error
				// windowSet is true: intel has no window, so the case's default is not announced.
				plan, err = planCase(cmd.ErrOrStderr(), caseDir, cfgPath, true)
				if err != nil {
					return err
				}
				cfgPath = plan.configPath
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			if plan != nil {
				plan.placeStore(cmd.ErrOrStderr(), cfg)
			}
			if len(cfg.Feeds) == 0 {
				return fmt.Errorf("%s has no feeds: add a `feeds:` entry (docs/CONFIG.md)", cfgPath)
			}
			feeds, err := cfg.BuildFeeds(d.env)
			if err != nil {
				return err
			}
			for _, name := range cfg.DisabledFeeds() {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: feed %s is listed but not enabled (enabled: true), so it is not asked and nothing is sent to it\n", name)
			}
			if len(feeds) == 0 {
				return fmt.Errorf("%s lists feeds but none is enabled: set `enabled: true` on the feed you mean to ask (docs/CONFIG.md)", cfgPath)
			}
			opts := cfg.IntelOptions()

			st, err := duckdb.OpenContext(cmd.Context(), cfg.StorePath(), false, duckdb.OpenOptions{})
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()
			if _, err := st.Migrate(); err != nil {
				return fmt.Errorf("migrate database: %w", err)
			}

			res, ierr := app.Intel(cmd.Context(), app.IntelDeps{Feeds: feeds, Store: st, Indicators: st},
				app.IntelRequest{Indicators: args, Fields: opts.IPFields, MaxIndicators: opts.MaxIndicators})
			if ierr != nil && len(res.Requested) == 0 {
				return ierr // nothing was asked: input problem, nothing to print
			}
			var perr error
			if output == "json" {
				perr = writeIntelJSON(cmd.OutOrStdout(), res)
			} else {
				perr = writeIntelTable(cmd.OutOrStdout(), res)
			}
			if ierr != nil {
				return ierr
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			if !res.Complete() {
				return fmt.Errorf("intel incomplete, no clean result: %d lookup(s) did not get an answer", len(res.Failures))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfgPath, "config", "", "path to the YAML config (required without --case; with --case, one of the case's configs)")
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeIntelTable(w io.Writer, r app.IntelResult) error {
	src := "arguments"
	if r.Run != "" {
		src = "latest stored run " + r.Run
	}
	fmt.Fprintf(w, "indicators  %d from %s\n", len(r.Requested), src)
	if r.Skipped > 0 {
		fmt.Fprintf(w, "skipped     %d value(s) in the run were not IP addresses\n", r.Skipped)
	}
	fmt.Fprintf(w, "note        %s\n\n", intelNote)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INDICATOR\tFEED\tVERDICT\tOBSERVED")
	for _, x := range r.Rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", x.Indicator, x.Source, x.Verdict, x.Observed.Format(time.RFC3339))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(r.Failures) == 0 {
		return nil
	}
	fmt.Fprintf(w, "\nCOULD NOT ASK (not an answer, not stored):\n")
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INDICATOR\tFEED\tREASON")
	for i, x := range r.Failures {
		if i == maxFailuresShown {
			fmt.Fprintf(tw, "...\t\t%d more (use --output json for all)\n", len(r.Failures)-i)
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%v\n", x.Indicator, x.Feed, x.Err)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no answer; this is not a clean result.\n", len(r.Failures))
	return nil
}

type intelRowJSON struct {
	Indicator string `json:"indicator"`
	Feed      string `json:"feed"`
	Verdict   string `json:"verdict"`
	Observed  string `json:"observed"`
}

type intelFailJSON struct {
	Indicator string `json:"indicator"`
	Feed      string `json:"feed"`
	Error     string `json:"error"`
}

func writeIntelJSON(w io.Writer, r app.IntelResult) error {
	out := struct {
		Note     string          `json:"note"`
		Run      string          `json:"run,omitempty"`
		Complete bool            `json:"complete"`
		Skipped  int             `json:"skipped_non_ip,omitempty"`
		Results  []intelRowJSON  `json:"results"`
		Failures []intelFailJSON `json:"failures"`
	}{Note: intelNote, Run: r.Run, Complete: r.Complete(), Skipped: r.Skipped,
		Results: []intelRowJSON{}, Failures: []intelFailJSON{}}
	for _, x := range r.Rows {
		out.Results = append(out.Results, intelRowJSON{x.Indicator, x.Source, x.Verdict, x.Observed.Format(time.RFC3339)})
	}
	for _, x := range r.Failures {
		out.Failures = append(out.Failures, intelFailJSON{x.Indicator, x.Feed, errText(x.Err)})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
