package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
)

// maxFailuresShown bounds the failure rows printed in the table; JSON lists them all.
const maxFailuresShown = 25

func newIntelCmdWith(d deps) *cobra.Command {
	var output string
	var fl *opFlags
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
			jb.IntelNote,
		RunE: func(cmd *cobra.Command, args []string) error {
			caseDir, cfgPath := fl.String("case"), fl.String("config")
			if cfgPath == "" && caseDir == "" {
				return usageErrorf("--config or --case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			res, ierr := jb.Intel(cmd.Context(), caseDir, args, jb.IntelOptions{Config: cfgPath, Env: d.env})
			if res == nil {
				return ierr // nothing was asked: input problem, nothing to print
			}
			for _, n := range res.Notes {
				fmt.Fprintln(cmd.ErrOrStderr(), n)
			}
			var perr error
			if output == "json" {
				perr = writeIndentedJSON(cmd.OutOrStdout(), res)
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
	fl = addOperationFlags(cmd, "intel")
	cmd.Args = fl.PositionalArgs()
	f := cmd.Flags()
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeIntelTable(w io.Writer, r *jb.IntelResult) error {
	src := "arguments"
	if r.Run != "" {
		src = "latest stored run " + r.Run
	}
	fmt.Fprintf(w, "indicators  %d from %s\n", len(r.Requested), src)
	if r.Skipped > 0 {
		fmt.Fprintf(w, "skipped     %d value(s) in the run were not IP addresses\n", r.Skipped)
	}
	fmt.Fprintf(w, "note        %s\n\n", r.Note)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INDICATOR\tFEED\tVERDICT\tOBSERVED")
	for _, x := range r.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", x.Indicator, x.Feed, x.Verdict, x.Observed)
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
		fmt.Fprintf(tw, "%s\t%s\t%s\n", x.Indicator, x.Feed, x.Error)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no answer; this is not a clean result.\n", len(r.Failures))
	return nil
}
