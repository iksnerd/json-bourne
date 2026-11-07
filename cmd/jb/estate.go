package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/adapters/rdap"
	"github.com/iksnerd/json-bourne/internal/estateseam"
)

const estateMaxFailsShow = 25

// rejectZero refuses a limit or timeout given as 0. The library reads 0 as "the
// default", which on the command line is what leaving the flag out means.
func rejectZero[T ~int | ~int64](cmd *cobra.Command, flag string, v T) error {
	if v == 0 && cmd.Flags().Changed(flag) {
		return usageErrorf("--%s must not be 0", flag)
	}
	return nil
}

// estateOptions are the options every estate command shares, from the process-level inputs.
func (d deps) estateOptions(file string) jb.EstateOptions {
	return jb.EstateOptions{File: file, Env: d.env, Now: d.now}
}

// estateCtx carries the test doubles of the adapters (see [estateseam]) into the library call.
func (d deps) estateCtx(ctx context.Context) context.Context {
	return estateseam.With(ctx, estateseam.Ports{PTR: d.ptr, RDAP: d.rdap, BGP: d.bgp, CT: d.ct, DNS: d.fwd, Sleep: d.sleep})
}

func newEstateCmdWith(d deps) *cobra.Command {
	var (
		caseDir  string
		file     string
		rdapURL  string
		resolver string
		timeout  time.Duration
		maxIPs   int
		output   string
	)
	cmd := &cobra.Command{
		Use:   "estate --case DIR IP [IP ...]",
		Short: "Record who holds an address (reverse DNS and RDAP) into the case's estate file",
		Long: "estate asks, for each address, a DNS resolver for its PTR record and an RDAP service for the\n" +
			"registration of the range that covers it, and merges the answers into a jb.estate/v2 file in the\n" +
			"case's estate directory (docs/CASE-SPEC.md section 4.5). Every node, edge and absence is stamped\n" +
			"with its source, the method (the exact query) and the time.\n\n" +
			"It is passive: queries go to the resolver and the RDAP service, never to the address, and the\n" +
			"HTTP dialer refuses a connection to it. Lookups are timed out, responses are size-limited and\n" +
			"the number of addresses per run is capped (a larger list is refused, not truncated).\n\n" +
			"A lookup that failed, timed out, was rate limited or got a non-2xx answer is never data: it is\n" +
			"listed, the run ends with INCOMPLETE and exit status 1, and nothing is stored for it. A real\n" +
			"not-found (HTTP 404, NXDOMAIN) is an answer and is recorded as an absence. A claim that\n" +
			"disagrees with one already in the file is reported as a CONFLICT, the recorded one stays, and\n" +
			"the run exits 1. Rewriting the file does not preserve comments.\n\n" +
			jb.EstateNote,
		RunE: func(cmd *cobra.Command, args []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if len(args) == 0 {
				return usageErrorf("give at least one IP address")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			if err := errors.Join(rejectZero(cmd, "max-ips", maxIPs), rejectZero(cmd, "timeout", timeout)); err != nil {
				return usageErrorf("%v", err)
			}
			res, err := jb.EstateIP(d.estateCtx(cmd.Context()), caseDir, args, jb.EstateIPOptions{EstateOptions: d.estateOptions(file),
				RDAPURL: rdapURL, Resolver: resolver, Timeout: timeout, MaxIPs: maxIPs})
			if err != nil {
				return err
			}
			var perr error
			if output == "json" {
				perr = writeIndentedJSON(cmd.OutOrStdout(), res)
			} else {
				perr = writeEstateTable(cmd.OutOrStdout(), res)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			switch {
			case !res.Complete():
				return fmt.Errorf("estate incomplete, no clean result: %d lookup(s) did not get an answer", len(res.Failures))
			case len(res.Conflicts) > 0:
				return fmt.Errorf("estate has %d conflict(s) with what is already recorded; nothing was overwritten", len(res.Conflicts))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&file, "file", jb.EstateDefaultFile, "estate file name inside the case's estate directory (created if missing, merged into if present)")
	f.StringVar(&rdapURL, "rdap-url", rdap.DefaultBaseURL, "RDAP service base URL (the rdap.org bootstrap redirects to the registry that holds the address)")
	f.StringVar(&resolver, "resolver", "", "DNS resolver HOST:PORT for the PTR lookups (default: the system resolver)")
	f.DurationVar(&timeout, "timeout", jb.EstateDefaultTimeout, "timeout for each lookup")
	f.IntVar(&maxIPs, "max-ips", jb.EstateDefaultMax, fmt.Sprintf("most addresses in one run, at most %d; more is refused, not truncated", jb.EstateMax))
	f.StringVar(&output, "output", "table", "output format: table or json")
	cmd.AddCommand(newEstateExtCmds(d)...)
	cmd.AddCommand(newEstateDriftCmds(d)...)
	cmd.AddCommand(newEstateFactsCmd(d))
	return cmd
}

func writeEstateTable(w io.Writer, r *jb.EstateIPResult) error {
	fmt.Fprintf(w, "addresses   %d\n", r.Addresses)
	fmt.Fprintf(w, "file        %s\n", r.File)
	fmt.Fprintf(w, "recorded    +%d node(s), +%d edge(s), +%d absence(s); %d already recorded", r.Added.Nodes, r.Added.Edges, r.Added.Absences, r.Unchanged)
	if !r.Wrote {
		fmt.Fprint(w, " (file not changed)")
	}
	fmt.Fprintf(w, "\nnote        %s\n", r.Note)
	if len(r.Conflicts) > 0 {
		fmt.Fprintf(w, "\nCONFLICT (reported, nothing overwritten):\n")
		for _, c := range r.Conflicts {
			fmt.Fprintf(w, "  %s\n", oneLine(c))
		}
	}
	if len(r.Failures) == 0 {
		return nil
	}
	fmt.Fprintf(w, "\nCOULD NOT ASK (not an answer, not stored):\n")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS\tLOOKUP\tREASON")
	for i, x := range r.Failures {
		if i == estateMaxFailsShow {
			fmt.Fprintf(tw, "...\t\t%d more (use --output json for all)\n", len(r.Failures)-i)
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", x.IP, x.Lookup, oneLine(x.Error))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no answer; this is not a clean result.\n", len(r.Failures))
	return nil
}
