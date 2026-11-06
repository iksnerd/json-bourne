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
	"github.com/iksnerd/json-bourne/internal/adapters/crtsh"
	"github.com/iksnerd/json-bourne/internal/config"
)

// extSpec is what differs between `estate asn`, `estate dns` and `estate ct`: the help
// text, the estate.external entry and the library function. Defaults, bounds and the
// adapters are the library's.
type extSpec struct {
	use, short, long string
	service          string // the estate.external entry that enables it
	call             func(ctx context.Context, caseDir string, targets []string, opts jb.EstateExternalOptions) (*jb.EstateExternalResult, error)
}

// estateExtSpecs are the three external collectors: what each asks, where, and how to build it.
func estateExtSpecs() []extSpec {
	return []extSpec{
		{
			use:   "asn --case DIR AS|IP [AS|IP ...]",
			short: "Record the prefixes an AS announces, or the route that covers an address (BGP data, third party)",
			long: "asn asks a public BGP data API (config estate.bgp_url, RIPEstat-style) which prefixes an AS number\n" +
				"announces and who holds it, or which route covers an address and which AS originates it, and\n" +
				"merges the answers into the case's estate file (source bgp).\n\n" +
				"This is a third-party service: the AS numbers and addresses you ask about are sent to it.",
			service: config.EstateBGP,
			call:    jb.EstateASN,
		},
		{
			use:   "dns --case DIR DOMAIN [DOMAIN ...]",
			short: "Record the A, AAAA, CNAME, MX, NS and SPF records of a domain you are authorised to profile",
			long: "dns asks a DNS resolver for the forward records of each domain (A, AAAA, CNAME, MX, NS and the\n" +
				"SPF policy among the TXT records; other TXT values are never read into the file) and merges the\n" +
				"answers into the case's estate file (source dns).\n\n" +
				"Use it for a domain you own or are authorised to profile. The names you ask about are sent to the\n" +
				"resolver, which asks the domain's own name servers on your behalf: jb never connects to the domain\n" +
				"or to any address it resolves to. --resolver cannot be a name inside the domain.",
			service: config.EstateDNS,
			call:    jb.EstateDNS,
		},
		{
			use:   "ct --case DIR DOMAIN [DOMAIN ...]",
			short: "Record candidate subdomains from certificate transparency (crt.sh, third party)",
			long: "ct asks a certificate transparency search (config estate.crtsh_url, crt.sh-style JSON) which names\n" +
				"appear on publicly logged certificates for each domain, and merges them into the case's estate\n" +
				"file as domain -> host edges (source crt.sh). The edges are candidates: inferred, never stated.\n\n" +
				"This is a third-party service: the domain names you ask about are sent to it. A result larger\n" +
				"than --max-names is cut and the run ends INCOMPLETE; the names kept are real, the rest unknown.",
			service: config.EstateCrtsh,
			call:    jb.EstateCT,
		},
	}
}

func newEstateExtCmds(d deps) []*cobra.Command {
	var cmds []*cobra.Command
	for _, s := range estateExtSpecs() {
		cmds = append(cmds, newExtCmd(d, s))
	}
	return cmds
}

func newExtCmd(d deps, s extSpec) *cobra.Command {
	var (
		caseDir, cfgPath, file, resolver, output string
		timeout, interval                        time.Duration
		maxTargets, maxNames                     int
	)
	isCT := s.service == config.EstateCrtsh
	cmd := &cobra.Command{
		Use:   s.use,
		Short: s.short,
		Long: s.long + "\n\n" +
			"Off by default. The service must be listed in `estate.external` in the case's config (docs/CONFIG.md);\n" +
			"until it is, nothing is sent and the command refuses. Requests are timed out, size-limited, spaced by\n" +
			"--min-interval and capped by --max-targets (a longer list is refused, not truncated).\n\n" +
			"A lookup that failed, timed out, was rate limited, got a non-2xx answer or was cut at a cap is listed,\n" +
			"the run ends with INCOMPLETE and exit status 1, and nothing is stored for a failed lookup. A real\n" +
			"not-found is an answer and is recorded as an absence. A claim that disagrees with one already in the\n" +
			"file is a CONFLICT: the recorded one stays and the run exits 1.\n\n" + jb.EstateExternalNote,
		RunE: func(cmd *cobra.Command, args []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if len(args) == 0 {
				return usageErrorf("give at least one target")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			rejects := []error{rejectZero(cmd, "max-targets", maxTargets), rejectZero(cmd, "timeout", timeout)}
			if isCT {
				rejects = append(rejects, rejectZero(cmd, "max-names", maxNames))
			}
			if err := errors.Join(rejects...); err != nil {
				return usageErrorf("%v", err)
			}
			opts := jb.EstateExternalOptions{EstateOptions: d.estateOptions(file), Config: cfgPath,
				Timeout: timeout, MinInterval: interval, NoMinInterval: interval == 0, MaxTargets: maxTargets,
				Resolver: resolver, MaxNames: maxNames}
			res, err := s.call(cmd.Context(), caseDir, args, opts)
			if err != nil {
				return err
			}
			var perr error
			if output == "json" {
				perr = writeIndentedJSON(cmd.OutOrStdout(), res)
			} else {
				perr = writeExtTable(cmd.OutOrStdout(), res)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			switch {
			case !res.Complete():
				return fmt.Errorf("estate incomplete, no clean result: %d lookup(s) did not get a full answer", len(res.Failures))
			case len(res.Conflicts) > 0:
				return fmt.Errorf("estate has %d conflict(s) with what is already recorded; nothing was overwritten", len(res.Conflicts))
			}
			return nil
		},
	}
	defTimeout, defInterval := jb.EstateExternalDefaults(s.service)
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&cfgPath, "config", "", "config with the `estate:` section (default: the case's only config)")
	f.StringVar(&file, "file", jb.EstateDefaultFile, "estate file name inside the case's estate directory (created if missing, merged into if present)")
	f.DurationVar(&timeout, "timeout", defTimeout, "timeout for each request")
	f.DurationVar(&interval, "min-interval", defInterval, "least time between two requests")
	f.IntVar(&maxTargets, "max-targets", jb.EstateExternalDefaultMax, fmt.Sprintf("most targets in one run, at most %d; more is refused, not truncated", jb.EstateExternalMax))
	f.StringVar(&output, "output", "table", "output format: table or json")
	if s.service == config.EstateDNS {
		f.StringVar(&resolver, "resolver", "", "DNS resolver HOST:PORT (default: the system resolver)")
	}
	if isCT {
		f.IntVar(&maxNames, "max-names", crtsh.DefaultMaxNames, "most distinct names kept per domain, at most 2000; more ends the run INCOMPLETE")
	}
	return cmd
}

func writeExtTable(w io.Writer, r *jb.EstateExternalResult) error {
	fmt.Fprintf(w, "service     %s (asked: %s)\n", r.Service, r.Asked)
	fmt.Fprintf(w, "targets     %d\n", len(r.Targets))
	fmt.Fprintf(w, "file        %s\n", r.File)
	fmt.Fprintf(w, "recorded    +%d node(s), +%d edge(s), +%d absence(s); %d already recorded", r.Added.Nodes, r.Added.Edges, r.Added.Absences, r.Unchanged)
	if !r.Wrote {
		fmt.Fprint(w, " (file not changed)")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "note        %s\n", r.Note)
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note        %s\n", oneLine(n))
	}
	if len(r.Conflicts) > 0 {
		fmt.Fprintf(w, "\nCONFLICT (reported, nothing overwritten):\n")
		for _, c := range r.Conflicts {
			fmt.Fprintf(w, "  %s\n", oneLine(c))
		}
	}
	if len(r.Failures) == 0 {
		return nil
	}
	fmt.Fprintf(w, "\nNO FULL ANSWER (failed lookups are not stored; a truncated one keeps only what was read):\n")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tLOOKUP\tREASON")
	for i, x := range r.Failures {
		if i == estateMaxFailsShow {
			fmt.Fprintf(tw, "...\t\t%d more (use --output json for all)\n", len(r.Failures)-i)
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", x.Target, x.Lookup, oneLine(x.Error))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no full answer; this is not a clean result.\n", len(r.Failures))
	return nil
}
