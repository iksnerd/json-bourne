package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/dnsptr"
	"github.com/iksnerd/json-bourne/internal/adapters/rdap"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// estateNote is printed with every result, in every format, next to the data so it
// travels with a pasted table.
const estateNote = "An estate map shows who holds and runs infrastructure, not who typed the commands. " +
	"A CDN or proxy edge address's ownership says nothing about the visitor behind it. " +
	"Lookups went to a DNS resolver and an RDAP service only; no address was contacted."

const (
	estateDefaultFile  = "estate.yaml"
	estateDefaultMax   = 20
	estateHardMax      = 100
	estateDefaultTO    = 10 * time.Second
	estateMaxFailsShow = 25
)

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
			"registration of the range that covers it, and merges the answers into a jb.estate/v1 file in the\n" +
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
			estateNote,
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
			if maxIPs < 1 || maxIPs > estateHardMax {
				return usageErrorf("--max-ips must be 1 to %d, got %d", estateHardMax, maxIPs)
			}
			if timeout < time.Second || timeout > time.Minute {
				return usageErrorf("--timeout must be 1s to 1m, got %s", timeout)
			}
			if err := casefile.ValidEstateName(file); err != nil {
				return usageErrorf("--file: %v", err)
			}
			addrs := make([]netip.Addr, 0, len(args))
			for _, a := range args {
				ip, err := netip.ParseAddr(strings.TrimSpace(a))
				if err != nil || ip.Zone() != "" {
					return usageErrorf("%q is not an IP address", a)
				}
				addrs = append(addrs, ip.Unmap())
			}

			// The flags are checked even when a test replaces the adapters.
			rc, err := rdap.New(rdapURL)
			if err != nil {
				return usageErrorf("--rdap-url: %v", err)
			}
			rc.Timeout = timeout
			pr, err := buildResolver(resolver, timeout, addrs)
			if err != nil {
				return usageErrorf("--resolver: %v", err)
			}
			var reg core.RDAPRegistry = rc
			var ptr core.PTRResolver = pr
			if d.rdap != nil {
				reg = d.rdap
			}
			if d.ptr != nil {
				ptr = d.ptr
			}

			c, err := casefile.Load(caseDir)
			if err != nil {
				return err
			}
			base := &casefile.Estate{APIVersion: casefile.EstateAPIVersion, ID: "estate", Caveat: casefile.DefaultEstateCaveat}
			existing, err := casefile.LoadEstateFile(c, file)
			switch {
			case err == nil:
				base = existing
			case !errors.Is(err, fs.ErrNotExist):
				// Never replace a file that could not be read: it may hold evidence.
				return err
			}

			res, cerr := app.CollectEstate(cmd.Context(), app.EstateDeps{PTR: ptr, RDAP: reg, Now: d.now},
				app.EstateRequest{IPs: args, MaxIPs: maxIPs})
			if cerr != nil {
				if errors.Is(cerr, app.ErrTooManyIPs) {
					return usageErrorf("%v", cerr)
				}
				return cerr
			}
			merged, mr := casefile.MergeEstate(base, res.Estate)
			wrote := mr.AddedNodes+mr.AddedEdges+mr.AddedAbsences > 0
			if wrote {
				if err := casefile.SaveEstateFile(c, file, merged); err != nil {
					return err
				}
			}
			rep := estateRun{File: c.Paths.Estate + "/" + file, Wrote: wrote, Merge: mr, Failures: res.Failures, Addresses: len(res.IPs)}
			var perr error
			if output == "json" {
				perr = writeEstateJSON(cmd.OutOrStdout(), rep)
			} else {
				perr = writeEstateTable(cmd.OutOrStdout(), rep)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			switch {
			case len(res.Failures) > 0:
				return fmt.Errorf("estate incomplete, no clean result: %d lookup(s) did not get an answer", len(res.Failures))
			case len(mr.Conflicts) > 0:
				return fmt.Errorf("estate has %d conflict(s) with what is already recorded; nothing was overwritten", len(mr.Conflicts))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&file, "file", estateDefaultFile, "estate file name inside the case's estate directory (created if missing, merged into if present)")
	f.StringVar(&rdapURL, "rdap-url", rdap.DefaultBaseURL, "RDAP service base URL (the rdap.org bootstrap redirects to the registry that holds the address)")
	f.StringVar(&resolver, "resolver", "", "DNS resolver HOST:PORT for the PTR lookups (default: the system resolver)")
	f.DurationVar(&timeout, "timeout", estateDefaultTO, "timeout for each lookup")
	f.IntVar(&maxIPs, "max-ips", estateDefaultMax, fmt.Sprintf("most addresses in one run, at most %d; more is refused, not truncated", estateHardMax))
	f.StringVar(&output, "output", "table", "output format: table or json")
	cmd.AddCommand(newEstateExtCmds(d)...)
	cmd.AddCommand(newEstateDriftCmds(d)...)
	return cmd
}

// buildResolver returns the PTR adapter. A custom resolver is a host:port that is not
// one of the addresses being looked up.
func buildResolver(spec string, timeout time.Duration, targets []netip.Addr) (core.PTRResolver, error) {
	r := dnsptr.New(nil, "system resolver")
	r.Timeout = timeout
	if spec == "" {
		return r, nil
	}
	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("%q must be HOST:PORT", spec)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("%q has no valid port", spec)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		for _, t := range targets {
			if a.Unmap() == t {
				return nil, fmt.Errorf("%s is one of the addresses being investigated; it cannot be the resolver", host)
			}
		}
	}
	r.R = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, spec)
	}}
	r.Label = "resolver " + spec
	return r, nil
}

type estateRun struct {
	File      string
	Wrote     bool
	Addresses int
	Merge     casefile.MergeResult
	Failures  []app.EstateFailure
}

func writeEstateTable(w io.Writer, r estateRun) error {
	fmt.Fprintf(w, "addresses   %d\n", r.Addresses)
	fmt.Fprintf(w, "file        %s\n", r.File)
	fmt.Fprintf(w, "recorded    +%d node(s), +%d edge(s), +%d absence(s); %d already recorded", r.Merge.AddedNodes, r.Merge.AddedEdges, r.Merge.AddedAbsences, r.Merge.Unchanged)
	if !r.Wrote {
		fmt.Fprint(w, " (file not changed)")
	}
	fmt.Fprintf(w, "\nnote        %s\n", estateNote)
	if len(r.Merge.Conflicts) > 0 {
		fmt.Fprintf(w, "\nCONFLICT (reported, nothing overwritten):\n")
		for _, c := range r.Merge.Conflicts {
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
		fmt.Fprintf(tw, "%s\t%s\t%s\n", x.IP, x.Lookup, oneLine(errText(x.Err)))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no answer; this is not a clean result.\n", len(r.Failures))
	return nil
}

func writeEstateJSON(w io.Writer, r estateRun) error {
	type fail struct {
		IP     string `json:"ip"`
		Lookup string `json:"lookup"`
		Error  string `json:"error"`
	}
	out := struct {
		Note      string   `json:"note"`
		File      string   `json:"file"`
		Complete  bool     `json:"complete"`
		Wrote     bool     `json:"wrote"`
		Addresses int      `json:"addresses"`
		Added     any      `json:"added"`
		Unchanged int      `json:"unchanged"`
		Failures  []fail   `json:"failures"`
		Conflicts []string `json:"conflicts"`
	}{Note: estateNote, File: r.File, Complete: len(r.Failures) == 0, Wrote: r.Wrote, Addresses: r.Addresses,
		Added:     map[string]int{"nodes": r.Merge.AddedNodes, "edges": r.Merge.AddedEdges, "absences": r.Merge.AddedAbsences},
		Unchanged: r.Merge.Unchanged, Failures: []fail{}, Conflicts: []string{}}
	out.Conflicts = append(out.Conflicts, r.Merge.Conflicts...)
	for _, x := range r.Failures {
		out.Failures = append(out.Failures, fail{x.IP, x.Lookup, errText(x.Err)})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
