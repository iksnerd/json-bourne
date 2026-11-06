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

	"github.com/iksnerd/json-bourne/internal/adapters/bgp"
	"github.com/iksnerd/json-bourne/internal/adapters/crtsh"
	"github.com/iksnerd/json-bourne/internal/adapters/dnsfwd"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	extDefaultMax = 10
	extHardMax    = 50
)

// extSpec is what differs between `estate asn`, `estate dns` and `estate ct`.
type extSpec struct {
	use, short, long string
	service          string        // the estate.external entry that enables it
	what             string        // what leaves the machine, for the refusal message
	interval         time.Duration // default --min-interval
	timeout          time.Duration // default --timeout
	// build returns the collector and the place the question goes, after the gate.
	build func(cfg *config.File, d deps, o extOpts) (collect extCollect, deps app.ExternalDeps, dest string, err error)
}

type extCollect func(context.Context, app.ExternalDeps, app.ExternalRequest) (app.ExternalResult, error)

// extOpts are the flags a builder reads.
type extOpts struct {
	timeout  time.Duration
	resolver string
	maxNames int
	targets  []string
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
			service:  config.EstateBGP,
			what:     "the AS numbers and addresses asked about",
			interval: time.Second, timeout: 10 * time.Second,
			build: func(cfg *config.File, d deps, o extOpts) (extCollect, app.ExternalDeps, string, error) {
				base := cfg.Estate.BGPURL
				if base == "" {
					base = bgp.DefaultBaseURL
				}
				c, err := bgp.New(base)
				if err != nil {
					return nil, app.ExternalDeps{}, "", fmt.Errorf("estate.bgp_url: %w", err)
				}
				c.Timeout = o.timeout
				var src core.BGPSource = c
				if d.bgp != nil {
					src = d.bgp
				}
				return app.CollectASN, app.ExternalDeps{BGP: src, Now: d.now}, base, nil
			},
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
			service:  config.EstateDNS,
			what:     "the domain names asked about",
			interval: 250 * time.Millisecond, timeout: 5 * time.Second,
			build: func(_ *config.File, d deps, o extOpts) (extCollect, app.ExternalDeps, string, error) {
				r, dest, err := buildForwardResolver(o.resolver, o.timeout, o.targets)
				if err != nil {
					return nil, app.ExternalDeps{}, "", fmt.Errorf("--resolver: %w", err)
				}
				var fw core.DNSForward = r
				if d.fwd != nil {
					fw = d.fwd
				}
				return app.CollectDNS, app.ExternalDeps{DNS: fw, Now: d.now}, dest, nil
			},
		},
		{
			use:   "ct --case DIR DOMAIN [DOMAIN ...]",
			short: "Record candidate subdomains from certificate transparency (crt.sh, third party)",
			long: "ct asks a certificate transparency search (config estate.crtsh_url, crt.sh-style JSON) which names\n" +
				"appear on publicly logged certificates for each domain, and merges them into the case's estate\n" +
				"file as domain -> host edges (source crt.sh). The edges are candidates: inferred, never stated.\n\n" +
				"This is a third-party service: the domain names you ask about are sent to it. A result larger\n" +
				"than --max-names is cut and the run ends INCOMPLETE; the names kept are real, the rest unknown.",
			service:  config.EstateCrtsh,
			what:     "the domain names asked about",
			interval: time.Second, timeout: 30 * time.Second,
			build: func(cfg *config.File, d deps, o extOpts) (extCollect, app.ExternalDeps, string, error) {
				base := cfg.Estate.CrtshURL
				if base == "" {
					base = crtsh.DefaultBaseURL
				}
				c, err := crtsh.New(base)
				if err != nil {
					return nil, app.ExternalDeps{}, "", fmt.Errorf("estate.crtsh_url: %w", err)
				}
				c.Timeout = o.timeout
				c.MaxNames = o.maxNames
				var src core.CTSource = c
				if d.ct != nil {
					src = d.ct
				}
				return app.CollectCT, app.ExternalDeps{CT: src, Now: d.now}, base, nil
			},
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
			"file is a CONFLICT: the recorded one stays and the run exits 1.\n\n" + estateExtNote,
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
			if maxTargets < 1 || maxTargets > extHardMax {
				return usageErrorf("--max-targets must be 1 to %d, got %d", extHardMax, maxTargets)
			}
			if timeout < time.Second || timeout > 2*time.Minute {
				return usageErrorf("--timeout must be 1s to 2m, got %s", timeout)
			}
			if interval < 0 || interval > time.Minute {
				return usageErrorf("--min-interval must be 0 to 1m, got %s", interval)
			}
			if isCT {
				if maxNames < 1 || maxNames > 2000 {
					return usageErrorf("--max-names must be 1 to 2000, got %d", maxNames)
				}
			}
			if err := casefile.ValidEstateName(file); err != nil {
				return usageErrorf("--file: %v", err)
			}
			c, err := casefile.Load(caseDir)
			if err != nil {
				return err
			}
			// The gate comes before any adapter is built and before any request.
			cfgFile, cfgErr := chooseCaseConfig(c, cfgPath, "estate")
			var cfg *config.File
			if cfgErr == nil {
				cfg, cfgErr = config.Load(cfgFile)
			}
			if cfgErr != nil && !isUsage(cfgErr) {
				return cfgErr
			}
			if cfg == nil || !cfg.EstateEnabled(s.service) {
				return usageErrorf("the %q service is not enabled, so nothing was sent. It is off by default because %s would leave this machine. "+
					"List it under `estate: {external: [%s]}` in the case's config to allow it (docs/CONFIG.md)", s.service, s.what, s.service)
			}
			collect, edeps, dest, err := s.build(cfg, d, extOpts{timeout: timeout, resolver: resolver, maxNames: maxNames, targets: args})
			if err != nil {
				return usageErrorf("%v", err)
			}
			edeps.Sleep = d.sleep

			base := &casefile.Estate{APIVersion: casefile.EstateAPIVersion, ID: "estate", Caveat: casefile.DefaultEstateCaveat}
			existing, err := casefile.LoadEstateFile(c, file)
			switch {
			case err == nil:
				base = existing
			case !errors.Is(err, fs.ErrNotExist):
				return err // never replace a file that could not be read: it may hold evidence
			}

			res, cerr := collect(cmd.Context(), edeps, app.ExternalRequest{Targets: args, MaxTargets: maxTargets, Interval: interval})
			if cerr != nil {
				return usageErrorf("%v", cerr) // the collectors fail only on bad input; a lookup failure is in res.Failures
			}
			merged, mr := casefile.MergeEstate(base, res.Estate)
			wrote := mr.AddedNodes+mr.AddedEdges+mr.AddedAbsences > 0
			if wrote {
				if err := casefile.SaveEstateFile(c, file, merged); err != nil {
					return err
				}
			}
			rep := extReport{Service: s.service, Dest: dest, File: c.Paths.Estate + "/" + file, Wrote: wrote, Merge: mr, Result: res}
			var perr error
			if output == "json" {
				perr = writeExtJSON(cmd.OutOrStdout(), rep)
			} else {
				perr = writeExtTable(cmd.OutOrStdout(), rep)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			switch {
			case len(res.Failures) > 0:
				return fmt.Errorf("estate incomplete, no clean result: %d lookup(s) did not get a full answer", len(res.Failures))
			case len(mr.Conflicts) > 0:
				return fmt.Errorf("estate has %d conflict(s) with what is already recorded; nothing was overwritten", len(mr.Conflicts))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&cfgPath, "config", "", "config with the `estate:` section (default: the case's only config)")
	f.StringVar(&file, "file", estateDefaultFile, "estate file name inside the case's estate directory (created if missing, merged into if present)")
	f.DurationVar(&timeout, "timeout", s.timeout, "timeout for each request")
	f.DurationVar(&interval, "min-interval", s.interval, "least time between two requests")
	f.IntVar(&maxTargets, "max-targets", extDefaultMax, fmt.Sprintf("most targets in one run, at most %d; more is refused, not truncated", extHardMax))
	f.StringVar(&output, "output", "table", "output format: table or json")
	if s.service == config.EstateDNS {
		f.StringVar(&resolver, "resolver", "", "DNS resolver HOST:PORT (default: the system resolver)")
	}
	if isCT {
		f.IntVar(&maxNames, "max-names", crtsh.DefaultMaxNames, "most distinct names kept per domain, at most 2000; more ends the run INCOMPLETE")
	}
	return cmd
}

func isUsage(err error) bool { return core.IsUsage(err) }

const estateExtNote = "These are candidates and observations, not proof. A name on a certificate may not be live. " +
	"An address, prefix or origin AS that belongs to a CDN, proxy or shared host says nothing about who runs the site or the visitor behind it. " +
	"An estate map shows infrastructure, not who typed the commands. No target host was contacted: the question went to the service named below."

// buildForwardResolver returns the forward-DNS adapter and where it asks. A custom
// resolver is HOST:PORT, and not a name inside any domain being profiled.
func buildForwardResolver(spec string, timeout time.Duration, domains []string) (*dnsfwd.Resolver, string, error) {
	r := dnsfwd.New(nil, "system resolver (the local hosts file may answer address and CNAME questions first)")
	r.Timeout = timeout
	if spec == "" {
		return r, "the system resolver", nil
	}
	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, "", fmt.Errorf("%q must be HOST:PORT", spec)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, "", fmt.Errorf("%q has no valid port", spec)
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(h); err != nil {
		for _, dom := range domains {
			dom, derr := app.NormaliseDomain(dom)
			if derr == nil && (h == dom || strings.HasSuffix(h, "."+dom)) {
				return nil, "", fmt.Errorf("%s is inside %s, the domain being profiled; it cannot be the resolver", host, dom)
			}
		}
	}
	r.R = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, spec)
	}}
	r.Label = "resolver " + spec + " (the local hosts file may answer address and CNAME questions first)"
	return r, "resolver " + spec, nil
}

type extReport struct {
	Service string
	Dest    string
	File    string
	Wrote   bool
	Merge   casefile.MergeResult
	Result  app.ExternalResult
}

func writeExtTable(w io.Writer, r extReport) error {
	fmt.Fprintf(w, "service     %s (asked: %s)\n", r.Service, r.Dest)
	fmt.Fprintf(w, "targets     %d\n", len(r.Result.Targets))
	fmt.Fprintf(w, "file        %s\n", r.File)
	fmt.Fprintf(w, "recorded    +%d node(s), +%d edge(s), +%d absence(s); %d already recorded", r.Merge.AddedNodes, r.Merge.AddedEdges, r.Merge.AddedAbsences, r.Merge.Unchanged)
	if !r.Wrote {
		fmt.Fprint(w, " (file not changed)")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "note        %s\n", estateExtNote)
	for _, n := range r.Result.Notes {
		fmt.Fprintf(w, "note        %s\n", oneLine(n))
	}
	if len(r.Merge.Conflicts) > 0 {
		fmt.Fprintf(w, "\nCONFLICT (reported, nothing overwritten):\n")
		for _, c := range r.Merge.Conflicts {
			fmt.Fprintf(w, "  %s\n", oneLine(c))
		}
	}
	if len(r.Result.Failures) == 0 {
		return nil
	}
	fmt.Fprintf(w, "\nNO FULL ANSWER (failed lookups are not stored; a truncated one keeps only what was read):\n")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tLOOKUP\tREASON")
	for i, x := range r.Result.Failures {
		if i == estateMaxFailsShow {
			fmt.Fprintf(tw, "...\t\t%d more (use --output json for all)\n", len(r.Result.Failures)-i)
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", x.Target, x.Lookup, oneLine(errText(x.Err)))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no full answer; this is not a clean result.\n", len(r.Result.Failures))
	return nil
}

func writeExtJSON(w io.Writer, r extReport) error {
	type fail struct {
		Target string `json:"target"`
		Lookup string `json:"lookup"`
		Error  string `json:"error"`
	}
	out := struct {
		Note      string   `json:"note"`
		Notes     []string `json:"notes"`
		Service   string   `json:"service"`
		Asked     string   `json:"asked"`
		File      string   `json:"file"`
		Complete  bool     `json:"complete"`
		Wrote     bool     `json:"wrote"`
		Targets   []string `json:"targets"`
		Added     any      `json:"added"`
		Unchanged int      `json:"unchanged"`
		Failures  []fail   `json:"failures"`
		Conflicts []string `json:"conflicts"`
	}{Note: estateExtNote, Notes: append([]string{}, r.Result.Notes...), Service: r.Service, Asked: r.Dest, File: r.File,
		Complete: len(r.Result.Failures) == 0, Wrote: r.Wrote, Targets: append([]string{}, r.Result.Targets...),
		Added:     map[string]int{"nodes": r.Merge.AddedNodes, "edges": r.Merge.AddedEdges, "absences": r.Merge.AddedAbsences},
		Unchanged: r.Merge.Unchanged, Failures: []fail{}, Conflicts: []string{}}
	out.Conflicts = append(out.Conflicts, r.Merge.Conflicts...)
	for _, x := range r.Result.Failures {
		out.Failures = append(out.Failures, fail{x.Target, x.Lookup, errText(x.Err)})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
