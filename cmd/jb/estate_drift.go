package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/rdap"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

const driftStateFile = "estate-drift-state.json"
const driftLogFile = "estate-drift.log"

// estateDriftNote travels with every drift result, in every format.
const estateDriftNote = "Drift is a difference between two passive observations of the estate, not proof of compromise and not attribution: " +
	"an address, prefix or origin AS that belongs to a CDN, proxy or shared host changes for reasons that say nothing about ownership. " +
	"Only observations made by the same source and the same method are compared; anything else is listed as not comparable. " +
	"A name on a certificate is a candidate, not a live host. An estate map shows infrastructure, not who typed the commands."

// estateSkipNote is the standing statement about what is not here.
const estateSkipNote = "jb does not port wha's active estate checks (port scans, HTTP or TLS probes of the estate's own hosts, GitHub lookups): " +
	"jb is passive only, and an active check against an owned asset needs an authorisation model jb does not have (docs/POLICY.md)."

func newEstateDriftCmds(d deps) []*cobra.Command {
	return []*cobra.Command{newEstateRefreshCmd(d), newEstateDiffCmd(d), newEstatePromoteCmd(d)}
}

// ---- refresh ----

func newEstateRefreshCmd(d deps) *cobra.Command {
	var (
		caseDir, cfgPath, file, rdapURL, resolver, output string
		timeout                                           time.Duration
		maxTargets                                        int
	)
	cmd := &cobra.Command{
		Use:   "refresh --case DIR",
		Short: "Ask again what the estate file already records and keep the answers as a new dated snapshot",
		Long: "refresh reads the targets out of the case's estate file (the domains, addresses and AS numbers it records\n" +
			"as having been asked about), re-runs the passive collectors for them, and writes the result to a NEW file,\n" +
			"<estate>/snapshots/<UTC time>.yaml (docs/CASE-SPEC.md section 4.5.1). The estate file is not touched: a\n" +
			"snapshot becomes the baseline only when you run `jb estate promote`. An existing snapshot is never overwritten.\n\n" +
			"It is passive. Reverse DNS and RDAP for addresses always run; BGP, DNS and certificate transparency run only\n" +
			"for services listed under `estate.external` in the case's config (docs/CONFIG.md). A service that is not\n" +
			"enabled is SKIPPED and listed, and nothing is sent for it. The run is bounded: --max-targets counts distinct\n" +
			"targets, and a longer list is refused, not truncated; each service keeps its request spacing and caps.\n\n" +
			"Any lookup that failed, timed out, was rate limited, was cut at a cap or was not asked makes the run\n" +
			"INCOMPLETE: the snapshot is still written, marked `complete: false` with the reasons, the command exits 1,\n" +
			"and `jb estate diff` and `jb estate promote` refuse it. A real not-found is an answer and is recorded.\n\n" +
			"To keep a diff meaningful, refresh with the same --resolver and --rdap-url as the baseline: a different\n" +
			"resolver is a different method, and its answers are listed as not comparable.\n\n" + estateExtNote + "\n\n" + estateSkipNote,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			if maxTargets < 1 || maxTargets > estateHardMax {
				return usageErrorf("--max-targets must be 1 to %d, got %d", estateHardMax, maxTargets)
			}
			if timeout < time.Second || timeout > time.Minute {
				return usageErrorf("--timeout must be 1s to 1m, got %s", timeout)
			}
			if err := casefile.ValidEstateName(file); err != nil {
				return usageErrorf("--file: %v", err)
			}
			c, err := casefile.Load(caseDir)
			if err != nil {
				return err
			}
			base, err := casefile.LoadEstateFile(c, file)
			if err != nil {
				return fmt.Errorf("baseline: %w", err) // a missing or corrupt baseline is never an empty one
			}
			targets := app.EstateTargets(base)

			// The switches come from the case's config. No config means nothing external.
			var cfg *config.File
			if cfgFile, cerr := chooseCaseConfig(c, cfgPath, "estate"); cerr == nil {
				if cfg, cerr = config.Load(cfgFile); cerr != nil {
					return cerr
				}
			} else if !isUsage(cerr) {
				return cerr
			}
			enabled := func(s string) bool { return cfg != nil && cfg.EstateEnabled(s) }

			rd := app.RefreshDeps{Enabled: enabled, Now: d.now}
			rd.Estate.Now = d.now
			rd.Ext.Now, rd.Ext.Sleep = d.now, d.sleep
			// Address lookups (rdns, rdap).
			var addrs []netip.Addr
			for _, a := range targets.Addresses {
				ip, perr := netip.ParseAddr(a)
				if perr != nil {
					return fmt.Errorf("estate file records %q as an address target, which does not parse", a)
				}
				addrs = append(addrs, ip)
			}
			if len(addrs) > 0 {
				rc, err := rdap.New(rdapURL)
				if err != nil {
					return usageErrorf("--rdap-url: %v", err)
				}
				rc.Timeout = timeout
				pr, err := buildResolver(resolver, timeout, addrs)
				if err != nil {
					return usageErrorf("--resolver: %v", err)
				}
				rd.Estate.PTR, rd.Estate.RDAP = pr, rc
				if d.ptr != nil {
					rd.Estate.PTR = d.ptr
				}
				if d.rdap != nil {
					rd.Estate.RDAP = d.rdap
				}
			}
			// External collectors: built only when enabled and there is something to ask.
			req := app.RefreshRequest{Base: base, BasedOn: c.Paths.Estate + "/" + file, MaxTargets: maxTargets}
			for _, s := range estateExtSpecs() {
				if !enabled(s.service) {
					continue
				}
				var n int
				var list []string
				switch s.service {
				case config.EstateBGP:
					list = append(append(list, targets.BGPIPs...), targets.BGPASNs...)
				case config.EstateDNS:
					list = targets.DNS
				case config.EstateCrtsh:
					list = targets.CT
				}
				if n = len(list); n == 0 {
					continue
				}
				_, ed, _, berr := s.build(cfg, d, extOpts{timeout: timeout, resolver: resolver, maxNames: 500, targets: list})
				if berr != nil {
					return usageErrorf("%v", berr)
				}
				switch s.service {
				case config.EstateBGP:
					rd.Ext.BGP, req.BGPInterval = ed.BGP, s.interval
				case config.EstateDNS:
					rd.Ext.DNS, req.DNSInterval = ed.DNS, s.interval
				case config.EstateCrtsh:
					rd.Ext.CT, req.CTInterval = ed.CT, s.interval
				}
			}

			snap, err := app.RefreshEstate(cmd.Context(), rd, req)
			if err != nil {
				if errors.Is(err, app.ErrTooManyTargets) || errors.Is(err, app.ErrNoTargets) {
					return usageErrorf("%v", err)
				}
				return err
			}
			rel, err := casefile.WriteEstateSnapshot(c, snap)
			if err != nil {
				return err
			}
			var perr error
			if output == "json" {
				perr = writeRefreshJSON(cmd.OutOrStdout(), rel, snap)
			} else {
				perr = writeRefreshTable(cmd.OutOrStdout(), rel, snap)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			if !snap.Complete {
				return fmt.Errorf("estate refresh incomplete, no clean result: %d lookup(s) did not get a full answer; snapshot %s is marked incomplete and is not a baseline", len(snap.Failures), snap.ID)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&cfgPath, "config", "", "config with the `estate:` section (default: the case's only config)")
	f.StringVar(&file, "file", estateDefaultFile, "the baseline estate file whose targets are re-asked")
	f.StringVar(&rdapURL, "rdap-url", rdap.DefaultBaseURL, "RDAP service base URL")
	f.StringVar(&resolver, "resolver", "", "DNS resolver HOST:PORT for PTR and forward lookups (default: the system resolver)")
	f.DurationVar(&timeout, "timeout", estateDefaultTO, "timeout for each request")
	f.IntVar(&maxTargets, "max-targets", estateDefaultMax, fmt.Sprintf("most distinct targets in one run, at most %d; more is refused, not truncated", estateHardMax))
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeRefreshTable(w io.Writer, rel string, s *casefile.EstateSnapshot) error {
	fmt.Fprintf(w, "snapshot    %s\n", s.ID)
	fmt.Fprintf(w, "file        %s\n", rel)
	fmt.Fprintf(w, "based on    %s (not modified; `jb estate promote` adopts a complete snapshot)\n", s.BasedOn)
	fmt.Fprintf(w, "complete    %v\n", s.Complete)
	fmt.Fprintf(w, "recorded    %d node(s), %d edge(s), %d absence(s)\n", len(s.Estate.Nodes), len(s.Estate.Edges), len(s.Estate.Absences))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tSTATE\tTARGETS\tNOTE")
	for _, sv := range s.Services {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", sv.Name, strings.ToUpper(sv.State), sv.Targets, sv.Reason)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "note        %s\n", estateExtNote)
	if len(s.Failures) == 0 {
		return nil
	}
	fmt.Fprintf(w, "\nNO FULL ANSWER (failed lookups are not stored):\n")
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tLOOKUP\tREASON")
	for i, x := range s.Failures {
		if i == estateMaxFailsShow {
			fmt.Fprintf(tw, "...\t\t%d more (use --output json for all)\n", len(s.Failures)-i)
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", x.Target, x.Lookup, x.Reason)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no full answer; this snapshot is not a baseline.\n", len(s.Failures))
	return nil
}

func writeRefreshJSON(w io.Writer, rel string, s *casefile.EstateSnapshot) error {
	out := struct {
		Note     string                     `json:"note"`
		Snapshot string                     `json:"snapshot"`
		File     string                     `json:"file"`
		BasedOn  string                     `json:"based_on"`
		Complete bool                       `json:"complete"`
		Nodes    int                        `json:"nodes"`
		Edges    int                        `json:"edges"`
		Absences int                        `json:"absences"`
		Services []casefile.SnapshotService `json:"services"`
		Failures []casefile.SnapshotFailure `json:"failures"`
	}{estateExtNote, s.ID, rel, s.BasedOn, s.Complete, len(s.Estate.Nodes), len(s.Estate.Edges), len(s.Estate.Absences), s.Services, s.Failures}
	if out.Failures == nil {
		out.Failures = []casefile.SnapshotFailure{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ---- diff ----

func newEstateDiffCmd(d deps) *cobra.Command {
	var (
		caseDir, cfgPath, file, from, to, output string
		alert                                    bool
		ttl                                      = app.DefaultWatchTTL
	)
	cmd := &cobra.Command{
		Use:   "diff --case DIR [--from REF] [--to REF]",
		Short: "Report what changed on the estate between two states, comparing like with like",
		Long: "diff compares two states of the estate and reports nodes, edges and absences ADDED, REMOVED and CHANGED. It\n" +
			"reads two files and sends nothing. A state is a snapshot id (20261106T100000Z), an estate file name\n" +
			"(estate.yaml) or snapshots/<id>.yaml. By default --from is the baseline estate file (--file) and --to is\n" +
			"the newest snapshot, which `jb estate refresh` writes.\n\n" +
			"Only observations made by the SAME source and the SAME method are compared: the method is the exact\n" +
			"question, including the resolver or service it went to. A question that exists on one side only, because the\n" +
			"method or the resolver changed or a service was skipped, is listed under NOT COMPARABLE with its counts; it\n" +
			"is never counted as drift and never hidden. A real not-found (an absence) is an answer: \"was present, now\n" +
			"absent\" and the reverse are changes. Every change carries the time each side observed it.\n\n" +
			"An incomplete snapshot on either side is refused (exit 1): its missing answers would read as removals.\n" +
			"A corrupt or unknown file is an error, never an empty baseline.\n\n" +
			"Findings (detector estate_drift): a new or removed NS or MX, or a changed origin AS, is high; a changed\n" +
			"address is activity; a new certificate-transparency name is check. The tag is stable for the same drift, and\n" +
			"the summary holds the subject and counts only. With --alert they go to the case's alert sinks (log,\n" +
			"webhook), held back by --ttl as `jb watch` does. Exit 0 means the comparison ran, whether or not it found\n" +
			"drift.\n\n" + estateDriftNote,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			if ttl <= 0 {
				return usageErrorf("--ttl must be positive, got %s", ttl)
			}
			if err := casefile.ValidEstateName(file); err != nil {
				return usageErrorf("--file: %v", err)
			}
			c, err := casefile.Load(caseDir)
			if err != nil {
				return err
			}
			if from == "" {
				from = file
			}
			if to == "" {
				latest, err := casefile.LatestEstateSnapshot(c)
				if err != nil {
					return err
				}
				if latest == nil {
					return usageErrorf("there is no snapshot to compare with; run `jb estate refresh --case %s` first, or name one with --to", caseDir)
				}
				to = latest.ID
			}
			fs, err := casefile.LoadEstateState(c, from)
			if err != nil {
				return fmt.Errorf("--from: %w", err)
			}
			ts, err := casefile.LoadEstateState(c, to)
			if err != nil {
				return fmt.Errorf("--to: %w", err)
			}
			diff, err := app.DiffEstates(fs, ts)
			if err != nil {
				return err
			}
			findings := app.DriftFindings(diff)

			var delivery *app.DriftDelivery
			var derr error
			if alert {
				delivery, derr = deliverDrift(cmd, d, c, cfgPath, ttl, findings)
			}
			var perr error
			if output == "json" {
				perr = writeDiffJSON(cmd.OutOrStdout(), diff, findings, delivery)
			} else {
				perr = writeDiffTable(cmd.OutOrStdout(), diff, findings, delivery)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			return derr
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&file, "file", estateDefaultFile, "the baseline estate file, the default --from")
	f.StringVar(&from, "from", "", "the earlier state: snapshot id, or estate file name (default: --file)")
	f.StringVar(&to, "to", "", "the later state: snapshot id, or estate file name (default: the newest snapshot)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	f.BoolVar(&alert, "alert", false, "send findings that are new to the case's alert sinks (log in the evidence directory, and any webhook)")
	f.StringVar(&cfgPath, "config", "", "with --alert: the config whose `alerts:` apply (default: the case's only config)")
	f.Var((*windowValue)(&ttl), "ttl", "with --alert: how long an alerted tag stays quiet unless its severity rises")
	return cmd
}

func deliverDrift(cmd *cobra.Command, d deps, c *casefile.Case, cfgFlag string, ttl time.Duration, findings []core.Finding) (*app.DriftDelivery, error) {
	if _, err := casefile.Guard(c.EvidenceDir()); err != nil {
		return nil, fmt.Errorf("refusing to write alerts into %s: %w", c.Paths.Evidence, err)
	}
	cfgFile, err := chooseCaseConfig(c, cfgFlag, "estate")
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, err
	}
	extra, err := cfg.BuildAlerts(d.env)
	if err != nil {
		return nil, err
	}
	evidence := c.EvidenceDir()
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		return nil, fmt.Errorf("evidence directory: %w", err)
	}
	logSink := &alertlog.Sink{Out: cmd.ErrOrStderr(), Path: filepath.Join(evidence, driftLogFile)}
	var sink core.AlertSink = logSink
	if len(extra) > 0 {
		sink = core.FanOut{Required: logSink, Optional: extra}
	}
	now := d.now()
	res, err := app.DeliverDrift(cmd.Context(), watchstate.Store{Path: filepath.Join(evidence, driftStateFile)}, sink, now, ttl, "estate-drift-"+casefile.SnapshotID(now), findings)
	return &res, err
}

func writeDiffTable(w io.Writer, df app.EstateDiff, findings []core.Finding, del *app.DriftDelivery) error {
	side := func(label string, s app.DriftSide) {
		fmt.Fprintf(w, "%-8s %s (%s): %d node(s), %d edge(s), %d absence(s), latest observation %s\n", label, s.Ref, s.Path, s.Nodes, s.Edges, s.Absences, s.Observed)
	}
	side("from", df.From)
	side("to", df.To)
	fmt.Fprintf(w, "compared %d question(s) (same source and same method); %d not comparable\n", df.Compared, len(df.NotComparable))
	fmt.Fprintf(w, "changes  %d added, %d removed, %d changed (nodes %d/%d/%d, edges %d/%d/%d, absences %d/%d/%d)\n",
		df.Count(app.ChangeAdded, ""), df.Count(app.ChangeRemoved, ""), df.Count(app.ChangeChanged, ""),
		df.Count(app.ChangeAdded, app.ItemNode), df.Count(app.ChangeRemoved, app.ItemNode), df.Count(app.ChangeChanged, app.ItemNode),
		df.Count(app.ChangeAdded, app.ItemEdge), df.Count(app.ChangeRemoved, app.ItemEdge), df.Count(app.ChangeChanged, app.ItemEdge),
		df.Count(app.ChangeAdded, app.ItemAbsence), df.Count(app.ChangeRemoved, app.ItemAbsence), df.Count(app.ChangeChanged, app.ItemAbsence))
	fmt.Fprintf(w, "note     %s\n", estateDriftNote)
	if len(df.Changes) > 0 {
		fmt.Fprintln(w, "\nCHANGES")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "KIND\tTYPE\tSUBJECT\tSOURCE\tFROM OBSERVED\tTO OBSERVED\tDETAIL")
		for _, c := range df.Changes {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", strings.ToUpper(c.Kind), c.Type, c.Subject, c.Source, c.FromObserved, c.ToObserved, c.Detail)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(df.NotComparable) > 0 {
		fmt.Fprintln(w, "\nNOT COMPARABLE (different source or method, not drift)")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SIDE\tSOURCE\tCLAIMS\tOBSERVED\tMETHOD")
		for _, n := range df.NotComparable {
			if n.Side == "both" {
				fmt.Fprintf(tw, "both\t-\t%d\t-\t%s\n", n.Claims, n.Reason)
				continue
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", n.Side, n.Source, n.Claims, n.Observed, oneLine(n.Method))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(findings) > 0 {
		fmt.Fprintln(w, "\nFINDINGS")
		for _, f := range findings {
			fmt.Fprintf(w, "[%s] %s  (tag %s)\n", core.SeverityName(f.Severity), f.Summary, f.Tag)
		}
	} else {
		fmt.Fprintln(w, "\nno findings")
	}
	if del != nil {
		fmt.Fprintf(w, "\nalerts   %d new, %d held back (already alerted within the ttl)\n", del.New, del.Suppressed)
	}
	return nil
}

func writeDiffJSON(w io.Writer, df app.EstateDiff, findings []core.Finding, del *app.DriftDelivery) error {
	type jf struct {
		Detector string         `json:"detector"`
		Tag      string         `json:"tag"`
		Severity string         `json:"severity"`
		Summary  string         `json:"summary"`
		Detail   map[string]any `json:"detail"`
	}
	fs := make([]jf, 0, len(findings))
	for _, f := range findings {
		fs = append(fs, jf{f.Detector, f.Tag, core.SeverityName(f.Severity), f.Summary, f.Detail})
	}
	type counts struct {
		Added   int `json:"added"`
		Removed int `json:"removed"`
		Changed int `json:"changed"`
	}
	cnt := func(typ string) counts {
		return counts{df.Count(app.ChangeAdded, typ), df.Count(app.ChangeRemoved, typ), df.Count(app.ChangeChanged, typ)}
	}
	out := struct {
		Note string `json:"note"`
		app.EstateDiff
		Counts   map[string]counts  `json:"counts"`
		Findings []jf               `json:"findings"`
		Alerts   *app.DriftDelivery `json:"alerts,omitempty"`
	}{estateDriftNote, df, map[string]counts{"all": cnt(""), "nodes": cnt(app.ItemNode), "edges": cnt(app.ItemEdge), "absences": cnt(app.ItemAbsence)}, fs, del}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ---- promote ----

func newEstatePromoteCmd(d deps) *cobra.Command {
	var caseDir, file string
	cmd := &cobra.Command{
		Use:   "promote --case DIR SNAPSHOT-ID",
		Short: "Adopt a complete snapshot as the baseline estate file (the old baseline is archived first)",
		Long: "promote copies the estate map out of a complete snapshot into the baseline estate file, so later diffs are\n" +
			"measured from it. It is the only way a snapshot becomes the baseline. The current baseline is first written to\n" +
			"<estate>/archive/ and is never overwritten there. An incomplete snapshot is refused, and so is one that skipped\n" +
			"a service, because the new baseline would silently lose that service's claims. Promoting accepts the drift the\n" +
			"snapshot shows: the next diff will no longer report it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if err := casefile.ValidEstateName(file); err != nil {
				return usageErrorf("--file: %v", err)
			}
			if !casefile.ValidSnapshotID(args[0]) {
				return usageErrorf("%q is not a snapshot id (20261106T100000Z)", args[0])
			}
			c, err := casefile.Load(caseDir)
			if err != nil {
				return err
			}
			archived, err := app.PromoteSnapshot(c, args[0], file, d.now())
			if err != nil {
				if errors.Is(err, app.ErrNotPromotable) {
					return usageErrorf("%v", err)
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "promoted    %s\nbaseline    %s/%s\nold baseline kept at %s\n", args[0], c.Paths.Estate, file, archived)
			return nil
		},
	}
	cmd.Flags().StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	cmd.Flags().StringVar(&file, "file", estateDefaultFile, "the baseline estate file to replace")
	return cmd
}
