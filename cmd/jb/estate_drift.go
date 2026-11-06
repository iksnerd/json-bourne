package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/adapters/rdap"
	"github.com/iksnerd/json-bourne/internal/app"
)

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
			"resolver is a different method, and its answers are listed as not comparable.\n\n" + jb.EstateExternalNote + "\n\n" + estateSkipNote,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			if err := errors.Join(rejectZero(cmd, "max-targets", maxTargets), rejectZero(cmd, "timeout", timeout)); err != nil {
				return usageErrorf("%v", err)
			}
			res, err := jb.EstateRefresh(cmd.Context(), caseDir, jb.EstateRefreshOptions{EstateOptions: d.estateOptions(file),
				Config: cfgPath, RDAPURL: rdapURL, Resolver: resolver, Timeout: timeout, MaxTargets: maxTargets})
			if err != nil {
				return err
			}
			var perr error
			if output == "json" {
				perr = writeIndentedJSON(cmd.OutOrStdout(), res)
			} else {
				perr = writeRefreshTable(cmd.OutOrStdout(), res)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			if !res.Complete() {
				return fmt.Errorf("estate refresh incomplete, no clean result: %d lookup(s) did not get a full answer; snapshot %s is marked incomplete and is not a baseline", len(res.Failures), res.Snapshot)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&cfgPath, "config", "", "config with the `estate:` section (default: the config whose `commands:` lists this command, else the case's only config)")
	f.StringVar(&file, "file", jb.EstateDefaultFile, "the baseline estate file whose targets are re-asked")
	f.StringVar(&rdapURL, "rdap-url", rdap.DefaultBaseURL, "RDAP service base URL")
	f.StringVar(&resolver, "resolver", "", "DNS resolver HOST:PORT for PTR and forward lookups (default: the system resolver)")
	f.DurationVar(&timeout, "timeout", jb.EstateDefaultTimeout, "timeout for each request")
	f.IntVar(&maxTargets, "max-targets", jb.EstateDefaultMax, fmt.Sprintf("most distinct targets in one run, at most %d; more is refused, not truncated", jb.EstateMax))
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeRefreshTable(w io.Writer, r *jb.EstateRefreshResult) error {
	fmt.Fprintf(w, "snapshot    %s\n", r.Snapshot)
	fmt.Fprintf(w, "file        %s\n", r.File)
	fmt.Fprintf(w, "based on    %s (not modified; `jb estate promote` adopts a complete snapshot)\n", r.BasedOn)
	fmt.Fprintf(w, "complete    %v\n", r.Complete())
	fmt.Fprintf(w, "recorded    %d node(s), %d edge(s), %d absence(s)\n", r.Nodes, r.Edges, r.Absences)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tSTATE\tTARGETS\tNOTE")
	for _, sv := range r.Services {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", sv.Name, strings.ToUpper(sv.State), sv.Targets, sv.Reason)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "note        %s\n", r.Note)
	if len(r.Failures) == 0 {
		return nil
	}
	fmt.Fprintf(w, "\nNO FULL ANSWER (failed lookups are not stored):\n")
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tLOOKUP\tREASON")
	for i, x := range r.Failures {
		if i == estateMaxFailsShow {
			fmt.Fprintf(tw, "...\t\t%d more (use --output json for all)\n", len(r.Failures)-i)
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", x.Target, x.Lookup, x.Reason)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nINCOMPLETE: %d lookup(s) got no full answer; this snapshot is not a baseline.\n", len(r.Failures))
	return nil
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
			"drift.\n\n" + jb.EstateDriftNote,
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
			res, derr := jb.EstateDiff(cmd.Context(), caseDir, jb.EstateDiffOptions{EstateOptions: d.estateOptions(file),
				From: from, To: to, Alert: alert, Config: cfgPath, TTL: ttl, Out: cmd.ErrOrStderr()})
			if res == nil {
				return derr
			}
			var perr error
			if output == "json" {
				perr = writeIndentedJSON(cmd.OutOrStdout(), res)
			} else {
				perr = writeDiffTable(cmd.OutOrStdout(), res)
			}
			if perr != nil {
				return fmt.Errorf("write output: %w", perr)
			}
			if derr != nil {
				return derr
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	f.StringVar(&file, "file", jb.EstateDefaultFile, "the baseline estate file, the default --from")
	f.StringVar(&from, "from", "", "the earlier state: snapshot id, or estate file name (default: --file)")
	f.StringVar(&to, "to", "", "the later state: snapshot id, or estate file name (default: the newest snapshot)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	f.BoolVar(&alert, "alert", false, "send findings that are new to the case's alert sinks (log in the evidence directory, and any webhook)")
	f.StringVar(&cfgPath, "config", "", "with --alert: the config whose `alerts:` apply (default: the config whose `commands:` lists this command, else the case's only config)")
	f.Var((*windowValue)(&ttl), "ttl", "with --alert: how long an alerted tag stays quiet unless its severity rises")
	return cmd
}

func writeDiffTable(w io.Writer, r *jb.EstateDiffResult) error {
	df := r.EstateComparison
	side := func(label string, s app.DriftSide) {
		fmt.Fprintf(w, "%-8s %s (%s): %d node(s), %d edge(s), %d absence(s), latest observation %s\n", label, s.Ref, s.Path, s.Nodes, s.Edges, s.Absences, s.Observed)
	}
	side("from", df.From)
	side("to", df.To)
	fmt.Fprintf(w, "compared %d question(s) (same source and same method); %d not comparable\n", df.Compared, len(df.NotComparable))
	all, nodes, edges, absences := r.Counts["all"], r.Counts["nodes"], r.Counts["edges"], r.Counts["absences"]
	fmt.Fprintf(w, "changes  %d added, %d removed, %d changed (nodes %d/%d/%d, edges %d/%d/%d, absences %d/%d/%d)\n",
		all.Added, all.Removed, all.Changed,
		nodes.Added, nodes.Removed, nodes.Changed,
		edges.Added, edges.Removed, edges.Changed,
		absences.Added, absences.Removed, absences.Changed)
	fmt.Fprintf(w, "note     %s\n", r.Note)
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
	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "\nFINDINGS")
		for _, f := range r.Findings {
			fmt.Fprintf(w, "[%s] %s  (tag %s)\n", f.Severity, f.Summary, f.Tag)
		}
	} else {
		fmt.Fprintln(w, "\nno findings")
	}
	if r.Alerts != nil {
		fmt.Fprintf(w, "\nalerts   %d new, %d held back (already alerted within the ttl)\n", r.Alerts.New, r.Alerts.Suppressed)
	}
	return nil
}

// ---- promote ----

func newEstatePromoteCmd(d deps) *cobra.Command {
	var caseDir, file, output string
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
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			res, err := jb.EstatePromote(caseDir, args[0], d.estateOptions(file))
			if err != nil {
				return err
			}
			if output == "json" {
				return writeIndentedJSON(cmd.OutOrStdout(), res)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "promoted    %s\nbaseline    %s\nold baseline kept at %s\n", res.Promoted, res.Baseline, res.Archived)
			return nil
		},
	}
	cmd.Flags().StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md) (required)")
	cmd.Flags().StringVar(&file, "file", jb.EstateDefaultFile, "the baseline estate file to replace")
	cmd.Flags().StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}
