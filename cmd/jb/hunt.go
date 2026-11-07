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

	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

func newHuntCmd() *cobra.Command { return newHuntCmdWith(defaultDeps()) }

func newHuntCmdWith(d deps) *cobra.Command {
	var (
		cfgPath string
		caseDir string
		window  time.Duration
		output  string
		search  []string
		sfield  string
		untilS  string
		noStore bool
	)
	cmd := &cobra.Command{
		Use:   "hunt",
		Short: "Fetch a window of events, store them and run the detectors",
		Long: "hunt fetches the last --window of events (and the window before it, as the baseline),\n" +
			"stores them in the evidence database and runs every configured detector.\n" +
			"It exits 1 when any source or detector did not complete, and says which. A detector that\n" +
			"returns findings and an error has its findings listed and the detector marked incomplete.\n\n" +
			"--until TIME hunts a past window instead: [TIME - window, TIME), with the baseline the same\n" +
			"length immediately before it. TIME is RFC 3339 with a zone (2026-10-01T00:00:00Z); a time\n" +
			"without a zone, with fractions of a second, or after now is refused, and so is a window over\n" +
			"31d. Nothing else changes: the same rules, scopes, filters and INCOMPLETE test apply, and the\n" +
			"detectors read exactly the stored events inside the two windows. The run is stored as\n" +
			"hunt-until-<end>-w<seconds> (search-until-... with --search), so it never collides with a live\n" +
			"run, and hunting the same window again replaces it and counts nothing twice. See\n" +
			"docs/BACKFILL.md. A newly stored backfill is the newest run by creation time, so a later\n" +
			"`jb intel` without addresses reads it; its output names the run.\n\n" +
			"With --case DIR the hunt runs inside a case (docs/CASE-SPEC.md). The case is loaded and\n" +
			"checked as `jb case check` does, and the hunt is refused when the evidence directory is\n" +
			"not safe from git. The config is --config (one of the case's `config:` entries, or a file\n" +
			"inside the case), else the config whose `commands:` lists hunt, else the case's only config. --window defaults to the case's windows.default\n" +
			"when not given; an explicit --window wins. A relative store.path is relative to the case\n" +
			"directory, and an empty one means <case>/<paths.evidence>/jb.duckdb.\n\n" +
			"--search TERM narrows every source for this one run, on the server, by a phrase match of TERM\n" +
			"against one field (default message; a source's search_field or --search-field changes it), ANDed\n" +
			"with the configured filters. Repeat it to AND more terms (at most 4). TERM is data: at most 256\n" +
			"bytes, no control characters, never part of query text. A search that matches nothing counts\n" +
			"the same window without the filter, so the output says \"no match; index alive\" (the term is\n" +
			"absent) or that the index is empty or unreachable (nothing can be said). The detectors read the\n" +
			"stored evidence for the window, which includes earlier runs' events, not only the matches; the\n" +
			"run is stored as search-<time>.\n\n" + noStoreLong,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfgPath == "" && caseDir == "" {
				return usageErrorf("--config is required")
			}
			if window <= 0 {
				return usageErrorf("--window must be positive, got %s", window)
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			if err := config.CheckSearch(search, sfield); err != nil {
				return usageErrorf("%v", err)
			}

			var untilT time.Time
			if untilS != "" {
				var err error
				if untilT, err = parseUntil(untilS, d.now()); err != nil {
					return usageErrorf("%v", err)
				}
			}

			if err := checkUntilWindow(window, untilT); err != nil {
				return err
			}

			// The flags become the library's options; the library does the rest and hands
			// each advice line to Notice as it arises, so stderr keeps the order and timing
			// it always had.
			stderr := cmd.ErrOrStderr()
			opts := jb.HuntOptions{
				Window: window, Until: untilT, Env: d.env, Now: d.now, NoStore: noStore,
				Search: search, SearchField: sfield, ConfigPath: cfgPath,
				Notice: func(note string) { fmt.Fprintln(stderr, note) },
			}
			var res *jb.Result
			var huntErr error
			if caseDir != "" {
				if !cmd.Flags().Changed("window") {
					opts.Window = 0 // the case's windows.default, else the library's default hour
				}
				res, huntErr = jb.HuntCase(cmd.Context(), caseDir, jb.CaseHuntOptions{HuntOptions: opts, Config: cfgPath})
			} else {
				cfg, err := jb.LoadConfig(cfgPath)
				if err != nil {
					return err
				}
				res, huntErr = jb.Hunt(cmd.Context(), cfg, opts)
			}
			if res == nil {
				return huntErr
			}

			// Print whatever was learned before reporting why the hunt stopped.
			if len(res.Sources) > 0 { // none means the hunt never started (bad input)
				var perr error
				if output == "json" {
					perr = writeJSON(cmd.OutOrStdout(), res)
				} else {
					perr = writeTable(cmd.OutOrStdout(), *res)
				}
				if perr != nil && huntErr == nil {
					huntErr = fmt.Errorf("write output: %w", perr)
				}
			}
			if huntErr != nil {
				return huntErr
			}
			if res.SearchAbsent() {
				return nil // the term is absent from a live index: an answer, not a failure
			}
			if failed := res.Failed(); len(failed) > 0 {
				return fmt.Errorf("hunt incomplete, no clean result: %d component(s) did not finish: %v", len(failed), failed)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfgPath, "config", "", "path to the YAML config (required without --case; with --case, one of the case's configs)")
	f.StringVar(&caseDir, "case", "", "case directory to hunt in (docs/CASE-SPEC.md)")
	window = 60 * time.Minute
	f.Var((*windowValue)(&window), "window", "length of the window to hunt, ending now (or at --until): 90m, 24h or 7d (default 60m; with --case, the case's windows.default when it sets one)")
	f.StringVar(&output, "output", "table", "output format: table or json")
	f.StringVar(&untilS, "until", "", "hunt the past window ending at TIME (RFC 3339 with a zone, not after now) instead of the one ending now; not offered on watch, which always ends now")
	f.StringArrayVar(&search, "search", nil, "narrow every source by a phrase match of TERM for this run; repeat to AND more terms (at most 4)")
	f.BoolVar(&noStore, "no-store", false, noStoreUsage)
	f.StringVar(&sfield, "search-field", "", "field --search matches against (default: the source's search_field, else message)")
	return cmd
}

// noStoreUsage, noStoreLong and notStoredLine are the words of --no-store, shared by hunt
// and activity so the two commands cannot drift.
const (
	noStoreUsage = "run over a private temporary store that is deleted when the command returns: nothing is written to the evidence database"
	noStoreLong  = "--no-store runs the same code over a private temporary store (mode 0700, outside the case and\n" +
		"the evidence directory), deleted when the command returns. The evidence database is not opened,\n" +
		"created or changed, and the output says `not stored` (stored: false in JSON). Detectors then see\n" +
		"only the events fetched by this run, not those saved by earlier runs, so a result can differ from a\n" +
		"stored run. Use it for a question that must leave no evidence."
	notStoredLine = "not stored: this run left no evidence"
)

// sourceNote is the NOTE column of a source row: the error, or what a zero means.
func sourceNote(s app.SourceResult) string {
	if s.NoMatch() {
		return fmt.Sprintf("%s (%d document(s) in the window and the one before it without the filter)", s.NoMatchText(), s.IndexDocs)
	}
	return errText(s.Err)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeTable(w io.Writer, r app.Result) error {
	absent := r.SearchAbsent()
	fmt.Fprintf(w, "run       %s\n", r.Run)
	if !r.Stored {
		fmt.Fprintln(w, notStoredLine)
	}
	if !r.Until.IsZero() {
		fmt.Fprintf(w, "until     %s (historical window; not relative to now)\n", stamp(r.Until))
	}
	fmt.Fprintf(w, "window    %s to %s\nbaseline  %s to %s\n\n",
		r.Window.From.Format(time.RFC3339), r.Window.To.Format(time.RFC3339),
		r.Baseline.From.Format(time.RFC3339), r.Baseline.To.Format(time.RFC3339))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tSTATUS\tEVENTS\tNOTE")
	for _, s := range r.Sources {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", s.Name, s.Status, s.Events, sourceNote(s))
	}
	fmt.Fprintln(tw, "\t\t\t")
	fmt.Fprintln(tw, "DETECTOR\tSTATUS\tFINDINGS\tNOTE")
	for _, d := range r.Detectors {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", d.Name, d.Status, d.Findings, errText(d.Err))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	if note := app.DisabledNote(r.Disabled); note != "" {
		fmt.Fprintln(w, note)
	}
	for _, src := range r.Sources {
		if src.Unparsable == 0 {
			continue
		}
		fmt.Fprintf(w, "UNPARSABLE: %s received %d document(s) it could not parse (%.1f%% of %d); they are in no event.\n",
			src.Name, src.Unparsable, 100*src.UnparsableShare(), src.Events+int64(src.Unparsable))
		if src.HighUnparsable() {
			fmt.Fprintf(w, "HIGH UNPARSABLE SHARE: %s is at or above %.0f%%; the mapper may not match this index, and the detectors are judging a fraction of it.\n",
				src.Name, app.HighUnparsableShare*100)
		}
	}
	if len(r.Search) > 0 {
		writeSearchSummary(w, r, r.Search, absent)
	}
	if failed := r.Failed(); len(failed) > 0 && !absent {
		fmt.Fprintf(w, "INCOMPLETE: %d component(s) did not finish; this is not a clean result.\n", len(failed))
	}
	if len(r.Findings) == 0 && absent {
		return nil // the search summary has said everything there is to say
	}
	if len(r.Findings) == 0 {
		if r.Complete() && len(r.Disabled) > 0 {
			fmt.Fprintln(w, "No findings; every enabled source and detector completed (the DISABLED ones above were not read or run).")
		} else if r.Complete() {
			fmt.Fprintln(w, "No findings; every source and detector completed.")
		} else {
			fmt.Fprintln(w, "No findings from the components that completed.")
		}
		return nil
	}
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tDETECTOR\tTAG\tSUMMARY")
	for _, f := range r.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", core.SeverityName(f.Severity), f.Detector, f.Tag, f.Summary)
	}
	return tw.Flush()
}

// writeJSON prints a library result as its `--output json` document: json.Marshal of the
// value, indented. The keys are the library's (RFC 0013), so the command line, the Go API
// and the MCP tools cannot disagree.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeSearchSummary says what a search came to, source by source, so a zero is never
// left to be read as one thing: absent from a live index, or nothing can be said.
func writeSearchSummary(w io.Writer, r app.Result, search []string, absent bool) {
	quoted := make([]string, len(search))
	for i, t := range search {
		quoted[i] = fmt.Sprintf("%q", t)
	}
	terms := strings.Join(quoted, " AND ")
	fmt.Fprintf(w, "SEARCH %s: the detectors read the stored evidence for the window, including events saved by earlier runs, not only the matches.\n", terms)
	if absent {
		fmt.Fprintf(w, "SEARCH RESULT: no match in %d source(s), and each index answered an unfiltered count, so the term is absent from the window and the one before it; the index is not empty.\n", len(r.Sources))
		for _, s := range r.Sources {
			if s.Kept > 0 { // the stored evidence still holds the earlier fetch's events
				fmt.Fprintf(w, "SEARCH RESULT: %s: %s.\n", s.Name, s.NoMatchText())
			}
		}
		return
	}
	for _, s := range r.Sources {
		switch {
		case s.NoMatch():
			fmt.Fprintf(w, "SEARCH RESULT: %s: %s.\n", s.Name, s.NoMatchText())
		case s.Status == app.StatusOK:
			fmt.Fprintf(w, "SEARCH RESULT: %s: %d matching event(s) fetched.\n", s.Name, s.Events)
		default:
			fmt.Fprintf(w, "SEARCH RESULT: %s: %s; nothing can be said about the term here.\n", s.Name, s.Outcome())
		}
	}
}
