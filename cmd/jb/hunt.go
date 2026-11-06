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
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

// runDeps is the one place a built config becomes the ports of app.Hunt and app.Activity,
// so every command that runs detectors applies the same `sources:` scopes. dets may be a
// subset of rt.Detectors (jb activity skips those that cannot report activity); a scope
// for a detector left out is dropped with it, because Hunt refuses a scope that names no
// detector.
func runDeps(rt *config.Runtime, dets []core.Detector, st *duckdb.Store) app.Deps {
	return watchrun.RunDeps(rt, dets, st)
}

// disabledOf is what the config switched off, as the use cases carry it into a result.
func disabledOf(rt *config.Runtime) []app.Disabled { return watchrun.Disabled(rt) }

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
			"inside the case) or the case's only config. --window defaults to the case's windows.default\n" +
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
			if sfield != "" && len(search) == 0 {
				return usageErrorf("--search-field needs --search")
			}
			if len(search) > 0 {
				if err := config.ValidateSearch(search); err != nil {
					return usageErrorf("%v", err)
				}
			}

			var untilT time.Time
			if untilS != "" {
				var err error
				if untilT, err = parseUntil(untilS, d.now()); err != nil {
					return usageErrorf("%v", err)
				}
			}

			scope := renameScope(caseDir, cfgPath)
			var plan *casePlan
			if caseDir != "" {
				var err error
				plan, err = planCase(cmd.ErrOrStderr(), caseDir, cfgPath, "hunt", cmd.Flags().Changed("window"))
				if err != nil {
					return err
				}
				cfgPath = plan.configPath
				if plan.window > 0 {
					window = plan.window
				}
			}

			wp, err := planWindow(d.now(), window, untilT)
			if err != nil {
				return err
			}

			cfg, rt, err := openCaseSearch(cmd.ErrOrStderr(), d.env, cfgPath, plan, search, sfield)
			if err != nil {
				return err
			}
			defer rt.Close() // ends any plugin child process, on success, failure and interrupt alike
			st, err := config.OpenRunStore(cmd.Context(), cfg, noStore, plan.keepOut()...)
			if err != nil {
				return err
			}
			defer st.Close() // removes a --no-store scratch store, on success, failure and interrupt alike

			w := wp.W
			prefix := "hunt"
			if len(search) > 0 {
				prefix = "search" // a narrowed subset is not a hunt of the window
			}
			run := wp.runID(prefix)
			fmt.Fprintf(cmd.ErrOrStderr(), "hunting %s [%s, %s) with %d source(s), %d detector(s)\n",
				run, w.From.Format(time.RFC3339), w.To.Format(time.RFC3339), len(rt.Sources), len(rt.Detectors))
			if note := app.DisabledNote(disabledOf(rt)); note != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), note)
			}
			if len(search) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "narrowed by %d search term(s) on field %s; the detectors read the stored evidence for the window, which includes events saved by earlier runs, not only the matches\n", len(search), searchFieldName(sfield))
			}

			res, huntErr := app.Hunt(cmd.Context(), runDeps(rt, rt.Detectors, st), run, w)
			res.Until = wp.Until
			// Advice only: the detectors have just read the store, and if one set of documents
			// sits under two labels they counted it twice. The verdict below is not touched.
			warnSourceOverlap(cmd.Context(), cmd.ErrOrStderr(), st, core.Window{From: w.Previous().From, To: w.To}, scope)

			// Print whatever was learned before reporting why the hunt stopped.
			if len(res.Sources) > 0 { // none means the hunt never started (bad input)
				var perr error
				if output == "json" {
					perr = writeJSON(cmd.OutOrStdout(), res, search)
				} else {
					perr = writeTable(cmd.OutOrStdout(), res, search)
				}
				if perr != nil && huntErr == nil {
					huntErr = fmt.Errorf("write output: %w", perr)
				}
			}
			if huntErr != nil {
				return huntErr
			}
			if len(search) > 0 && searchAbsent(res) {
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

func searchFieldName(override string) string {
	if override != "" {
		return override
	}
	return "message (or each source's search_field)"
}

// searchAbsent reports whether a search matched nothing anywhere and every index was
// shown alive: every source finished with no match, and no detector failed except by
// having nothing to judge. That is the answer "the term is absent", which is not a
// failure, and not a clean result about anything else either.
func searchAbsent(r app.Result) bool {
	if len(r.Sources) == 0 {
		return false
	}
	for _, s := range r.Sources {
		if !s.NoMatch() {
			return false
		}
	}
	for _, d := range r.Detectors {
		if d.Status != app.StatusOK && d.Status != app.StatusNoRecords {
			return false
		}
	}
	return true
}

// sourceNote is the NOTE column of a source row: the error, or what a zero means.
func sourceNote(s app.SourceResult) string {
	if s.NoMatch() {
		return fmt.Sprintf("no match; index alive (%d document(s) in the window and the one before it without the filter)", s.IndexDocs)
	}
	return errText(s.Err)
}

var severityNames = map[core.Severity]string{
	core.SevInfo: "info", core.SevCheck: "check", core.SevActivity: "activity",
	core.SevHigh: "high", core.SevCritical: "critical",
}

func severityName(s core.Severity) string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return fmt.Sprintf("sev%d", int(s))
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeTable(w io.Writer, r app.Result, search []string) error {
	absent := len(search) > 0 && searchAbsent(r)
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
	if len(search) > 0 {
		writeSearchSummary(w, r, search, absent)
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", severityName(f.Severity), f.Detector, f.Tag, f.Summary)
	}
	return tw.Flush()
}

type jsonComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Events *int64 `json:"events,omitempty"`
	// Outcome, IndexAlive and IndexDocuments are set on a source. IndexDocuments is the
	// count of the unfiltered liveness probe, present only with IndexAlive.
	Outcome        string `json:"outcome,omitempty"`
	IndexAlive     *bool  `json:"index_alive,omitempty"`
	IndexDocuments *int64 `json:"index_documents,omitempty"`
	// Unparsable and UnparsableShare are set only when a source reported unparsable documents.
	// Duplicates is set when documents were dropped because another source of the run
	// returned them first; they are not in Events.
	Duplicates      *int64   `json:"duplicates,omitempty"`
	Unparsable      *int     `json:"unparsable,omitempty"`
	UnparsableShare *float64 `json:"unparsable_share,omitempty"`
	HighUnparsable  bool     `json:"high_unparsable,omitempty"`
	Findings        *int     `json:"findings,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type jsonFinding struct {
	Detector string         `json:"detector"`
	Tag      string         `json:"tag"`
	Severity string         `json:"severity"`
	Summary  string         `json:"summary"`
	Window   [2]time.Time   `json:"window"`
	Baseline [2]time.Time   `json:"baseline"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// jsonSearch is present only for a run with --search.
type jsonSearch struct {
	Terms  []string `json:"terms"`
	Absent bool     `json:"absent"` // matched nothing, and every index was shown alive
}

type jsonResult struct {
	Search    *jsonSearch     `json:"search,omitempty"`
	Run       string          `json:"run"`
	Until     *time.Time      `json:"until,omitempty"` // set only for a historical window (--until)
	Window    [2]time.Time    `json:"window"`
	Baseline  [2]time.Time    `json:"baseline"`
	Complete  bool            `json:"complete"`
	Stored    bool            `json:"stored"` // false: the run went to a temporary store (--no-store)
	Sources   []jsonComponent `json:"sources"`
	Detectors []jsonComponent `json:"detectors"`
	Findings  []jsonFinding   `json:"findings"`
	// Disabled lists what the config switched off (neither read nor run); present only
	// when something is, so the output of a config without enabled: false is unchanged.
	Disabled []jsonDisabled `json:"disabled,omitempty"`
}

// jsonDisabled names one source or detector the config switched off.
type jsonDisabled struct {
	Kind string `json:"kind"` // source or detector
	Name string `json:"name"`
}

func jsonDisabledOf(ds []app.Disabled) []jsonDisabled {
	var out []jsonDisabled
	for _, d := range ds {
		out = append(out, jsonDisabled{Kind: d.Kind, Name: d.Name})
	}
	return out
}

func writeJSON(w io.Writer, r app.Result, search []string) error {
	absent := len(search) > 0 && searchAbsent(r)
	out := jsonResult{
		Run: r.Run, Window: [2]time.Time{r.Window.From, r.Window.To},
		Baseline: [2]time.Time{r.Baseline.From, r.Baseline.To}, Complete: r.Complete() || absent, Stored: r.Stored,
		Sources: []jsonComponent{}, Detectors: []jsonComponent{}, Findings: []jsonFinding{},
	}
	out.Until = tptr(r.Until)
	out.Disabled = jsonDisabledOf(r.Disabled)
	if len(search) > 0 {
		out.Search = &jsonSearch{Terms: search, Absent: absent}
	}
	for _, s := range r.Sources {
		n := s.Events
		c := jsonComponent{Name: s.Name, Status: string(s.Status), Events: &n, Error: errText(s.Err), Outcome: s.Outcome()}
		if s.IndexAlive {
			alive, docs := true, s.IndexDocs
			c.IndexAlive, c.IndexDocuments = &alive, &docs
		}
		if s.Duplicates > 0 {
			dup := s.Duplicates
			c.Duplicates = &dup
		}
		if s.Unparsable > 0 {
			u, share := s.Unparsable, s.UnparsableShare()
			c.Unparsable, c.UnparsableShare, c.HighUnparsable = &u, &share, s.HighUnparsable()
		}
		out.Sources = append(out.Sources, c)
	}
	for _, d := range r.Detectors {
		n := d.Findings
		out.Detectors = append(out.Detectors, jsonComponent{Name: d.Name, Status: string(d.Status), Findings: &n, Error: errText(d.Err)})
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			Detector: f.Detector, Tag: f.Tag, Severity: severityName(f.Severity), Summary: f.Summary,
			Window:   [2]time.Time{f.Window.From, f.Window.To},
			Baseline: [2]time.Time{f.Baseline.From, f.Baseline.To}, Detail: f.Detail,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
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
		return
	}
	for _, s := range r.Sources {
		switch {
		case s.NoMatch():
			fmt.Fprintf(w, "SEARCH RESULT: %s: no match; index alive.\n", s.Name)
		case s.Status == app.StatusOK:
			fmt.Fprintf(w, "SEARCH RESULT: %s: %d matching event(s) fetched.\n", s.Name, s.Events)
		default:
			fmt.Fprintf(w, "SEARCH RESULT: %s: %s; nothing can be said about the term here.\n", s.Name, s.Outcome())
		}
	}
}
