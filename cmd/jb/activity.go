package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

func newActivityCmdWith(d deps) *cobra.Command {
	var (
		cfgPath string
		caseDir string
		window  = 24 * time.Hour
		output  string
		untilS  string
		noStore bool
	)
	cmd := &cobra.Command{
		Use:   "activity --case DIR",
		Short: "Is the actor active from any client? ACTIVE, QUIET or INCOMPLETE",
		Long: "activity runs the case's fingerprint and behaviour detectors over the last --window\n" +
			"and the window before it, and answers with one verdict.\n\n" +
			"--window defaults to 24h, a fixed value, so the same call always asks the same question.\n" +
			"The case's windows.default does not apply here: it is the default of `jb hunt --case` and\n" +
			"`jb watch`, and a case can change it. Pass --window to ask about a different span.\n\n" +
			"--until TIME asks the same question of a past window, [TIME - window, TIME), with the window\n" +
			"before it as the baseline. TIME is RFC 3339 with a zone (2026-10-01T00:00:00Z); a time without\n" +
			"a zone, with fractions of a second, or after now is refused, and so is a window over 31d. The\n" +
			"run is stored as activity-until-<end>-w<seconds>. See docs/BACKFILL.md.\n\n" +
			"  ACTIVE      a detector found a genuine event in the window.\n" +
			"  QUIET       every source and detector completed over the whole window, nothing was\n" +
			"              truncated or mostly unreadable, and no genuine event was found.\n" +
			"  INCOMPLETE  no genuine event was found, but something did not finish. This is not\n" +
			"              QUIET: an absence in what was not read proves nothing. Exit 1.\n\n" +
			"A fingerprint actor is matched by its exact user agent, so a rotated client is invisible\n" +
			"to it; a behaviour action is matched by what the client does, whatever it calls itself.\n" +
			"Run both to answer \"from any client\". Scanner noise sharing an actor's user agent,\n" +
			"and traffic relayed by the configured ignore keys, addresses or user agents, are never\n" +
			"counted as the actor, and no address is ever used to attribute an event. Detectors that\n" +
			"do not report activity (authspike, signup, newkey) are skipped, and named.\n\n" +
			"The events are fetched from the configured sources and saved as run activity-<time>,\n" +
			"as `jb hunt` does. The case is checked as `jb hunt --case` checks it.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if window <= 0 {
				return usageErrorf("--window must be positive, got %s", window)
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output must be table or json, got %q", output)
			}
			// windowSet is true: the verdict's window is --window (default 24h), not the case's
			// hunt default, so the same command always asks the same question.
			var untilT time.Time
			if untilS != "" {
				var uerr error
				if untilT, uerr = parseUntil(untilS, d.now()); uerr != nil {
					return usageErrorf("%v", uerr)
				}
			}
			wp, err := planWindow(d.now(), window, untilT)
			if err != nil {
				return err
			}
			plan, err := planCase(cmd.ErrOrStderr(), caseDir, cfgPath, "activity", true)
			if err != nil {
				return err
			}
			cfg, rt, err := openCase(cmd.ErrOrStderr(), d.env, plan.configPath, plan)
			if err != nil {
				return err
			}
			defer rt.Close() // ends any plugin child process, on success, failure and interrupt alike
			var dets []core.Detector
			var skipped []string
			for _, det := range rt.Detectors {
				if _, ok := det.(core.ActivityReporter); ok {
					dets = append(dets, det)
				} else {
					skipped = append(skipped, det.Name())
				}
			}
			if note := app.DisabledNote(disabledOf(rt)); note != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), note)
			}
			if len(dets) == 0 {
				if note := app.DisabledNote(disabledOf(rt)); note != "" {
					return usageErrorf("config %s has no enabled fingerprint or behaviour detector, so it cannot say whether an actor is active. %s", plan.configPath, note)
				}
				return usageErrorf("config %s has no fingerprint or behaviour detector, so it cannot say whether an actor is active", plan.configPath)
			}
			if len(skipped) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: not an activity detector, skipped: %s\n", strings.Join(skipped, ", "))
			}
			st, err := config.OpenRunStore(cmd.Context(), cfg, noStore, plan.keepOut()...)
			if err != nil {
				return err
			}
			defer st.Close() // removes a --no-store scratch store, on success, failure and interrupt alike

			run := wp.runID("activity")
			res, aerr := app.Activity(cmd.Context(), runDeps(rt, dets, st), run, wp.W)
			res.Until = wp.Until
			warnSourceOverlap(cmd.Context(), cmd.ErrOrStderr(), st, core.Window{From: wp.W.Previous().From, To: wp.W.To}, renameScope(caseDir, cfgPath))

			if len(res.Sources) > 0 {
				var perr error
				if output == "json" {
					perr = writeActivityJSON(cmd.OutOrStdout(), res)
				} else {
					perr = writeActivityTable(cmd.OutOrStdout(), res)
				}
				if perr != nil && aerr == nil {
					aerr = fmt.Errorf("write output: %w", perr)
				}
			}
			if aerr != nil {
				return aerr
			}
			if res.Verdict == app.VerdictIncomplete {
				return fmt.Errorf("activity incomplete, not QUIET: %s", strings.Join(res.Reasons, "; "))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md); required")
	f.StringVar(&cfgPath, "config", "", "one of the case's configs (default: the case's only config)")
	f.Var((*windowValue)(&window), "window", "length of the window, ending now (or at --until): 90m, 24h or 7d (default 24h, never the case's windows.default)")
	f.StringVar(&untilS, "until", "", "ask about the past window ending at TIME (RFC 3339 with a zone, not after now) instead of the one ending now; not offered on watch, which always ends now")
	f.StringVar(&output, "output", "table", "output format: table or json")
	f.BoolVar(&noStore, "no-store", false, noStoreUsage)
	return cmd
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// lastText says when the subject last had a genuine event, and where that was.
func lastText(s core.ActivitySubject) string {
	switch {
	case !s.Last.IsZero():
		return stamp(s.Last)
	case !s.LastEarlier.IsZero():
		return "none in window; " + stamp(s.LastEarlier) + " before it"
	}
	return "none"
}

func subjectNote(s core.ActivitySubject) string {
	var parts []string
	if s.Noise > 0 {
		parts = append(parts, fmt.Sprintf("%d noise", s.Noise))
	}
	if s.Ignored > 0 {
		parts = append(parts, fmt.Sprintf("%d from ignored infrastructure", s.Ignored))
	}
	if s.Kind == "common" && !s.Active && s.Current > 0 {
		parts = append(parts, "ordinary traffic, failure share unchanged")
	}
	if s.Note != "" {
		parts = append(parts, s.Note)
	}
	return strings.Join(parts, "; ")
}

func writeActivityTable(w io.Writer, r app.ActivityResult) error {
	fmt.Fprintf(w, "run       %s\n", r.Run)
	if !r.Stored {
		fmt.Fprintln(w, notStoredLine)
	}
	if !r.Until.IsZero() {
		fmt.Fprintf(w, "until     %s (historical window; not relative to now)\n", stamp(r.Until))
	}
	fmt.Fprintf(w, "window    %s to %s\nbaseline  %s to %s\n\n",
		stamp(r.Window.From), stamp(r.Window.To), stamp(r.Baseline.From), stamp(r.Baseline.To))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tSTATUS\tEVENTS FETCHED\tUNPARSABLE\tOUTCOME")
	for _, s := range r.Sources {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", s.Name, s.Status, s.Events, s.Unparsable, s.Outcome()+noteSuffix(s.Err))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, d := range r.Detectors {
		fmt.Fprintf(w, "\ndetector %s: %s%s\n", d.Name, d.Status, noteSuffix(d.Err))
		if d.Status != app.StatusOK {
			continue
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SUBJECT\tKIND\tWINDOW\tPRECEDING\tLAST GENUINE\tNOTE")
		for _, s := range d.Report.Subjects {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n", s.Subject, s.Kind, s.Current, s.Previous, lastText(s), subjectNote(s))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if d.Report.Unparsable > 0 {
			fmt.Fprintf(w, "  %d of %d event(s) read could not be judged (%.1f%%)\n", d.Report.Unparsable, d.Report.Seen, 100*d.UnparsableShare())
		}
		for _, n := range d.Report.Notes {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
	fmt.Fprintln(w)
	if note := app.DisabledNote(r.Disabled); note != "" {
		fmt.Fprintln(w, note)
	}
	if r.Verdict == app.VerdictActive && !r.Complete() {
		fmt.Fprintf(w, "NOTE: ACTIVE stands, but the check is also incomplete: %s.\n", strings.Join(r.Reasons, "; "))
	}
	_, err := fmt.Fprintln(w, verdictLine(r))
	return err
}

func noteSuffix(err error) string {
	if err == nil {
		return ""
	}
	return ": " + err.Error()
}

// judgedText says, per detector, how much it read and how that divides into the events
// that would be activity (an actor, a rare action) and routine traffic (a common action,
// which only counts when its failure share moved). It never calls a count "genuine"
// unless the detector's own rules did.
func judgedText(r app.ActivityResult) string {
	var parts []string
	for _, d := range r.Detectors {
		if d.Status != app.StatusOK {
			parts = append(parts, fmt.Sprintf("%s: not judged (%s)", d.Name, d.Status))
			continue
		}
		c := d.Counts()
		p := fmt.Sprintf("%s read %d events in the window, actor/rare-action events: %d (window), %d (preceding)", d.Name, c.Read, c.Current, c.Previous)
		if c.CommonCurrent+c.CommonPrevious > 0 {
			p += fmt.Sprintf("; common-action events (ordinary traffic): %d (window), %d (preceding)", c.CommonCurrent, c.CommonPrevious)
		}
		parts = append(parts, p)
	}
	return "judged: " + strings.Join(parts, " | ")
}

// verdictLine is the last line of the output: the verdict, the window, the sources read
// and the counts actually fetched, then what each detector judged.
func verdictLine(r app.ActivityResult) string {
	var srcs []string
	for _, s := range r.Sources {
		srcs = append(srcs, fmt.Sprintf("%s (%d events fetched)", s.Name, s.Events))
	}
	var dets []string
	for _, d := range r.Detectors {
		dets = append(dets, d.Name)
	}
	until := ""
	if !r.Until.IsZero() {
		until = fmt.Sprintf(" [historical, --until %s]", stamp(r.Until))
	}
	head := fmt.Sprintf("%s: window %s to %s (%s)%s; sources read: %s, events fetched cover the window and the one before it; detectors: %s; %s;",
		r.Verdict, stamp(r.Window.From), stamp(r.Window.To), r.Window.Duration(), until,
		strings.Join(srcs, ", "), strings.Join(dets, ", "), judgedText(r))
	enabled := ""
	if note := app.DisabledNote(r.Disabled); note != "" {
		head += " " + note + ";"
		enabled = "enabled "
	}
	switch r.Verdict {
	case app.VerdictActive:
		tail := ""
		if len(r.Flagged) > 0 {
			tail = "; common action(s) flagged by a moved failure share: " + strings.Join(r.Flagged, ", ")
		}
		if last, ok := r.Last(); ok {
			return head + " last activity " + stamp(last) + tail + "."
		}
		return head + strings.TrimPrefix(tail, ";") + "."
	case app.VerdictQuiet:
		return head + " every " + enabled + "source and detector completed and none found an actor or rare action active; common-action traffic is ordinary unless its failure share moved."
	}
	return head + " this is not QUIET because " + strings.Join(r.Reasons, "; ") + "."
}

type jsonSubject struct {
	Subject     string     `json:"subject"`
	Kind        string     `json:"kind"`
	Active      bool       `json:"active"`
	Window      int        `json:"window_events"`
	Preceding   int        `json:"preceding_events"`
	Last        *time.Time `json:"last_genuine,omitempty"`
	LastEarlier *time.Time `json:"last_genuine_preceding,omitempty"`
	Noise       int        `json:"noise,omitempty"`
	Ignored     int        `json:"ignored,omitempty"`
	Note        string     `json:"note,omitempty"`
}

type jsonActivityDetector struct {
	Name       string        `json:"name"`
	Status     string        `json:"status"`
	Error      string        `json:"error,omitempty"`
	Seen       int           `json:"events_read"`
	Unparsable int           `json:"unparsable"`
	Subjects   []jsonSubject `json:"subjects"`
	Notes      []string      `json:"notes,omitempty"`
}

type jsonActivity struct {
	Run       string                 `json:"run"`
	Until     *time.Time             `json:"until,omitempty"` // set only for a historical window (--until)
	Verdict   string                 `json:"verdict"`
	Complete  bool                   `json:"complete"`
	Stored    bool                   `json:"stored"` // false: the run went to a temporary store (--no-store)
	Reasons   []string               `json:"reasons"`
	Window    [2]time.Time           `json:"window"`
	Baseline  [2]time.Time           `json:"baseline"`
	Sources   []jsonComponent        `json:"sources"`
	Detectors []jsonActivityDetector `json:"detectors"`
	// Current and Previous count actor and rare-action events; CommonCurrent and
	// CommonPrevious count routine common-action traffic, which is not activity by volume.
	Current        int      `json:"genuine_events_window"`
	Previous       int      `json:"genuine_events_preceding"`
	CommonCurrent  int      `json:"common_action_events_window"`
	CommonPrevious int      `json:"common_action_events_preceding"`
	Flagged        []string `json:"common_actions_flagged"`
	// Disabled lists what the config switched off (neither read nor run); present only
	// when something is.
	Disabled []jsonDisabled `json:"disabled,omitempty"`
}

func tptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func writeActivityJSON(w io.Writer, r app.ActivityResult) error {
	out := jsonActivity{
		Run: r.Run, Verdict: string(r.Verdict), Complete: r.Complete(), Stored: r.Stored, Reasons: append([]string{}, r.Reasons...),
		Until:    tptr(r.Until),
		Window:   [2]time.Time{r.Window.From, r.Window.To},
		Baseline: [2]time.Time{r.Baseline.From, r.Baseline.To},
		Sources:  []jsonComponent{}, Detectors: []jsonActivityDetector{},
		Current: r.Current, Previous: r.Previous,
		CommonCurrent: r.CommonCurrent, CommonPrevious: r.CommonPrevious,
		Flagged:  append([]string{}, r.Flagged...),
		Disabled: jsonDisabledOf(r.Disabled),
	}
	for _, s := range r.Sources {
		n := s.Events
		c := jsonComponent{Name: s.Name, Status: string(s.Status), Events: &n, Error: errText(s.Err)}
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
		jd := jsonActivityDetector{Name: d.Name, Status: string(d.Status), Error: errText(d.Err),
			Seen: d.Report.Seen, Unparsable: d.Report.Unparsable, Subjects: []jsonSubject{}, Notes: d.Report.Notes}
		for _, s := range d.Report.Subjects {
			jd.Subjects = append(jd.Subjects, jsonSubject{
				Subject: s.Subject, Kind: s.Kind, Active: s.Active, Window: s.Current, Preceding: s.Previous,
				Last: tptr(s.Last), LastEarlier: tptr(s.LastEarlier), Noise: s.Noise, Ignored: s.Ignored, Note: s.Note,
			})
		}
		out.Detectors = append(out.Detectors, jd)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
