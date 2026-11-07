package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/app"
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
			"  ACTIVE      a detector found a genuine event in the window. A detector that stopped early\n" +
			"              still counts if it had proved a finding; the output then says it is incomplete\n" +
			"              and the exit code is 1, as for INCOMPLETE.\n" +
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
			if err := checkUntilWindow(window, untilT); err != nil {
				return err
			}

			// The flags become the library's options; the library does the rest and hands
			// each advice line to Notice as it arises, so stderr keeps its order and timing.
			stderr := cmd.ErrOrStderr()
			res, aerr := jb.Activity(cmd.Context(), caseDir, jb.ActivityOptions{
				Config: cfgPath, Window: window, Until: untilT, Env: d.env, Now: d.now, NoStore: noStore,
				Notice: func(note string) { fmt.Fprintln(stderr, note) },
			})
			if res == nil {
				return aerr
			}

			if len(res.Sources) > 0 {
				var perr error
				if output == "json" {
					perr = writeJSON(cmd.OutOrStdout(), res)
				} else {
					perr = writeActivityTable(cmd.OutOrStdout(), *res)
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
			if res.Verdict == app.VerdictActive && !res.Complete() {
				return fmt.Errorf("activity ACTIVE, but the check is incomplete: %s", strings.Join(res.Reasons, "; "))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md); required")
	f.StringVar(&cfgPath, "config", "", "one of the case's configs (default: the config whose `commands:` lists this command, else the case's only config)")
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

// ageText says how long before end the last genuine event was, e.g. "18h12m ago". It
// counts from the end of the run's window (the injected clock, or --until), never from the
// wall clock, so the same question gives the same answer. Hours do not roll into days.
func ageText(last, end time.Time) string {
	d := end.Sub(last).Truncate(time.Minute)
	if d < time.Minute {
		return "under 1m ago"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	}
	return fmt.Sprintf("%dh%dm ago", int(d/time.Hour), int(d%time.Hour/time.Minute))
}

// lastHolder is the active subject that holds the time r.Last reports, so the headline
// says whose time it is. On equal times the first subject in report order wins.
func lastHolder(r app.ActivityResult) (core.ActivitySubject, bool) {
	last, ok := r.Last()
	if !ok {
		return core.ActivitySubject{}, false
	}
	for _, d := range r.Detectors {
		for _, s := range d.Report.Subjects {
			if s.Active && s.Last.Equal(last) {
				return s, true
			}
		}
	}
	return core.ActivitySubject{}, false
}

// lastWho names the subject the headline time belongs to, with its kind unless it is an actor.
func lastWho(s core.ActivitySubject) string {
	switch s.Kind {
	case "actor":
		return s.Subject + ", "
	case "common":
		return s.Subject + ", common action, "
	}
	return s.Subject + ", " + s.Kind + " action, "
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
			if d.Findings > 0 {
				fmt.Fprintf(w, "  %d finding(s) proved before the detector stopped; they count as activity, and the detector is still incomplete.\n", d.Findings)
			}
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
			p := fmt.Sprintf("%s: not judged (%s)", d.Name, d.Status)
			if d.Findings > 0 {
				p += fmt.Sprintf(", %d finding(s) proved before it stopped", d.Findings)
			}
			parts = append(parts, p)
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
		if s, ok := lastHolder(r); ok {
			return head + " last activity " + stamp(s.Last) + " (" + lastWho(s) + ageText(s.Last, r.Window.To) + ")" + tail + "."
		}
		return head + strings.TrimPrefix(tail, ";") + "."
	case app.VerdictQuiet:
		return head + " every " + enabled + "source and detector completed and none found an actor or rare action active; common-action traffic is ordinary unless its failure share moved."
	}
	return head + " this is not QUIET because " + strings.Join(r.Reasons, "; ") + "."
}
