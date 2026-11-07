package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// DefaultWatchTTL is how long a surfaced tag stays quiet. One ongoing condition
// alerts once, then again after this long if it is still there.
const DefaultWatchTTL = 3 * time.Hour

// DefaultWatchKeep is how long the events and findings of past watch hunts stay in the
// store. Every cycle stores a window plus its baseline under a new run id, so without a
// limit the store grows by that much each cycle for as long as the watch runs.
const DefaultWatchKeep = 48 * time.Hour

// DefaultHealthRepeat is how often an identical, unchanged outage alerts again.
const DefaultHealthRepeat = 30 * time.Minute

// WatchRunPrefix is what a watch run id starts with: "watch" + "-" + the cycle's time.
// Retention deletes only run ids that start with it, so no other command's evidence is
// reachable by it. The prefix is reserved: a hunt run id must not begin with it.
const WatchRunPrefix = "watch-"

// watchNameRE is what a watcher's name may be: it becomes part of a file name and of a
// run id, so it is short, lower case, starts with a letter and holds no separator a path
// or a run id gives meaning to ("/" and ".").
var watchNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// ValidWatchName reports why name cannot name a watcher, or nil. The empty name is the
// unnamed watcher and is valid.
func ValidWatchName(name string) error {
	if name == "" || watchNameRE.MatchString(name) {
		return nil
	}
	return fmt.Errorf("watch name %q: use 1 to 32 characters, a lower-case letter first, then lower-case letters, digits, _ or -", name)
}

// WatchRunPrefixFor is the run-id prefix of a watcher, without the cycle's time: "watch"
// for the unnamed watcher, "watch-<name>" for a named one. Run ids are this + "-" + a
// UTC stamp, so they start with WatchRunPrefix whatever the name and retention applies.
func WatchRunPrefixFor(name string) string {
	if name == "" {
		return "watch"
	}
	return "watch-" + name
}

// Synthetic tags. They are never deduped: a cycle that could not see everything
// must say so every time it happens.
const (
	TagIncomplete = "watch-incomplete"
	TagCycleError = "watch-cycle-error"
	TagStateLoad  = "watch-state-load"
	TagStateSave  = "watch-state-save"
	TagGap        = "watch-gap"
	TagCycle      = "watch-cycle"
	TagPrune      = "watch-prune"
	TagStatusSave = "watch-status-save"
	TagRecovered  = "watch-recovered"
)

// HuntFunc runs one hunt over w under run. The command wires it to Hunt with real
// adapters; tests wire it to fakes.
type HuntFunc func(ctx context.Context, run string, w core.Window) (Result, error)

// WatchDeps are the ports a watch works through.
type WatchDeps struct {
	// Name is the watcher's name (`jb watch --name`), "" for the unnamed one. It is
	// stamped on every alert and cycle line so that the logs are attributable, and the
	// runs it creates are named by WatchRunPrefixFor(Name).
	Name string
	// Disabled is what the config switched off. The cycle line states it every cycle, so
	// a quiet cycle is never read as having looked at what it did not.
	Disabled []Disabled
	Hunt     HuntFunc
	State    core.WatchStateStore
	Alerts   core.AlertSink
	Now      func() time.Time
	// Wait blocks for d or until ctx ends; it reports false when ctx ended first.
	// Nil means a real timer.
	Wait func(ctx context.Context, d time.Duration) bool
	// Prune removes watch runs created before the given time and reports how much it
	// removed. Nil means no retention. It must keep the newest watch run.
	Prune func(ctx context.Context, before time.Time) (core.PruneResult, error)
	// Status, when set, receives the watcher's status record at start and after every
	// cycle, so a program can ask whether the watcher is alive without parsing the log.
	Status core.WatchStatusSink
}

// WatchOptions configure a watch.
type WatchOptions struct {
	Every  time.Duration // between cycle starts
	Window time.Duration // hunt window per cycle; must be at least Every
	TTL    time.Duration // dedupe lifetime of a tag; zero means DefaultWatchTTL
	// Keep is how long Prune lets a watch run live; zero means DefaultWatchKeep. It must
	// cover the two windows a cycle stores, or the store would be emptied under the cycle.
	Keep time.Duration
	// Repeat is the least time between two alerts for the same, unchanged outage; zero
	// means DefaultHealthRepeat. A value at or below Every alerts every cycle. A change
	// in the failure text, or a recovery, alerts at once whatever Repeat is. Findings
	// are never held back by it.
	Repeat time.Duration
	Once   bool
}

// CycleStatus is the verdict of a cycle. Quiet and Failed are never the same.
type CycleStatus string

const (
	CycleQuiet      CycleStatus = "quiet"      // complete, nothing new
	CycleFindings   CycleStatus = "findings"   // complete, something new
	CycleIncomplete CycleStatus = "incomplete" // something did not finish: the answer is unknown
	CycleFailed     CycleStatus = "failed"     // the cycle itself broke
)

// Healthy reports whether the cycle saw everything it was meant to see.
func (s CycleStatus) Healthy() bool { return s == CycleQuiet || s == CycleFindings }

// CycleReport is the account of one cycle.
type CycleReport struct {
	Run        string
	Window     core.Window
	Status     CycleStatus
	Result     Result
	Surfaced   []core.Alert // delivered, health alerts first, then findings most severe first
	New        int          // delivered finding alerts
	Suppressed int          // findings held back by the TTL
	Failed     []string     // components that did not finish
	Gap        string       // non-empty when time went unexamined before this cycle; set only on a cycle that completed
	Err        error        // the first thing that broke the cycle itself

	OptionalFailed int // alerts the required sink took and an optional sink (a webhook) did not; the cycle is FAILED

	Repeated  int               // outage alerts held back because the same failure was alerted within Repeat
	Recovered int               // recovery alerts delivered
	Pruned    *core.PruneResult // set when retention ran and succeeded

	complete bool // the hunt ran to the end and no component failed: the whole window was examined

	repeatEvery, keepFor time.Duration // for the cycle line
	name                 string        // the watcher's name, for the cycle line
	disabled             []Disabled    // what the config switched off, for the cycle line
}

// Validate rejects options that would leave gaps or spin.
func (o WatchOptions) Validate() error {
	switch {
	case o.Every <= 0:
		return errors.New("watch: interval must be positive")
	case o.Window <= 0:
		return errors.New("watch: window must be positive")
	case o.Window < o.Every:
		return fmt.Errorf("watch: window %s is shorter than the interval %s, so events between cycles would never be examined", o.Window, o.Every)
	case o.TTL < 0:
		return errors.New("watch: ttl must not be negative")
	case o.Keep < 0:
		return errors.New("watch: keep must not be negative")
	case o.Repeat < 0:
		return errors.New("watch: repeat must not be negative")
	case o.Keep > 0 && o.Keep < 2*o.Window:
		return fmt.Errorf("watch: keep %s is shorter than the two windows (%s) each cycle stores, so retention would delete what the cycle just fetched", o.Keep, 2*o.Window)
	}
	return nil
}

func (o WatchOptions) ttl() time.Duration {
	if o.TTL == 0 {
		return DefaultWatchTTL
	}
	return o.TTL
}

func (o WatchOptions) keep() time.Duration {
	if o.Keep == 0 {
		return DefaultWatchKeep
	}
	return o.Keep
}

func (o WatchOptions) repeat() time.Duration {
	if o.Repeat == 0 {
		return DefaultHealthRepeat
	}
	return o.Repeat
}

func (d WatchDeps) check() error {
	if d.Hunt == nil || d.State == nil || d.Alerts == nil || d.Now == nil {
		return errors.New("watch: hunt, state, alerts and clock are required")
	}
	return nil
}

// WatchCycle runs one hunt and surfaces what is new.
//
//   - A finding is surfaced unless its tag was surfaced within the TTL at the same
//     or a higher severity. The dedupe key is the tag alone; the stored severity
//     only lets an escalation through. A finding without a tag has no identity and
//     is always surfaced.
//   - A source or detector that did not finish becomes an alert of its own. Its
//     silence is never read as quiet.
//   - A tag is remembered only after its alert was delivered, so an undelivered
//     alert is offered again next cycle.
//
// The returned error is non-nil only for a cycle that could not run at all (bad
// dependencies or options, or ctx ending). Everything else is in the report.
func WatchCycle(ctx context.Context, d WatchDeps, o WatchOptions, run string) (CycleReport, error) {
	return watchCycle(ctx, d, o, run, time.Time{})
}

// watchCycle runs one cycle. lastComplete is the end of the most recent window whose
// cycle completed, or the zero time when this process has none: a cycle that completes
// but whose window starts after it has left the time between unexamined, and says so.
// A cycle that does not complete reports no gap: the outage alert says a source is down,
// and the gap is reported once, on the cycle that recovers.
func watchCycle(ctx context.Context, d WatchDeps, o WatchOptions, run string, lastComplete time.Time) (CycleReport, error) {
	if err := d.check(); err != nil {
		return CycleReport{}, err
	}
	if err := o.Validate(); err != nil {
		return CycleReport{}, err
	}
	if err := ValidWatchName(d.Name); err != nil {
		return CycleReport{}, err
	}
	if d.Name != "" {
		d.Alerts = namedSink{inner: d.Alerts, name: d.Name} // every alert says which watcher raised it
	}
	now := d.Now().UTC().Truncate(time.Second)
	at := now.Format(time.RFC3339)
	rep := CycleReport{Run: run, Window: core.Window{From: now.Add(-o.Window), To: now},
		repeatEvery: o.repeat(), keepFor: o.keep(), name: d.Name, disabled: d.Disabled}
	ttl := o.ttl()

	// A health alert with a key is an outage: an identical one is delivered at most once
	// per Repeat. One without a key (a gap, a state problem) is always delivered.
	type healthAlert struct {
		a       core.Alert
		key, fp string
	}
	var health []healthAlert
	addHealth := func(kind, tag, detector, text string) {
		health = append(health, healthAlert{a: core.Alert{Kind: kind, Tag: tag, Severity: "high", Detector: detector, Text: text, Run: run, At: at}})
	}
	addOutage := func(kind, tag, name, text, fp string) {
		health = append(health, healthAlert{
			a:   core.Alert{Kind: kind, Tag: tag, Severity: "high", Detector: name, Text: text, Run: run, At: at},
			key: tag + "|" + name, fp: fp,
		})
	}
	fail := func(err error) {
		if rep.Err == nil {
			rep.Err = err
		}
	}
	state, err := d.State.Load(ctx)
	if err != nil {
		// Start with no memory rather than not watching: repeats are noise, a stopped
		// watcher is not safe.
		fail(err)
		state = core.WatchState{}
		addHealth(core.AlertError, TagStateLoad, "", fmt.Sprintf("watch state could not be loaded (%v); starting with no memory, expect repeats", err))
	}
	if state.Seen == nil {
		state.Seen = map[string]core.SeenTag{}
	}
	if state.Health == nil {
		state.Health = map[string]core.HealthSeen{}
	}

	res, huntErr := d.Hunt(ctx, run, rep.Window)
	rep.Result = res
	if ctx.Err() != nil {
		return rep, ctx.Err()
	}
	if huntErr != nil {
		fail(huntErr)
		addOutage(core.AlertError, TagCycleError, "hunt", fmt.Sprintf("hunt %s did not run to the end: %v", run, huntErr), fingerprint(huntErr.Error(), run))
	}
	rep.Failed = res.Failed()
	rep.complete = huntErr == nil && len(rep.Failed) == 0
	if rep.complete && !lastComplete.IsZero() && rep.Window.From.After(lastComplete) {
		rep.Gap = fmt.Sprintf("%s of events between %s and %s were never examined: no cycle that completed covered them",
			rep.Window.From.Sub(lastComplete).Round(time.Second), lastComplete.UTC().Format(time.RFC3339), rep.Window.From.UTC().Format(time.RFC3339))
		health = append([]healthAlert{{a: core.Alert{Kind: core.AlertIncomplete, Tag: TagGap, Severity: "high", Text: rep.Gap, Run: run, At: at}}}, health...)
	}
	failing := map[string]bool{} // outage keys that are down this cycle
	if huntErr != nil {
		failing[TagCycleError+"|hunt"] = true
	}
	for _, f := range res.Failures() {
		reason := string(f.Status)
		if f.Err != nil {
			reason += ": " + f.Err.Error()
		}
		addOutage(core.AlertIncomplete, TagIncomplete, f.Name,
			fmt.Sprintf("%s did not complete in %s (%s); its result is unknown, not clean", f.Name, run, reason), fingerprint(reason, run))
		failing[TagIncomplete+"|"+f.Name] = true
	}

	// Decide which findings are new. Nothing is recorded as seen until delivered.
	var fresh []core.Finding
	for _, f := range res.Findings {
		if f.Tag != "" {
			if prev, ok := state.Seen[f.Tag]; ok && inTTL(prev.At, now, ttl) && f.Severity <= prev.Severity {
				rep.Suppressed++
				continue
			}
		}
		fresh = append(fresh, f)
	}
	sort.SliceStable(fresh, func(i, j int) bool {
		if fresh[i].Severity != fresh[j].Severity {
			return fresh[i].Severity > fresh[j].Severity
		}
		return fresh[i].Tag < fresh[j].Tag
	})

	deliver := func(a core.Alert) bool {
		if err := d.Alerts.Deliver(ctx, a); err != nil {
			fail(fmt.Errorf("deliver alert %q: %w", a.Tag, err))
			var oe *core.OptionalDeliveryError
			if !errors.As(err, &oe) {
				return false
			}
			// The required sink (the log) has it: remembered, so it is not offered again,
			// but the cycle is failed and the failure counted.
			rep.OptionalFailed++
		}
		rep.Surfaced = append(rep.Surfaced, a)
		return true
	}
	// Health alerts first: they say how far the findings below can be trusted.
	repeat := o.repeat()
	for _, h := range health {
		if h.key != "" {
			if prev, ok := state.Health[h.key]; ok && prev.Fingerprint == h.fp && inTTL(prev.At, now, repeat) {
				rep.Repeated++ // same failure, alerted recently: the cycle line still reports it
				continue
			}
		}
		if deliver(h.a) && h.key != "" {
			state.Health[h.key] = core.HealthSeen{At: now, Fingerprint: h.fp}
		}
	}
	// A recovery alerts at once. A component whose status is unknown this cycle (the hunt
	// itself broke, so no component reported) has not recovered.
	keys := make([]string, 0, len(state.Health))
	for key := range state.Health {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_, name, _ := strings.Cut(key, "|")
		if failing[key] || (huntErr != nil && key != TagCycleError+"|hunt") {
			continue
		}
		prev := state.Health[key]
		text := fmt.Sprintf("%s recovered: it finished in %s after being reported down at %s", name, run, prev.At.UTC().Format(time.RFC3339))
		if deliver(core.Alert{Kind: core.AlertRecovered, Tag: TagRecovered, Severity: "info", Detector: name, Text: text, Run: run, At: at}) {
			delete(state.Health, key)
			rep.Recovered++
		}
	}
	for _, f := range fresh {
		a := core.Alert{Kind: core.AlertFinding, Tag: f.Tag, Severity: core.SeverityName(f.Severity),
			Detector: f.Detector, Text: f.Summary, Run: run, At: at}
		if deliver(a) {
			rep.New++
			if f.Tag != "" {
				state.Seen[f.Tag] = core.SeenTag{At: now, Severity: f.Severity}
			}
		}
	}

	for tag, s := range state.Seen { // an expired entry decides nothing
		if !inTTL(s.At, now, ttl) {
			delete(state.Seen, tag)
		}
	}
	if err := d.State.Save(ctx, state); err != nil {
		fail(err)
		// Never silent: without the state the next cycle repeats everything.
		deliver(core.Alert{Kind: core.AlertError, Tag: TagStateSave, Severity: "high", Run: run, At: at,
			Text: fmt.Sprintf("watch state could not be saved (%v); the next cycle will repeat findings", err)})
	}

	if d.Prune != nil {
		pr, err := d.Prune(ctx, now.Add(-o.keep()))
		if err != nil {
			fail(err)
			// Never silent: a store that cannot be pruned grows without limit.
			deliver(core.Alert{Kind: core.AlertError, Tag: TagPrune, Severity: "high", Run: run, At: at,
				Text: fmt.Sprintf("retention could not prune watch runs older than %s (%v); the evidence store keeps growing", o.keep(), err)})
		} else {
			rep.Pruned = &pr
		}
	}

	switch {
	case rep.Err != nil:
		rep.Status = CycleFailed
	case len(rep.Failed) > 0 || rep.Gap != "":
		rep.Status = CycleIncomplete
	case rep.New > 0:
		rep.Status = CycleFindings
	default:
		rep.Status = CycleQuiet
	}
	hb := core.Alert{Kind: core.AlertCycle, Tag: TagCycle, Severity: "info", Run: run, At: at, Text: cycleLine(rep)}
	if err := d.Alerts.Deliver(ctx, hb); err != nil {
		fail(fmt.Errorf("deliver cycle line: %w", err))
		rep.Status = CycleFailed
		var oe *core.OptionalDeliveryError
		if errors.As(err, &oe) {
			rep.OptionalFailed++
		}
	}
	return rep, nil
}

// namedSink stamps the watcher's name on every alert it passes on.
type namedSink struct {
	inner core.AlertSink
	name  string
}

func (n namedSink) Deliver(ctx context.Context, a core.Alert) error {
	a.Watcher = n.name
	return n.inner.Deliver(ctx, a)
}

func inTTL(at, now time.Time, ttl time.Duration) bool {
	// An entry dated in the future (clock step, edited file) must not mute a tag.
	return !at.After(now) && now.Sub(at) < ttl
}

func cycleLine(r CycleReport) string {
	var line string
	every := "every source and detector"
	if len(r.disabled) > 0 {
		every = "every enabled source and detector"
	}
	switch r.Status {
	case CycleQuiet:
		line = fmt.Sprintf("CYCLE QUIET: %s completed; no new findings (%d held back by ttl)", every, r.Suppressed)
	case CycleFindings:
		line = fmt.Sprintf("CYCLE FINDINGS: %d new, %d held back by ttl; %s completed", r.New, r.Suppressed, every)
	case CycleIncomplete:
		line = fmt.Sprintf("CYCLE INCOMPLETE: %d component(s) did not finish %v, gap=%t; this is not a quiet result (%d new findings)", len(r.Failed), r.Failed, r.Gap != "", r.New)
	default:
		line = fmt.Sprintf("CYCLE FAILED: %v; this is not a quiet result (%d new findings)", r.Err, r.New)
	}
	if n := DisabledNote(r.disabled); n != "" {
		line += "; " + n
	}
	if r.OptionalFailed > 0 {
		line += fmt.Sprintf("; %d alert(s) not delivered to an optional sink (they are in this log)", r.OptionalFailed)
	}
	if r.Repeated > 0 {
		line += fmt.Sprintf("; still down: %d unchanged outage alert(s) held back, repeated at most every %s", r.Repeated, r.repeatEvery)
	}
	if r.Recovered > 0 {
		line += fmt.Sprintf("; %d component(s) recovered", r.Recovered)
	}
	if n := r.Result.UnparsableNote(); n != "" {
		line += "; " + n
	}
	if r.Pruned != nil {
		line += fmt.Sprintf("; pruned %d run(s), %d event(s), %d finding(s) older than %s", r.Pruned.Runs, r.Pruned.Events, r.Pruned.Findings, r.keepFor)
	}
	return line
}

var (
	reTime = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})|\d{8}T\d{6}Z`)
	reWS   = regexp.MustCompile(`\s+`)
)

// fingerprint is a failure's text with what changes every cycle taken out (the run id
// and timestamps, which the window of an error message carries). Anything else that
// differs is a different failure: an HTTP 502 turning into a 503 alerts at once.
func fingerprint(text, run string) string {
	text = strings.ReplaceAll(text, run, "<run>")
	text = reTime.ReplaceAllString(text, "<time>")
	return strings.TrimSpace(reWS.ReplaceAllString(text, " "))
}

// Watch runs WatchCycle once (Once) or until ctx ends. A cycle that fails is
// reported and the next one still runs. It returns the last report; the caller
// derives the exit code of a Once run from its Status. Cancelling ctx ends the loop
// without an error.
func Watch(ctx context.Context, d WatchDeps, o WatchOptions, runPrefix string) (CycleReport, error) {
	if err := d.check(); err != nil {
		return CycleReport{}, err
	}
	if err := o.Validate(); err != nil {
		return CycleReport{}, err
	}
	if err := ValidWatchName(d.Name); err != nil {
		return CycleReport{}, err
	}
	if d.Prune != nil && runPrefix != WatchRunPrefixFor(d.Name) {
		// Retention deletes the runs of this watcher by their exact shape; runs named
		// otherwise would never be pruned, or would be pruned as another watcher's.
		return CycleReport{}, fmt.Errorf("watch: run prefix %q is not %q, the prefix of watcher %q, so retention would not find its runs", runPrefix, WatchRunPrefixFor(d.Name), d.Name)
	}
	wait := d.Wait
	if wait == nil {
		wait = realWait
	}
	var last CycleReport
	// End of the latest window whose cycle completed. Held in memory only: a restart during
	// an outage forgets it, so the first cycle after the restart reports no gap even if
	// time went unexamined before the restart. Not persisted in this change.
	var lastCompleteTo time.Time
	d.publish(ctx, o, nil, d.Now().UTC(), d.Now().UTC())
	for {
		start := d.Now().UTC().Truncate(time.Second)
		run := runPrefix + "-" + start.Format("20060102T150405Z")
		rep, err := watchCycle(ctx, d, o, run, lastCompleteTo)
		if err != nil {
			if ctx.Err() != nil {
				return last, nil
			}
			return rep, err // misconfiguration: retrying cannot help
		}
		last = rep
		if rep.complete {
			lastCompleteTo = rep.Window.To // an incomplete cycle examined nothing it can vouch for
		}
		ended, next := d.Now().UTC(), time.Time{}
		if !o.Once {
			next = start.Add(o.Every)
			if next.Before(ended) {
				next = ended // a cycle that overran Every starts the next at once
			}
		}
		d.publish(ctx, o, &rep, ended, next)
		if o.Once {
			return last, nil
		}
		if !wait(ctx, max(0, o.Every-d.Now().Sub(start))) {
			return last, nil
		}
	}
}

// publish writes the status record: rep is nil before the first cycle. A failure is an
// alert, never a stopped watcher; the cycle's own result does not depend on the record.
func (d WatchDeps) publish(ctx context.Context, o WatchOptions, rep *CycleReport, now, next time.Time) {
	if d.Status == nil {
		return
	}
	s := core.WatchStatus{Every: o.Every, Window: o.Window, TTL: o.ttl(), Keep: o.keep(), Repeat: o.repeat(), Updated: now, NextDue: next}
	if rep != nil {
		s.Last = &core.WatchCycleSummary{
			Run: rep.Run, Verdict: strings.ToUpper(string(rep.Status)), Ended: now, Window: rep.Window,
			New: rep.New, Suppressed: rep.Suppressed, Repeated: rep.Repeated, Recovered: rep.Recovered,
			Failed: append([]string(nil), rep.Failed...),
		}
	}
	if err := d.Status.Save(ctx, s); err != nil {
		alerts := d.Alerts
		if d.Name != "" {
			alerts = namedSink{inner: alerts, name: d.Name}
		}
		// Never silent: without the record a program reads this watcher as stale.
		_ = alerts.Deliver(ctx, core.Alert{Kind: core.AlertError, Tag: TagStatusSave, Severity: "high", At: now.Format(time.RFC3339),
			Text: fmt.Sprintf("watch status could not be saved (%v); programs reading it will see this watcher as stale", err)})
	}
}

func realWait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
