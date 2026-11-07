package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Verdict is the answer to "is the actor active". There are three, and the third is not
// a flavour of the second: QUIET is claimed only when everything that could have shown
// activity was read to the end.
type Verdict string

const (
	// VerdictActive: at least one detector found a genuine event in the window.
	VerdictActive Verdict = "ACTIVE"
	// VerdictQuiet: every source and detector completed over the whole window, nothing
	// was truncated or mostly unreadable, and no detector found a genuine event.
	VerdictQuiet Verdict = "QUIET"
	// VerdictIncomplete: no genuine event was found, but something did not finish, so
	// the absence proves nothing.
	VerdictIncomplete Verdict = "INCOMPLETE"
)

// ActivityDetector is one detector's contribution to the verdict.
type ActivityDetector struct {
	Name   string
	Status Status
	Err    error
	Report core.ActivityReport // empty unless Status is StatusOK
	// Findings is how many findings Detect proved. It can be non-zero when Status is not
	// StatusOK: a detector that could not judge one rule still returns the others.
	Findings int
}

// UnparsableShare is Unparsable / Seen for the detector, or 0 when it read nothing.
func (d ActivityDetector) UnparsableShare() float64 {
	if d.Report.Seen <= 0 || d.Report.Unparsable <= 0 {
		return 0
	}
	return float64(d.Report.Unparsable) / float64(d.Report.Seen)
}

// ActivityResult is the full account of one activity check.
type ActivityResult struct {
	Run      string
	Window   core.Window
	Baseline core.Window
	// Until is set by the caller when the window was chosen with --until; zero for a live check.
	Until     time.Time
	Sources   []SourceResult
	Detectors []ActivityDetector
	Verdict   Verdict
	// Disabled is what the config switched off: neither read nor run. A QUIET verdict
	// is about the enabled components only, and states so.
	Disabled []Disabled
	// Stored is false when the run went to a temporary store that was deleted afterwards
	// (`--no-store`); see Result.Stored.
	Stored bool
	// Reasons lists, for INCOMPLETE and for an ACTIVE that is also incomplete, what did
	// not finish. It is empty when the check completed.
	Reasons []string
	// Current and Previous sum the events of actor and rare-action subjects (every Kind
	// but KindCommon), active or not, in the window and the one before it. Only these are
	// activity-shaped. CommonCurrent and CommonPrevious sum the routine traffic of common
	// actions, which says nothing by its volume; a common action counts as activity only
	// when the detector marks it Active, and is then named in Flagged.
	Current, Previous             int
	CommonCurrent, CommonPrevious int
	Flagged                       []string
	// Notes are advice lines for the operator, as [Result.Notes]. Not part of the JSON.
	Notes []string `json:"-"`
}

// KindCommon is the ActivitySubject.Kind of an ordinary action judged by its failure
// share, not by how often it occurs (the behaviour detector's "common" class).
const KindCommon = "common"

// DetectorCounts is what one detector judged, from the subjects it reported.
type DetectorCounts struct {
	Read                          int // events the detector read in the window
	Current, Previous             int // actor and rare-action events
	CommonCurrent, CommonPrevious int // common-action events
}

// Counts sums the detector's subjects by kind.
func (d ActivityDetector) Counts() DetectorCounts {
	c := DetectorCounts{Read: d.Report.Seen}
	for _, s := range d.Report.Subjects {
		if s.Kind == KindCommon {
			c.CommonCurrent += s.Current
			c.CommonPrevious += s.Previous
		} else {
			c.Current += s.Current
			c.Previous += s.Previous
		}
	}
	return c
}

// Complete reports whether nothing that could have shown activity was left unread.
func (r ActivityResult) Complete() bool { return len(r.Reasons) == 0 }

// SourceEvents sums the events fetched by every source over the window and the one before it.
func (r ActivityResult) SourceEvents() int64 {
	var n int64
	for _, s := range r.Sources {
		n += s.Events
	}
	return n
}

// Last is the latest genuine event time of any active subject, and whether there is one.
func (r ActivityResult) Last() (time.Time, bool) {
	var last time.Time
	for _, d := range r.Detectors {
		for _, s := range d.Report.Subjects {
			if s.Active && s.Last.After(last) {
				last = s.Last
			}
		}
	}
	return last, !last.IsZero()
}

// Activity fetches the window and the one before it from every source, stores them, and
// asks every detector whether the actor was active, with the same noise and
// infrastructure rules its Detect applies. Every detector in d must implement
// core.ActivityReporter. A source or detector failing does not stop the others; it is
// recorded, and it makes the verdict INCOMPLETE unless a genuine event was found.
//
// The returned error is non-nil only when the check could not proceed (bad input, the
// context ending, the findings not being saved). The result is then still usable, and
// its Verdict is never QUIET.
func Activity(ctx context.Context, d Deps, run string, w core.Window) (ActivityResult, error) {
	res := ActivityResult{Run: run, Window: w, Baseline: w.Previous(), Verdict: VerdictIncomplete, Disabled: d.Disabled, Stored: !d.Scratch}
	for _, det := range d.Detectors {
		if _, ok := det.(core.ActivityReporter); !ok {
			return res, fmt.Errorf("activity: detector %q cannot report activity", det.Name())
		}
	}
	hr, err := Hunt(ctx, d, run, w)
	res.Sources = hr.Sources
	if err != nil {
		res.Reasons = append(res.Reasons, err.Error())
		return res, err
	}

	cur := boundedReader{inner: d.Reader, bound: w}
	prev := boundedReader{inner: d.Reader, bound: res.Baseline}
	for i, det := range d.Detectors {
		ad := ActivityDetector{Name: det.Name(), Status: hr.Detectors[i].Status, Err: hr.Detectors[i].Err, Findings: hr.Detectors[i].Findings}
		if ad.Status == StatusOK {
			dc, dp := d.readersFor(det.Name(), cur, prev)
			rep, aerr := det.(core.ActivityReporter).Activity(ctx, dc, dp, w)
			if aerr != nil {
				ad.Status, ad.Err = classify(aerr), aerr
			} else {
				ad.Report = rep
			}
		}
		res.Detectors = append(res.Detectors, ad)
	}
	if err := ctx.Err(); err != nil {
		res.Reasons = append(res.Reasons, err.Error())
		return res, err
	}
	res.assess()
	return res, nil
}

// assess sets Verdict and Reasons from the sources and detectors.
func (r *ActivityResult) assess() {
	active := false
	for _, d := range r.Detectors {
		if d.Status != StatusOK && d.Findings > 0 {
			active = true // a finding proved before the detector gave up is a genuine event
		}
		c := d.Counts()
		r.Current += c.Current
		r.Previous += c.Previous
		r.CommonCurrent += c.CommonCurrent
		r.CommonPrevious += c.CommonPrevious
		for _, s := range d.Report.Subjects {
			if s.Active {
				active = true
				if s.Kind == KindCommon {
					r.Flagged = append(r.Flagged, d.Name+":"+s.Subject)
				}
			}
		}
	}
	var reasons []string
	for _, s := range r.Sources {
		switch {
		case s.Status != StatusOK:
			reasons = append(reasons, fmt.Sprintf("source %s did not finish (%s)", s.Name, s.Status))
		case s.HighUnparsable():
			reasons = append(reasons, fmt.Sprintf("source %s: %.0f%% of its documents could not be parsed", s.Name, 100*s.UnparsableShare()))
		}
	}
	for _, d := range r.Detectors {
		switch {
		case d.Status != StatusOK:
			reasons = append(reasons, fmt.Sprintf("detector %s did not finish (%s)", d.Name, d.Status))
		case d.Report.Truncated:
			reasons = append(reasons, fmt.Sprintf("detector %s stopped reading at a cap; its counts are lower bounds", d.Name))
		case d.UnparsableShare() >= HighUnparsableShare:
			reasons = append(reasons, fmt.Sprintf("detector %s could not judge %.0f%% of the events it read", d.Name, 100*d.UnparsableShare()))
		}
	}
	if len(r.Detectors) == 0 {
		reasons = append(reasons, "no detector ran")
	}
	if len(r.Sources) == 0 {
		reasons = append(reasons, "no source was read")
	}
	r.Reasons = reasons
	switch {
	case active:
		r.Verdict = VerdictActive // a genuine event was read; other gaps cannot undo it
	case len(reasons) == 0:
		r.Verdict = VerdictQuiet
	default:
		r.Verdict = VerdictIncomplete
	}
}

// ActorStatusDeps are the ports ActorStatus works through.
type ActorStatusDeps struct {
	Detectors []core.Detector
	Finder    core.FieldEventFinder
}

// ActorStatus asks every detector that keeps actors when each of them last matched in
// the stored evidence. It reads the store only. It is an error when no detector keeps
// actors.
func ActorStatus(ctx context.Context, d ActorStatusDeps) ([]core.ActorHistory, error) {
	if d.Finder == nil {
		return nil, errors.New("actor status: no evidence reader")
	}
	var out []core.ActorHistory
	found := false
	for _, det := range d.Detectors {
		h, ok := det.(core.ActorHistorian)
		if !ok {
			continue
		}
		found = true
		hs, err := h.History(ctx, d.Finder)
		if err != nil {
			return nil, err
		}
		out = append(out, hs...)
	}
	if !found {
		return nil, errors.New("actor status: the config has no detector that keeps actors (type: fingerprint)")
	}
	return out, nil
}
