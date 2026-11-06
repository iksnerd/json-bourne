package core

import (
	"context"
	"iter"
	"time"
)

// Liveness is what a filtered Source learned about its index when a filtered window
// matched nothing: it counted the same window without the filter. Probed is false when
// no probe ran (the window matched, or the source has no filter). A probe that found no
// documents at all is an error from Fetch (ErrNoRecords), never a Liveness.
type Liveness struct {
	Probed     bool
	IndexTotal int64 // documents in the window without the filter; meaningful only when Probed
}

// LivenessReporter is an optional port of a Source: whether its most recent Fetch
// proved the index alive while the filtered window held nothing. It is what separates
// "the term is absent" from "the index is empty or unreachable".
type LivenessReporter interface {
	Liveness() Liveness
}

// ActivitySubject is what a detector counted for one thing it watches (an actor, an
// action). Every count is of events actually read; none is inferred.
type ActivitySubject struct {
	Subject string // actor id or action name; never an address
	Kind    string // detector-defined: "actor", "rare", "common"
	// Current and Previous count the events the detector treats as genuine in the window
	// and in the same-length window before it. Noise and infrastructure are in neither.
	Current, Previous int
	// Last is the latest genuine event in the window, zero when there is none or when
	// the subject is not active. LastEarlier is the same for the preceding window, set
	// only by a detector that tracks it.
	Last, LastEarlier time.Time
	// Active is the detector's own decision that this subject is active in the window.
	// For a subject with heavy legitimate traffic it is not "Current > 0".
	Active bool
	// Noise and Ignored count events that matched the subject and were set aside:
	// scanner noise, and traffic relayed by our own infrastructure.
	Noise, Ignored int
	Note           string
}

// ActivityReport is one detector's account of a window.
type ActivityReport struct {
	Subjects []ActivitySubject
	// Seen counts the events the detector read in the window; Unparsable the ones it
	// could not judge. A detector that cannot read most of its input is blind, not quiet.
	Seen, Unparsable int
	// Truncated is set when the detector stopped reading at a cap, so a count is a
	// lower bound.
	Truncated bool
	Notes     []string
}

// ActivityReporter is an optional port of a Detector: it answers "is anything this
// detector watches active in the window", with the same noise and infrastructure rules
// Detect applies, because both read the events through one code path.
type ActivityReporter interface {
	Activity(ctx context.Context, cur, prev EventReader, w Window) (ActivityReport, error)
}

// FieldEventFinder reads stored events whose named field equals a value, newest first.
// The query is fixed by the implementation and the field and value are parameters; no
// caller supplies query text.
type FieldEventFinder interface {
	EventsByField(ctx context.Context, field, value string) iter.Seq2[Event, error]
}

// ActorHistory is when one matching rule of an actor last matched in the stored evidence.
type ActorHistory struct {
	Actor, Label string
	Indicator    string // the user agent, matched by full-string equality
	// LastGenuine is the latest stored event that is neither noise nor relayed by our
	// infrastructure; zero when none was found.
	LastGenuine time.Time
	// Scanned counts stored events with this indicator that were examined (newest
	// first, stopping at the first genuine one); Noise and Ignored are the part of
	// Scanned that was set aside; Unparsable could not be judged.
	Scanned, Noise, Ignored, Unparsable int
	// Capped is set when the scan stopped at its cap without finding a genuine event,
	// so "no genuine match" is not established.
	Capped bool
}

// ActorHistorian is an optional port of a Detector: when each of its actors last
// matched in the stored evidence.
type ActorHistorian interface {
	History(ctx context.Context, f FieldEventFinder) ([]ActorHistory, error)
}
