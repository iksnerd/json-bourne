// Package core holds the domain types and the ports of json-bourne.
//
// It imports the standard library only. Adapters (Elasticsearch, nginx, DuckDB,
// intel feeds) implement these interfaces; the use cases in internal/app depend on
// nothing else. internal/archtest enforces that.
package core

import (
	"context"
	"errors"
	"iter"
	"time"
)

// ErrNoRecords means a source or detector parsed zero records. It is an error on
// purpose: an empty result that looks like a clean negative is a wrong answer
// shaped like a finding.
var ErrNoRecords = errors.New("no records")

// ErrSourceUnavailable means the backend could not be reached or refused the query.
var ErrSourceUnavailable = errors.New("source unavailable")

// Severity orders findings by how urgently a human should look.
type Severity int

const (
	SevInfo Severity = iota
	SevCheck
	SevActivity
	SevHigh
	SevCritical
)

// Window is a half-open time range [From, To).
type Window struct{ From, To time.Time }

// Duration is the length of the window.
func (w Window) Duration() time.Duration { return w.To.Sub(w.From) }

// Previous returns the window of the same length that ends where w begins.
// Detectors compare against it: a raw count means nothing without a baseline.
func (w Window) Previous() Window {
	d := w.Duration()
	return Window{From: w.From.Add(-d), To: w.From}
}

// Event is one normalised log record. Fields holds source-specific attributes;
// Raw is the original document, kept so a finding can be traced to evidence.
type Event struct {
	Time   time.Time
	Source string
	Kind   string
	Fields map[string]any
	Raw    []byte
	// DocKey identifies the underlying document within its DocScope when the source can
	// say (for Elasticsearch, concrete index and _id). It is never stored. Hunt uses it
	// to count a document once when two sources of one scope both return it. Empty means
	// the source cannot say, and the event is never treated as a duplicate.
	DocKey string
	// Returners names the sources that returned this document, when more than one source of
	// a scope did and Hunt stored it once (under Source, which is one of them). The store
	// keeps it, so a detector scoped to any of them still reads the document in a later
	// hunt. Empty means only Source returned it.
	Returners []string
}

// DocScoped is an optional port of a Source: DocScope names the store whose DocKeys it
// emits (for Elasticsearch, the cluster URL). Two sources with the same non-empty scope
// may read the same document, and Hunt keeps one copy of each DocKey, from the smallest source name that returned it.
type DocScoped interface {
	DocScope() string
}

// MapResult is the outcome for one document of a batch: the event it became, or a
// statement that the document is not in the format the mapper reads. Exactly one of
// the two holds. Unparsable documents are counted by the source, never dropped silently.
type MapResult struct {
	Event      Event
	Unparsable bool
}

// BatchMapper turns a batch of raw documents into events in one call. It returns exactly
// one MapResult per input document, in order, or an error; it never returns fewer, so
// a document cannot vanish. An error means the mapper could not be trusted for this
// batch and the source must fail rather than carry on with the rest.
type BatchMapper interface {
	MapBatch(ctx context.Context, docs []map[string]any) ([]MapResult, error)
}

// Finding is one detector result. Detail carries the numbers behind it, for both
// windows, so a reader can check the comparison.
type Finding struct {
	Detector string
	Tag      string // stable condition key; dedupe on this, never on prose
	Severity Severity
	Window   Window
	Baseline Window
	Summary  string
	Detail   map[string]any
}

// Reputation is one external observation about an indicator at a point in time.
// Reputation is a time series, so every lookup is appended, never overwritten.
type Reputation struct {
	Indicator string
	Verdict   string
	Observed  time.Time
	Source    string
}

// VerdictNotFound is the verdict a feed records when it answered that it has never
// seen the indicator (for example an HTTP 404). It is an answer. It is not the same
// as "could not ask", which is a LookupError and is never stored as a verdict.
const VerdictNotFound = "not_found"

var (
	// ErrRateLimited means the feed refused the lookup because a quota was reached.
	ErrRateLimited = errors.New("feed rate limited")
	// ErrBudgetExceeded means the lookup was not attempted because the per-run lookup
	// cap was reached.
	ErrBudgetExceeded = errors.New("lookup budget exceeded")
	// ErrFeedFailed means the feed could not be asked or did not answer usefully
	// (network error, timeout, non-success status, unreadable body).
	ErrFeedFailed = errors.New("feed lookup failed")
)

// LookupError is the failure of one indicator's lookup. A feed returns the
// reputations it has together with an error that joins one LookupError per
// indicator it could not answer, so a partial result is never mistaken for a
// complete one.
type LookupError struct {
	Indicator string
	Err       error
}

func (e *LookupError) Error() string { return e.Indicator + ": " + e.Err.Error() }
func (e *LookupError) Unwrap() error { return e.Err }

// LookupErrors returns every LookupError inside err, in order, looking through
// wrapping and errors.Join. It returns nil for a nil or plain error.
func LookupErrors(err error) []*LookupError {
	if err == nil {
		return nil
	}
	var out []*LookupError
	if le, ok := err.(*LookupError); ok {
		return append(out, le)
	}
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			out = append(out, LookupErrors(e)...)
		}
	case interface{ Unwrap() error }:
		out = append(out, LookupErrors(u.Unwrap())...)
	}
	return out
}

// Source yields events for a window. Implementations stream, and stop when ctx ends.
type Source interface {
	Name() string
	Fetch(ctx context.Context, w Window) iter.Seq2[Event, error]
}

// EventReader is the read side of the evidence store.
type EventReader interface {
	Events(ctx context.Context, w Window) iter.Seq2[Event, error]
}

// Detector compares the current window with the same-length preceding one.
// It returns ErrNoRecords when the current window holds nothing to judge.
//
// A detector that cannot finish returns the findings it can prove from the evidence it
// read, together with the error. It never returns a finding that depends on the part it
// failed to read, or that it could not support. The host keeps those findings and marks
// the detector incomplete: an error with findings is incomplete-with-findings, never
// quiet, and a detector that has nothing to prove returns no findings with its error.
type Detector interface {
	Name() string
	Detect(ctx context.Context, cur, prev EventReader, w Window) ([]Finding, error)
}

// Feed looks indicators up in an external reputation source. It must be passive: it
// asks the feed's own API and never contacts the indicator.
//
// Lookup returns one Reputation per indicator it could answer (including a
// VerdictNotFound answer) and, for every indicator it could not, a LookupError joined
// into the returned error. A failure is never reported as an empty or "unknown"
// Reputation. A reputation snapshot is context about an address, not attribution, and
// must not feed a detector.
type Feed interface {
	Name() string
	Lookup(ctx context.Context, indicators []string) ([]Reputation, error)
}

// Sink persists events and findings. Saving the same run twice replaces it.
type Sink interface {
	SaveEvents(ctx context.Context, run string, evs iter.Seq2[Event, error]) error
	SaveFindings(ctx context.Context, run string, fs []Finding) error
}
