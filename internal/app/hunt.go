package app

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// DefaultConcurrency bounds how many sources, and then how many detectors, run at once.
const DefaultConcurrency = 4

// Deps are the ports Hunt works through. Nothing here is an adapter type.
type Deps struct {
	Sources   []core.Source
	Detectors []core.Detector
	Sink      core.Sink
	// Reader reads back what Sink saved. Detectors never see a Source directly: they
	// judge the stored evidence, so a finding can be traced to rows in the store.
	Reader core.EventReader
	// Concurrency bounds parallel components per phase. Zero means DefaultConcurrency.
	Concurrency int
	// Scopes restricts the detectors named in it to the events of the listed sources,
	// by source name, in both the current and the preceding window. A detector with no
	// entry reads every source. An entry that is empty, names a source that is not in
	// Sources, or names no detector in Detectors is refused: a scope that silently
	// matched nothing would read as a quiet detector.
	Scopes map[string][]string
	// Disabled lists the sources and detectors the config switched off. They are not in
	// Sources or Detectors, so they are never fetched or run; Hunt copies them into
	// Result so that no report can leave out what was not read.
	Disabled []Disabled
	// Scratch says Sink and Reader are a private temporary store that is deleted when the
	// command returns (`--no-store`). The code is the same; the result says Stored false.
	Scratch bool
}

// Disabled is one source or detector switched off in the config (`enabled: false`).
type Disabled struct {
	Kind string // "source" or "detector"
	Name string
}

// DisabledNote is the one clause that states what a run did not read or run, or "" when
// nothing is switched off. A disabled component is never shown with a status: it has no
// row in a table, so it cannot read as ok or quiet.
func DisabledNote(ds []Disabled) string {
	if len(ds) == 0 {
		return ""
	}
	parts := make([]string, len(ds))
	for i, d := range ds {
		parts[i] = d.Kind + " " + d.Name
	}
	return "DISABLED: " + strings.Join(parts, ", ") + " (enabled: false in the config; not read, not run, and not part of any result above)"
}

// Status is the outcome of one component. Anything but StatusOK means the answer for
// that component is missing, which is not the same as a clean result.
type Status string

const (
	StatusOK          Status = "ok"
	StatusNoRecords   Status = "no_records"
	StatusUnavailable Status = "unavailable"
	StatusCanceled    Status = "canceled"
	StatusError       Status = "error"
)

// SourceResult is what one source contributed.
type SourceResult struct {
	Name   string
	Status Status
	Events int64 // events streamed into the sink; only a complete save when Status is ok
	// Unparsable counts documents the source received and could not parse (zero for a
	// source that does not report it). They are in no event: Events alone would make
	// a window of garbage with a few good lines look healthy.
	Unparsable int
	// IndexAlive is true when a filtered fetch matched nothing and the source then
	// counted the same window without the filter and found documents. IndexDocs is that
	// count, the answer of the probe and nothing derived. With IndexAlive, zero Events
	// means "the filter matched nothing in a live index", not a dead source.
	IndexAlive bool
	IndexDocs  int64
	// Duplicates counts documents this source returned that another source of the same
	// run, reading the same store, had already returned. They are in no Events count and
	// are not stored again, so overlapping filters never double count.
	Duplicates int64
	Err        error
}

// Outcome says in a few words what the source's window came to, so a zero is never left
// to be read as one thing. It is "matched", "no match, index alive", or, for a source
// that did not finish, why not.
func (s SourceResult) Outcome() string {
	switch {
	case s.Status == StatusOK && s.IndexAlive && s.Events == 0:
		return "no match; index alive"
	case s.Status == StatusOK && s.Duplicates > 0:
		return fmt.Sprintf("matched (%d already returned by another source)", s.Duplicates)
	case s.Status == StatusOK:
		return "matched"
	case s.Status == StatusNoRecords:
		return "index empty or nothing readable"
	case s.Status == StatusUnavailable:
		return "unreachable"
	case s.Status == StatusCanceled:
		return "canceled"
	}
	return "failed"
}

// NoMatch reports whether the source finished, fetched nothing and showed its index
// alive: the one outcome where an absent term is a finding and not a failure.
func (s SourceResult) NoMatch() bool {
	return s.Status == StatusOK && s.IndexAlive && s.Events == 0
}

// HighUnparsableShare is the fraction of a source's documents that may be unparsable
// before the output says so loudly: a mapper that no longer matches its index is a
// blind detector, not a quiet one.
const HighUnparsableShare = 0.20

// UnparsableShare is Unparsable / (Events + Unparsable), or 0 when the source saw nothing.
func (s SourceResult) UnparsableShare() float64 {
	total := s.Events + int64(s.Unparsable)
	if total <= 0 || s.Unparsable <= 0 {
		return 0
	}
	return float64(s.Unparsable) / float64(total)
}

// HighUnparsable reports whether the share is at or above HighUnparsableShare.
func (s SourceResult) HighUnparsable() bool { return s.UnparsableShare() >= HighUnparsableShare }

// Unparsable sums the unparsable documents of every source.
func (r Result) Unparsable() int {
	n := 0
	for _, s := range r.Sources {
		n += s.Unparsable
	}
	return n
}

// UnparsableNote is one clause for a status line, or "" when every document parsed:
// the count, the share, and "HIGH" when a source is at or above HighUnparsableShare.
func (r Result) UnparsableNote() string {
	n := r.Unparsable()
	if n == 0 {
		return ""
	}
	var events int64
	high := ""
	for _, s := range r.Sources {
		events += s.Events
		if s.HighUnparsable() {
			high = fmt.Sprintf("; HIGH: %s is at or above %.0f%% unparsable, its detectors may be blind", s.Name, HighUnparsableShare*100)
			break
		}
	}
	return fmt.Sprintf("%d unparsable document(s), %.1f%% of those received%s", n, 100*float64(n)/float64(events+int64(n)), high)
}

// DetectorResult is what one detector concluded.
type DetectorResult struct {
	Name     string
	Status   Status
	Findings int // findings the detector returned, before cross-detector dedupe
	Err      error
}

// Result is the full account of one hunt.
type Result struct {
	Run      string
	Window   core.Window
	Baseline core.Window
	// Until is set by the caller (never by Hunt) when the window was chosen with
	// --until instead of ending now; zero for a live hunt. Hunt itself reads no clock:
	// everything it does is relative to Window.
	Until     time.Time
	Sources   []SourceResult
	Detectors []DetectorResult
	Findings  []core.Finding // deduped by Tag, most severe first
	// Disabled is what the config switched off: neither read nor run, so absent from
	// Sources and Detectors. A report states it beside them.
	Disabled []Disabled
	// Stored is false when the run went to a temporary store that was deleted afterwards
	// (`--no-store`), so it left no evidence and no stored run to cite.
	Stored bool
	// Search is the ad-hoc search terms the run was narrowed by (`--search`); nil for a
	// run without one. The sources fetched only the matches, so their counts are about
	// the term, while the detectors still read the stored evidence of the window.
	Search []string
	// Notes are advice lines for the operator, in the order they arose: a case outside
	// version control, a window taken from the case, where the store sits, what was
	// disabled, a source label stored twice. The package jb fills them (Hunt never does);
	// the CLI prints them to stderr. They are not part of the JSON document.
	Notes []string `json:"-"`
}

// SearchAbsent reports whether a search matched nothing anywhere and every index was
// shown alive: every source finished with no match, and no detector failed except by
// having nothing to judge. That is the answer "the term is absent", which is not a
// failure, and not a clean result about anything else either. False for a run without
// a search.
func (r Result) SearchAbsent() bool {
	if len(r.Search) == 0 || len(r.Sources) == 0 {
		return false
	}
	for _, s := range r.Sources {
		if !s.NoMatch() {
			return false
		}
	}
	for _, d := range r.Detectors {
		if d.Status != StatusOK && d.Status != StatusNoRecords {
			return false
		}
	}
	return true
}

// Failed returns the names of the components that did not finish with StatusOK.
// A hunt with failed components is incomplete and must never be shown as clean.
func (r Result) Failed() []string {
	var out []string
	for _, f := range r.Failures() {
		out = append(out, f.Name)
	}
	return out
}

// Failure is one component that did not finish, with why.
type Failure struct {
	Name   string // "source X" or "detector Y"
	Status Status
	Err    error
}

// Failures lists the components that did not finish with StatusOK, sources first.
func (r Result) Failures() []Failure {
	var out []Failure
	for _, s := range r.Sources {
		if s.Status != StatusOK {
			out = append(out, Failure{"source " + s.Name, s.Status, s.Err})
		}
	}
	for _, d := range r.Detectors {
		if d.Status != StatusOK {
			out = append(out, Failure{"detector " + d.Name, d.Status, d.Err})
		}
	}
	return out
}

// Complete reports whether every source and detector finished with StatusOK.
func (r Result) Complete() bool { return len(r.Failed()) == 0 }

func classify(err error) Status {
	switch {
	case err == nil:
		return StatusOK
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return StatusCanceled
	case errors.Is(err, core.ErrNoRecords):
		return StatusNoRecords
	case errors.Is(err, core.ErrSourceUnavailable):
		return StatusUnavailable
	default:
		return StatusError
	}
}

// SourceRun is the run id under which one source's events are stored. The sink
// replaces a run when it is saved again, so sources must not share one.
func SourceRun(run, source string) string { return run + "/" + source }

// Hunt fetches the events of w and of the window before it from every source, stores
// them, runs every detector over the stored evidence and stores the findings under run.
//
// A source or detector failing is recorded in the Result and does not stop the others.
// A detector that returns findings and an error has its findings kept, stored and
// counted; its status is still not ok, so the hunt is incomplete.
// The returned error is non-nil only when the hunt itself could not proceed: bad
// input, the context ending, or the findings not being saved. The Result is always
// usable, and carries whatever was completed.
func Hunt(ctx context.Context, d Deps, run string, w core.Window) (Result, error) {
	res := Result{Run: run, Window: w, Baseline: w.Previous(), Disabled: d.Disabled, Stored: !d.Scratch}
	if err := validate(d, run, w); err != nil {
		return res, err
	}
	n := d.Concurrency
	if n <= 0 {
		n = DefaultConcurrency
	}

	// The detectors compare w with the window before it, so both are fetched.
	fetch := core.Window{From: res.Baseline.From, To: w.To}
	var sinkMu sync.Mutex // DuckDB has one writer; sink calls never overlap.

	res.Sources = make([]SourceResult, len(d.Sources))
	scopes := sharedScopes(d.Sources)
	pend := make([]*pending, len(d.Sources))
	forEach(ctx, n, len(d.Sources), func(i int) {
		res.Sources[i], pend[i] = ingest(ctx, &sinkMu, d.Sink, d.Sources[i], run, fetch, scopes)
	}, func(i int) {
		res.Sources[i] = SourceResult{Name: d.Sources[i].Name(), Status: StatusCanceled, Err: ctx.Err()}
	})
	if err := ctx.Err(); err != nil {
		for i, p := range pend {
			if p != nil {
				res.Sources[i] = SourceResult{Name: d.Sources[i].Name(), Status: StatusCanceled, Err: err}
			}
		}
		return res, err
	}
	// Every source of a shared scope has been read, so the winner of each shared document
	// is known: the smallest source name among those that returned it. Store the copies.
	won := map[*docSet]map[string][]*sharedDoc{}
	for _, ds := range scopes {
		won[ds] = ds.byWinner()
	}
	forEach(ctx, n, len(d.Sources), func(i int) {
		if p := pend[i]; p != nil {
			res.Sources[i] = p.store(ctx, &sinkMu, d.Sink, run, won[p.docs][p.name])
		}
	}, func(i int) {
		if pend[i] != nil {
			res.Sources[i] = SourceResult{Name: d.Sources[i].Name(), Status: StatusCanceled, Err: ctx.Err()}
		}
	})
	if err := ctx.Err(); err != nil {
		return res, err
	}

	cur := boundedReader{inner: d.Reader, bound: w}
	prev := boundedReader{inner: d.Reader, bound: res.Baseline}
	found := make([][]core.Finding, len(d.Detectors))
	res.Detectors = make([]DetectorResult, len(d.Detectors))
	forEach(ctx, n, len(d.Detectors), func(i int) {
		det := d.Detectors[i]
		dc, dp := d.readersFor(det.Name(), cur, prev)
		var fs []core.Finding
		var err error
		if hd, ok := det.(core.HistoryDetector); ok {
			// The one place a detector gets a history, and so the same path for hunt,
			// activity and watch. Each detector gets its own, built from its scope.
			fs, err = hd.DetectWithHistory(ctx, dc, dp, w, d.historyFor(det.Name()))
		} else {
			fs, err = det.Detect(ctx, dc, dp, w)
		}
		// Findings returned beside an error are kept: they are proven from evidence
		// the detector read, and the error alone makes the run incomplete (core.Detector).
		r := DetectorResult{Name: det.Name(), Status: classify(err), Err: err, Findings: len(fs)}
		found[i] = fs
		res.Detectors[i] = r
	}, func(i int) {
		res.Detectors[i] = DetectorResult{Name: d.Detectors[i].Name(), Status: StatusCanceled, Err: ctx.Err()}
	})
	if err := ctx.Err(); err != nil {
		return res, err
	}

	var all []core.Finding
	for _, fs := range found { // detector order, so the result is deterministic
		all = append(all, fs...)
	}
	res.Findings = dedupe(all)

	sinkMu.Lock()
	err := d.Sink.SaveFindings(ctx, run, res.Findings)
	sinkMu.Unlock()
	if err != nil {
		return res, fmt.Errorf("save findings for run %q: %w", run, err)
	}
	return res, nil
}

func validate(d Deps, run string, w core.Window) error {
	switch {
	case run == "":
		return errors.New("hunt: run id is empty")
	case !w.From.Before(w.To):
		return errors.New("hunt: window is empty or inverted")
	case d.Sink == nil || d.Reader == nil:
		return errors.New("hunt: sink and reader are required")
	case len(d.Sources) == 0:
		return errors.New("hunt: no sources")
	case len(d.Detectors) == 0:
		return errors.New("hunt: no detectors")
	}
	seen := map[string]bool{}
	for _, s := range d.Sources {
		if seen[s.Name()] {
			return fmt.Errorf("hunt: duplicate source name %q (its events would replace each other)", s.Name())
		}
		seen[s.Name()] = true
	}
	sources := seen
	seen = map[string]bool{}
	for _, det := range d.Detectors {
		if seen[det.Name()] {
			return fmt.Errorf("hunt: duplicate detector name %q", det.Name())
		}
		seen[det.Name()] = true
	}
	for det, names := range d.Scopes {
		if !seen[det] {
			return fmt.Errorf("hunt: scope for detector %q, which is not among the detectors", det)
		}
		if len(names) == 0 {
			return fmt.Errorf("hunt: detector %q has an empty source scope; remove it to read every source", det)
		}
		for _, n := range names {
			if !sources[n] {
				return fmt.Errorf("hunt: detector %q is scoped to source %q, which is not among the sources", det, n)
			}
		}
	}
	return nil
}

// readersFor returns the readers a detector is handed: cur and prev, narrowed to the
// sources of its scope when it has one. Hunt and Activity both go through it, so the
// scope is applied in one place.
func (d Deps) readersFor(detector string, cur, prev core.EventReader) (core.EventReader, core.EventReader) {
	names, ok := d.Scopes[detector]
	if !ok {
		return cur, prev
	}
	return sourceReader{inner: cur, names: names}, sourceReader{inner: prev, names: names}
}

// sourceReader passes through only the events stored under one of names, and the shared
// documents one of names returned (Event.Returners, kept by the store). ingest stamps every event with the name of the source
// that returned it, so the stored source column is the source name whatever the mapper
// put in Event.Source.
type sourceReader struct {
	inner core.EventReader
	names []string
}

func (s sourceReader) reads(ev core.Event) bool {
	if slices.Contains(s.names, ev.Source) {
		return true
	}
	return slices.ContainsFunc(ev.Returners, func(r string) bool { return slices.Contains(s.names, r) })
}

func (s sourceReader) Events(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	return func(yield func(core.Event, error) bool) {
		for ev, err := range s.inner.Events(ctx, w) {
			if err == nil && !s.reads(ev) {
				continue
			}
			if !yield(ev, err) {
				return
			}
		}
	}
}

// ingest streams one source into the sink. The sink pulls from the iterator while
// it holds the writer lock, so the writes are serialised and nothing is buffered.
//
// A source of a shared scope (sharedScopes) is not stored yet: which source keeps a
// shared document is known only once every source has been read, so it is collected
// into the scope's docSet and the returned pending stores it afterwards.
func ingest(ctx context.Context, mu *sync.Mutex, sink core.Sink, src core.Source, run string, w core.Window, shared map[string]*docSet) (SourceResult, *pending) {
	var docs *docSet
	if ds, ok := src.(core.DocScoped); ok {
		docs = shared[ds.DocScope()]
	}
	if docs != nil {
		p := &pending{name: src.Name(), src: src, docs: docs}
		for ev, err := range src.Fetch(ctx, w) {
			if err != nil {
				p.fetchErr = err
				break
			}
			ev.Source = src.Name()
			if err := docs.reserve(ev); err != nil {
				p.fetchErr = err
				break
			}
			if ev.DocKey == "" {
				p.keyless = append(p.keyless, ev)
				continue
			}
			p.keyed++
			docs.claim(ev)
		}
		if p.fetchErr != nil {
			docs.fail(p.name)
		}
		return SourceResult{Name: src.Name()}, p
	}
	r := SourceResult{Name: src.Name()}
	sourceFailed := false // the source itself yielded an error, as opposed to the sink refusing an empty save
	counted := func(yield func(core.Event, error) bool) {
		for ev, err := range src.Fetch(ctx, w) {
			if err == nil {
				// The stored source column is the name of the source that returned the
				// event: scoped detectors select on it, so a mapper that labels its
				// events differently must not move them out of the source's scope.
				ev.Source = src.Name()
				r.Events++
			} else {
				sourceFailed = true
			}
			if !yield(ev, err) {
				return
			}
		}
	}
	mu.Lock()
	err := sink.SaveEvents(ctx, SourceRun(run, src.Name()), iter.Seq2[core.Event, error](counted))
	mu.Unlock()
	return finish(r, src, err, sourceFailed), nil
}

// finish classifies the outcome of saving one source and adds what the source reports.
func finish(r SourceResult, src core.Source, err error, sourceFailed bool) SourceResult {
	r.Status, r.Err = classify(err), err
	if pc, ok := src.(core.ParseCounter); ok {
		r.Unparsable = pc.Unparsable()
	}
	if lr, ok := src.(core.LivenessReporter); ok {
		l := lr.Liveness()
		// The sink refuses to replace a run with nothing, so a filter that matched nothing
		// in a live index arrives here as no_records. The source has just shown its index
		// alive, and yielded no error itself: that is an answer, and nothing was saved.
		if r.Status == StatusNoRecords && r.Events == 0 && !sourceFailed && l.Probed {
			r.Status, r.Err = StatusOK, nil
		}
		if r.Status == StatusOK && l.Probed {
			r.IndexAlive, r.IndexDocs = true, l.IndexTotal
		}
	}
	// Everything this source returned was already returned by another source: nothing was
	// saved, and the sink refused the empty save. The documents are in the evidence under
	// the other source, so this is an answer, not a dead source.
	if r.Status == StatusNoRecords && r.Events == 0 && r.Duplicates > 0 && !sourceFailed {
		r.Status, r.Err = StatusOK, nil
	}
	return r
}

// pending is a source of a shared scope that has been read but not stored.
type pending struct {
	name     string
	src      core.Source
	docs     *docSet
	keyless  []core.Event // events with no identity: never merged, always stored
	keyed    int64        // events with an identity that the source returned
	fetchErr error
}

// store saves what the source won: its keyless events and the shared documents for which
// it is the smallest returning source. The others it returned are duplicates.
func (p *pending) store(ctx context.Context, mu *sync.Mutex, sink core.Sink, run string, won []*sharedDoc) SourceResult {
	r := SourceResult{Name: p.name, Duplicates: p.keyed - int64(len(won))}
	stream := func(yield func(core.Event, error) bool) {
		for _, ev := range p.keyless {
			r.Events++
			if !yield(ev, nil) {
				return
			}
		}
		for _, d := range won {
			r.Events++
			if !yield(d.ev, nil) {
				return
			}
		}
		if p.fetchErr != nil {
			yield(core.Event{}, p.fetchErr)
		}
	}
	mu.Lock()
	err := sink.SaveEvents(ctx, SourceRun(run, p.name), iter.Seq2[core.Event, error](stream))
	mu.Unlock()
	return finish(r, p.src, err, p.fetchErr != nil)
}

// docSet remembers the documents one run has seen from sources of one scope: for each
// DocKey the copy to store, which is the one from the smallest source name, and every
// source that returned it. Memory is one event per distinct document.
type docSet struct {
	mu     sync.Mutex
	docs   map[string]*sharedDoc
	failed map[string]bool // sources whose read ended in an error: they do not own a shared document
	bytes  int64           // estimated size of what is held, bounded by sharedBufferLimit
}

// sharedBufferLimit bounds what the sources of one shared scope may hold in memory at
// once (an estimate: the raw document plus a fixed overhead per event). The stored copy of
// a shared document is chosen only after every source has been read, so the events wait in
// memory; past the limit the source fails and the run is incomplete, never out of memory.
var sharedBufferLimit int64 = 256 << 20

// reserve accounts for one more held event and refuses it past the limit. A document
// already held counts once: the copy that replaces it is not extra.
func (d *docSet) reserve(ev core.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ev.DocKey != "" {
		if _, held := d.docs[ev.DocKey]; held {
			return nil
		}
	}
	n := int64(len(ev.Raw)+len(ev.DocKey)) + 256
	if d.bytes+n > sharedBufferLimit {
		return fmt.Errorf("shared-scope buffer limit of %d MiB reached: sources of one cluster that overlap are held in memory until all are read; hunt fewer overlapping sources or a shorter window", sharedBufferLimit>>20)
	}
	d.bytes += n
	return nil
}

type sharedDoc struct {
	key       string
	ev        core.Event // the copy to store, from the winner
	winner    string
	returners []string
}

// claim records that ev.Source returned the document ev.DocKey. The result does not
// depend on the order of the calls: the winner is the smallest name, whenever it arrives.
func (d *docSet) claim(ev core.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	doc := d.docs[ev.DocKey]
	if doc == nil {
		d.docs[ev.DocKey] = &sharedDoc{key: ev.DocKey, ev: ev, winner: ev.Source, returners: []string{ev.Source}}
		return
	}
	if !slices.Contains(doc.returners, ev.Source) {
		doc.returners = append(doc.returners, ev.Source)
	}
	if ev.Source < doc.winner {
		doc.ev, doc.winner = ev, ev.Source
	}
}

// fail records that a source's read ended in an error. Its run is rolled back when it is
// stored, so it must not own a document that a source which read cleanly also returned.
func (d *docSet) fail(source string) {
	d.mu.Lock()
	d.failed[source] = true
	d.mu.Unlock()
}

// byWinner groups the documents by the source that stores them, in DocKey order, and sets
// Returners on a document more than one source returned. The owner is the smallest name
// among the sources that read cleanly; if every returner failed it is the smallest of them
// (the evidence is lost with the run, which is reported). Call it once every source has
// been read. A document the owner did not map itself keeps the first copy's fields: they
// describe the same document, only the mapper that read it differs.
func (d *docSet) byWinner() map[string][]*sharedDoc {
	out := map[string][]*sharedDoc{}
	for _, doc := range d.docs {
		owner := doc.winner
		if d.failed[owner] {
			for _, r := range slices.Sorted(slices.Values(doc.returners)) {
				if !d.failed[r] {
					owner = r
					break
				}
			}
		}
		doc.ev.Source = owner
		doc.winner = owner
		if len(doc.returners) > 1 {
			doc.ev.Returners = slices.Sorted(slices.Values(doc.returners))
		}
		out[owner] = append(out[owner], doc)
	}
	for _, l := range out {
		sort.Slice(l, func(i, j int) bool { return l[i].key < l[j].key })
	}
	return out
}

// sharedScopes returns a docSet for each scope that two or more sources report, so a
// run with one source per cluster keeps no per-document memory. The source that keeps a
// shared document is the smallest name among those that returned it, so it depends on
// neither the order of the sources nor on which read first.
func sharedScopes(srcs []core.Source) map[string]*docSet {
	n := map[string]int{}
	for _, s := range srcs {
		if ds, ok := s.(core.DocScoped); ok && ds.DocScope() != "" {
			n[ds.DocScope()]++
		}
	}
	out := map[string]*docSet{}
	for scope, c := range n {
		if c > 1 {
			out[scope] = &docSet{docs: map[string]*sharedDoc{}, failed: map[string]bool{}}
		}
	}
	return out
}

// forEach runs fn(i) for i in [0, count) with at most limit running at once. An index
// not started because ctx ended is passed to skipped instead.
func forEach(ctx context.Context, limit, count int, fn, skipped func(i int)) {
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range count {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			skipped(i)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}()
	}
	wg.Wait()
}

// dedupe keeps one finding per Tag: the most severe, the first seen on a tie. A
// finding without a Tag has no identity to dedupe on, so it is kept as it is.
func dedupe(fs []core.Finding) []core.Finding {
	idx := map[string]int{}
	var out []core.Finding
	for _, f := range fs {
		if f.Tag == "" {
			out = append(out, f)
			continue
		}
		if i, ok := idx[f.Tag]; ok {
			if f.Severity > out[i].Severity {
				out[i] = f
			}
			continue
		}
		idx[f.Tag] = len(out)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// boundedReader clamps every read to bound, so a detector handed "the current
// window" cannot read the baseline by accident, or the reverse.
type boundedReader struct {
	inner core.EventReader
	bound core.Window
}

func (b boundedReader) Events(ctx context.Context, w core.Window) iter.Seq2[core.Event, error] {
	if w.From.Before(b.bound.From) {
		w.From = b.bound.From
	}
	if w.To.After(b.bound.To) {
		w.To = b.bound.To
	}
	if !w.From.Before(w.To) {
		return func(func(core.Event, error) bool) {}
	}
	return b.inner.Events(ctx, w)
}
