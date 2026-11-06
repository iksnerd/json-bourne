package core

import (
	"context"
	"errors"
	"time"
)

// Read-only dashboard ports. `jb serve` shows the evidence store, the watch files and
// the estate map to a human. Everything these ports return came from evidence and is
// untrusted text: it holds log content, so an adapter that renders it must escape it.
// None of these ports can write, and none takes SQL: the questions are fixed.

// ErrAbsent means the thing asked for is not there (no database file yet, no
// watch.log, no estate directory). It is an answer, and a panel says why it is empty;
// it is not a failure and never renders as a clean result.
var ErrAbsent = errors.New("not present")

// StoreStats is the row count summary of the evidence store.
type StoreStats struct {
	SchemaVersion int
	Runs          int64
	Events        int64
	Findings      int64
	Reputation    int64
	FirstSeen     time.Time // zero when there are no events
	LastSeen      time.Time
}

// RunGroup is one hunt or watch cycle: the run ids that share the part before the
// first "/" (the findings run "watch-X" and its event runs "watch-X/<source>").
type RunGroup struct {
	ID        string
	Created   time.Time // earliest run record in the group
	EventRuns int       // how many "<id>/<source>" event runs were stored
	Events    int64     // stored rows, not de-duplicated across runs
	Findings  int64
}

// Incomplete says a run holds no events. The store does not persist per-source
// completion, so this is the one signal it can give honestly: a hunt whose sources
// all failed or returned nothing stores no event run, and that is not a quiet result.
func (g RunGroup) Incomplete() bool { return g.Events == 0 }

// Count is one row of a top-N table.
type Count struct {
	Label string
	N     int64
}

// EventSummary counts the stored events of one run group.
type EventSummary struct {
	Rows     int64
	BySource []Count
	ByKind   []Count
	ByStatus []Count
	TopPaths []Count // query string and fragment removed before grouping
	TopKeys  []Count
}

// DashboardFields names the event fields the summary groups on. They are source
// specific (the default mapper emits path, status and client_ip), so the operator
// names them, as a detector's config does.
type DashboardFields struct {
	Path, Status, Key string
}

// StoredFinding is a finding with the run it was saved under.
type StoredFinding struct {
	Run string
	Finding
}

// StoredEvent is an event with the run it was saved under. Raw is never filled.
type StoredEvent struct {
	Run string
	Event
}

// DashboardStore is the read side of the evidence store as the dashboard needs it.
// Every method is bounded by its limit and by ctx. Implementations must be backed by
// a read-only handle enforced by the storage engine.
type DashboardStore interface {
	Stats(ctx context.Context) (StoreStats, error)
	Runs(ctx context.Context, limit int) ([]RunGroup, error)
	// Run returns ErrNotFound (wrapped) when no run has that group id.
	Run(ctx context.Context, group string) (RunGroup, error)
	EventSummary(ctx context.Context, group string, f DashboardFields, top int) (EventSummary, error)
	RecentEvents(ctx context.Context, group string, limit int) ([]StoredEvent, error)
	RunFindings(ctx context.Context, group string, limit int) ([]StoredFinding, error)
	LatestFindings(ctx context.Context, limit int) ([]StoredFinding, error)
	LatestReputation(ctx context.Context, limit int) ([]Reputation, error)
	Close() error
}

// LogTailer returns the last n lines of the watch alert log. ErrAbsent when there is
// no log.
type LogTailer interface {
	Tail(ctx context.Context, n int) ([]string, error)
}

// WatchStatePeeker reads the watch state without changing it (the writer's Load
// moves a corrupt file aside; a viewer must not). ErrAbsent when there is no file,
// ErrStateCorrupt when it cannot be trusted.
type WatchStatePeeker interface {
	Peek(ctx context.Context) (WatchState, error)
}

// EstateGraph is a loaded estate file as the dashboard shows it.
type EstateGraph struct {
	ID       string
	Caveat   string
	Nodes    []EstateNode
	Edges    []EstateEdge
	Absences []EstateAbsence
	// Assessments are opinion, kept apart from the claims. The dashboard marks them so.
	Assessments []EstateAssessment
}

// EstateNode, EstateEdge and EstateAbsence carry the provenance every claim has.
type EstateNode struct {
	ID, Kind, Label, Source, Method, Observed string
	Facts                                     []EstateFact
}

// EstateFact is one observation about a node, with the provenance every claim has.
type EstateFact struct {
	Key, Value, Source, Method, Observed string
}

// EstateAssessment is one author's judgement about a node. It is opinion, not
// observation. Basis holds node ids or "<node id>#<fact key>".
type EstateAssessment struct {
	ID, Subject, Label, By, Decided string
	Basis                           []string
	Note                            string
}

type EstateEdge struct {
	From, To, Relation, Source, Method, Observed, Confidence, InferredFrom string
}

type EstateAbsence struct {
	Subject, Source, Method, Observed, Answer string
}

// EstateReader loads the estate files. ErrAbsent (wrapped, with the reason) when
// there is no estate directory or it holds no file.
type EstateReader interface {
	Estates(ctx context.Context) ([]EstateGraph, error)
}
