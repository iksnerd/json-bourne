package core

import (
	"context"
	"time"
)

// PruneResult counts what one PruneRuns removed. A caller reports it; pruning that
// cannot say how much it deleted is not allowed.
type PruneResult struct {
	Runs     int64 // run ids removed (one per source plus one for the findings of each hunt)
	Events   int64
	Findings int64
}

// RunPruner removes old runs from the evidence store.
//
// PruneRuns deletes the events, the findings and the run records of every hunt whose
// id is exactly prefix followed by a UTC stamp (20060102T150405Z; nothing more, so
// "watch-a-" never matches the runs of "watch-ab-" or "watch-a-b-", and "watch-" never
// matches a named watcher's) and whose newest record is older than before, in one
// transaction: either all of it goes or none. The most recent such hunt is never
// removed, however old, and a run id that is not of that shape is never touched.
// A hunt's run ids are the id itself (its findings) and id + "/" + source (its events);
// they are removed together.
type RunPruner interface {
	PruneRuns(ctx context.Context, prefix string, before time.Time) (PruneResult, error)
}

// ParseCounter is an optional port of a Source: how many documents of its most recent
// Fetch it could not parse. They are in no event, so this is the only place they show.
type ParseCounter interface {
	Unparsable() int
}
