package jb

import (
	"fmt"
	"time"

	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

type (
	// WatcherStatus is one watcher of a case as [WatchStatus] found it.
	WatcherStatus = watchrun.WatcherStatus
	// WatcherState is what a watcher is doing: running, stale, stopped or unknown.
	WatcherState = watchrun.State
)

// Watcher states. Only WatcherRunning means a watcher is alive and cycling.
const (
	// WatcherRunning: the lock is held and a cycle ended within WatchHeartbeatFactor intervals.
	WatcherRunning = watchrun.StateRunning
	// WatcherStale: the lock is held, but no cycle ended in that time.
	WatcherStale = watchrun.StateStale
	// WatcherStopped: there is a status record and no process holds the lock.
	WatcherStopped = watchrun.StateStopped
	// WatcherUnknown: there is no readable status record (a watcher from an older build,
	// or one that never started); WatcherStatus.Reason says which.
	WatcherUnknown = watchrun.StateUnknown
)

// WatchHeartbeatFactor is how many of a watcher's intervals may pass after its last
// cycle ended before a watcher that still holds its lock is called stale.
const WatchHeartbeatFactor = watchrun.HeartbeatFactor

// WatchStatusOptions select the watchers [WatchStatus] reports.
type WatchStatusOptions struct {
	// Names limits the answer to these watchers; "" in it is the unnamed watcher. Nil
	// means every watcher found in the case's evidence directory. A named watcher with
	// neither lock nor record is reported as WatcherUnknown, not left out.
	Names []string
	// Config names one of the case's configs, as in [CaseHuntOptions], and keeps only the
	// watchers whose record says they run it.
	Config string
	// Now is the clock for the heartbeat. Nil means time.Now.
	Now func() time.Time
}

// WatchStatus reports whether the watchers of a case are alive and what they run, from
// the status record each `jb watch` keeps in the case's evidence directory and from its
// lock. It reads two small files per watcher, never takes the lock and writes nothing,
// so it is safe to call while a watcher runs. The result is ordered by name, the
// unnamed watcher first; a case with no watcher gives an empty result and no error.
func WatchStatus(caseDir string, opts WatchStatusOptions) ([]WatcherStatus, error) {
	for _, n := range opts.Names {
		if err := app.ValidWatchName(n); err != nil {
			return nil, usagef("name: %v", err)
		}
	}
	o := watchrun.StatusOptions{Names: opts.Names}
	if opts.Now != nil {
		o.Now = opts.Now()
	}
	out, err := watchrun.CaseStatus(caseDir, opts.Config, o)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return out, nil
}
