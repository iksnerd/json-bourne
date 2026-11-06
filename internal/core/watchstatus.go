package core

import (
	"context"
	"time"
)

// WatchCycleSummary is what a status record keeps of the last finished cycle. It holds
// names and counts, never an error text, so it cannot carry a credential.
type WatchCycleSummary struct {
	Run        string
	Verdict    string // QUIET, FINDINGS, INCOMPLETE or FAILED
	Ended      time.Time
	Window     Window
	New        int
	Suppressed int
	Repeated   int
	Recovered  int
	Failed     []string // components that did not finish
}

// WatchStatus is what the watch loop knows about itself: how it runs, the last cycle
// and when the next one is due. The adapter adds what the loop does not know (PID,
// start time, config path) and writes it where a program can read it.
type WatchStatus struct {
	Every, Window, TTL, Keep, Repeat time.Duration
	Updated                          time.Time
	Last                             *WatchCycleSummary // nil before the first cycle ends
	NextDue                          time.Time          // zero for a run that does one cycle
}

// WatchStatusSink publishes a WatchStatus. Save replaces the previous one atomically.
type WatchStatusSink interface {
	Save(ctx context.Context, s WatchStatus) error
}
