package core

import "context"

// KeyCounter is an optional port of a Source: it counts events of any kind for a set of
// keys, with the source's own filter removed. It makes a network call, unlike
// LivenessReporter, which reports state cached from the last Fetch.
//
// A key is data. An implementation sends it as a value inside a request body, refuses a
// key it cannot send safely, and puts no key in an error or a log line.
type KeyCounter interface {
	// CountKeys returns, for every key asked about, how many events carried it in w.
	// A key with no event maps to 0. An error means no count can be trusted.
	CountKeys(ctx context.Context, keys []string, w Window) (map[string]int64, error)
	// CountAll reports how many events of any kind the source's index holds in w.
	CountAll(ctx context.Context, w Window) (int64, error)
}

// KeyHistory counts keys across the distinct indices a detector reads. It is safe for
// concurrent use. A failure, including an index that cannot show history, is an error:
// a zero from a blind index must never look like a key with no history.
type KeyHistory interface {
	Counts(ctx context.Context, keys []string, w Window) (map[string]int64, error)
}

// HistoryDetector is a Detector that can judge with a KeyHistory. The host prefers
// DetectWithHistory over Detect. A detector configured to need history returns an error
// from Detect and never falls back to the preceding window.
type HistoryDetector interface {
	Detector
	DetectWithHistory(ctx context.Context, cur, prev EventReader, w Window, h KeyHistory) ([]Finding, error)
}
