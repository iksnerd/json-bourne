package core

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AlertKind says why an Alert exists. The values are part of the wire contract of
// AlertSink: a delivery adapter may route or filter on them.
const (
	AlertFinding    = "finding"    // a detector finding that is new this cycle
	AlertIncomplete = "incomplete" // a source or detector did not finish, or time went unexamined: the result is unknown, not quiet
	AlertError      = "error"      // the cycle itself failed (hunt error, state problem)
	AlertCycle      = "cycle"      // end-of-cycle heartbeat, so a silent watcher is distinguishable from a broken one
	AlertRecovered  = "recovered"  // a component that was reported down finished again
)

// Alert is one message from a watch cycle to a human. It holds plain values only
// (strings, JSON-tagged), so it can cross a process boundary unchanged: a delivery
// adapter may be a library today and a separate process later.
type Alert struct {
	Kind     string `json:"kind"`
	Tag      string `json:"tag"`
	Severity string `json:"severity"` // SeverityName: info, check, activity, high, critical
	Detector string `json:"detector,omitempty"`
	Text     string `json:"text"`
	Run      string `json:"run,omitempty"`
	At       string `json:"at"` // RFC 3339, UTC
	// Watcher is the name of the watcher that raised the alert (`jb watch --name`), so
	// that the logs of two watchers on one case can be told apart. Empty for the
	// unnamed watcher, and then absent from every rendering.
	Watcher string `json:"watcher,omitempty"`
}

// AlertSink delivers one alert. It returns nil only when the alert was delivered;
// any other outcome is an error, never a silent drop. The watch loop treats an
// undelivered alert as not yet seen, so it is offered again next cycle.
type AlertSink interface {
	Deliver(ctx context.Context, a Alert) error
}

// WatchState is what a watcher remembers between cycles and restarts: when each
// condition tag last fired, and how severe it was then.
type WatchState struct {
	Seen map[string]SeenTag
	// Health holds the outages already alerted, keyed by component, so an identical
	// failure is not repeated every cycle. Findings never use it.
	Health map[string]HealthSeen
}

// HealthSeen is the record of one outage having been alerted: when, and the
// fingerprint of the failure text at that time.
type HealthSeen struct {
	At          time.Time
	Fingerprint string
}

// SeenTag is the record of one tag having been surfaced.
type SeenTag struct {
	At       time.Time
	Severity Severity
}

// ErrStateCorrupt means the persisted watch state could not be trusted.
var ErrStateCorrupt = errors.New("watch state is corrupt")

// WatchStateStore persists WatchState. Load returns an empty state and no error
// when nothing has been saved yet, and an error wrapping ErrStateCorrupt when what
// is there cannot be trusted. Save replaces the state atomically.
type WatchStateStore interface {
	Load(ctx context.Context) (WatchState, error)
	Save(ctx context.Context, s WatchState) error
}

var severityNames = [...]string{SevInfo: "info", SevCheck: "check", SevActivity: "activity", SevHigh: "high", SevCritical: "critical"}

// SeverityName is the stable text form of a severity.
func SeverityName(s Severity) string {
	if s >= 0 && int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprintf("sev%d", int(s))
}

// ParseSeverity is the inverse of SeverityName.
func ParseSeverity(n string) (Severity, bool) {
	for i, v := range severityNames {
		if v == n {
			return Severity(i), true
		}
	}
	return 0, false
}

// OptionalDeliveryError means the required sink delivered the alert and an optional
// sink did not. The alert counts as delivered (the required log is the source of
// truth, and offering it again would duplicate it in every sink that did get it), but
// the failure is never silent: the watch loop fails the cycle on it.
type OptionalDeliveryError struct{ Err error }

func (e *OptionalDeliveryError) Error() string { return "optional alert sink: " + e.Err.Error() }
func (e *OptionalDeliveryError) Unwrap() error { return e.Err }

// FanOut delivers each alert to a required sink and then to every optional one.
//
//   - If Required fails, the alert is undelivered: the error is returned as is and no
//     optional sink is tried, so the next cycle's retry cannot duplicate it elsewhere.
//   - If Required succeeds, every optional sink is tried whatever the others did. Their
//     failures come back together as one *OptionalDeliveryError.
type FanOut struct {
	Required AlertSink
	Optional []AlertSink
}

// Deliver implements AlertSink.
func (f FanOut) Deliver(ctx context.Context, a Alert) error {
	if err := f.Required.Deliver(ctx, a); err != nil {
		return err
	}
	var errs []error
	for _, s := range f.Optional {
		if err := s.Deliver(ctx, a); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return &OptionalDeliveryError{Err: errors.Join(errs...)}
	}
	return nil
}
