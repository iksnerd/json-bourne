package jb

import (
	"time"

	"github.com/iksnerd/json-bourne/internal/config"
)

// The schema of an operation has no duration and no time: a window, a timeout and an
// until are strings that the handler reads here, with the functions the command line
// uses (config.ParseWindow, config.ParseUntil, config.ParseWhen, config.ParseAge). A
// value that does not parse is a [UsageError] that names the property.

// windowArg reads a window such as 90m, 24h or 7d. An absent property is zero, which the
// typed function reads as its own default.
func windowArg(a argv, name, s string) (time.Duration, error) {
	if !a.has(name) {
		return 0, nil
	}
	d, err := config.ParseWindow(s)
	if err != nil {
		return 0, usagef("%s: %v", name, err)
	}
	if d <= 0 {
		return 0, usagef("%s must be positive, got %s", name, d)
	}
	return d, nil
}

// untilArg reads the end of a past window (RFC 3339 with a zone, not after now).
func untilArg(a argv, name, s string) (time.Time, error) {
	if !a.has(name) {
		return time.Time{}, nil
	}
	t, err := config.ParseUntil(name, s, time.Now())
	if err != nil {
		return time.Time{}, usagef("%v", err)
	}
	return t, nil
}

// whenArg reads an RFC 3339 time or a YYYY-MM-DD date; absent is the zero time.
func whenArg(name, s string) (time.Time, error) {
	t, err := config.ParseWhen(name, s)
	if err != nil {
		return time.Time{}, usagef("%v", err)
	}
	return t, nil
}

// durationArg reads a Go duration such as 10s. An absent property is zero, which the
// typed function reads as its own default. An explicit 0 is refused, as the command
// line refuses --timeout 0: the library would read it as "the default".
func durationArg(a argv, name, s string) (time.Duration, error) {
	if !a.has(name) {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, usagef("%s %q: not a duration such as 10s: %v", name, s, err)
	}
	if d == 0 {
		return 0, usagef("%s must not be 0", name)
	}
	return d, nil
}
