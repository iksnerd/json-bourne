package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The functions in this file read the text forms of a time or an age. The command line
// and the operation handlers (RFC 0010) both call them, so a flag and a tool argument
// accept the same text and refuse the same text. label names the argument in a message:
// "--until" on the command line, "until" in a tool call.

// ParseUntil reads an RFC 3339 time that carries its zone ("2026-10-01T00:00:00Z" or
// "2026-10-01T02:00:00+02:00"). A time without a zone is refused, not read as UTC or
// local: the same text means different instants on different machines, and a window that
// silently moves by the zone offset shows the wrong hours as quiet. Fractions of a second
// are refused too, because the window edges are whole seconds and rounding would move
// them. A time after now is refused: there is nothing to fetch there yet.
func ParseUntil(label, s string, now time.Time) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q: want RFC 3339 with a zone, such as 2026-10-01T00:00:00Z or 2026-10-01T02:00:00+02:00 (a time without a zone is ambiguous and is refused): %w", label, s, err)
	}
	if t.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("%s %q: whole seconds only; the window edges are not rounded", label, s)
	}
	t = t.UTC()
	if t.After(now.UTC().Truncate(time.Second)) {
		return time.Time{}, fmt.Errorf("%s %s is after now (%s): a window cannot end in the future", label, t.Format(time.RFC3339), now.UTC().Truncate(time.Second).Format(time.RFC3339))
	}
	return t, nil
}

// ParseAge reads an age such as 14d, 2w or anything time.ParseDuration accepts (72h).
func ParseAge(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(s, suffix); ok {
			v, err := strconv.ParseUint(n, 10, 32)
			if err != nil {
				return 0, fmt.Errorf("%q is not a duration like 14d, 72h or 2w", s)
			}
			return time.Duration(v) * unit, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration like 14d, 72h or 2w", s)
	}
	return d, nil
}

// ParseWhen reads an RFC 3339 time or a YYYY-MM-DD date (UTC). Empty is the zero time.
func ParseWhen(label, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%s %q: expected an RFC 3339 time or a YYYY-MM-DD date", label, v)
}
