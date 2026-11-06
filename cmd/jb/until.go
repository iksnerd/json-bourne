package main

import (
	"fmt"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// maxUntilWindow is the longest --window a historical hunt accepts. A live hunt has no
// cap of its own, but a historical one is a backfill: its window and the baseline
// before it come from the source in one go, and a month-long window ends in a fetch of
// two months. Loop over days (docs/BACKFILL.md) instead of asking for one huge window.
const maxUntilWindow = 31 * 24 * time.Hour

// parseUntil reads --until: an RFC 3339 time that carries its zone ("2026-10-01T00:00:00Z"
// or "2026-10-01T02:00:00+02:00"). A time without a zone is refused, not read as UTC or
// local: the same text means different instants on different machines, and a window that
// silently moves by the zone offset shows the wrong hours as quiet. Fractions of a second
// are refused too, because the window edges are whole seconds and rounding would move
// them. A time after now is refused: there is nothing to fetch there yet.
func parseUntil(s string, now time.Time) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--until %q: want RFC 3339 with a zone, such as 2026-10-01T00:00:00Z or 2026-10-01T02:00:00+02:00 (a time without a zone is ambiguous and is refused): %w", s, err)
	}
	if t.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("--until %q: whole seconds only; the window edges are not rounded", s)
	}
	t = t.UTC()
	if t.After(now.UTC().Truncate(time.Second)) {
		return time.Time{}, fmt.Errorf("--until %s is after now (%s): a window cannot end in the future", t.Format(time.RFC3339), now.UTC().Truncate(time.Second).Format(time.RFC3339))
	}
	return t, nil
}

// windowPlan is the window a command hunts: ending now, or ending at --until.
type windowPlan struct {
	W     core.Window
	Until time.Time // zero for a live window
}

func (p windowPlan) Historical() bool { return !p.Until.IsZero() }

// planWindow returns the window [to - length, to) where to is until when given, else now
// (whole seconds). The baseline is w.Previous() as ever: nothing here is relative to the
// clock except the live default.
func planWindow(now time.Time, length time.Duration, until time.Time) (windowPlan, error) {
	if until.IsZero() {
		to := now.UTC().Truncate(time.Second)
		return windowPlan{W: core.Window{From: to.Add(-length), To: to}}, nil
	}
	if length > maxUntilWindow {
		return windowPlan{}, usageErrorf("--window %s is longer than the %s a historical hunt accepts; hunt it a day at a time (docs/BACKFILL.md)", length, maxUntilWindow)
	}
	return windowPlan{W: core.Window{From: until.Add(-length), To: until}, Until: until}, nil
}

// runID names the run a hunt is stored under. A live run is <prefix>-<end of window>, as
// it always was. A historical run is <prefix>-until-<end of window>-w<length in seconds>:
// it cannot collide with a live run started in the same second, the window it covers is in
// the name, and the same window hunted again is the same run, which the store replaces
// rather than adds to. The length is in the name because two windows that end together
// but differ in length are different evidence and must not replace each other.
// Retention only ever touches "watch-" ids, and a historical run never begins with it.
func (p windowPlan) runID(prefix string) string {
	end := p.W.To.UTC().Format("20060102T150405Z")
	if !p.Historical() {
		return prefix + "-" + end
	}
	return fmt.Sprintf("%s-until-%s-w%ds", prefix, end, int64(p.W.Duration()/time.Second))
}
