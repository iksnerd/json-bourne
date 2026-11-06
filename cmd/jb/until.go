package main

import (
	"fmt"
	"time"

	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// maxUntilWindow is the longest --window a historical hunt accepts. A live hunt has no
// cap of its own, but a historical one is a backfill: its window and the baseline
// before it come from the source in one go, and a month-long window ends in a fetch of
// two months. Loop over days (docs/BACKFILL.md) instead of asking for one huge window.
const maxUntilWindow = 31 * 24 * time.Hour

// parseUntil reads --until (see config.ParseUntil for the rules).
func parseUntil(s string, now time.Time) (time.Time, error) {
	return config.ParseUntil("--until", s, now)
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
