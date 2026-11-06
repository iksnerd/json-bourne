package main

import (
	"time"

	jb "github.com/iksnerd/json-bourne"

	"github.com/iksnerd/json-bourne/internal/config"
)

// parseUntil reads --until (see config.ParseUntil for the rules).
func parseUntil(s string, now time.Time) (time.Time, error) {
	return config.ParseUntil("--until", s, now)
}

// checkUntilWindow refuses a --window the historical limit forbids, in the words of the
// flag. A live window has no cap of its own, but a historical one is a backfill: its
// window and the baseline before it come from the source in one go, and a month-long
// window ends in a fetch of two months. Loop over days (docs/BACKFILL.md) instead of
// asking for one huge window. The window, its run id and the baseline are the library's
// (jb.Hunt, jb.Activity); only the flag's own wording is here.
func checkUntilWindow(length time.Duration, until time.Time) error {
	if !until.IsZero() && length > jb.MaxHistoricalWindow {
		return usageErrorf("--window %s is longer than the %s a historical hunt accepts; hunt it a day at a time (docs/BACKFILL.md)", length, jb.MaxHistoricalWindow)
	}
	return nil
}
