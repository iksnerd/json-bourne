package jb

import (
	"testing"
	"time"
)

// Two accepted historical windows must never share a run id: the id encodes whole
// seconds, so a window that is not a whole number of seconds is refused, live or past.
func TestPlanRefusesSubSecondWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	until := now.Add(-time.Hour)
	for _, win := range []time.Duration{1500 * time.Millisecond, 1900 * time.Millisecond, time.Second + time.Nanosecond} {
		for _, u := range []time.Time{{}, until} {
			_, _, err := plan(now, HuntOptions{Until: u, Window: win}, "hunt")
			if err == nil || !IsUsage(err) {
				t.Errorf("window %s until=%v: want usage error, got %v", win, u, err)
			}
		}
	}
	if _, _, err := plan(now, HuntOptions{Until: until, Window: 90 * time.Second}, "hunt"); err != nil {
		t.Errorf("whole-second window refused: %v", err)
	}
}
