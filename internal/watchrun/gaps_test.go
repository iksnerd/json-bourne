package watchrun

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/watchstatus"
	"github.com/iksnerd/json-bourne/internal/core"
)

// gapFixture writes a watcher "a" with the given interval (0: no status record) and one
// cycle line at each offset from hT0.
func gapFixture(t *testing.T, every time.Duration, offsets ...time.Duration) string {
	t.Helper()
	dir := t.TempDir()
	var lines []string
	for _, o := range offsets {
		lines = append(lines, cyc(hT0.Add(o), "watch-a-r", "QUIET"))
	}
	writeLog(t, dir, "a", lines...)
	if every > 0 {
		saveRecord(t, dir, every)
	}
	return dir
}

func saveRecord(t *testing.T, dir string, every time.Duration) {
	t.Helper()
	w := watchstatus.Writer{Path: filepath.Join(dir, File(StatusFile, "a")), Name: "a", PID: 1, Started: hT0}
	st := core.WatchStatus{Every: every, Window: time.Hour, TTL: time.Hour, Keep: 48 * time.Hour, Repeat: time.Hour, Updated: hT0}
	if err := w.Save(context.Background(), st); err != nil {
		t.Fatal(err)
	}
}

func gapsOf(t *testing.T, dir string, now time.Time) core.WatchHistory {
	t.Helper()
	h, err := History{Evidence: dir}.Read(context.Background(), "a", now)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The rule is the one of jb watch status: strictly more than HeartbeatFactor intervals.
// Exactly that many is not a marker.
func TestGapBetweenCyclesIsStrictlyMoreThanThreeIntervals(t *testing.T) {
	e := 5 * time.Minute
	limit := HeartbeatFactor * e
	for _, tc := range []struct {
		name string
		gap  time.Duration
		want bool
	}{
		{"3E minus 1s", limit - time.Second, false},
		{"exactly 3E", limit, false},
		{"3E plus 1s", limit + time.Second, true},
	} {
		dir := gapFixture(t, e, 0, tc.gap)
		h := gapsOf(t, dir, hT0.Add(tc.gap)) // now is the second cycle, so no trailing span
		if got := len(h.Gaps) == 1; got != tc.want {
			t.Errorf("%s: gaps = %+v, want marker %v", tc.name, h.Gaps, tc.want)
		}
		if tc.want && (!h.Gaps[0].From.Equal(hT0) || !h.Gaps[0].To.Equal(hT0.Add(tc.gap))) {
			t.Errorf("%s: span = %+v", tc.name, h.Gaps[0])
		}
	}
}

func TestTrailingGapIsOpenAndHasNoLeadingGap(t *testing.T) {
	e := 5 * time.Minute
	dir := gapFixture(t, e, 0, time.Minute)
	last := hT0.Add(time.Minute)
	if h := gapsOf(t, dir, last.Add(3*e)); len(h.Gaps) != 0 {
		t.Errorf("exactly 3E after the last cycle: %+v", h.Gaps)
	}
	h := gapsOf(t, dir, last.Add(3*e+time.Second))
	if len(h.Gaps) != 1 || !h.Gaps[0].From.Equal(last) || !h.Gaps[0].To.IsZero() {
		t.Fatalf("trailing = %+v, want one open span from the last cycle", h.Gaps)
	}
	// Time before the first cycle read is never judged.
	if h := gapsOf(t, gapFixture(t, e, time.Hour), hT0.Add(time.Hour)); len(h.Gaps) != 0 {
		t.Errorf("leading span drawn: %+v", h.Gaps)
	}
}

func TestUnknownIntervalJudgesNothing(t *testing.T) {
	dir := gapFixture(t, 0, 0, 10*time.Hour)
	h := gapsOf(t, dir, hT0.Add(48*time.Hour))
	if h.Every != 0 || len(h.Gaps) != 0 || len(h.Cycles) != 2 {
		t.Errorf("no record: every %v gaps %+v", h.Every, h.Gaps)
	}
}

func TestACutLogStillJudgesTheSpansItShows(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 0; i < 300; i++ {
		at := hT0.Add(time.Duration(i) * time.Minute)
		if i >= 290 {
			at = at.Add(time.Hour) // one long silence in the kept tail
		}
		lines = append(lines, cyc(at, "watch-a-r", "QUIET"))
	}
	writeLog(t, dir, "a", lines...)
	saveRecord(t, dir, time.Minute)
	last := hT0.Add(299*time.Minute + time.Hour)
	h, err := History{Evidence: dir, MaxBytes: 4000}.Read(context.Background(), "a", last)
	if err != nil || !h.Cut {
		t.Fatalf("cut %v err %v", h.Cut, err)
	}
	if len(h.Gaps) != 1 || !h.Gaps[0].From.Equal(hT0.Add(289*time.Minute)) {
		t.Errorf("gaps = %+v, want the one silence inside the kept tail and none before it", h.Gaps)
	}
}

func TestOverdueIsTheRuleOfWatchStatus(t *testing.T) {
	e := time.Minute
	if Overdue(hT0, hT0.Add(3*e), e) || !Overdue(hT0, hT0.Add(3*e+time.Nanosecond), e) {
		t.Error("Overdue must be strictly more than HeartbeatFactor intervals")
	}
}
