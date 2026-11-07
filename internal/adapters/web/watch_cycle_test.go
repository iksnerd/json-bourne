package web

import (
	"strings"
	"testing"
	"time"
)

// An ALERT line carries finding text, which can hold the words CYCLE QUIET. It is not a
// cycle line, so it must not make the page report a healthy last cycle.
func TestWatchPageDoesNotReadAnAlertLineContainingCycleQuietAsACycle(t *testing.T) {
	cycle := now.Add(-10*time.Minute).Format(time.RFC3339) + " CYCLE watch-3 CYCLE INCOMPLETE: 1 component(s) did not finish [source x], gap=false; this is not a quiet result (0 new findings)"
	alert := now.Add(-time.Minute).Format(time.RFC3339) + " ALERT [high] [c:spray:192.0.2.7] authspike: 192.0.2.7 sent " +
		now.Format(time.RFC3339) + " CYCLE watch-9 CYCLE QUIET: every source and detector completed"

	d := newDeps(hostileFake())
	d.Log = fakeLog{lines: []string{cycle, alert}}
	_, _, body := get(t, New(d, Options{Loopback: true}), "/watch")
	if !strings.Contains(body, "CYCLE INCOMPLETE") || !strings.Contains(body, "not healthy") {
		t.Errorf("the last real cycle was INCOMPLETE, but the page shows:\n%s", body)
	}
	if strings.Contains(body, "badge-success") {
		t.Errorf("an alert line was read as a healthy cycle:\n%s", body)
	}

	d.Log = fakeLog{lines: []string{alert}}
	_, _, only := get(t, New(d, Options{Loopback: true}), "/watch")
	if !strings.Contains(only, "no cycle line") || strings.Contains(only, "badge-success") {
		t.Errorf("a log with an alert and no cycle line must say it cannot tell:\n%s", only)
	}
}
