package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real hunt and a real watch cycle write the store, the log and the status record;
// the timeline reads them back through the real dashboard wiring. The log's cycle time
// is moved to the present (the fake search holds data around fixedNow, the store stamps
// the real clock), which changes nothing the parser reads.
func TestServeTimelineShowsAHuntAndAWatchCycleThenAMarkerWhenTheClockPassesThreeIntervals(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	if code, _, stderr := run(t, d, "hunt", "--case", dir); code != 0 {
		t.Fatalf("hunt exit %d: %s", code, stderr)
	}
	if code, stdout, stderr := run(t, d, "watch", "--case", dir, "--once"); code != 0 {
		t.Fatalf("watch exit %d\n%s\n%s", code, stdout, stderr)
	}
	real := time.Now().UTC().Truncate(time.Second)
	cycleAt := real.Add(-2 * time.Minute)
	logPath := filepath.Join(dir, "evidence", "watch.log")
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.ReplaceAll(string(b), fixedNow.Format(time.RFC3339), cycleAt.Format(time.RFC3339))
	if err := os.WriteFile(logPath, []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}

	at := func(now time.Time) string {
		sd := testDeps(nil)
		sd.now = func() time.Time { return now }
		base, _, stop := startServe(t, sd, "--case", dir, "--addr", "127.0.0.1:0")
		defer stop()
		code, body := fetch(t, base+"/timeline?w=1h")
		if code != 200 {
			t.Fatalf("/timeline = %d\n%s", code, body)
		}
		return body
	}
	body := at(real.Add(time.Minute))
	for _, want := range []string{"authspike", "192.0.2.7", "(hunt)", "(unnamed)", "CYCLE FINDINGS", "<td>cycle</td>"} {
		if !strings.Contains(body, want) {
			t.Errorf("timeline lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<td>no cycle recorded</td>") {
		t.Errorf("a marker was drawn two minutes after the last cycle:\n%s", body)
	}
	// The default interval is 5m: well past 3 intervals after the cycle, the span is reported.
	late := at(cycleAt.Add(3*5*time.Minute + 3*time.Minute))
	if !strings.Contains(late, "<td>no cycle recorded</td>") || !strings.Contains(late, "No cycle line in watch.log since "+cycleAt.Format(time.RFC3339)) {
		t.Errorf("no marker after 3 intervals:\n%s", late)
	}
}
