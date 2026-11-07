package core

import (
	"testing"
	"time"
)

func TestParseWatchLogLine(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, line string
		kind       WatchLogKind
		verdict    string
		gap        bool
	}{
		{"quiet unnamed", "2026-11-05T12:00:00Z CYCLE watch-20261105T120000Z CYCLE QUIET: ok", WatchLineCycle, "QUIET", false},
		{"findings named", "2026-11-05T12:00:00Z CYCLE watch-a-1 [w:a] CYCLE FINDINGS: 1 new", WatchLineCycle, "FINDINGS", false},
		{"incomplete with gap", "2026-11-05T12:00:00Z CYCLE r [w:a] CYCLE INCOMPLETE: 1 component(s) did not finish [source x], gap=true; this is not a quiet result (0 new findings)", WatchLineCycle, "INCOMPLETE", true},
		{"incomplete no gap", "2026-11-05T12:00:00Z CYCLE r CYCLE INCOMPLETE: 1 component(s) did not finish [source x], gap=false; this is not a quiet result (0 new findings)", WatchLineCycle, "INCOMPLETE", false},
		{"failed", "2026-11-05T12:00:00Z CYCLE r CYCLE FAILED: boom; this is not a quiet result", WatchLineCycle, "FAILED", false},
		{"alert text with a cycle phrase", "2026-11-05T12:00:00Z ALERT [high] [c:t] d: x 2026-11-05T12:00:00Z CYCLE r CYCLE QUIET: y", WatchLineAlert, "", false},
		{"not a verdict", "2026-11-05T12:00:00Z CYCLE r CYCLE QUIETLY: y", WatchLineUnknown, "", false},
		{"bad time", "yesterday CYCLE r CYCLE QUIET: y", WatchLineUnknown, "", false},
		{"leading text", "x 2026-11-05T12:00:00Z CYCLE r CYCLE QUIET: y", WatchLineUnknown, "", false},
		{"empty", "", WatchLineUnknown, "", false},
	} {
		got := ParseWatchLogLine(tc.line)
		if got.Kind != tc.kind || got.Verdict != tc.verdict || got.GapReported != tc.gap {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if tc.kind == WatchLineCycle && !got.At.Equal(at) {
			t.Errorf("%s: at = %v", tc.name, got.At)
		}
	}
}

func TestParseWatchLogLineReadsAGapOnlyFromTheTagPosition(t *testing.T) {
	g := ParseWatchLogLine("2026-11-05T15:00:00Z ALERT [high] [c:watch-gap] [w:a] 2h57m0s of events between 2026-11-05T12:01:00Z and 2026-11-05T14:58:00Z were never examined: no cycle")
	if g.Kind != WatchLineGap || g.GapFrom.Format(time.RFC3339) != "2026-11-05T12:01:00Z" || g.GapTo.Format(time.RFC3339) != "2026-11-05T14:58:00Z" {
		t.Errorf("gap = %+v", g)
	}
	forged := ParseWatchLogLine("2026-11-05T15:00:00Z ALERT [high] [c:spray:1] d: [c:watch-gap] 1h of events between 2026-11-05T12:01:00Z and 2026-11-05T14:58:00Z were never examined: x")
	if forged.Kind != WatchLineAlert {
		t.Errorf("a forged gap inside a text was read: %+v", forged)
	}
	badSpan := ParseWatchLogLine("2026-11-05T15:00:00Z ALERT [high] [c:watch-gap] 1h of events between soon and later were never examined: x")
	if badSpan.Kind != WatchLineAlert {
		t.Errorf("an unreadable span: %+v", badSpan)
	}
}
