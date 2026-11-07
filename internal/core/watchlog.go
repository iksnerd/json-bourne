package core

import (
	"regexp"
	"time"
)

// The line grammar of watch[.NAME].log, as alertlog.Line writes it. The parser lives in
// core so every reader (the history reader, the Watch page) reads a line the same way.
// Log lines carry detector output and error text, so each pattern is anchored at the
// start of the line and reads a field only from its fixed position: the words
// "CYCLE QUIET" inside an ALERT line, or a forged "[c:watch-gap]" deeper in a text, are
// never read.

var (
	cycleLineRE = regexp.MustCompile(`^(\S+) CYCLE (\S*)(?: \[w:([^\]]*)\])? CYCLE (QUIET|FINDINGS|INCOMPLETE|FAILED)(?::| |$)`)
	// alertHeadRE is the head of any alert line: time, ALERT, [severity], [c:tag].
	alertHeadRE = regexp.MustCompile(`^(\S+) ALERT \[[^\]]*\] \[c:([^\]]*)\](?: \[w:([^\]]*)\])? ?`)
	gapTextRE   = regexp.MustCompile(`^(\S+) of events between (\S+) and (\S+) were never examined: `)
	gapIncRE    = regexp.MustCompile(`^ ?\d+ component\(s\) did not finish .*?, gap=(true|false); this is not a quiet result \(\d+ new findings\)`)
)

// WatchLogKind says what a log line is.
type WatchLogKind int

const (
	WatchLineUnknown WatchLogKind = iota // not understood: counted, never guessed at
	WatchLineCycle                       // an end-of-cycle line with a closed-set verdict
	WatchLineGap                         // a watch-gap alert with a readable span
	WatchLineAlert                       // any other well-formed alert line
)

// WatchLogLine is one parsed line. Only the fields of its Kind are set.
type WatchLogLine struct {
	Kind    WatchLogKind
	At      time.Time
	Watcher string // the [w:...] text; callers prefer the file's name
	// Cycle
	Run, Verdict string
	GapReported  bool
	// Gap
	GapFrom, GapTo time.Time
}

// ParseWatchLogLine reads one line of a watch log. A line that is neither a cycle line
// nor an alert line, or whose time or verdict does not parse, is WatchLineUnknown.
func ParseWatchLogLine(line string) WatchLogLine {
	if m := cycleLineRE.FindStringSubmatch(line); m != nil {
		at, err := time.Parse(time.RFC3339, m[1])
		if err != nil {
			return WatchLogLine{}
		}
		l := WatchLogLine{Kind: WatchLineCycle, At: at.UTC(), Run: m[2], Watcher: m[3], Verdict: m[4]}
		if m[4] == "INCOMPLETE" {
			if g := gapIncRE.FindStringSubmatch(line[len(m[0]):]); g != nil {
				l.GapReported = g[1] == "true"
			}
		}
		return l
	}
	if m := alertHeadRE.FindStringSubmatch(line); m != nil {
		at, err := time.Parse(time.RFC3339, m[1])
		if err != nil {
			return WatchLogLine{}
		}
		if m[2] == "watch-gap" {
			if g := gapTextRE.FindStringSubmatch(line[len(m[0]):]); g != nil {
				from, e1 := time.Parse(time.RFC3339, g[2])
				to, e2 := time.Parse(time.RFC3339, g[3])
				if e1 == nil && e2 == nil {
					return WatchLogLine{Kind: WatchLineGap, At: at.UTC(), Watcher: m[3], GapFrom: from.UTC(), GapTo: to.UTC()}
				}
			}
		}
		return WatchLogLine{Kind: WatchLineAlert, At: at.UTC(), Watcher: m[3]}
	}
	return WatchLogLine{}
}
