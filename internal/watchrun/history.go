package watchrun

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstatus"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
)

// History reads the cycle history of every watcher in one evidence directory from
// watch[.NAME].log and watch-status[.NAME].json. It reads at most MaxBytes from the end
// of each log (alertlog.MaxTailBytes when zero) and one small record per watcher, and
// it never writes or locks.
type History struct {
	Evidence string
	MaxBytes int64
}

var _ core.WatchHistoryReader = History{}

// Watchers lists the watchers that have a log or a status record, "" (the unnamed one)
// first, then by name. A missing directory is no watcher, not an error.
func (h History) Watchers(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(h.Evidence)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("evidence directory: %w", err)
	}
	var names []string
	for _, e := range ents {
		for _, kind := range []string{LogFile, StatusFile} {
			if n, ok := NameFrom(kind, e.Name()); ok && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	slices.Sort(names)
	return names, nil
}

// Read returns the cycles of the watcher called name, oldest first, with the interval
// and retention from its status record and a duration source for its newest cycle.
// The record is used only if it belongs to name. core.ErrAbsent (wrapped) when there is
// no log.
func (h History) Read(ctx context.Context, name string, now time.Time) (core.WatchHistory, error) {
	var out core.WatchHistory
	if err := app.ValidWatchName(name); err != nil {
		return out, err
	}
	max := h.MaxBytes
	if max <= 0 {
		max = alertlog.MaxTailBytes
	}
	lines, cut, err := alertlog.ReadTail(ctx, filepath.Join(h.Evidence, File(LogFile, name)), max)
	if err != nil {
		return out, err
	}
	out.Cut = cut
	var gaps []core.WatchLogLine
	for _, l := range lines {
		p := core.ParseWatchLogLine(l)
		switch p.Kind {
		case core.WatchLineCycle:
			out.Cycles = append(out.Cycles, core.WatchCycleLine{At: p.At, Run: p.Run, Verdict: p.Verdict, GapReported: p.GapReported})
		case core.WatchLineGap:
			gaps = append(gaps, p)
		case core.WatchLineAlert:
		default:
			out.Unparsed++
		}
	}
	// A cycle's gap span is in the watch-gap alert written in the same cycle, so with
	// the same time. Join on that time only.
	for i := range out.Cycles {
		c := &out.Cycles[i]
		if !c.GapReported {
			continue
		}
		for _, g := range gaps {
			if g.At.Equal(c.At) {
				c.GapFrom, c.GapTo = g.GapFrom, g.GapTo
				break
			}
		}
	}
	// Equal times keep log order, so the result is the same for the same file.
	slices.SortStableFunc(out.Cycles, func(a, b core.WatchCycleLine) int { return a.At.Compare(b.At) })
	h.fillStatus(&out, name)
	out.Gaps = Gaps(out.Cycles, out.Every, now)
	return out, nil
}

// fillStatus takes the interval, retention and last cycle from the watcher's status
// record. A missing, unreadable, non-regular or foreign record leaves them zero.
func (h History) fillStatus(out *core.WatchHistory, name string) {
	p := filepath.Join(h.Evidence, File(StatusFile, name))
	if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
		return
	}
	rec, err := watchstatus.Read(p)
	if err != nil || rec.Name != name {
		return
	}
	out.Every = time.Duration(rec.EverySeconds) * time.Second
	out.Keep = time.Duration(rec.KeepSeconds) * time.Second
	if c := rec.LastCycle; c != nil {
		out.Last = &core.WatchCycleSummary{Run: c.Run, Verdict: c.Verdict, Ended: c.Ended,
			Window: core.Window{From: c.WindowFrom, To: c.WindowTo}, New: c.New, Suppressed: c.Suppressed,
			Repeated: c.Repeated, Recovered: c.Recovered, Failed: append([]string(nil), c.Failed...)}
	}
}

// Gaps judges the spans with no cycle line, at the instant now. A span between two
// consecutive cycles is reported when it is Overdue, the rule of `jb watch status`.
// The span after the last cycle is reported open (To zero) by the same rule. There is
// no span before the first cycle read, and none when the interval is unknown (every is
// zero): no default is guessed. cycles must be oldest first.
func Gaps(cycles []core.WatchCycleLine, every time.Duration, now time.Time) []core.WatchNoCycle {
	if every <= 0 || len(cycles) == 0 {
		return nil
	}
	var out []core.WatchNoCycle
	for i := 1; i < len(cycles); i++ {
		if Overdue(cycles[i-1].At, cycles[i].At, every) {
			out = append(out, core.WatchNoCycle{From: cycles[i-1].At, To: cycles[i].At})
		}
	}
	if last := cycles[len(cycles)-1].At; Overdue(last, now, every) {
		out = append(out, core.WatchNoCycle{From: last})
	}
	return out
}
