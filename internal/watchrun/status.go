package watchrun

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/runlock"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstatus"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// StatusFile is the unnamed watcher's status record (docs/CASE-SPEC.md section 3.1).
const StatusFile = "watch-status.json"

// HeartbeatFactor is how many intervals may pass after the last cycle ended before a
// watcher that still holds its lock is called stale.
const HeartbeatFactor = 3

// Overdue reports whether more than HeartbeatFactor intervals passed between since and
// now. The comparison is strict: exactly that many is not overdue. `jb watch status`
// judges a watcher with it, and the timeline judges the spans between cycle lines with
// it, so the two share one factor and one comparison.
func Overdue(since, now time.Time, every time.Duration) bool {
	return now.Sub(since) > HeartbeatFactor*every
}

// NameFrom is the inverse of File: the watcher name in a file name of the kind unnamed
// ("watch.lock" gives "" for "watch.lock" and "a" for "watch.a.lock"). ok is false for a
// file that is not that kind, or whose name is not a valid watcher name.
func NameFrom(unnamed, file string) (name string, ok bool) {
	if file == unnamed {
		return "", true
	}
	ext := filepath.Ext(unnamed)
	prefix := strings.TrimSuffix(unnamed, ext) + "."
	if !strings.HasPrefix(file, prefix) || !strings.HasSuffix(file, ext) || len(file) <= len(prefix)+len(ext) {
		return "", false
	}
	name = file[len(prefix) : len(file)-len(ext)]
	if name == "" || app.ValidWatchName(name) != nil {
		return "", false
	}
	return name, true
}

// RelConfig is the config's path relative to the case, with "/" separators: the form the
// status record carries and the config filter compares. Empty when either path is empty
// or the config is not inside the case.
func RelConfig(caseDir, configPath string) string {
	if caseDir == "" || configPath == "" {
		return ""
	}
	rel, err := filepath.Rel(caseDir, configPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return filepath.ToSlash(rel)
}

// State is what a watcher is doing, as far as its lock and its record show.
type State string

const (
	StateRunning State = "running" // lock held and a cycle ended within HeartbeatFactor intervals
	StateStale   State = "stale"   // lock held, but no cycle ended in that time
	StateStopped State = "stopped" // a record, and no process holds the lock
	StateUnknown State = "unknown" // no readable record
)

// WatcherStatus is one watcher as Status found it.
type WatcherStatus struct {
	Name     string
	State    State
	Reason   string // why, in one sentence, for stale, stopped and unknown
	LockHeld bool
	PID      int // the lock holder's when held, else the record's

	// From the record; zero when there is none.
	Started                          time.Time
	Config                           string
	Every, Window, TTL, Keep, Repeat time.Duration
	Last                             *core.WatchCycleSummary
	NextDue                          time.Time
}

// StatusOptions select and judge the watchers of a case.
type StatusOptions struct {
	// Names limits the answer to these watchers; "" in it is the unnamed watcher. Nil means
	// every watcher found. A named watcher with neither lock nor record is reported unknown.
	Names []string
	// Config, a case-relative path with "/" separators, keeps only the watchers whose
	// record says they run that config.
	Config string
	// Now is the clock; zero means time.Now.
	Now time.Time
}

// CaseStatus is Status for the case in caseDir. configFlag, when set, is one of the
// case's configs (as `--config` on `jb hunt --case`) and keeps only the watchers that
// run it. It loads case.yaml but does not run the evidence guard: it reads two small
// files and writes nothing.
func CaseStatus(caseDir, configFlag string, o StatusOptions) ([]WatcherStatus, error) {
	c, err := casefile.Load(caseDir)
	if err != nil {
		return nil, fmt.Errorf("case %s: %w", caseDir, err)
	}
	if configFlag != "" {
		abs, err := config.ChooseCaseConfig(c, configFlag, "watch")
		if err != nil {
			return nil, err
		}
		if o.Config = RelConfig(c.Dir, abs); o.Config == "" {
			return nil, fmt.Errorf("config %s is not inside the case, so no watcher records it", configFlag)
		}
	}
	return Status(c.EvidenceDir(), o)
}

// Status reports every watcher of the case whose evidence directory is evidence. It
// reads the status records and probes the locks; it never takes a lock and never writes.
// The result is ordered by name, the unnamed watcher first.
func Status(evidence string, o StatusOptions) ([]WatcherStatus, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	names := slices.Clone(o.Names)
	for _, n := range names {
		if err := app.ValidWatchName(n); err != nil {
			return nil, err
		}
	}
	if o.Names == nil {
		ents, err := os.ReadDir(evidence)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("evidence directory: %w", err)
		}
		for _, e := range ents {
			for _, kind := range []string{LockFile, StatusFile} {
				if n, ok := NameFrom(kind, e.Name()); ok && !slices.Contains(names, n) {
					names = append(names, n)
				}
			}
		}
	}
	slices.Sort(names)
	var out []WatcherStatus
	for _, n := range names {
		s := inspect(evidence, n, o.Now)
		if o.Config != "" && s.Config != o.Config {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func inspect(evidence, name string, now time.Time) WatcherStatus {
	s := WatcherStatus{Name: name, State: StateUnknown}
	h, herr := runlock.Probe(filepath.Join(evidence, File(LockFile, name)))
	s.LockHeld, s.PID = h.Held, h.PID
	rec, rerr := watchstatus.Read(filepath.Join(evidence, File(StatusFile, name)))
	ok := false
	switch {
	case errors.Is(rerr, fs.ErrNotExist):
		s.Reason = "no status record (a watcher from an older build, or one that never started)"
	case rerr != nil:
		s.Reason = rerr.Error()
	case rec.Name != name:
		s.Reason = fmt.Sprintf("the record in %s belongs to watcher %q", File(StatusFile, name), rec.Name)
	default:
		s.fill(rec)
		ok = true
	}
	if !ok {
		if herr != nil {
			s.Reason += "; lock not probed: " + herr.Error()
		}
		return s
	}
	switch {
	case herr != nil:
		s.State, s.Reason = StateUnknown, "lock not probed: "+herr.Error()
	case !h.Held:
		s.PID = rec.PID
		s.State, s.Reason = StateStopped, "no process holds the lock"
	default:
		beat, what := s.Started, "started"
		if s.Last != nil {
			beat, what = s.Last.Ended, "last cycle ended"
		}
		limit := HeartbeatFactor * s.Every
		if Overdue(beat, now, s.Every) {
			s.State = StateStale
			s.Reason = fmt.Sprintf("the lock is held by PID %d but the %s %s ago, over %d x every (%s)", s.PID, what, now.Sub(beat).Round(time.Second), HeartbeatFactor, limit)
		} else {
			s.State = StateRunning
		}
	}
	return s
}

func (s *WatcherStatus) fill(r watchstatus.Record) {
	s.Started, s.Config = r.Started, r.Config
	s.Every, s.Window = time.Duration(r.EverySeconds)*time.Second, time.Duration(r.WindowSeconds)*time.Second
	s.TTL, s.Keep, s.Repeat = time.Duration(r.TTLSeconds)*time.Second, time.Duration(r.KeepSeconds)*time.Second, time.Duration(r.RepeatSeconds)*time.Second
	s.NextDue = r.NextDue
	if c := r.LastCycle; c != nil {
		s.Last = &core.WatchCycleSummary{Run: c.Run, Verdict: c.Verdict, Ended: c.Ended, Window: core.Window{From: c.WindowFrom, To: c.WindowTo},
			New: c.New, Suppressed: c.Suppressed, Repeated: c.Repeated, Recovered: c.Recovered, Failed: c.Failed}
	}
}

// StatusResult is the answer to "are the watchers alive": every watcher found and the
// instant the answer was judged at. It is what `jb watch status` reports.
type StatusResult struct {
	// Checked is the clock the heartbeat was judged against.
	Checked  time.Time
	Watchers []WatcherStatus
}
