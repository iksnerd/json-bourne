package watchrun

import (
	"encoding/json"
	"time"
)

// The JSON document of `jb watch status --output json`. A key is a contract with
// scripts: do not rename or drop one.

type watcherJSON struct {
	Name          string     `json:"name"`
	State         string     `json:"state"`
	Reason        string     `json:"reason,omitempty"`
	LockHeld      bool       `json:"lockHeld"`
	PID           int        `json:"pid,omitempty"`
	Started       *time.Time `json:"started,omitempty"`
	Config        string     `json:"config,omitempty"`
	EverySeconds  int64      `json:"everySeconds,omitempty"`
	WindowSeconds int64      `json:"windowSeconds,omitempty"`
	TTLSeconds    int64      `json:"ttlSeconds,omitempty"`
	KeepSeconds   int64      `json:"keepSeconds,omitempty"`
	RepeatSeconds int64      `json:"repeatSeconds,omitempty"`
	LastCycle     *cycleJSON `json:"lastCycle,omitempty"`
	NextDue       *time.Time `json:"nextDue,omitempty"`
}

type cycleJSON struct {
	Run        string    `json:"run"`
	Verdict    string    `json:"verdict"`
	Ended      time.Time `json:"ended"`
	WindowFrom time.Time `json:"windowFrom"`
	WindowTo   time.Time `json:"windowTo"`
	New        int       `json:"new"`
	Suppressed int       `json:"suppressed"`
	Repeated   int       `json:"repeated"`
	Recovered  int       `json:"recovered"`
	Failed     []string  `json:"failed"`
}

// MarshalJSON prints one watcher as `jb watch status --output json` lists it.
func (s WatcherStatus) MarshalJSON() ([]byte, error) {
	j := watcherJSON{Name: s.Name, State: string(s.State), Reason: s.Reason, LockHeld: s.LockHeld, PID: s.PID, Config: s.Config,
		EverySeconds: int64(s.Every / time.Second), WindowSeconds: int64(s.Window / time.Second), TTLSeconds: int64(s.TTL / time.Second),
		KeepSeconds: int64(s.Keep / time.Second), RepeatSeconds: int64(s.Repeat / time.Second)}
	if !s.Started.IsZero() {
		t := s.Started
		j.Started = &t
	}
	if !s.NextDue.IsZero() {
		t := s.NextDue
		j.NextDue = &t
	}
	if c := s.Last; c != nil {
		j.LastCycle = &cycleJSON{Run: c.Run, Verdict: c.Verdict, Ended: c.Ended, WindowFrom: c.Window.From, WindowTo: c.Window.To,
			New: c.New, Suppressed: c.Suppressed, Repeated: c.Repeated, Recovered: c.Recovered, Failed: append([]string{}, c.Failed...)}
	}
	return json.Marshal(j)
}

// MarshalJSON prints {"checked", "watchers"}, with [] for no watcher.
func (r StatusResult) MarshalJSON() ([]byte, error) {
	out := struct {
		Checked  time.Time       `json:"checked"`
		Watchers []WatcherStatus `json:"watchers"`
	}{Checked: r.Checked.UTC(), Watchers: r.Watchers}
	if out.Watchers == nil {
		out.Watchers = []WatcherStatus{}
	}
	return json.Marshal(out)
}
