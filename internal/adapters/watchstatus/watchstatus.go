// Package watchstatus writes and reads the watcher's status record: one small JSON file
// that says who the watcher is, how it runs, how its last cycle ended and when the next
// is due. It is the machine-readable answer to "is this watcher alive": a program reads
// it instead of parsing watch.log or the lock file. The record holds names, counts and
// times, never an error text or a credential. The file is replaced atomically, as the
// dedupe state is.
package watchstatus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/safefile"
)

// APIVersion is the only version Read accepts. It changes when the format changes
// incompatibly.
const APIVersion = "jb.watch-status/v1"

// Record is the file's content.
type Record struct {
	APIVersion    string    `json:"apiVersion"`
	Name          string    `json:"name"`
	PID           int       `json:"pid"`
	Started       time.Time `json:"started"`
	Updated       time.Time `json:"updated"`
	Config        string    `json:"config"`
	EverySeconds  int64     `json:"everySeconds"`
	WindowSeconds int64     `json:"windowSeconds"`
	TTLSeconds    int64     `json:"ttlSeconds"`
	KeepSeconds   int64     `json:"keepSeconds"`
	RepeatSeconds int64     `json:"repeatSeconds"`
	LastCycle     *Cycle    `json:"lastCycle,omitempty"`
	NextDue       time.Time `json:"nextDue,omitzero"`
}

// Cycle is the last finished cycle.
type Cycle struct {
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

// Writer is a core.WatchStatusSink over a file. The fields after Path are what the
// watch loop does not know and the record needs.
type Writer struct {
	Path    string
	Name    string
	PID     int
	Started time.Time
	Config  string // the config's path relative to the case, with "/" separators
}

var _ core.WatchStatusSink = Writer{}

func secs(d time.Duration) int64 { return int64(d / time.Second) }

// Save writes the record to a temporary file in the same directory, syncs it and
// renames it over the target, so a reader sees the old record or the new one.
func (w Writer) Save(_ context.Context, s core.WatchStatus) error {
	r := Record{
		APIVersion: APIVersion, Name: w.Name, PID: w.PID, Started: w.Started.UTC(), Updated: s.Updated.UTC(), Config: w.Config,
		EverySeconds: secs(s.Every), WindowSeconds: secs(s.Window), TTLSeconds: secs(s.TTL), KeepSeconds: secs(s.Keep), RepeatSeconds: secs(s.Repeat),
	}
	if !s.NextDue.IsZero() {
		r.NextDue = s.NextDue.UTC()
	}
	if c := s.Last; c != nil {
		failed := append([]string{}, c.Failed...)
		r.LastCycle = &Cycle{Run: c.Run, Verdict: c.Verdict, Ended: c.Ended.UTC(), WindowFrom: c.Window.From.UTC(), WindowTo: c.Window.To.UTC(),
			New: c.New, Suppressed: c.Suppressed, Repeated: c.Repeated, Recovered: c.Recovered, Failed: failed}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(w.Path), filepath.Base(w.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("save watch status: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("save watch status: %w", err)
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("save watch status: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return fmt.Errorf("save watch status: %w", err)
	}
	if err := os.Rename(name, w.Path); err != nil {
		os.Remove(name)
		return fmt.Errorf("save watch status: %w", err)
	}
	return nil
}

// maxRecordBytes bounds what Read takes; a record is a few hundred bytes.
const maxRecordBytes = 1 << 20

// Read parses a record strictly: an unknown field, trailing data, another apiVersion,
// no PID or no start time is an error. A missing file is an error that wraps
// os.ErrNotExist. Read never changes the file.
func Read(path string) (Record, error) {
	b, err := safefile.ReadAll(path, maxRecordBytes)
	if err != nil {
		return Record{}, fmt.Errorf("read watch status: %w", err)
	}
	var probe struct { // also rejects trailing data, which a Decoder would not
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return Record{}, fmt.Errorf("watch status %s: %w", path, err)
	}
	if probe.APIVersion != APIVersion {
		return Record{}, fmt.Errorf("watch status %s: apiVersion %q, this build reads %q; the watcher rewrites the file at its next cycle (restart a watcher from an older build)", path, probe.APIVersion, APIVersion)
	}
	var r Record
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("watch status %s: %w", path, err)
	}
	switch {
	case r.PID <= 0:
		return Record{}, fmt.Errorf("watch status %s: no pid", path)
	case r.EverySeconds <= 0:
		return Record{}, fmt.Errorf("watch status %s: everySeconds must be positive", path)
	case r.Started.IsZero():
		return Record{}, fmt.Errorf("watch status %s: no started time", path)
	}
	return r, nil
}
