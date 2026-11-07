// Package watchstate keeps the watch loop's dedupe memory in one JSON file.
package watchstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/safefile"
)

// version stays 1: "health" is an optional section, absent from files written before it
// existed (they load as a state with no outages) and omitted while no outage is open.
// A build that predates it rejects a file that has it as corrupt and keeps it as
// <path>.corrupt, which loses only dedupe memory.
const version = 1

// Store is a core.WatchStateStore over a file.
type Store struct{ Path string }

var _ core.WatchStateStore = Store{}

type file struct {
	Version int                    `json:"version"`
	Seen    map[string]entry       `json:"seen"`
	Health  map[string]healthEntry `json:"health,omitempty"`
}

type healthEntry struct {
	At          time.Time `json:"at"`
	Fingerprint string    `json:"fingerprint"`
}

type entry struct {
	At       time.Time `json:"at"`
	Severity string    `json:"severity"`
}

// Load reads the file strictly: unknown fields, trailing data, a wrong version, an
// unknown severity or an empty tag are all corruption. A missing file is a cold
// start and not an error. A corrupt file is moved to <path>.corrupt so what was
// wrong stays inspectable, and the error wraps core.ErrStateCorrupt.
func (s Store) Load(context.Context) (core.WatchState, error) {
	empty := core.WatchState{Seen: map[string]core.SeenTag{}}
	b, err := safefile.ReadAll(s.Path, maxPeekBytes)
	var perr error
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return empty, nil
	case errors.Is(err, safefile.ErrNotRegular):
		// Not ours to move aside: a directory or FIFO at the path is the operator's.
		return empty, fmt.Errorf("%w: %v", core.ErrStateCorrupt, err)
	case errors.Is(err, safefile.ErrTooLarge):
		perr = err
	case err != nil:
		return empty, fmt.Errorf("read watch state: %w", err)
	}
	var st core.WatchState
	if perr == nil {
		st, perr = parse(b)
	}
	if perr != nil {
		moved := ""
		if rerr := os.Rename(s.Path, s.Path+".corrupt"); rerr == nil {
			moved = "; kept as " + s.Path + ".corrupt"
		}
		return empty, fmt.Errorf("%w: %s: %v%s", core.ErrStateCorrupt, s.Path, perr, moved)
	}
	return st, nil
}

func parse(b []byte) (core.WatchState, error) {
	var f file
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return core.WatchState{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return core.WatchState{}, errors.New("data after the JSON document")
	}
	if f.Version != version {
		return core.WatchState{}, fmt.Errorf("version %d, want %d", f.Version, version)
	}
	st := core.WatchState{Seen: make(map[string]core.SeenTag, len(f.Seen))}
	for key, h := range f.Health {
		switch {
		case key == "":
			return core.WatchState{}, errors.New("empty health key")
		case h.At.IsZero():
			return core.WatchState{}, fmt.Errorf("health %q: no time", key)
		}
		if st.Health == nil {
			st.Health = make(map[string]core.HealthSeen, len(f.Health))
		}
		st.Health[key] = core.HealthSeen{At: h.At.UTC(), Fingerprint: h.Fingerprint}
	}
	for tag, e := range f.Seen {
		sev, ok := core.ParseSeverity(e.Severity)
		switch {
		case tag == "":
			return core.WatchState{}, errors.New("empty tag")
		case !ok:
			return core.WatchState{}, fmt.Errorf("tag %q: unknown severity %q", tag, e.Severity)
		case e.At.IsZero():
			return core.WatchState{}, fmt.Errorf("tag %q: no time", tag)
		}
		st.Seen[tag] = core.SeenTag{At: e.At.UTC(), Severity: sev}
	}
	return st, nil
}

// Save writes the state to a temporary file in the same directory, syncs it and
// renames it over the target, so a crash leaves the old state or the new one.
func (s Store) Save(_ context.Context, st core.WatchState) error {
	f := file{Version: version, Seen: make(map[string]entry, len(st.Seen))}
	for tag, t := range st.Seen {
		f.Seen[tag] = entry{At: t.At.UTC(), Severity: core.SeverityName(t.Severity)}
	}
	if len(st.Health) > 0 {
		f.Health = make(map[string]healthEntry, len(st.Health))
		for key, h := range st.Health {
			f.Health[key] = healthEntry{At: h.At.UTC(), Fingerprint: h.Fingerprint}
		}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("save watch state: %w", err)
	}
	name := tmp.Name()
	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("save watch state: %w", err)
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("save watch state: %w", err)
	}
	if err := os.Rename(name, s.Path); err != nil {
		os.Remove(name)
		return fmt.Errorf("save watch state: %w", err)
	}
	return nil
}
