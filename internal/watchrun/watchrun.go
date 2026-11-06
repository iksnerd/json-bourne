// Package watchrun builds the ports of app.Watch from a loaded case config: the
// evidence-directory file names, the one-watcher-per-name lock, the hunt and prune
// functions that open the store for one operation at a time, and the alert sinks.
// `jb watch` and the Go package jb both call it, so a watcher behaves the same either
// way. Like internal/config it is a wiring layer and may import adapters.
package watchrun

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/adapters/runlock"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// The unnamed watcher's files. A named watcher inserts its name before the extension.
const (
	StateFile = "watch-state.json"
	LogFile   = "watch.log"
	LockFile  = "watch.lock"
)

// File is the evidence-directory file of one kind for the watcher called name:
// "watch-state.json" unnamed, "watch-state.a.json" for name "a", and likewise for
// "watch.log" and "watch.lock".
func File(unnamed, name string) string {
	if name == "" {
		return unnamed
	}
	ext := filepath.Ext(unnamed)
	return strings.TrimSuffix(unnamed, ext) + "." + name + ext
}

// Acquire takes the lock of the watcher called name on the case whose evidence
// directory is evidence. A second watcher of the same name is refused with a
// *runlock.HeldError naming the PID that holds it.
func Acquire(evidence, name string) (*runlock.Lock, error) {
	return runlock.Acquire(filepath.Join(evidence, File(LockFile, name)))
}

// RunDeps is the one place a built config becomes the ports of app.Hunt and
// app.Activity, so every command that runs detectors applies the same `sources:`
// scopes. dets may be a subset of rt.Detectors; a scope for a detector left out is
// dropped with it, because Hunt refuses a scope that names no detector.
func RunDeps(rt *config.Runtime, dets []core.Detector, st *duckdb.Store) app.Deps {
	scopes := map[string][]string{}
	for _, d := range dets {
		if sc, ok := rt.Scopes[d.Name()]; ok {
			scopes[d.Name()] = sc
		}
	}
	return app.Deps{Sources: rt.Sources, Detectors: dets, Scopes: scopes, Sink: st, Reader: st, Disabled: Disabled(rt)}
}

// Disabled is what the config switched off, as the use cases carry it into a result.
func Disabled(rt *config.Runtime) []app.Disabled {
	var out []app.Disabled
	for _, n := range rt.DisabledSources {
		out = append(out, app.Disabled{Kind: "source", Name: n})
	}
	for _, n := range rt.DisabledDetectors {
		out = append(out, app.Disabled{Kind: "detector", Name: n})
	}
	return out
}

// Params are what Deps needs.
type Params struct {
	Name     string // watcher name, "" for the unnamed one
	Evidence string // the case's evidence directory (created by the caller)
	Cfg      *config.File
	RT       *config.Runtime
	Env      config.Env
	Now      func() time.Time
	// Out receives alerts (the CLI passes stdout); the same lines go to the log file.
	Out io.Writer
	// AfterHunt, when set, runs after each cycle's hunt with the open store and the
	// two windows read. The CLI uses it for its advice about documents stored under
	// two labels; it must not change the cycle's verdict.
	AfterHunt func(ctx context.Context, st core.SourceOverlapReader, win core.Window)
}

// Deps builds the app.WatchDeps and reports how many webhooks were configured. The
// local log is the required sink and is written first; a webhook is extra.
func Deps(p Params) (app.WatchDeps, int, error) {
	logSink := &alertlog.Sink{Out: p.Out, Path: filepath.Join(p.Evidence, File(LogFile, p.Name))}
	var alerts core.AlertSink = logSink
	extra, err := p.Cfg.BuildAlerts(p.Env)
	if err != nil {
		return app.WatchDeps{}, 0, err
	}
	if len(extra) > 0 {
		alerts = core.FanOut{Required: logSink, Optional: extra}
	}
	storePath := p.Cfg.StorePath()
	open := func(ctx context.Context) (*duckdb.Store, error) {
		// The store is opened for one operation and closed again: DuckDB admits one
		// process at a time, and `jb db` must still work between cycles.
		st, err := duckdb.OpenContext(ctx, storePath, false, duckdb.OpenOptions{})
		if err != nil {
			return nil, fmt.Errorf("open database: %w", err)
		}
		if _, err := st.Migrate(); err != nil {
			st.Close()
			return nil, fmt.Errorf("migrate database: %w", err)
		}
		return st, nil
	}
	return app.WatchDeps{
		Name:     p.Name,
		Disabled: Disabled(p.RT),
		Hunt: func(ctx context.Context, run string, w core.Window) (app.Result, error) {
			st, err := open(ctx)
			if err != nil {
				return app.Result{Run: run, Window: w, Baseline: w.Previous()}, err
			}
			defer st.Close()
			res, herr := app.Hunt(ctx, RunDeps(p.RT, p.RT.Detectors, st), run, w)
			if p.AfterHunt != nil {
				p.AfterHunt(ctx, st, core.Window{From: w.Previous().From, To: w.To})
			}
			return res, herr
		},
		Prune: func(ctx context.Context, before time.Time) (core.PruneResult, error) {
			st, err := open(ctx)
			if err != nil {
				return core.PruneResult{}, err
			}
			defer st.Close()
			// Only this watcher's runs: prefix + a stamp, so "watch-a-" never reaches
			// "watch-ab-" and the unnamed "watch-" never reaches a named watcher's.
			return st.PruneRuns(ctx, app.WatchRunPrefixFor(p.Name)+"-", before)
		},
		State:  watchstate.Store{Path: filepath.Join(p.Evidence, File(StateFile, p.Name))},
		Alerts: alerts,
		Now:    p.Now,
	}, len(extra), nil
}
