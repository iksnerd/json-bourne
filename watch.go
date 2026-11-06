package jb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/runlock"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

type (
	// CycleReport is the account of one watch cycle.
	CycleReport = app.CycleReport
	// CycleStatus is the verdict of a cycle: quiet, findings, incomplete or failed.
	CycleStatus = app.CycleStatus
)

// Cycle statuses. Only CycleQuiet and CycleFindings are healthy; an incomplete or
// failed cycle is never a quiet one.
const (
	CycleQuiet      = app.CycleQuiet
	CycleFindings   = app.CycleFindings
	CycleIncomplete = app.CycleIncomplete
	CycleFailed     = app.CycleFailed
)

// ErrWatcherRunning is wrapped by the error [Watch] returns when another watcher of
// the same name already runs on the case.
var ErrWatcherRunning = errors.New("a watcher with this name is already running on the case")

// WatchOptions are the options of [Watch]. Zero values take the defaults of `jb watch`.
type WatchOptions struct {
	// Name makes this one of several watchers on a case (^[a-z][a-z0-9_-]{0,31}$): its
	// own state, log, lock and run ids. Empty is the unnamed watcher.
	Name string
	// Config names one of the case's configs, as in [CaseHuntOptions].
	Config string
	// Every is the time between cycle starts; zero means 5 minutes.
	Every time.Duration
	// Window is each cycle's hunt window, at least Every; zero means the case's
	// windows.default, else one hour. A case's default can be long (24h): the first
	// cycle then re-reports whatever happened inside it, so pass Window for a watch
	// that should only look at the recent past.
	Window time.Duration
	// TTL is how long an alerted tag stays quiet unless its severity rises; zero means 3h.
	TTL time.Duration
	// Keep is how long past watch runs stay in the store, at least twice Window; zero
	// means 48h, or twice Window when longer.
	Keep time.Duration
	// Repeat is the least time between alerts for the same unchanged outage; zero means 30m.
	Repeat time.Duration
	// Once runs one cycle and returns its report instead of looping until ctx ends.
	Once bool
	// Out receives each alert as it is raised. Nil discards: alerts are always appended
	// to the watcher's log file in the case's evidence directory as well.
	Out io.Writer
	// Env resolves the variables the config names. Nil reads the process environment.
	Env Env
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Watch runs the case's hunt every Every and alerts on what is new, with the rules of
// `jb watch --case DIR`: a source or detector that did not finish raises its own alert
// and the cycle is Incomplete, never quiet; alerts are deduplicated per watcher; a
// webhook in the config's `alerts:` is delivered in addition to the log; and old watch
// runs of this watcher are pruned.
//
// Without Once, Watch runs until ctx ends and returns the last cycle's report. With
// Once it runs one cycle. The error is for what stopped the watcher from running; a
// cycle that ran but is not healthy is in the report, so check
// report.Status.Healthy() before calling a watch clean.
func Watch(ctx context.Context, caseDir string, opts WatchOptions) (*CycleReport, error) {
	if err := app.ValidWatchName(opts.Name); err != nil {
		return nil, fmt.Errorf("jb: name: %w", err)
	}
	for _, d := range []struct {
		n string
		v time.Duration
	}{{"Every", opts.Every}, {"Window", opts.Window}, {"TTL", opts.TTL}, {"Keep", opts.Keep}, {"Repeat", opts.Repeat}} {
		if d.v < 0 {
			return nil, fmt.Errorf("jb: %s must not be negative, got %s", d.n, d.v)
		}
	}
	if opts.Every == 0 {
		opts.Every = 5 * time.Minute
	}
	if opts.Env == nil {
		opts.Env = config.OSEnv
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}

	plan, err := config.PlanCase(caseDir, opts.Config, opts.Window != 0)
	if err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}
	window := opts.Window
	if window == 0 {
		window = plan.Window
	}
	if window == 0 {
		window = time.Hour
	}
	keep := opts.Keep
	if keep == 0 {
		keep = max(app.DefaultWatchKeep, 2*window) // never shorter than what a cycle stores
	}
	wopts := app.WatchOptions{Every: opts.Every, Window: window, TTL: opts.TTL, Keep: keep, Repeat: opts.Repeat, Once: opts.Once}
	if wopts.TTL == 0 {
		wopts.TTL = app.DefaultWatchTTL
	}
	if wopts.Repeat == 0 {
		wopts.Repeat = app.DefaultHealthRepeat
	}
	if err := wopts.Validate(); err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}

	evidence := plan.Case.EvidenceDir()
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		return nil, fmt.Errorf("jb: evidence directory: %w", err)
	}
	// One watcher per name and case, taken before anything is built or read.
	lock, err := watchrun.Acquire(evidence, opts.Name)
	if err != nil {
		var held *runlock.HeldError
		if errors.As(err, &held) {
			return nil, fmt.Errorf("jb: %w (%w)", ErrWatcherRunning, err)
		}
		return nil, fmt.Errorf("jb: watch lock: %w", err)
	}
	defer lock.Release()

	cfg, err := config.Load(plan.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}
	config.PlaceCaseStore(plan.Case, cfg)
	cfg.UseCase(plan.Case)
	rt, err := cfg.Build(opts.Env)
	if err != nil {
		return nil, fmt.Errorf("jb: build config: %w", err)
	}
	defer rt.Close() // ends any plugin child process

	deps, _, err := watchrun.Deps(watchrun.Params{
		Name: opts.Name, Evidence: evidence, Cfg: cfg, RT: rt, Env: opts.Env, Now: opts.Now, Out: opts.Out,
	})
	if err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}
	rep, err := app.Watch(ctx, deps, wopts, app.WatchRunPrefixFor(opts.Name))
	return &rep, err
}
