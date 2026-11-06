// Package jb is the public Go API of json-bourne.
//
// It runs the same hunt as `jb hunt`: fetch a window of events from the configured
// sources, keep them as evidence in a local DuckDB file, and run the detectors, each
// comparing the window with the one before it.
//
// The rules of the CLI hold here. A hunt is clean only when [Result.Complete] is true.
// A source or detector that read nothing reports [StatusNoRecords], never an empty
// success, and an error from [Hunt] never means "nothing happened".
//
// Importing this package links DuckDB, so it needs cgo and a C compiler.
package jb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Types re-exported from the internal packages. They are aliases, so values flow
// between this package and the CLI without conversion.
type (
	// Config is a parsed, validated config file. Credentials are not resolved yet.
	Config = config.File
	// Result is the outcome of one hunt: per-source and per-detector status, and the
	// findings, most severe first.
	Result = app.Result
	// SourceResult is what one source contributed to a hunt.
	SourceResult = app.SourceResult
	// DetectorResult is what one detector judged.
	DetectorResult = app.DetectorResult
	// Status is how a component ended: ok, no_records, unavailable, canceled or error.
	Status = app.Status
	// Finding is one thing a detector found, with the numbers of both windows.
	Finding = core.Finding
	// Severity orders findings by how urgently a human should look.
	Severity = core.Severity
	// Window is a half-open time range [From, To).
	Window = core.Window
	// Env looks up a credential by variable name.
	Env = config.Env
)

// Component statuses.
const (
	StatusOK          = app.StatusOK
	StatusNoRecords   = app.StatusNoRecords
	StatusUnavailable = app.StatusUnavailable
	StatusCanceled    = app.StatusCanceled
	StatusError       = app.StatusError
)

// Finding severities, lowest first.
const (
	SevInfo     = core.SevInfo
	SevCheck    = core.SevCheck
	SevActivity = core.SevActivity
	SevHigh     = core.SevHigh
	SevCritical = core.SevCritical
)

// ErrNoRecords is returned (wrapped) by a source or detector that read zero records.
var ErrNoRecords = core.ErrNoRecords

// MaxHistoricalWindow is the longest window a hunt ending in the past accepts.
const MaxHistoricalWindow = 31 * 24 * time.Hour

// LoadConfig reads and validates the YAML config at path. The file holds the names of
// environment variables, never credentials.
func LoadConfig(path string) (*Config, error) { return config.Load(path) }

// HuntOptions says which window to hunt and where credentials come from.
type HuntOptions struct {
	// Window is the length of the window. Zero means one hour. The baseline is the
	// window of the same length immediately before it.
	Window time.Duration
	// Until ends the window at this time, for a past window. Zero means now. It must
	// have whole seconds, must not be in the future, and with Window over
	// [MaxHistoricalWindow] is refused.
	Until time.Time
	// Env resolves the variables the config names. Nil reads the process environment.
	Env Env
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Hunt fetches the window and its baseline, stores both as evidence, runs every enabled
// detector and returns what it learned. The returned Result is filled in even when err
// is not nil, as far as the hunt got.
//
// A nil error means the hunt ran, not that it is clean: check [Result.Complete] and
// [Result.Failed] before telling anyone nothing was found.
func Hunt(ctx context.Context, cfg *Config, opts HuntOptions) (*Result, error) {
	if cfg == nil {
		return nil, errors.New("jb: nil config")
	}
	return hunt(ctx, cfg, opts)
}

// CaseHuntOptions are the options of [HuntCase].
type CaseHuntOptions struct {
	HuntOptions
	// Config names one of the case's configs, as listed in case.yaml, or a file inside
	// the case. Empty means the case's only config; a case that lists several needs it.
	Config string
}

// HuntCase hunts inside a case, with the rules of `jb hunt --case DIR`: the case is
// loaded and checked, the hunt is refused when its evidence directory is not safe from
// git, the detectors can read the case's data files (actor files), and the evidence is
// stored under the case's evidence directory unless the config says otherwise. When
// Window is zero the case's windows.default is used, else one hour.
//
// Like [Hunt], a nil error does not mean the result is clean: check [Result.Complete].
func HuntCase(ctx context.Context, caseDir string, opts CaseHuntOptions) (*Result, error) {
	plan, err := config.PlanCase(caseDir, opts.Config, opts.Window != 0)
	if err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}
	cfg, err := config.Load(plan.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}
	config.PlaceCaseStore(plan.Case, cfg)
	cfg.UseCase(plan.Case) // detectors read the case's data files
	if opts.Window == 0 {
		opts.Window = plan.Window
	}
	return hunt(ctx, cfg, opts.HuntOptions)
}

func hunt(ctx context.Context, cfg *Config, opts HuntOptions) (*Result, error) {
	if opts.Window < 0 {
		return nil, fmt.Errorf("jb: window must be positive, got %s", opts.Window)
	}
	if opts.Window == 0 {
		opts.Window = time.Hour
	}
	if opts.Env == nil {
		opts.Env = config.OSEnv
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	w, run, err := plan(now(), opts)
	if err != nil {
		return nil, err
	}

	rt, err := cfg.Build(opts.Env)
	if err != nil {
		return nil, fmt.Errorf("jb: build config: %w", err)
	}
	defer rt.Close() // ends any plugin child process

	st, err := duckdb.OpenContext(ctx, cfg.StorePath(), false, duckdb.OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("jb: open database: %w", err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		return nil, fmt.Errorf("jb: migrate database: %w", err)
	}

	scopes := map[string][]string{}
	for _, d := range rt.Detectors {
		if sc, ok := rt.Scopes[d.Name()]; ok {
			scopes[d.Name()] = sc
		}
	}
	var disabled []app.Disabled
	for _, n := range rt.DisabledSources {
		disabled = append(disabled, app.Disabled{Kind: "source", Name: n})
	}
	for _, n := range rt.DisabledDetectors {
		disabled = append(disabled, app.Disabled{Kind: "detector", Name: n})
	}

	res, herr := app.Hunt(ctx, app.Deps{
		Sources: rt.Sources, Detectors: rt.Detectors, Scopes: scopes,
		Sink: st, Reader: st, Disabled: disabled,
	}, run, w)
	res.Until = opts.Until
	return &res, herr
}

// plan returns the window and run id for opts, with the same rules as `jb hunt --until`.
func plan(now time.Time, opts HuntOptions) (core.Window, string, error) {
	if opts.Until.IsZero() {
		to := now.UTC().Truncate(time.Second)
		return core.Window{From: to.Add(-opts.Window), To: to}, "hunt-" + to.Format("20060102T150405Z"), nil
	}
	if opts.Until.Nanosecond() != 0 {
		return core.Window{}, "", errors.New("jb: Until must be whole seconds; window edges are not rounded")
	}
	until := opts.Until.UTC()
	if until.After(now.UTC().Truncate(time.Second)) {
		return core.Window{}, "", fmt.Errorf("jb: Until %s is in the future", until.Format(time.RFC3339))
	}
	if opts.Window > MaxHistoricalWindow {
		return core.Window{}, "", fmt.Errorf("jb: Window %s is longer than the %s a historical hunt accepts", opts.Window, MaxHistoricalWindow)
	}
	run := fmt.Sprintf("hunt-until-%s-w%ds", until.Format("20060102T150405Z"), int64(opts.Window/time.Second))
	return core.Window{From: until.Add(-opts.Window), To: until}, run, nil
}
