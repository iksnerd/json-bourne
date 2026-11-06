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
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

type (
	// ActivityResult is the answer to "is the actor active": a verdict, the reasons
	// when it is not complete, and what each detector judged.
	ActivityResult = app.ActivityResult
	// Verdict is ACTIVE, QUIET or INCOMPLETE. INCOMPLETE is not QUIET.
	Verdict = app.Verdict
)

// Activity verdicts.
const (
	VerdictActive     = app.VerdictActive
	VerdictQuiet      = app.VerdictQuiet
	VerdictIncomplete = app.VerdictIncomplete
)

// ActivityOptions are the options of [Activity].
type ActivityOptions struct {
	// Config names one of the case's configs, as in [CaseHuntOptions].
	Config string
	// Window is the length of the window; zero means 24 hours (not the case's hunt
	// default, so the same call always asks the same question).
	Window time.Duration
	// Until ends the window at this time, for a past window; zero means now. Same rules
	// as [HuntOptions.Until].
	Until time.Time
	// Env resolves the variables the config names. Nil reads the process environment.
	Env Env
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Activity asks whether the actors a case names are active from any client, with the
// rules of `jb activity --case DIR`: it fetches the window, stores it as run
// activity-<time>, and runs the case's fingerprint and behaviour detectors. The
// verdict is [VerdictQuiet] only when every source and detector completed over the
// whole window; otherwise it is [VerdictIncomplete], which is not quiet.
//
// A nil error means the question was asked, not that the answer is quiet: read
// result.Verdict.
func Activity(ctx context.Context, caseDir string, opts ActivityOptions) (*ActivityResult, error) {
	if opts.Window < 0 {
		return nil, fmt.Errorf("jb: window must be positive, got %s", opts.Window)
	}
	if opts.Window == 0 {
		opts.Window = DefaultActivityWindow
	}
	if opts.Env == nil {
		opts.Env = config.OSEnv
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	w, run, err := plan(now(), HuntOptions{Window: opts.Window, Until: opts.Until}, "activity")
	if err != nil {
		return nil, err
	}
	cp, err := config.PlanCase(caseDir, opts.Config, "activity", true)
	if err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}
	cfg, err := config.Load(cp.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("jb: %w", err)
	}
	config.PlaceCaseStore(cp.Case, cfg)
	cfg.UseCase(cp.Case)
	rt, err := cfg.Build(opts.Env)
	if err != nil {
		return nil, fmt.Errorf("jb: build config: %w", err)
	}
	defer rt.Close()

	var dets []core.Detector
	for _, d := range rt.Detectors {
		if _, ok := d.(core.ActivityReporter); ok {
			dets = append(dets, d)
		}
	}
	if len(dets) == 0 {
		return nil, errors.New("jb: the config has no enabled fingerprint or behaviour detector, so it cannot say whether an actor is active")
	}
	st, err := duckdb.OpenContext(ctx, cfg.StorePath(), false, duckdb.OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("jb: open database: %w", err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		return nil, fmt.Errorf("jb: migrate database: %w", err)
	}
	res, aerr := app.Activity(ctx, watchrun.RunDeps(rt, dets, st), run, w)
	res.Until = opts.Until
	return &res, aerr
}
