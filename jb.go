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
	"fmt"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/watchrun"
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

// The defaults of the Go functions. They are the defaults of the CLI commands of the
// same name, and a test in cmd/jb fails if the two differ.
const (
	// DefaultWindow is the hunt window of [Hunt], [HuntCase] and [Watch] when none is given
	// (a case's windows.default replaces it for the case functions).
	DefaultWindow = time.Hour
	// DefaultActivityWindow is the window of [Activity] when none is given.
	DefaultActivityWindow = 24 * time.Hour
	// DefaultWatchEvery is the time between cycles of [Watch] when none is given.
	DefaultWatchEvery = 5 * time.Minute
)

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
	// NoStore runs the same hunt over a private temporary store that is deleted before
	// the function returns, so nothing is written to the evidence database and
	// [Result.Stored] is false. Detectors then see only the events this run fetched,
	// not those saved by earlier runs, so a result can differ from a stored run.
	NoStore bool
	// Search narrows every source for this one run, on the server, by a phrase match of
	// each term against one field, ANDed with the configured filters (`jb hunt --search`).
	// At most 4 terms; a term is data: 1 to 256 bytes, no control character, not blank, no
	// padding. A refused search returns a [UsageError] before any request is sent. The run
	// is stored as search-<time>, not hunt-<time>. The detectors still read the stored
	// evidence of the window, including events saved by earlier runs, not only the
	// matches.
	//
	// A term that matches nothing in a live index is an answer, not a failure: check
	// [Result.SearchAbsent] before reading [Result.Complete], which is false for it
	// because the detectors had nothing to judge. The CLI prints that case as complete.
	Search []string
	// SearchField is the field Search matches against. Empty means each source's
	// search_field, else "message". It needs Search.
	SearchField string
	// ConfigPath is the file cfg was read from. It only words the advice in
	// [Result].Notes (the command that fixes a source label stored twice names it); empty
	// leaves a generic "--config FILE". [HuntCase] ignores it: the case names the config.
	ConfigPath string
	// Notice, when set, is called with each advice line as it arises, before the call
	// returns, so a caller can show it while sources are still being read. The same lines
	// are in [Result].Notes, and a Notice call also happens for a line raised before an
	// error that returns no Result.
	Notice func(note string)
}

// notes collects the advice lines of one call, in order, and hands each to the caller's
// Notice as it arises.
type notes struct {
	lines  []string
	notice func(string)
}

func (n *notes) add(s string) {
	n.lines = append(n.lines, s)
	if n.notice != nil {
		n.notice(s)
	}
}

// Hunt fetches the window and its baseline, stores both as evidence, runs every enabled
// detector and returns what it learned. The returned Result is filled in even when err
// is not nil, as far as the hunt got.
//
// A nil error means the hunt ran, not that it is clean: check [Result.Complete] and
// [Result.Failed] before telling anyone nothing was found.
func Hunt(ctx context.Context, cfg *Config, opts HuntOptions) (*Result, error) {
	if cfg == nil {
		return nil, usagef("nil config")
	}
	if len(opts.Search) > 0 || opts.SearchField != "" {
		// Narrow a copy: the caller's Config is theirs and may be reused for a plain
		// hunt. The terms are checked here, before an adapter is built or a request sent.
		narrowed := *cfg
		if err := narrowed.UseSearch(opts.Search, opts.SearchField); err != nil {
			return nil, usagef("%v", err)
		}
		cfg = &narrowed
	}
	return hunt(ctx, cfg, opts, &notes{notice: opts.Notice}, app.RenameScope("", opts.ConfigPath))
}

// CaseHuntOptions are the options of [HuntCase].
type CaseHuntOptions struct {
	HuntOptions
	// Config names one of the case's configs, as listed in case.yaml, or a file inside
	// the case. A relative path is looked for in the case directory first, then in the
	// working directory; either way the real path (symlinks followed) must be inside the
	// case. Empty means the case's only config; a case that lists several needs it.
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
	n := &notes{notice: opts.Notice}
	plan, err := config.PlanCase(caseDir, opts.Config, "hunt", opts.Window != 0)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	for _, note := range plan.Notes {
		n.add(note)
	}
	cfg, err := config.Load(plan.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if err := cfg.UseSearch(opts.Search, opts.SearchField); err != nil {
		return nil, usagef("%v", err)
	}
	if note := config.PlaceCaseStore(plan.Case, cfg); note != "" {
		n.add(note)
	}
	cfg.UseCase(plan.Case) // detectors read the case's data files
	if opts.Window == 0 {
		opts.Window = plan.Window
	}
	return hunt(ctx, cfg, opts.HuntOptions, n, app.RenameScope(caseDir, opts.Config), plan.Case.Dir, plan.Case.EvidenceDir())
}

// searchFieldName words the field of an ad-hoc search for the note of a hunt.
func searchFieldName(override string) string {
	if override != "" {
		return override
	}
	return "message (or each source's search_field)"
}

// hunt runs a hunt over a config that is already narrowed by opts.Search. It raises the
// advice lines of the run in the order the CLI has always printed them.
func hunt(ctx context.Context, cfg *Config, opts HuntOptions, n *notes, scope string, keepOut ...string) (*Result, error) {
	if opts.Window < 0 {
		return nil, usagef("window must be positive, got %s", opts.Window)
	}
	if opts.Window == 0 {
		opts.Window = DefaultWindow
	}
	if opts.Env == nil {
		opts.Env = config.OSEnv
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	prefix := "hunt"
	if len(opts.Search) > 0 {
		prefix = "search" // a narrowed subset is not a hunt of the window
	}
	w, run, err := plan(now(), opts, prefix)
	if err != nil {
		return nil, err
	}

	rt, err := cfg.Build(opts.Env)
	if err != nil {
		return nil, err
	}
	defer rt.Close() // ends any plugin child process

	st, err := config.OpenRunStore(ctx, cfg, opts.NoStore, keepOut...)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer st.Close() // removes the scratch store of NoStore

	n.add(fmt.Sprintf("hunting %s [%s, %s) with %d source(s), %d detector(s)",
		run, w.From.Format(time.RFC3339), w.To.Format(time.RFC3339), len(rt.Sources), len(rt.Detectors)))
	if note := app.DisabledNote(watchrun.Disabled(rt)); note != "" {
		n.add(note)
	}
	if len(opts.Search) > 0 {
		n.add(fmt.Sprintf("narrowed by %d search term(s) on field %s; the detectors read the stored evidence for the window, which includes events saved by earlier runs, not only the matches", len(opts.Search), searchFieldName(opts.SearchField)))
	}

	res, herr := app.Hunt(ctx, watchrun.RunDeps(rt, rt.Detectors, st), run, w)
	res.Until = opts.Until
	res.Search = append([]string(nil), opts.Search...)
	// Advice only: the detectors have just read the store, and if one set of documents
	// sits under two labels they counted it twice. The verdict is not touched.
	if advice := app.OverlapAdvice(ctx, st, core.Window{From: w.Previous().From, To: w.To}, scope); advice != "" {
		n.add(strings.TrimSuffix(advice, "\n"))
	}
	res.Notes = n.lines
	return &res, herr
}

// plan returns the window and run id for opts, with the same rules as `jb hunt --until`.
func plan(now time.Time, opts HuntOptions, prefix string) (core.Window, string, error) {
	if opts.Until.IsZero() {
		to := now.UTC().Truncate(time.Second)
		return core.Window{From: to.Add(-opts.Window), To: to}, prefix + "-" + to.Format("20060102T150405Z"), nil
	}
	if opts.Until.Nanosecond() != 0 {
		return core.Window{}, "", usagef("Until must be whole seconds; window edges are not rounded")
	}
	until := opts.Until.UTC()
	if until.After(now.UTC().Truncate(time.Second)) {
		return core.Window{}, "", usagef("Until %s is in the future", until.Format(time.RFC3339))
	}
	if opts.Window > MaxHistoricalWindow {
		return core.Window{}, "", usagef("Window %s is longer than the %s a historical hunt accepts", opts.Window, MaxHistoricalWindow)
	}
	run := fmt.Sprintf("%s-until-%s-w%ds", prefix, until.Format("20060102T150405Z"), int64(opts.Window/time.Second))
	return core.Window{From: until.Add(-opts.Window), To: until}, run, nil
}
