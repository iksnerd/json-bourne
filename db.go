package jb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Types of the database functions. They are aliases of the plain data types the store
// reports, so the JSON of `jb db ... --output json` and the Go value are one thing.
type (
	// StoreUsage is what the evidence database holds: counts, sizes, and usage by run
	// kind and by source label.
	StoreUsage = core.StoreUsage
	// KindUsage is what one run kind (for watch, one watcher) holds.
	KindUsage = core.KindUsage
	// LabelUsage is what one source label holds.
	LabelUsage = core.LabelUsage
	// RunKind is the kind of a stored run: hunt, hunt-until, activity, and so on.
	RunKind = core.RunKind
	// EventPruneResult is the plan of a prune and, when applied, what was done.
	EventPruneResult = core.EventPruneResult
	// PruneRun is one hunt a prune looked at, with the action taken on it.
	PruneRun = core.PruneRun
	// PruneTotals sums the hunts a prune removes.
	PruneTotals = core.PruneTotals
	// CompactResult describes a compaction: sizes, schema version and rows per table.
	CompactResult = core.CompactResult
	// TableCount is a row count of one table.
	TableCount = core.TableCount
)

// The run kinds [DBPrune] may remove. Watch runs are not among them: `jb watch --keep`
// owns their retention.
const (
	RunKindHunt          = core.KindHunt
	RunKindHuntUntil     = core.KindHuntUntil
	RunKindActivity      = core.KindActivity
	RunKindActivityUntil = core.KindActivityUntil
	RunKindSearch        = core.KindSearch
	RunKindSearchUntil   = core.KindSearchUntil
)

// Errors of [DBRenameSource], matched with errors.Is.
var (
	// ErrSourceOverlap: the new label already holds documents the old label also holds,
	// and Merge was not set.
	ErrSourceOverlap = core.ErrSourceOverlap
	// ErrNoSuchSource: no stored event carries the old label.
	ErrNoSuchSource = core.ErrNoSuchSource
)

// DBOptions say which evidence database a database function works on.
type DBOptions struct {
	// Config names the config that places the store. With a case directory it is one of
	// the case's configs, as in [CaseHuntOptions.Config] (empty: the case's only config,
	// or the one that declares `commands: [rename-source]`, which is the name every
	// `jb db` command chooses by). With no case directory it is the path of a YAML
	// config. A function reads the config's store path and no credential.
	Config string
}

// dbStore is the store a database function works on, and the directory its output may
// be placed in: the case's evidence directory, or the store's own directory when the
// store was named by a config alone.
type dbStore struct {
	path  string
	root  string
	notes []string
}

// resolveDBStore finds the store the way the `jb db` commands do. It never creates one:
// a missing file is a wrong path, not an empty store.
func resolveDBStore(caseDir, cfgPath string) (dbStore, error) {
	if caseDir == "" && cfgPath == "" {
		return dbStore{}, core.Usagef("one of --case DIR or --config FILE is required (it names the store)")
	}
	var s dbStore
	if caseDir == "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return dbStore{}, err
		}
		s.path = cfg.StorePath()
		s.root = filepath.Dir(s.path)
	} else {
		plan, err := config.PlanCase(caseDir, cfgPath, "rename-source", true)
		if err != nil {
			return dbStore{}, err
		}
		s.notes = append(s.notes, plan.Notes...)
		cfg, err := config.Load(plan.ConfigPath)
		if err != nil {
			return dbStore{}, err
		}
		if note := config.PlaceCaseStore(plan.Case, cfg); note != "" {
			s.notes = append(s.notes, note)
		}
		s.path = cfg.StorePath()
		s.root = plan.Case.EvidenceDir()
	}
	if _, err := os.Stat(s.path); err != nil {
		return dbStore{}, fmt.Errorf("no evidence database at %s: %w", s.path, err)
	}
	return s, nil
}

// openDB opens the store. A store that needs migrating is refused read-only with the
// way out named.
func openDB(ctx context.Context, path string, readOnly bool) (*duckdb.Store, error) {
	st, err := duckdb.OpenContext(ctx, path, readOnly, duckdb.OpenOptions{})
	switch {
	case errors.Is(err, duckdb.ErrLocked):
		return nil, fmt.Errorf("refusing: %w", err)
	case errors.Is(err, duckdb.ErrSchemaBehind):
		return nil, fmt.Errorf("open database: %w; any `jb hunt` or `jb watch` cycle migrates it, and so does `jb db prune --apply`", err)
	case err != nil:
		return nil, fmt.Errorf("open database: %w", err)
	}
	return st, nil
}

// DBStatusResult is what [DBStatus] reports. Its JSON is the output of
// `jb db status --output json`; first_seen and last_seen are null when the store holds
// no events.
type DBStatusResult struct {
	Path        string     `json:"path"`
	Schema      int        `json:"schema_version"`
	BuildSchema int        `json:"build_schema_version"`
	Runs        int64      `json:"runs"`
	Events      int64      `json:"events"`
	Findings    int64      `json:"findings"`
	Reputation  int64      `json:"reputation"`
	FirstSeen   *time.Time `json:"first_seen"`
	LastSeen    *time.Time `json:"last_seen"`

	// Notes are advice the CLI prints to stderr, such as a store outside the case's
	// evidence directory. They are not part of the JSON.
	Notes []string `json:"-"`
}

// DBStatus reports the database path, schema version and row counts, as `jb db status`
// does. caseDir may be empty, then opts.Config is the path of a config file. The store
// is opened read-only, which the engine enforces, and is never created.
func DBStatus(ctx context.Context, caseDir string, opts DBOptions) (*DBStatusResult, error) {
	s, err := resolveDBStore(caseDir, opts.Config)
	if err != nil {
		return nil, err
	}
	st, err := duckdb.OpenContext(ctx, s.path, true, duckdb.OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("open database read-only: %w", err)
	}
	defer st.Close()
	x, err := st.Stats()
	if err != nil {
		return nil, fmt.Errorf("read database stats: %w", err)
	}
	return &DBStatusResult{Path: x.Path, Schema: x.Version, BuildSchema: duckdb.Version, Runs: x.Runs, Events: x.Events,
		Findings: x.Findings, Reputation: x.Reputation, FirstSeen: utcPtr(x.FirstSeen), LastSeen: utcPtr(x.LastSeen),
		Notes: s.notes}, nil
}

// utcPtr is t in UTC, or nil for the zero time.
func utcPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// DBUsageOverlap counts the documents stored under two source labels, which a detector
// would count twice. AtLeast is true when the count stopped at five label pairs. Error
// says why the check did not run.
type DBUsageOverlap struct {
	Pairs     int    `json:"label_pairs"`
	Documents int64  `json:"documents"`
	AtLeast   bool   `json:"at_least"`
	Error     string `json:"error,omitempty"`
}

// DBUsageResult is what [DBUsage] reports. Its JSON is the output of
// `jb db usage --output json`.
type DBUsageResult struct {
	StoreUsage
	Overlap DBUsageOverlap `json:"documents_under_two_labels"`

	// Notes are advice the CLI prints to stderr. They are not part of the JSON.
	Notes []string `json:"-"`
}

// Complete reports whether every part of the answer was measured. It is false when the
// check for documents stored under two labels did not run (Overlap.Error says why);
// the counts above it are still right, but "no overlap" must not be read from them.
func (r *DBUsageResult) Complete() bool { return r != nil && r.Overlap.Error == "" }

// DBUsage measures what the evidence database holds, by run kind and by source label,
// as `jb db usage` does. The store is opened read-only and is never created. A store
// another process holds read-write is waited for (the lock wait of the store), then
// refused.
func DBUsage(ctx context.Context, caseDir string, opts DBOptions) (*DBUsageResult, error) {
	s, err := resolveDBStore(caseDir, opts.Config)
	if err != nil {
		return nil, err
	}
	st, err := openDB(ctx, s.path, true)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	u, err := st.StoreUsage(ctx)
	if err != nil {
		return nil, fmt.Errorf("measure database: %w", err)
	}
	rep := &DBUsageResult{StoreUsage: u, Notes: s.notes}
	if u.Events > 0 {
		stt, err := st.Stats()
		switch {
		case err != nil:
			rep.Overlap.Error = err.Error()
		case !stt.FirstSeen.IsZero():
			ov, oerr := app.SourceOverlaps(ctx, st, core.Window{From: stt.FirstSeen, To: stt.LastSeen.Add(time.Second)})
			if oerr != nil {
				rep.Overlap.Error = oerr.Error()
			}
			for _, o := range ov {
				rep.Overlap.Pairs++
				rep.Overlap.Documents += o.Docs
			}
			rep.Overlap.AtLeast = rep.Overlap.Pairs >= 5
		}
	}
	return rep, nil
}
