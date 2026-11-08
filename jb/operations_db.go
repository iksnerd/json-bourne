package jb

import (
	"context"
	"time"

	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/ops"
)

// The `jb db` operations. Each names the store by a case directory, a config or both;
// the typed function says what it takes, and a call with neither is a usage error.

// dbInput is the input of db_status and db_usage.
type dbInput struct {
	Case string "jb:\"case\" desc:\"case directory (docs/CASE-SPEC.md); the store is placed as `jb hunt --case` places it\""
	DBOptions
}

type dbCompactInput struct {
	Case string "jb:\"case\" desc:\"case directory (docs/CASE-SPEC.md); the store is placed as `jb hunt --case` places it\""
	DBCompactOptions
}

type dbRenameSourceInput struct {
	Case string "jb:\"case\" desc:\"case directory (docs/CASE-SPEC.md); the store is placed as `jb hunt --case` places it\""
	DBRenameSourceOptions
}

type dbPruneInput struct {
	Case         string   "jb:\"case\" desc:\"case directory (docs/CASE-SPEC.md); the store is placed as `jb hunt --case` places it\""
	Config       string   `jb:"config" desc:"YAML config naming the store (with --case: one of the case's configs)"`
	Run          []string `jb:"run" desc:"remove exactly this hunt id (repeatable, at most 20); instead of --kind, --older-than and --keep-latest; never a watch run"`
	Kind         string   `jb:"kind" desc:"run kinds to prune, comma separated: hunt, hunt-until, activity, activity-until, search, search-until (required; never watch)"`
	OlderThan    string   `jb:"older_than" desc:"prune hunts whose newest record is older than this (14d, 72h, 2w) (required)"`
	KeepLatest   int      `jb:"keep_latest" default:"1" min:"0" desc:"always keep the N newest hunts of each selected kind, whatever their age"`
	DropFindings bool     `jb:"drop_findings" desc:"also delete the pruned hunts' findings and run records (default: keep them, marked pruned)"`
	Apply        bool     `jb:"apply" desc:"do it (default: dry run)"`
}

type dbReputationInput struct {
	Case      string   "jb:\"case\" desc:\"case directory (docs/CASE-SPEC.md); the store is placed as `jb intel --case` places it\""
	Config    string   `jb:"config" desc:"YAML config naming the store (with --case: one of the case's configs)"`
	Indicator []string `jb:"indicator" desc:"only this IP address (repeat for up to 100)"`
	Source    string   `jb:"source" desc:"only rows from this source (feed name)"`
	Since     string   `jb:"since" desc:"only rows observed at or after this RFC 3339 time or YYYY-MM-DD date"`
	Until     string   `jb:"until" desc:"only rows observed before this RFC 3339 time or YYYY-MM-DD date (exclusive)"`
	Limit     int      `jb:"limit" min:"0" max:"10000" desc:"most rows to return (default 1000, at most 10000)"`
	Latest    bool     `jb:"latest" desc:"newest row of each indicator from each source"`
}

func dbOperations() []registered {
	return []registered{
		register("db_status", "Show the database counts",
			"Show the evidence database path, its schema version and its row counts. The store is opened read-only, which the engine enforces, and is never created.",
			true, ops.CLI{Command: []string{"db", "status"}},
			func(ctx context.Context, in dbInput, _ Env, _ argv) (any, error) {
				return both(DBStatus(ctx, in.Case, in.DBOptions))
			}),
		register("db_usage", "Show what the database holds",
			"Measure what the evidence database holds, by run kind and by source label, and count documents stored under two labels, which a detector would count twice. The store is opened read-only and is never created."+untrusted,
			true, ops.CLI{Command: []string{"db", "usage"}},
			func(ctx context.Context, in dbInput, _ Env, _ argv) (any, error) {
				return both(DBUsage(ctx, in.Case, in.DBOptions))
			}),
		register("db_reputation", "List stored reputation rows",
			"List the reputation rows that intel stored: indicator, verdict, observed time and feed. A snapshot is context, not attribution. A result cut at the row cap says so (complete is false). The store is opened read-only and is never created."+untrusted,
			true, ops.CLI{Command: []string{"db", "reputation"}},
			func(ctx context.Context, in dbReputationInput, _ Env, _ argv) (any, error) {
				opts := ReputationOptions{Config: in.Config, Indicators: in.Indicator, Source: in.Source, Limit: in.Limit, Latest: in.Latest}
				var err error
				if opts.Since, err = whenArg("since", in.Since); err != nil {
					return nil, err
				}
				if opts.Until, err = whenArg("until", in.Until); err != nil {
					return nil, err
				}
				return both(Reputation(ctx, in.Case, opts))
			}),
		register("db_prune", "Delete the events of old runs",
			"Delete the stored events (the raw documents) of old one-off hunt, activity and search runs, in one transaction. A dry run unless apply is true: it prints what would go and changes nothing. Findings stay unless drop_findings is set; watch runs and reputation rows are never touched.",
			false, ops.CLI{Command: []string{"db", "prune"}},
			func(ctx context.Context, in dbPruneInput, _ Env, a argv) (any, error) {
				opts := DBPruneOptions{Config: in.Config, DropFindings: in.DropFindings, Apply: in.Apply}
				if a.has("run") {
					opts.RunIDs = in.Run
					if len(opts.RunIDs) == 0 {
						opts.RunIDs = []string{""} // an empty list is refused by name, not read as "no run"
					}
				}
				if a.has("kind") {
					ks, err := core.ParsePrunableKinds(in.Kind)
					if err != nil {
						return nil, usagef("%v", err)
					}
					opts.Kinds = ks
				}
				if a.has("older_than") {
					age, err := ageArg(in.OlderThan)
					if err != nil {
						return nil, err
					}
					opts.OlderThan = age
				}
				if a.has("keep_latest") {
					opts.KeepLatest = &in.KeepLatest
				}
				return both(DBPrune(ctx, in.Case, opts))
			}),
		register("db_compact", "Write a compacted copy of the database",
			"Write a compacted copy of the evidence database to a new file. It never replaces the original and never overwrites a file; swapping the files is the caller's. A dry run unless apply is true.",
			false, ops.CLI{Command: []string{"db", "compact"}},
			func(ctx context.Context, in dbCompactInput, _ Env, _ argv) (any, error) {
				return both(DBCompact(ctx, in.Case, in.DBCompactOptions))
			}),
		register("db_rename_source", "Relabel stored events",
			"Relabel the events stored under source label old as new, in one transaction, without touching run ids or findings. A dry run unless apply is true. An overlap (new already holds documents old also holds) refuses the rename unless merge is set; the result still reports the counts it found.",
			false, ops.CLI{Command: []string{"db", "rename-source"}, Positional: []string{"old", "new"}},
			func(ctx context.Context, in dbRenameSourceInput, _ Env, _ argv) (any, error) {
				return both(DBRenameSource(ctx, in.Case, in.DBRenameSourceOptions))
			}),
	}
}

func ageArg(s string) (age time.Duration, err error) {
	age, err = config.ParseAge(s)
	if err != nil {
		return 0, usagef("older_than: %v", err)
	}
	if age <= 0 {
		return 0, usagef("older_than must be positive")
	}
	return age, nil
}
