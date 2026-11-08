package jb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// The mutating database functions. Each takes Apply, whose zero value is a dry run: the
// store is then opened read-only, which the storage engine enforces, so a dry run cannot
// change the file. None of them creates a store, and none prints a stored document or an
// address from one.

// DefaultPruneKeepLatest is how many of the newest hunts of each selected kind
// [DBPrune] keeps when [DBPruneOptions.KeepLatest] is nil.
const DefaultPruneKeepLatest = 1

// MaxPruneRunIDs is the most run ids one [DBPrune] may name.
const MaxPruneRunIDs = core.MaxPruneRunIDs

// DBPruneOptions say which runs [DBPrune] removes the events of. Choose them either by
// kind and age (Kinds, OlderThan, KeepLatest) or by exact id (RunIDs), never both.
type DBPruneOptions struct {
	// Config names the store, as in [DBOptions.Config].
	Config string
	// Kinds are the run kinds to prune: any of the RunKind constants. Required unless
	// RunIDs is set. Watch runs are refused, and there is no wildcard.
	Kinds []RunKind
	// OlderThan prunes hunts whose newest record is older than this. Required, and
	// positive, unless RunIDs is set.
	OlderThan time.Duration
	// KeepLatest keeps the N newest hunts of each selected kind whatever their age.
	// Nil means [DefaultPruneKeepLatest]; a pointer to 0 keeps none, so that choice is
	// always explicit.
	KeepLatest *int
	// RunIDs removes exactly these hunts whatever their age, instead of Kinds, OlderThan
	// and KeepLatest, which must then be unset. At most [MaxPruneRunIDs]; each id is
	// compared whole, never as a prefix or pattern. An id not in the store is an error
	// that names it, and nothing is deleted.
	RunIDs []string
	// DropFindings also deletes the pruned hunts' findings and run records. By default
	// only events go, and the run record is marked pruned. Reputation rows are never
	// touched.
	DropFindings bool
	// Apply deletes. The zero value is a dry run that opens the store read-only and
	// changes nothing.
	Apply bool
	// Now is the clock for the OlderThan cutoff. Nil means time.Now.
	Now func() time.Time
}

// DBPruneResult is what [DBPrune] plans and, with Apply, did. Its JSON is the output of
// `jb db prune --output json`: the store path, then the fields of [EventPruneResult].
type DBPruneResult struct {
	Store string `json:"store"`
	EventPruneResult

	// Notes are advice the CLI prints to stderr. They are not part of the JSON.
	Notes []string `json:"-"`
}

// DBPrune deletes the stored events (the raw documents) of old one-off runs, as
// `jb db prune` does, in ONE transaction. Without Apply it only returns the plan. The
// counts after Apply are the engine's own row counts, checked equal to the plan inside
// the transaction; a difference rolls everything back. The file does not shrink: see
// [DBCompact]. A caller's mistake in the selection returns a [UsageError].
func DBPrune(ctx context.Context, caseDir string, opts DBPruneOptions) (*DBPruneResult, error) {
	req := core.EventPruneRequest{DropFindings: opts.DropFindings, DryRun: !opts.Apply}
	if len(opts.RunIDs) > 0 {
		for _, c := range []struct {
			flag string
			set  bool
		}{
			{"kind", len(opts.Kinds) > 0},
			{"older-than", opts.OlderThan != 0},
			{"keep-latest", opts.KeepLatest != nil},
		} {
			if c.set {
				return nil, core.Usagef("--run selects exact runs and cannot be combined with --%s (--kind, --older-than and --keep-latest are the other way to choose)", c.flag)
			}
		}
		ids, err := core.ParseRunIDs(opts.RunIDs)
		if err != nil {
			return nil, core.Usagef("%v", err)
		}
		req.RunIDs = ids // KeepLatest stays 0: named runs are not ranked
	} else {
		names := make([]string, len(opts.Kinds))
		for i, k := range opts.Kinds {
			names[i] = string(k)
		}
		ks, err := core.ParsePrunableKinds(strings.Join(names, ","))
		if err != nil {
			return nil, core.Usagef("%v", err)
		}
		req.Kinds = ks
		switch {
		case opts.OlderThan == 0:
			return nil, core.Usagef("--older-than is required (for example 14d or 72h)")
		case opts.OlderThan < 0:
			return nil, core.Usagef("--older-than must be positive")
		}
		req.KeepLatest = DefaultPruneKeepLatest
		if opts.KeepLatest != nil {
			if *opts.KeepLatest < 0 {
				return nil, core.Usagef("--keep-latest must be 0 or more")
			}
			req.KeepLatest = *opts.KeepLatest
		}
		now := time.Now
		if opts.Now != nil {
			now = opts.Now
		}
		req.Before = now().Add(-opts.OlderThan)
	}

	s, err := resolveDBStore(caseDir, opts.Config)
	if err != nil {
		return nil, err
	}
	// A dry run opens read-only, so the engine itself guarantees it changes nothing.
	st, err := openDB(ctx, s.path, !opts.Apply)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if opts.Apply {
		if _, err := st.Migrate(); err != nil {
			return nil, fmt.Errorf("migrate database: %w", err)
		}
	}
	res, err := st.PruneRunEvents(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("prune: %w", err)
	}
	return &DBPruneResult{Store: s.path, EventPruneResult: res, Notes: s.notes}, nil
}

// DBCompactOptions say where [DBCompact] writes the compacted copy.
type DBCompactOptions struct {
	// Config names the store, as in [DBOptions.Config].
	Config string `jb:"config" desc:"YAML config naming the store (with --case: one of the case's configs)"`
	// To is the new file for the copy. Required. It must not exist (it is never
	// overwritten), its directory must exist and pass the same git-ignore guard as
	// evidence, and it must be inside the case's evidence directory (with no case, the
	// store's own directory) unless AllowOutsideEvidence.
	To string `jb:"to" desc:"the new file to write the compacted copy to (must not exist)"`
	// AllowOutsideEvidence lets To be outside the evidence directory. Its directory must
	// still pass the git-ignore guard.
	AllowOutsideEvidence bool `jb:"allow_outside_evidence" desc:"allow --to outside the evidence directory (its directory must still pass the git-ignore guard)"`
	// Apply writes the copy. The zero value is a dry run that opens the store read-only
	// and writes nothing. Apply opens the store read-write, which no other process can
	// share, so it is refused while anything holds the store.
	Apply bool `jb:"apply" desc:"write the copy (default: dry run)"`
}

// DBCompactResult is what [DBCompact] reports. Its JSON is the output of
// `jb db compact --output json`.
type DBCompactResult struct {
	CompactResult

	// Store is the path of the store that was compacted. It is not part of the JSON.
	Store string `json:"-"`
	// Notes are advice the CLI prints to stderr. They are not part of the JSON.
	Notes []string `json:"-"`
}

// DBCompact writes a compacted copy of the evidence database to opts.To, as
// `jb db compact` does. It never replaces the original and never overwrites a file;
// swapping the files is the caller's. With Apply it verifies the copy (rows per table,
// raw bytes, schema version, a read-only open) before it puts it at To, and deletes a
// copy that fails.
func DBCompact(ctx context.Context, caseDir string, opts DBCompactOptions) (*DBCompactResult, error) {
	if opts.To == "" {
		return nil, core.Usagef("--to FILE is required")
	}
	s, err := resolveDBStore(caseDir, opts.Config)
	if err != nil {
		return nil, err
	}
	target, err := checkCompactTarget(s, opts.To, opts.AllowOutsideEvidence)
	if err != nil {
		return nil, err
	}
	st, err := openDB(ctx, s.path, !opts.Apply)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	res, err := st.Compact(ctx, core.CompactRequest{Target: target, DryRun: !opts.Apply})
	if err != nil {
		return nil, fmt.Errorf("compact: %w", err)
	}
	return &DBCompactResult{CompactResult: res, Store: s.path, Notes: s.notes}, nil
}

// checkCompactTarget applies the rules that need no open store: absent, in a directory
// that exists, inside the evidence root unless allowed, and a directory the evidence
// guard accepts. It returns the absolute target.
func checkCompactTarget(s dbStore, to string, outside bool) (string, error) {
	abs, err := filepath.Abs(to)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(abs); err == nil {
		return "", fmt.Errorf("refusing: %s already exists; compact never overwrites a file", abs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("target %s: %w", abs, err)
	}
	dir := filepath.Dir(abs)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("refusing: the directory %s does not exist; compact does not create directories", dir)
	}
	if same, _ := sameFile(abs, s.path); same {
		return "", fmt.Errorf("refusing: the target is the store itself")
	}
	if !config.InsideDir(s.root, abs) && !outside {
		return "", fmt.Errorf("refusing: %s is outside the evidence directory %s, which git ignores; pass --allow-outside-evidence if you mean it", abs, s.root)
	}
	if _, err := casefile.Guard(dir); err != nil {
		return "", fmt.Errorf("refusing: %w", err)
	}
	return abs, nil
}

func sameFile(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

// DBRenameSourceOptions say which source label [DBRenameSource] relabels.
type DBRenameSourceOptions struct {
	// Config names the store, as in [DBOptions.Config].
	Config string `jb:"config" desc:"YAML config naming the store (with --case: one of the case's configs)"`
	// Old is a stored label: a valid source name, or a default kibana:<index> label.
	Old string `jb:"old" required:"true" desc:"the stored source label to relabel: a valid source name, or a default kibana:<index> label"`
	// New is a valid source name (the rule for `name:` in a config). It differs from Old.
	New string `jb:"new" required:"true" desc:"the new source label: a valid source name that differs from old"`
	// Merge, when New already holds documents Old also holds (same time, kind and
	// content digest), drops the rows of Old that New covers and relabels the rest.
	// Without it such an overlap refuses the rename, dry run or not.
	Merge bool `jb:"merge" desc:"when NEW already holds some of OLD's documents, drop OLD's copies and relabel the rest"`
	// Apply does the rename in one transaction. The zero value is a dry run that opens
	// the store read-only and changes nothing.
	Apply bool `jb:"apply" desc:"do the rename (default: dry run)"`
}

// DBRenameSourceResult counts a rename. Its JSON is the output of
// `jb db rename-source --output json`. After an [ErrSourceOverlap] or
// [ErrNoSuchSource] the counts say what was found and Applied is false.
type DBRenameSourceResult struct {
	Store      string `json:"store"`
	Old        string `json:"old"`
	New        string `json:"new"`
	Applied    bool   `json:"applied"`
	Events     int64  `json:"events"`
	Runs       int64  `json:"runs"`
	NewEvents  int64  `json:"new_events"`
	Overlap    int64  `json:"overlap"`
	Dropped    int64  `json:"dropped"`
	Relabelled int64  `json:"relabelled"`
	NoRaw      int64  `json:"no_raw"`

	// Notes are advice the CLI prints to stderr. They are not part of the JSON.
	Notes []string `json:"-"`
}

// sourceError carries a message for a person and the sentinel a caller matches.
type sourceError struct {
	msg string
	err error
}

func (e *sourceError) Error() string { return e.msg }
func (e *sourceError) Unwrap() error { return e.err }

// DBRenameSource relabels the events stored under source label Old as New, as
// `jb db rename-source` does, in one transaction. Run ids, findings and the identity
// rule are not touched. When the rename cannot proceed the result is still returned,
// non-nil, with the counts found, together with an error that matches [ErrSourceOverlap]
// or [ErrNoSuchSource]. A malformed label returns a [UsageError].
func DBRenameSource(ctx context.Context, caseDir string, opts DBRenameSourceOptions) (*DBRenameSourceResult, error) {
	if caseDir == "" && opts.Config == "" {
		return nil, core.Usagef("one of --case DIR or --config FILE is required (it names the store)")
	}
	if !config.ValidStoredLabel(opts.Old) {
		return nil, core.Usagef("OLD %q is not a stored source label: expected a source name (lower case letter first, then a-z 0-9 _ . : -, at most 64) or a default kibana:<index> label", opts.Old)
	}
	if !config.ValidSourceName(opts.New) {
		return nil, core.Usagef("NEW %q is not a valid source name: a lower case letter, then a-z 0-9 _ . : -, at most 64 characters", opts.New)
	}
	if opts.Old == opts.New {
		return nil, core.Usagef("OLD and NEW are the same label")
	}
	s, err := resolveDBStore(caseDir, opts.Config)
	if err != nil {
		return nil, err
	}
	// A dry run opens read-only, so the engine itself guarantees it changes nothing.
	st, err := openDB(ctx, s.path, !opts.Apply)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	r, rerr := st.RenameSource(ctx, core.RenameSourceRequest{Old: opts.Old, New: opts.New, Merge: opts.Merge, DryRun: !opts.Apply})
	res := &DBRenameSourceResult{Store: s.path, Old: r.Old, New: r.New, Applied: r.Applied, Events: r.Events, Runs: r.Runs,
		NewEvents: r.NewEvents, Overlap: r.Overlap, Dropped: r.Dropped, Relabelled: r.Relabelled, NoRaw: r.NoRaw, Notes: s.notes}
	switch {
	case errors.Is(rerr, core.ErrSourceOverlap):
		return res, &sourceError{fmt.Sprintf("refused: %q already holds %d of the documents under %q; nothing was changed. If they are the same documents, re-run with --merge to drop OLD's copies and relabel the rest", opts.New, r.Overlap, opts.Old), core.ErrSourceOverlap}
	case errors.Is(rerr, core.ErrNoSuchSource):
		return res, &sourceError{fmt.Sprintf("no event in %s carries the source label %q; nothing to do", s.path, opts.Old), core.ErrNoSuchSource}
	case rerr != nil:
		return res, fmt.Errorf("rename source: %w", rerr)
	}
	return res, nil
}
