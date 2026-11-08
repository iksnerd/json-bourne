package core

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Store maintenance: what is in the evidence store, how to remove the bulk of it
// that nothing else prunes, and how to write a smaller copy of the file. The adapter
// implements the ports; the commands decide when to call them.

// RunKind is the family a run id belongs to, derived from the whole shape of the id
// (never a bare prefix), so "hunt-" never claims "hunt-until-..." and a watcher's
// "watch-a-..." is never confused with another's.
type RunKind string

const (
	KindWatch         RunKind = "watch"          // watch-<stamp> and watch-<name>-<stamp>
	KindHunt          RunKind = "hunt"           // hunt-<stamp>
	KindHuntUntil     RunKind = "hunt-until"     // hunt-until-<stamp>-w<seconds>s
	KindActivity      RunKind = "activity"       // activity-<stamp>
	KindActivityUntil RunKind = "activity-until" // activity-until-<stamp>-w<seconds>s
	KindSearch        RunKind = "search"         // search-<stamp>
	KindSearchUntil   RunKind = "search-until"   // search-until-<stamp>-w<seconds>s
	KindOther         RunKind = "other"
)

// AllRunKinds is every kind, in the order reports list them.
var AllRunKinds = []RunKind{KindWatch, KindHunt, KindHuntUntil, KindActivity, KindActivityUntil, KindSearch, KindSearchUntil, KindOther}

// PrunableKinds are the kinds `jb db prune` may remove. Watch runs are not among them:
// `jb watch --keep` owns their retention, per watcher.
var PrunableKinds = []RunKind{KindHunt, KindHuntUntil, KindActivity, KindActivityUntil, KindSearch, KindSearchUntil}

const stampRE = `[0-9]{8}T[0-9]{6}Z`

var (
	liveRunRE  = regexp.MustCompile(`^(hunt|activity|search)-` + stampRE + `$`)
	untilRunRE = regexp.MustCompile(`^(hunt|activity|search)-until-` + stampRE + `-w[0-9]+s$`)
	watchRunRE = regexp.MustCompile(`^watch-(?:([a-z][a-z0-9_-]{0,31})-)?` + stampRE + `$`)
)

// HuntID returns the hunt a run id belongs to: the part before the first "/". A
// hunt's findings are stored under the hunt id and each source's events under
// id + "/" + source.
func HuntID(runID string) string {
	base, _, _ := strings.Cut(runID, "/")
	return base
}

// ClassifyRun returns the kind of a run id and, for a watch run, the watcher's name
// ("" for the unnamed watcher). Anything that is not exactly one of the shapes above is
// KindOther.
func ClassifyRun(runID string) (kind RunKind, watcher string) {
	base := HuntID(runID)
	if m := liveRunRE.FindStringSubmatch(base); m != nil {
		return RunKind(m[1]), ""
	}
	if m := untilRunRE.FindStringSubmatch(base); m != nil {
		return RunKind(m[1] + "-until"), ""
	}
	if m := watchRunRE.FindStringSubmatch(base); m != nil {
		return KindWatch, m[1]
	}
	return KindOther, ""
}

// ErrWatchKind is returned when a prune asks for watch runs.
var ErrWatchKind = errors.New("watch runs are not pruned here: use `jb watch --keep` (watch retention owns them and keeps each watcher's newest run)")

// ParsePrunableKinds reads a comma separated --kind value. It refuses an empty value,
// a wildcard, any watch kind or id, and anything it does not know, so a prune always
// names what it removes.
func ParsePrunableKinds(s string) ([]RunKind, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("--kind is required: name the run kinds to prune, one or more of " + kindList(PrunableKinds))
	}
	var out []RunKind
	seen := map[RunKind]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
			return nil, errors.New("--kind has an empty entry")
		case p == "all" || p == "*" || strings.ContainsAny(p, "*?"):
			return nil, fmt.Errorf("--kind %q: there is no wildcard; name the kinds (%s)", p, kindList(PrunableKinds))
		case p == string(KindWatch) || strings.HasPrefix(p, "watch-") || strings.HasPrefix(p, "watch/"):
			return nil, ErrWatchKind
		}
		k := RunKind(p)
		ok := false
		for _, pk := range PrunableKinds {
			ok = ok || pk == k
		}
		if !ok {
			return nil, fmt.Errorf("--kind %q is not a prunable run kind (%s)", p, kindList(PrunableKinds))
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, nil
}

func kindList(ks []RunKind) string {
	s := make([]string, len(ks))
	for i, k := range ks {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

// KindUsage is what one run kind (for watch, one watcher) holds. Runs counts hunts
// (the findings run plus its per-source event runs are one). RawBytes and FieldsBytes
// are the UNCOMPRESSED size of the raw documents and of the fields JSON: DuckDB
// compresses on disk, so they show proportions, not file size.
type KindUsage struct {
	Kind        RunKind   `json:"kind"`
	Watcher     string    `json:"watcher,omitempty"` // watch only; "" is the unnamed watcher
	Runs        int64     `json:"runs"`
	PrunedRuns  int64     `json:"runs_events_pruned"`
	Events      int64     `json:"events"`
	RawBytes    int64     `json:"raw_bytes"`
	FieldsBytes int64     `json:"fields_bytes"`
	Oldest      time.Time `json:"oldest,omitempty"`
	Newest      time.Time `json:"newest,omitempty"`
}

// LabelUsage is the same for one source label.
type LabelUsage struct {
	Label       string    `json:"label"`
	Runs        int64     `json:"runs"`
	Events      int64     `json:"events"`
	RawBytes    int64     `json:"raw_bytes"`
	FieldsBytes int64     `json:"fields_bytes"`
	Oldest      time.Time `json:"oldest,omitempty"`
	Newest      time.Time `json:"newest,omitempty"`
}

// StoreUsage is the answer of StoreUsageReader.
type StoreUsage struct {
	Path          string       `json:"path"`
	SchemaVersion int          `json:"schema_version"`
	Runs          int64        `json:"run_records"`
	Events        int64        `json:"events"`
	Findings      int64        `json:"findings"`
	Reputation    int64        `json:"reputation"`
	FileBytes     int64        `json:"file_bytes"`
	UsedBytes     int64        `json:"engine_used_bytes"` // blocks in use inside the file
	FreeBytes     int64        `json:"engine_free_bytes"` // blocks DuckDB would reuse; a compacted copy drops them
	Kinds         []KindUsage  `json:"kinds"`
	Labels        []LabelUsage `json:"labels"`
	// LegacyEvents counts the events with no document identity (doc_ident NULL): rows
	// written before schema 4. The reader tells only these apart by source label. When it is 0
	// on every store, that fallback has no row left to serve and can be deleted.
	LegacyEvents int64 `json:"events_without_doc_ident"`
}

// StoreUsageReader measures the store with fixed queries. It reads only, and works on
// a read-only handle.
type StoreUsageReader interface {
	StoreUsage(ctx context.Context) (StoreUsage, error)
}

// MaxPruneRunIDs is the most run ids one `jb db prune --run` may name.
const MaxPruneRunIDs = 20

// ParseRunIDs checks the values of `--run`: each is one hunt id, compared whole (no
// prefix, no pattern, no "/source" suffix). Watch ids are refused as --kind watch is,
// and so is any id that is not a hunt, activity or search id (ClassifyRun says "other").
// A repeated id is kept once. At most MaxPruneRunIDs values are accepted.
func ParseRunIDs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("--run needs at least one run id")
	}
	if len(values) > MaxPruneRunIDs {
		return nil, fmt.Errorf("--run given %d times; at most %d run ids at once", len(values), MaxPruneRunIDs)
	}
	var out []string
	seen := map[string]bool{}
	for _, id := range values {
		if id == "" {
			return nil, errors.New("--run has an empty run id")
		}
		if strings.ContainsAny(id, "*?%") {
			return nil, fmt.Errorf("--run %q: there is no wildcard; name the exact run id", id)
		}
		kind, _ := ClassifyRun(id)
		if kind == KindWatch {
			return nil, ErrWatchKind
		}
		if strings.Contains(id, "/") {
			return nil, fmt.Errorf("--run %q: name the hunt id (the part before the first \"/\"), not one source of it", id)
		}
		if kind == KindOther {
			return nil, fmt.Errorf("--run %q is not a hunt, activity or search run id (%s)", id, kindList(PrunableKinds))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// EventPruneRequest asks to remove the events of old runs of the named kinds, or of the
// runs named exactly in RunIDs.
type EventPruneRequest struct {
	// RunIDs, when set, selects exactly these hunts (see ParseRunIDs) and replaces the
	// selection by kind and age: Kinds, Before and KeepLatest must then be unset. A
	// named id that is not in the store is an error and nothing is changed.
	RunIDs       []string
	Kinds        []RunKind // only PrunableKinds; the adapter refuses anything else
	Before       time.Time // a hunt is old when its newest runs.created_at is before this
	KeepLatest   int       // the N newest hunts of each kind are kept whatever their age
	DropFindings bool      // also delete the findings and run records of the pruned hunts
	DryRun       bool      // plan only; works on a read-only handle
}

// Prune actions for a hunt.
const (
	ActionPrune       = "prune"
	ActionKeepLatest  = "keep-latest"
	ActionKeepRecent  = "keep-recent"
	ActionAlreadyDone = "events-already-pruned"
)

// PruneRun is one hunt the plan looked at.
type PruneRun struct {
	ID          string    `json:"id"`
	Kind        RunKind   `json:"kind"`
	Created     time.Time `json:"created_at"`
	Action      string    `json:"action"`
	Events      int64     `json:"events"`
	RawBytes    int64     `json:"raw_bytes"`
	FieldsBytes int64     `json:"fields_bytes"`
	Findings    int64     `json:"findings"`
}

// PruneTotals sums the hunts with ActionPrune.
type PruneTotals struct {
	Runs        int64 `json:"runs"`        // hunts
	RunRecords  int64 `json:"run_records"` // run ids (a hunt's findings run plus one per source)
	Events      int64 `json:"events"`
	RawBytes    int64 `json:"raw_bytes"`
	FieldsBytes int64 `json:"fields_bytes"`
	Findings    int64 `json:"findings"`
}

// EventPruneResult is the plan and, when Applied, what was done. Deleted is taken from
// the engine's row counts inside the transaction and has been checked equal to the plan
// before the commit; a difference rolls everything back.
type EventPruneResult struct {
	Applied      bool        `json:"applied"`
	ByRunID      bool        `json:"by_run_id"` // the runs were named with --run; the age and keep-latest rules did not apply
	DropFindings bool        `json:"drop_findings"`
	Before       time.Time   `json:"older_than_cutoff"`
	KeepLatest   int         `json:"keep_latest"`
	Runs         []PruneRun  `json:"runs"`
	Plan         PruneTotals `json:"plan"`
	Deleted      PruneTotals `json:"deleted"`
	Marked       int64       `json:"run_records_marked_pruned"` // default mode: records stamped pruned_at
}

// RunEventPruner removes the events of old runs in one transaction. Findings and run
// records stay (the run record is stamped pruned_at) unless DropFindings.
type RunEventPruner interface {
	PruneRunEvents(ctx context.Context, req EventPruneRequest) (EventPruneResult, error)
}

// CompactRequest asks for a compacted copy of the store at Target (a path that does not
// exist). DryRun reports sizes and writes nothing.
type CompactRequest struct {
	Target string
	DryRun bool
}

// TableCount is a row count of one table.
type TableCount struct {
	Table string `json:"table"`
	Rows  int64  `json:"rows"`
}

// CompactResult describes a compaction.
type CompactResult struct {
	Applied       bool         `json:"applied"`
	Target        string       `json:"target"`
	SourceBytes   int64        `json:"source_file_bytes"`
	UsedBytes     int64        `json:"engine_used_bytes"`
	FreeBytes     int64        `json:"engine_free_bytes"`
	EstimateBytes int64        `json:"estimated_copy_bytes"` // used blocks; a lower bound is possible, the copy is recompressed
	TargetBytes   int64        `json:"target_file_bytes"`
	SchemaVersion int          `json:"schema_version"`
	Source        []TableCount `json:"source_rows"`
	Copy          []TableCount `json:"copy_rows"`
}

// StoreCompactor writes a compacted copy of the open store. It never replaces the
// original and never overwrites an existing file.
type StoreCompactor interface {
	Compact(ctx context.Context, req CompactRequest) (CompactResult, error)
}
