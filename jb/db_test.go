package jb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

var dbNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type dbHunt struct {
	id    string
	n     int
	ageH  int
	label string
}

// dbHunts: three prunable hunts of different age, one recent, one watch run.
var dbHunts = []dbHunt{
	{"hunt-20261001T000000Z", 4, 500, ""},
	{"hunt-20261002T000000Z", 3, 400, ""},
	{"hunt-20261105T100000Z", 2, 2, ""},
	{"watch-20261001T000000Z", 7, 900, ""},
}

func dbEvents(source string, from, n int) []core.Event {
	var out []core.Event
	for i := from; i < from+n; i++ {
		out = append(out, core.Event{
			Time: dbNow.Add(-30*time.Minute + time.Duration(i)*time.Second), Source: source, Kind: "request",
			Fields: map[string]any{"n": float64(i)}, Raw: []byte(fmt.Sprintf(`192.0.2.7 GET /item/%d`, i)),
		})
	}
	return out
}

// dbSeq is the stream the tests hand to Store.SaveEvents. The store requires a document
// identity, so a bare event gets "test-doc/<source>/<kind>": the same line under two source
// labels stays two documents. An event that sets its own DocKey keeps it.
func dbSeq(evs []core.Event) func(func(core.Event, error) bool) {
	return func(yield func(core.Event, error) bool) {
		for _, e := range evs {
			if e.DocKey == "" {
				e.DocKey = "test-doc/" + e.Source + "/" + e.Kind
			}
			if !yield(e, nil) {
				return
			}
		}
	}
}

// seedDBAt writes a store at path with the hunts and returns nothing; synthetic data only.
func seedDBAt(t *testing.T, path string, hunts []dbHunt) {
	t.Helper()
	st, err := duckdb.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, h := range hunts {
		lab := h.label
		if lab == "" {
			lab = "ingress"
		}
		if err := st.SaveEvents(ctx, h.id+"/"+lab, dbSeq(dbEvents(lab, 0, h.n))); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveFindings(ctx, h.id, []core.Finding{{Detector: "d", Tag: "t-" + h.id, Summary: "s"}}); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	db, err := sql.Open("duckdb", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, h := range hunts {
		if _, err := db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = ? OR starts_with(run_id, ?)`,
			dbNow.Add(-time.Duration(h.ageH)*time.Hour).Format(time.RFC3339), h.id, h.id+"/"); err != nil {
			t.Fatal(err)
		}
	}
}

// seedDB writes a config beside a seeded store and returns both paths.
func seedDB(t *testing.T, hunts []dbHunt) (cfg, store string) {
	t.Helper()
	dir := t.TempDir()
	store = filepath.Join(dir, "jb.duckdb")
	cfg = filepath.Join(dir, "jb.yaml")
	y := fmt.Sprintf("sources:\n  - type: kibana\n    url: https://kibana.example.com\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-auth-*\ndetectors:\n  - type: authspike\n    key_field: client_ip\n    status_field: status\nstore:\n  path: %s\n", store)
	if err := os.WriteFile(cfg, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	seedDBAt(t, store, hunts)
	return cfg, store
}

func fileHash(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// keyPaths lists every JSON key path of v, so a test can pin the shape of a document.
func keyPaths(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var x any
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	var walk func(p string, x any)
	walk = func(p string, x any) {
		switch c := x.(type) {
		case map[string]any:
			for k, e := range c {
				walk(p+"."+k, e)
			}
		case []any:
			set[p+"[]"] = true
			for _, e := range c {
				walk(p+"[]", e)
			}
		default:
			set[p] = true
		}
	}
	walk("", x)
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameKeys(t *testing.T, name string, v any, want string) {
	t.Helper()
	got := strings.Join(keyPaths(t, v), "\n")
	if got != strings.TrimSpace(want) {
		t.Errorf("%s: JSON keys changed.\ngot:\n%s\nwant:\n%s", name, got, strings.TrimSpace(want))
	}
}

func TestDBStatusCountsAndKeys(t *testing.T) {
	cfg, store := seedDB(t, dbHunts)
	before := fileHash(t, store)
	s, err := DBStatus(t.Context(), "", DBOptions{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != store || s.Events != 16 || s.Findings != 4 || s.FirstSeen == nil || s.LastSeen == nil || s.Schema != s.BuildSchema {
		t.Errorf("status = %+v", s)
	}
	sameKeys(t, "status", s, `
.build_schema_version
.events
.findings
.first_seen
.last_seen
.path
.reputation
.runs
.schema_version`)
	if fileHash(t, store) != before {
		t.Error("DBStatus changed the file")
	}
}

func TestDBUsageSeesDocumentsUnderTwoLabelsAndKeys(t *testing.T) {
	cfg, store := seedDB(t, []dbHunt{{"hunt-20261105T100000Z", 3, 2, "a"}, {"hunt-20261105T110000Z", 3, 1, "b"}})
	before := fileHash(t, store)
	u, err := DBUsage(t.Context(), "", DBOptions{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if u.Events != 6 || u.Overlap.Pairs != 1 || u.Overlap.Documents != 3 || !u.Complete() {
		t.Errorf("usage = events %d overlap %+v complete %v", u.Events, u.Overlap, u.Complete())
	}
	if fileHash(t, store) != before {
		t.Error("DBUsage changed the file")
	}
	sameKeys(t, "usage", u, `
.documents_under_two_labels.at_least
.documents_under_two_labels.documents
.documents_under_two_labels.label_pairs
.engine_free_bytes
.engine_used_bytes
.events
.events_without_doc_ident
.file_bytes
.findings
.kinds[]
.kinds[].events
.kinds[].fields_bytes
.kinds[].kind
.kinds[].newest
.kinds[].oldest
.kinds[].raw_bytes
.kinds[].runs
.kinds[].runs_events_pruned
.labels[]
.labels[].events
.labels[].fields_bytes
.labels[].label
.labels[].newest
.labels[].oldest
.labels[].raw_bytes
.labels[].runs
.path
.reputation
.run_records
.schema_version`)
}

func TestDBUsageIsNotCompleteWhenTheOverlapCheckDidNotRun(t *testing.T) {
	r := &DBUsageResult{Overlap: DBUsageOverlap{Error: "boom"}}
	if r.Complete() {
		t.Error("a usage report whose overlap check failed said it was complete")
	}
	if (*DBUsageResult)(nil).Complete() {
		t.Error("nil result complete")
	}
}

// Every function refuses a missing store, names the path, and does not create it.
func TestDBFunctionsNeverCreateAStore(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "absent.duckdb")
	cfg := filepath.Join(dir, "jb.yaml")
	y := fmt.Sprintf("sources:\n  - type: kibana\n    url: https://kibana.example.com\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-auth-*\ndetectors:\n  - type: authspike\n    key_field: client_ip\n    status_field: status\nstore:\n  path: %s\n", store)
	if err := os.WriteFile(cfg, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	calls := map[string]func() error{
		"status": func() error { _, err := DBStatus(ctx, "", DBOptions{Config: cfg}); return err },
		"usage":  func() error { _, err := DBUsage(ctx, "", DBOptions{Config: cfg}); return err },
		"prune": func() error {
			_, err := DBPrune(ctx, "", DBPruneOptions{Config: cfg, Kinds: []RunKind{RunKindHunt}, OlderThan: time.Hour, Apply: true})
			return err
		},
		"compact": func() error {
			_, err := DBCompact(ctx, "", DBCompactOptions{Config: cfg, To: filepath.Join(dir, "c.duckdb"), Apply: true})
			return err
		},
		"rename": func() error {
			_, err := DBRenameSource(ctx, "", DBRenameSourceOptions{Config: cfg, Old: "a", New: "b", Apply: true})
			return err
		},
	}
	for name, call := range calls {
		err := call()
		if err == nil || !strings.Contains(err.Error(), "no evidence database at") || IsUsage(err) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := os.Stat(store); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a store was created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "c.duckdb")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a compact target was created: %v", err)
	}
}

func TestDBPruneDryRunChangesNothingAndApplyDoes(t *testing.T) {
	cfg, store := seedDB(t, dbHunts)
	before := fileHash(t, store)
	opts := DBPruneOptions{Config: cfg, Kinds: []RunKind{RunKindHunt}, OlderThan: 7 * 24 * time.Hour, Now: func() time.Time { return dbNow }}
	plan, err := DBPrune(t.Context(), "", opts)
	if err != nil {
		t.Fatal(err)
	}
	// The two old hunts go; the recent one is the newest hunt of its kind and is kept.
	if plan.Applied || plan.Plan.Runs != 2 || plan.Plan.Events != 7 || plan.Store != store {
		t.Errorf("plan = %+v", plan)
	}
	if fileHash(t, store) != before {
		t.Fatal("a dry run changed the file")
	}
	sameKeys(t, "prune", plan, `
.applied
.by_run_id
.deleted.events
.deleted.fields_bytes
.deleted.findings
.deleted.raw_bytes
.deleted.run_records
.deleted.runs
.drop_findings
.keep_latest
.older_than_cutoff
.plan.events
.plan.fields_bytes
.plan.findings
.plan.raw_bytes
.plan.run_records
.plan.runs
.run_records_marked_pruned
.runs[]
.runs[].action
.runs[].created_at
.runs[].events
.runs[].fields_bytes
.runs[].findings
.runs[].id
.runs[].kind
.runs[].raw_bytes
.store`)

	opts.Apply = true
	done, err := DBPrune(t.Context(), "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if !done.Applied || done.Deleted.Events != 7 {
		t.Errorf("applied = %+v", done)
	}
	if fileHash(t, store) == before {
		t.Error("Apply left the file unchanged")
	}
}

func TestDBPruneByRunIDDryRunAndKeepLatestNil(t *testing.T) {
	cfg, store := seedDB(t, dbHunts)
	before := fileHash(t, store)
	byID, err := DBPrune(t.Context(), "", DBPruneOptions{Config: cfg, RunIDs: []string{"hunt-20261001T000000Z"}})
	if err != nil {
		t.Fatal(err)
	}
	if !byID.ByRunID || byID.Plan.Runs != 1 || byID.Applied {
		t.Errorf("by id = %+v", byID)
	}
	// KeepLatest nil keeps the newest hunt of the kind; a pointer to 0 keeps none.
	now := func() time.Time { return dbNow }
	one := DBPruneOptions{Config: cfg, Kinds: []RunKind{RunKindHunt}, OlderThan: time.Hour, Now: now}
	r1, err := DBPrune(t.Context(), "", one)
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	one.KeepLatest = &zero
	r0, err := DBPrune(t.Context(), "", one)
	if err != nil {
		t.Fatal(err)
	}
	if r1.KeepLatest != DefaultPruneKeepLatest || r0.KeepLatest != 0 || r0.Plan.Runs <= r1.Plan.Runs {
		t.Errorf("keep-latest: default %d (%d hunts), zero %d (%d hunts)", r1.KeepLatest, r1.Plan.Runs, r0.KeepLatest, r0.Plan.Runs)
	}
	if fileHash(t, store) != before {
		t.Error("a dry run changed the file")
	}
}

func TestDBPruneRefusesWhatTheCLIRefuses(t *testing.T) {
	cfg, store := seedDB(t, dbHunts)
	before := fileHash(t, store)
	neg := -1
	zero := 0
	ids := func(n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("hunt-20261001T0000%02dZ", i))
		}
		return out
	}
	rows := map[string]struct {
		o    DBPruneOptions
		want string
	}{
		"no selector":         {DBPruneOptions{}, "--kind is required"},
		"watch kind":          {DBPruneOptions{Kinds: []RunKind{"watch"}, OlderThan: time.Hour}, "jb watch --keep"},
		"wildcard":            {DBPruneOptions{Kinds: []RunKind{"all"}, OlderThan: time.Hour}, "no wildcard"},
		"unknown kind":        {DBPruneOptions{Kinds: []RunKind{"other"}, OlderThan: time.Hour}, "not a prunable"},
		"no age":              {DBPruneOptions{Kinds: []RunKind{RunKindHunt}}, "--older-than is required"},
		"negative age":        {DBPruneOptions{Kinds: []RunKind{RunKindHunt}, OlderThan: -time.Hour}, "positive"},
		"negative keep":       {DBPruneOptions{Kinds: []RunKind{RunKindHunt}, OlderThan: time.Hour, KeepLatest: &neg}, "--keep-latest"},
		"run with kind":       {DBPruneOptions{RunIDs: ids(1), Kinds: []RunKind{RunKindHunt}}, "cannot be combined with --kind"},
		"run with age":        {DBPruneOptions{RunIDs: ids(1), OlderThan: time.Hour}, "cannot be combined with --older-than"},
		"run with keep":       {DBPruneOptions{RunIDs: ids(1), KeepLatest: &zero}, "cannot be combined with --keep-latest"},
		"run watch id":        {DBPruneOptions{RunIDs: []string{"watch-20261001T000000Z"}}, "jb watch --keep"},
		"run wildcard":        {DBPruneOptions{RunIDs: []string{"hunt-*"}}, "no wildcard"},
		"too many run ids":    {DBPruneOptions{RunIDs: ids(MaxPruneRunIDs + 1)}, "at most"},
		"run id of one input": {DBPruneOptions{RunIDs: []string{"hunt-20261001T000000Z/ingress"}}, "not one source"},
	}
	for name, tc := range rows {
		tc.o.Config, tc.o.Apply = cfg, true
		_, err := DBPrune(t.Context(), "", tc.o)
		if !IsUsage(err) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v (usage %v), want %q", name, err, IsUsage(err), tc.want)
		}
	}
	if _, err := DBPrune(t.Context(), "", DBPruneOptions{Kinds: []RunKind{RunKindHunt}, OlderThan: time.Hour}); !IsUsage(err) {
		t.Errorf("no store selection: %v", err)
	}
	if fileHash(t, store) != before {
		t.Error("a refused prune changed the file")
	}
}

func TestDBCompactDryRunWritesNothingAndApplyWritesTheCopy(t *testing.T) {
	cfg, store := seedDB(t, dbHunts)
	target := filepath.Join(filepath.Dir(store), "compact.duckdb")
	before := fileHash(t, store)
	dry, err := DBCompact(t.Context(), "", DBCompactOptions{Config: cfg, To: target})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Applied || dry.Store != store || dry.Target != target {
		t.Errorf("dry = %+v", dry)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) || fileHash(t, store) != before {
		t.Fatalf("a dry run wrote %s or changed the store (%v)", target, err)
	}
	sameKeys(t, "compact", dry, `
.applied
.copy_rows
.engine_free_bytes
.engine_used_bytes
.estimated_copy_bytes
.schema_version
.source_file_bytes
.source_rows[]
.source_rows[].rows
.source_rows[].table
.target
.target_file_bytes`)
	done, err := DBCompact(t.Context(), "", DBCompactOptions{Config: cfg, To: target, Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if !done.Applied || len(done.Copy) != len(done.Source) {
		t.Errorf("applied = %+v", done)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("no copy: %v", err)
	}
	if fileHash(t, store) != before {
		t.Error("compact changed the original")
	}
}

func TestDBCompactTargetRules(t *testing.T) {
	cfg, store := seedDB(t, dbHunts)
	dir := filepath.Dir(store)
	ctx := t.Context()
	if _, err := DBCompact(ctx, "", DBCompactOptions{Config: cfg}); !IsUsage(err) {
		t.Errorf("no To: %v", err)
	}
	for name, tc := range map[string]struct{ to, want string }{
		"is the store":     {store, "already exists"},
		"missing dir":      {filepath.Join(dir, "nope", "c.duckdb"), "does not exist"},
		"outside evidence": {filepath.Join(t.TempDir(), "c.duckdb"), "outside the evidence directory"},
	} {
		_, err := DBCompact(ctx, "", DBCompactOptions{Config: cfg, To: tc.to, Apply: true})
		if err == nil || IsUsage(err) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	out := filepath.Join(t.TempDir(), "c.duckdb")
	if _, err := DBCompact(ctx, "", DBCompactOptions{Config: cfg, To: out, Apply: true, AllowOutsideEvidence: true}); err != nil {
		t.Errorf("allowed outside: %v", err)
	}
}

func TestDBRenameSource(t *testing.T) {
	cfg, store := seedDB(t, []dbHunt{{"hunt-20261105T100000Z", 3, 2, "a"}})
	before := fileHash(t, store)
	dry, err := DBRenameSource(t.Context(), "", DBRenameSourceOptions{Config: cfg, Old: "a", New: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Applied || dry.Events != 3 || dry.Relabelled != 3 || dry.Store != store {
		t.Errorf("dry = %+v", dry)
	}
	if fileHash(t, store) != before {
		t.Fatal("a dry run changed the file")
	}
	sameKeys(t, "rename", dry, `
.applied
.dropped
.events
.new
.new_events
.no_raw
.old
.overlap
.relabelled
.runs
.store`)
	done, err := DBRenameSource(t.Context(), "", DBRenameSourceOptions{Config: cfg, Old: "a", New: "b", Apply: true})
	if err != nil || !done.Applied || done.Relabelled != 3 {
		t.Fatalf("apply: %+v %v", done, err)
	}
	if fileHash(t, store) == before {
		t.Error("Apply left the file unchanged")
	}
	// Nothing is stored under "a" any more.
	gone, err := DBRenameSource(t.Context(), "", DBRenameSourceOptions{Config: cfg, Old: "a", New: "c"})
	if !errors.Is(err, ErrNoSuchSource) || gone == nil || IsUsage(err) {
		t.Errorf("missing source: %v %+v", err, gone)
	}
}

func TestDBRenameSourceRefusesAnOverlapUnlessMerged(t *testing.T) {
	cfg, store := seedDB(t, []dbHunt{{"hunt-20261105T100000Z", 3, 2, "a"}, {"hunt-20261105T110000Z", 3, 1, "b"}})
	before := fileHash(t, store)
	res, err := DBRenameSource(t.Context(), "", DBRenameSourceOptions{Config: cfg, Old: "a", New: "b", Apply: true})
	if !errors.Is(err, ErrSourceOverlap) || res == nil || res.Overlap != 3 || res.Applied {
		t.Fatalf("overlap: %v %+v", err, res)
	}
	if fileHash(t, store) != before {
		t.Error("a refused rename changed the file")
	}
	merged, err := DBRenameSource(t.Context(), "", DBRenameSourceOptions{Config: cfg, Old: "a", New: "b", Merge: true})
	if err != nil || merged.Dropped != 3 || merged.Applied {
		t.Errorf("merge dry run: %v %+v", err, merged)
	}
	if fileHash(t, store) != before {
		t.Error("a merge dry run changed the file")
	}
}

func TestDBRenameSourceUsageErrors(t *testing.T) {
	cfg, _ := seedDB(t, dbHunts)
	for name, o := range map[string]DBRenameSourceOptions{
		"no store":   {Old: "a", New: "b"},
		"bad old":    {Config: cfg, Old: "A B", New: "b"},
		"bad new":    {Config: cfg, Old: "a", New: "kibana:*"},
		"same label": {Config: cfg, Old: "a", New: "a"},
	} {
		if _, err := DBRenameSource(t.Context(), "", o); !IsUsage(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// With a case, the store is placed as `jb hunt --case` places it and the config is chosen
// for rename-source: examples/case lists two configs and only hunt.yaml declares it.
func TestDBFunctionsOnACase(t *testing.T) {
	dir := copyCase(t)
	store := filepath.Join(dir, "evidence", "jb.duckdb")
	seedDBAt(t, store, dbHunts)
	s, err := DBStatus(t.Context(), dir, DBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != store || s.Events != 16 {
		t.Errorf("status = %+v", s)
	}
	// compact: the evidence directory is the root, so a target there is accepted and one
	// outside is refused.
	if _, err := DBCompact(t.Context(), dir, DBCompactOptions{To: filepath.Join(t.TempDir(), "c.duckdb")}); err == nil || !strings.Contains(err.Error(), "outside the evidence directory") {
		t.Errorf("outside evidence: %v", err)
	}
	if _, err := DBCompact(t.Context(), dir, DBCompactOptions{To: filepath.Join(dir, "evidence", "c.duckdb")}); err != nil {
		t.Errorf("inside evidence: %v", err)
	}
	// A config the case does not allow is a usage error, as for the other case functions.
	if _, err := DBUsage(t.Context(), dir, DBOptions{Config: "../outside.yaml"}); !IsUsage(err) {
		t.Errorf("config outside the case: %v", err)
	}
}
