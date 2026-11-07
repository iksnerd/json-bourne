package contract

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jb "github.com/iksnerd/json-bourne"
)

// pinned runs a hunt over the shipped example case so that the case holds a stored run,
// and returns the case and its fake Kibana.
func pinned(t *testing.T) (dir string, k *fakeKibana) {
	t.Helper()
	k = newKibana(t, searchDocs())
	dir = exampleCase(t, k)
	if _, err := jb.HuntCase(t.Context(), dir, huntOpts()); err != nil {
		t.Fatal(err)
	}
	return dir, k
}

func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Each result type that a CLI `--output json` document prints is marshalled and
// reduced to its skeleton (testdata/<name>.json). Renaming or removing a key, or
// turning an absent key into null, fails the test. Hunt and activity are compared
// byte for byte with the CLI goldens in shapes_cli_test.go.

func TestShapeCaseCheck(t *testing.T) {
	r, err := jb.CaseCheck(exampleCase(t, nil))
	pinShape(t, "case-check", must(t, r, err))
}

func TestShapeCaseShow(t *testing.T) {
	r, err := jb.CaseShow(exampleCase(t, nil), jb.CaseShowOptions{Config: "config/hunt.yaml"})
	pinShape(t, "case-show", must(t, r, err))
}

func TestShapeDoctor(t *testing.T) {
	r, err := jb.Doctor(t.Context(), jb.DoctorOptions{Case: exampleCase(t, nil), Env: env, Now: fixedNow, Version: "v0.0.0", Commit: "c", Date: "d"})
	pinShape(t, "doctor", must(t, r, err))
}

func TestShapeDBStatusUsageAndActorStatus(t *testing.T) {
	dir, _ := pinned(t)
	if _, err := jb.Activity(t.Context(), dir, jb.ActivityOptions{Config: fpConfig, Window: time.Hour, Env: env, Now: fixedNow}); err != nil {
		t.Fatal(err)
	}
	st, err := jb.DBStatus(t.Context(), dir, jb.DBOptions{})
	pinShape(t, "db-status", must(t, st, err))
	us, err := jb.DBUsage(t.Context(), dir, jb.DBOptions{})
	pinShape(t, "db-usage", must(t, us, err))
	as, err := jb.ActorStatus(t.Context(), dir, jb.ActorStatusOptions{Config: fpConfig})
	pinShape(t, "actor-status", must(t, as, err))
}

func TestShapeDBMaintenanceDryRuns(t *testing.T) {
	dir, _ := pinned(t)
	keep := 0
	pr, err := jb.DBPrune(t.Context(), dir, jb.DBPruneOptions{
		Kinds: []jb.RunKind{jb.RunKindHunt}, OlderThan: time.Minute, KeepLatest: &keep,
		Now: func() time.Time { return now.Add(48 * time.Hour) },
	})
	pinShape(t, "db-prune", must(t, pr, err))
	cr, err := jb.DBCompact(t.Context(), dir, jb.DBCompactOptions{To: filepath.Join(dir, "evidence", "compact.duckdb")})
	pinShape(t, "db-compact", must(t, cr, err))
	rr, err := jb.DBRenameSource(t.Context(), dir, jb.DBRenameSourceOptions{Old: "kibana:logs-http-*", New: "renamed"})
	pinShape(t, "db-rename-source", must(t, rr, err))
}

func TestShapeWatchCycleAndStatus(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k)
	rep, err := jb.Watch(t.Context(), dir, jb.WatchOptions{Once: true, Name: "t1", Config: fpConfig, Env: env, Now: fixedNow})
	pinShape(t, "watch-cycle", must(t, rep, err))
	ws, err := jb.WatchStatus(dir, jb.WatchStatusOptions{Now: fixedNow})
	pinShape(t, "watch-status", must(t, ws, err))
}

// intelCase adds a feed that answers from memory to the example case's hunt config.
func intelCase(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"192.0.2.7","noise":true,"riot":false,"classification":"malicious","last_seen":"2026-11-03"}`)
	}))
	t.Cleanup(srv.Close)
	dir := exampleCase(t, nil)
	p := filepath.Join(dir, "config", "hunt.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	add := fmt.Sprintf("\nfeeds:\n  - type: greynoise\n    base_url: %s\n    api_key_env: JB_GREYNOISE_API_KEY\n    min_interval: 0s\n", srv.URL)
	if err := os.WriteFile(p, append(b, []byte(add)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestShapeIntelAndReputation(t *testing.T) {
	dir := intelCase(t)
	res, err := jb.Intel(t.Context(), dir, []string{"192.0.2.7"}, jb.IntelOptions{Env: env, Config: "config/hunt.yaml"})
	pinShape(t, "intel", must(t, res, err))
	rep, err := jb.Reputation(t.Context(), dir, jb.ReputationOptions{Config: "config/hunt.yaml"})
	pinShape(t, "reputation", must(t, rep, err))
}

// A value built by hand, with every slice filled, pins keys that a quiet run leaves out.
func TestShapeIntelWithFailures(t *testing.T) {
	pinShape(t, "intel-failures", jb.IntelResult{
		Note: jb.IntelNote, Run: "hunt-x", Skipped: 1,
		Results:  []jb.IntelRow{{Indicator: "192.0.2.7", Feed: "f", Verdict: "v", Observed: "2026-11-05T12:00:00Z"}},
		Failures: []jb.IntelFailure{{Indicator: "192.0.2.50", Feed: "f", Error: "e"}},
	})
}

func TestShapeEstateResults(t *testing.T) {
	failure := []jb.EstateExternalFailure{{Target: "example.com", Lookup: "dns/A", Error: "e"}}
	pinShape(t, "estate-external", jb.EstateExternalResult{
		Note: jb.EstateExternalNote, Notes: []string{"n"}, Service: "dns", Asked: "a", File: "estate.yaml", Wrote: true,
		Targets: []string{"example.com"}, Added: jb.EstateAdded{Nodes: 1}, Unchanged: 1, Failures: failure, Conflicts: []string{"c"},
	})
	pinShape(t, "estate-ip", jb.EstateIPResult{
		Note: jb.EstateNote, File: "estate.yaml", Wrote: true, Addresses: 1, Added: jb.EstateAdded{Nodes: 1}, Unchanged: 1,
		Failures: []jb.EstateIPFailure{{IP: "192.0.2.10", Lookup: "rdns", Error: "e"}}, Conflicts: []string{"c"},
	})
	pinShape(t, "estate-refresh", jb.EstateRefreshResult{
		Note: jb.EstateExternalNote, Snapshot: "20261106T100000Z", File: "estate/snapshots/x.yaml", BasedOn: "estate.yaml",
		Nodes: 1, Edges: 1, Absences: 1, Services: []jb.EstateService{{}}, Failures: []jb.EstateSnapshotFailure{{}},
	})
	pinShape(t, "estate-promote", jb.EstatePromoteResult{Promoted: "20261106T100000Z", Baseline: "estate.yaml", Archived: "a"})
}

func TestShapeEstateDiffAndFactsImport(t *testing.T) {
	dir := exampleCase(t, nil)
	const file = "example-estate.yaml"
	d, err := jb.EstateDiff(t.Context(), dir, jb.EstateDiffOptions{EstateOptions: jb.EstateOptions{File: file, Now: fixedNow}, From: file, To: file})
	pinShape(t, "estate-diff", must(t, d, err))

	imp := filepath.Join(t.TempDir(), "export.json")
	body := `{"apiVersion":"jb.estate-facts/v1","method":"synthetic export","source_note":"synthetic","observed":"2026-11-05T08:00:00Z",
"facts":[{"node":"ip:192.0.2.10","key":"os","values":["linux"]}]}`
	if err := os.WriteFile(imp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := jb.EstateFactsImport(dir, imp, jb.EstateFactsImportOptions{EstateOptions: jb.EstateOptions{File: file, Now: fixedNow}})
	pinShape(t, "estate-facts-import", must(t, r, err))
}
