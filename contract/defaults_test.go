package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/jb"
)

// TestDocumentedConstants pins the numbers the doc comments and the README state.
func TestDocumentedConstants(t *testing.T) {
	for name, c := range map[string][2]time.Duration{
		"DefaultWindow":         {jb.DefaultWindow, time.Hour},
		"DefaultActivityWindow": {jb.DefaultActivityWindow, 24 * time.Hour},
		"DefaultWatchEvery":     {jb.DefaultWatchEvery, 5 * time.Minute},
		"MaxHistoricalWindow":   {jb.MaxHistoricalWindow, 31 * 24 * time.Hour},
		"DoctorReachTimeout":    {jb.DoctorReachTimeout, 4 * time.Second},
		"DoctorLockWait":        {jb.DoctorLockWait, 3 * time.Second},
		"EstateDefaultTimeout":  {jb.EstateDefaultTimeout, 10 * time.Second},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %s, want %s", name, c[0], c[1])
		}
	}
	for name, c := range map[string][2]int{
		"DefaultReputationRows":    {jb.DefaultReputationRows, 1000},
		"MaxReputationRows":        {jb.MaxReputationRows, 10000},
		"MaxReputationIndicators":  {jb.MaxReputationIndicators, 100},
		"DefaultPruneKeepLatest":   {jb.DefaultPruneKeepLatest, 1},
		"EstateDefaultMax":         {jb.EstateDefaultMax, 20},
		"EstateMax":                {jb.EstateMax, 100},
		"EstateExternalDefaultMax": {jb.EstateExternalDefaultMax, 10},
		"EstateExternalMax":        {jb.EstateExternalMax, 50},
		"EstateMaxNames":           {jb.EstateMaxNames, 2000},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %d, want %d", name, c[0], c[1])
		}
	}
	if jb.DefaultServeAddr != "127.0.0.1:8090" || jb.EstateDefaultFile != "estate.yaml" {
		t.Errorf("DefaultServeAddr = %q, EstateDefaultFile = %q", jb.DefaultServeAddr, jb.EstateDefaultFile)
	}
	// The status and verdict strings are what the JSON documents carry.
	if jb.StatusOK != "ok" || jb.StatusNoRecords != "no_records" || jb.StatusUnavailable != "unavailable" ||
		jb.StatusCanceled != "canceled" || jb.StatusError != "error" {
		t.Error("a component status string changed")
	}
	if jb.VerdictActive != "ACTIVE" || jb.VerdictQuiet != "QUIET" || jb.VerdictIncomplete != "INCOMPLETE" {
		t.Error("an activity verdict string changed")
	}
	// Severities are ordered, lowest first, and print as the JSON documents carry them.
	order := []jb.Severity{jb.SevInfo, jb.SevCheck, jb.SevActivity, jb.SevHigh, jb.SevCritical}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Errorf("severity %d is not above %d", order[i], order[i-1])
		}
	}
	// (How a severity prints in JSON is held by the hunt golden: "severity": "check".)
}

func TestZeroWindowsTakeTheDocumentedDefaults(t *testing.T) {
	k := newKibana(t, searchDocs())
	dir := exampleCase(t, k) // the case's windows.default is 1h

	res, err := jb.HuntCase(t.Context(), dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Env: env, Now: fixedNow, NoStore: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Window.To.Sub(res.Window.From); got != time.Hour {
		t.Errorf("HuntCase window = %s, want the case default 1h", got)
	}
	if !res.Baseline.To.Equal(res.Window.From) || res.Baseline.To.Sub(res.Baseline.From) != time.Hour {
		t.Errorf("the baseline is not the window of the same length right before: %v %v", res.Baseline, res.Window)
	}

	// A case that sets a longer default makes the zero window longer.
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 1h", "default: 3h")
	res, err = jb.HuntCase(t.Context(), dir, jb.CaseHuntOptions{Config: fpConfig, HuntOptions: jb.HuntOptions{Env: env, Now: fixedNow, NoStore: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Window.To.Sub(res.Window.From); got != 3*time.Hour {
		t.Errorf("HuntCase window = %s, want the case default 3h", got)
	}

	// Activity does not take the case's default: always 24 hours.
	act, err := jb.Activity(t.Context(), dir, jb.ActivityOptions{Config: fpConfig, Env: env, Now: fixedNow, NoStore: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := act.Window.To.Sub(act.Window.From); got != jb.DefaultActivityWindow {
		t.Errorf("Activity window = %s, want 24h", got)
	}

	// Hunt with no case: one hour, stored (NoStore false is the zero value).
	cfgPath := filepath.Join(t.TempDir(), "jb.yaml")
	body := "sources:\n  - type: kibana\n    url: " + k.srv.URL + "\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-http-*\n" +
		"detectors:\n  - type: authspike\n    key_field: client_ip\n    status_field: status\nstore:\n  path: " + filepath.Join(filepath.Dir(cfgPath), "jb.duckdb") + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := jb.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := jb.Hunt(t.Context(), cfg, jb.HuntOptions{Env: env, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if got := r2.Window.To.Sub(r2.Window.From); got != jb.DefaultWindow {
		t.Errorf("Hunt window = %s, want 1h", got)
	}
	if !r2.Stored {
		t.Error("the zero value of NoStore must store the run")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfgPath), "jb.duckdb")); err != nil {
		t.Errorf("a stored hunt left no store: %v", err)
	}
}

// treeDigest hashes every file under dir, so a test sees any byte a call changed.
func treeDigest(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	for p, h := range before {
		if after[p] != h {
			t.Errorf("%s changed %s", what, p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s created %s", what, p)
		}
	}
}

// The zero value of Apply is a dry run: the mutating functions change nothing, and the
// same call with Apply set does (so the check above is not vacuous).
func TestMutatingFunctionsAreDryRunsUnlessApplied(t *testing.T) {
	dir, _ := pinned(t)
	before := treeDigest(t, dir)

	keep := 0
	pr, err := jb.DBPrune(t.Context(), dir, jb.DBPruneOptions{Kinds: []jb.RunKind{jb.RunKindHunt}, OlderThan: time.Minute, KeepLatest: &keep, Now: func() time.Time { return time.Now().Add(48 * time.Hour) }})
	if err != nil || pr.Applied || pr.Plan.Events == 0 {
		t.Fatalf("prune dry run: %v %+v", err, pr)
	}
	to := filepath.Join(dir, "evidence", "compact.duckdb")
	if _, err := jb.DBCompact(t.Context(), dir, jb.DBCompactOptions{To: to}); err != nil {
		t.Fatal(err)
	}
	rr, err := jb.DBRenameSource(t.Context(), dir, jb.DBRenameSourceOptions{Old: "kibana:logs-http-*", New: "renamed"})
	if err != nil || rr.Applied || rr.Events == 0 {
		t.Fatalf("rename dry run: %v %+v", err, rr)
	}
	sameTree(t, "a dry run", before, treeDigest(t, dir))

	// Apply does it.
	rr, err = jb.DBRenameSource(t.Context(), dir, jb.DBRenameSourceOptions{Old: "kibana:logs-http-*", New: "renamed", Apply: true})
	if err != nil || !rr.Applied {
		t.Fatalf("rename: %v %+v", err, rr)
	}
	us, err := jb.DBUsage(t.Context(), dir, jb.DBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range us.Labels {
		found = found || l.Label == "renamed"
	}
	if !found {
		t.Errorf("Apply did not relabel the source: %+v", us.Labels)
	}
}

func TestEstateFactsImportIsADryRunUnlessApplied(t *testing.T) {
	dir := exampleCase(t, nil)
	const file = "example-estate.yaml"
	imp := filepath.Join(t.TempDir(), "export.json")
	body := `{"apiVersion":"jb.estate-facts/v1","method":"synthetic export","source_note":"synthetic","observed":"2026-11-05T08:00:00Z",
"facts":[{"node":"ip:192.0.2.10","key":"os","values":["linux"]}]}`
	if err := os.WriteFile(imp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before := treeDigest(t, dir)
	r, err := jb.EstateFactsImport(dir, imp, jb.EstateFactsImportOptions{EstateOptions: jb.EstateOptions{File: file}})
	if err != nil || r.Applied || r.Added != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	sameTree(t, "a dry run", before, treeDigest(t, dir))
	r, err = jb.EstateFactsImport(dir, imp, jb.EstateFactsImportOptions{EstateOptions: jb.EstateOptions{File: file}, Apply: true})
	if err != nil || !r.Applied {
		t.Fatalf("%v %+v", err, r)
	}
	if after := treeDigest(t, dir); after[filepath.Join(dir, "estate", file)] == before[filepath.Join(dir, "estate", file)] {
		t.Error("Apply did not write the estate file")
	}
}

// Read-only functions never create a store.
func TestReadOnlyFunctionsNeverCreateAStore(t *testing.T) {
	dir := exampleCase(t, nil)
	before := treeDigest(t, dir)
	if _, err := jb.DBStatus(t.Context(), dir, jb.DBOptions{}); err == nil {
		t.Error("DBStatus on a case with no store must say so")
	}
	if _, err := jb.DBUsage(t.Context(), dir, jb.DBOptions{}); err == nil {
		t.Error("DBUsage on a case with no store must say so")
	}
	if _, err := jb.Reputation(t.Context(), dir, jb.ReputationOptions{}); err == nil {
		t.Error("Reputation on a case with no store must say so")
	}
	if _, err := jb.CaseCheck(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := jb.CaseShow(dir, jb.CaseShowOptions{Config: "config/hunt.yaml"}); err != nil {
		t.Fatal(err)
	}
	if _, err := jb.Doctor(t.Context(), jb.DoctorOptions{Case: dir, Env: env}); err != nil {
		t.Fatal(err)
	}
	sameTree(t, "a read-only function", before, treeDigest(t, dir))
}
