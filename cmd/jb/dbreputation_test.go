package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/jb"
)

func seedRepCLI(t *testing.T, n int) (cfg, store string) {
	t.Helper()
	cfg, store = seedMaint(t, nil)
	st, err := duckdb.Open(store, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var rows []core.Reputation
	for i := 0; i < n; i++ {
		rows = append(rows, core.Reputation{Indicator: fmt.Sprintf("192.0.2.%d", i+10), Verdict: "benign",
			Observed: fixedNow.Add(-time.Duration(i) * time.Minute), Source: "greynoise"})
	}
	rows = append(rows, core.Reputation{Indicator: "192.0.2.10", Verdict: "malicious", Observed: fixedNow.Add(-time.Hour), Source: "greynoise"})
	if err := st.AppendReputation(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	return cfg, store
}

// The JSON the CLI prints is the library value, marshalled: one code path.
func TestDBReputationJSONIsTheLibraryValue(t *testing.T) {
	cfg, _ := seedRepCLI(t, 3)
	args := []string{"db", "reputation", "--config", cfg, "--indicator", "192.0.2.10", "--since", "2026-01-01", "--output", "json"}
	code, out, errs := run(t, testDeps(nil), args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	lib, err := jb.Reputation(t.Context(), "", jb.ReputationOptions{Config: cfg, Indicators: []string{"192.0.2.10"},
		Since: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(lib)
	var a, b bytes.Buffer
	if err := json.Compact(&a, []byte(out)); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	_ = json.Compact(&b, want)
	if a.String() != b.String() {
		t.Errorf("CLI\n%s\nlibrary\n%s", a.String(), b.String())
	}
	var got struct {
		Rows []map[string]string `json:"rows"`
	}
	_ = json.Unmarshal([]byte(out), &got)
	if len(got.Rows) != 2 || got.Rows[0]["verdict"] != "benign" || got.Rows[1]["verdict"] != "malicious" || len(got.Rows[0]) != 4 {
		t.Errorf("rows = %+v", got.Rows)
	}
}

func TestDBReputationTableUntilAndLatest(t *testing.T) {
	cfg, _ := seedRepCLI(t, 3)
	code, out, errs := run(t, testDeps(nil), "db", "reputation", "--config", cfg, "--latest", "--until", fixedNow.Add(-90*time.Second).Format(time.RFC3339))
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{"INDICATOR", "SOURCE", "192.0.2.12", "greynoise", "context, not attribution"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "192.0.2.11") {
		t.Errorf("--until is exclusive of newer rows:\n%s", out)
	}
}

func TestDBReputationTruncatedExitsOneAndUsageErrorsExitTwo(t *testing.T) {
	cfg, _ := seedRepCLI(t, 5)
	code, out, errs := run(t, testDeps(nil), "db", "reputation", "--config", cfg, "--limit", "2", "--output", "json")
	if code != 1 || !strings.Contains(errs, "INCOMPLETE") || !strings.Contains(out, `"truncated": true`) {
		t.Errorf("cut: exit %d\n%s\n%s", code, out, errs)
	}
	for name, args := range map[string][]string{
		"no store flag": {"db", "reputation"},
		"bad ip":        {"db", "reputation", "--config", cfg, "--indicator", "example.com"},
		"bad since":     {"db", "reputation", "--config", cfg, "--since", "yesterday"},
		"bad until":     {"db", "reputation", "--config", cfg, "--until", "soon"},
		"bad limit":     {"db", "reputation", "--config", cfg, "--limit", "10001"},
		"since>until":   {"db", "reputation", "--config", cfg, "--since", "2026-12-01", "--until", "2026-01-01"},
		"bad output":    {"db", "reputation", "--config", cfg, "--output", "xml"},
	} {
		if code, _, errs := run(t, testDeps(nil), args...); code != 2 {
			t.Errorf("%s: exit %d\n%s", name, code, errs)
		}
	}
}

func TestDBReputationMissingStoreIsNotCreated(t *testing.T) {
	cfg := writeConfig(t, "https://kibana.example.com")
	code, _, errs := run(t, testDeps(nil), "db", "reputation", "--config", cfg)
	if code == 0 || !strings.Contains(errs, "no evidence database at") {
		t.Errorf("exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(strings.TrimSuffix(cfg, ".yaml") + ".duckdb"); err == nil {
		t.Error("a store was created")
	}
}

func TestDBReputationHeldStoreIsRefusedWithTheHolder(t *testing.T) {
	cfg, store := seedRepCLI(t, 2)
	holdStore(t, store)
	t.Setenv(duckdb.EnvLockWait, "0")
	code, _, errs := run(t, testDeps(nil), "db", "reputation", "--config", cfg)
	if code != 1 || !strings.Contains(errs, "another process") {
		t.Errorf("exit %d\n%s", code, errs)
	}
}
