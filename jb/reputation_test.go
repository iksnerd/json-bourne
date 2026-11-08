package jb

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

var repT0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func repRow(ind, verdict, src string, ageMin int) core.Reputation {
	return core.Reputation{Indicator: ind, Verdict: verdict, Source: src, Observed: repT0.Add(-time.Duration(ageMin) * time.Minute)}
}

// repRows: three addresses, two feeds, several snapshots of 192.0.2.1.
var repRows = []core.Reputation{
	repRow("192.0.2.2", "benign", "greynoise", 10),
	repRow("192.0.2.1", "malicious", "greynoise", 5),
	repRow("192.0.2.1", "benign", "greynoise", 60),
	repRow("192.0.2.1", "listed", "dnsbl:zen.example.com", 30),
	repRow("198.51.100.9", "not_found", "greynoise", 120),
}

func appendRep(t *testing.T, path string, rows []core.Reputation) {
	t.Helper()
	st, err := duckdb.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendReputation(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
}

func repConfig(t *testing.T, rows []core.Reputation) (cfg, store string) {
	t.Helper()
	cfg, store = seedDB(t, nil)
	appendRep(t, store, rows)
	return cfg, store
}

func TestReputationOrderAndFields(t *testing.T) {
	cfg, store := repConfig(t, repRows)
	before := fileHash(t, store)
	r, err := Reputation(t.Context(), "", ReputationOptions{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if r.Path != store || !r.Complete() || r.Truncated || len(r.Rows) != 5 {
		t.Fatalf("result = %+v", r)
	}
	var got []string
	for _, x := range r.Rows {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s", x.Indicator, x.Source, x.Verdict, x.Observed))
	}
	want := []string{
		"192.0.2.1|greynoise|malicious|2026-11-05T11:55:00Z",
		"192.0.2.1|dnsbl:zen.example.com|listed|2026-11-05T11:30:00Z",
		"192.0.2.1|greynoise|benign|2026-11-05T11:00:00Z",
		"192.0.2.2|greynoise|benign|2026-11-05T11:50:00Z",
		"198.51.100.9|greynoise|not_found|2026-11-05T10:00:00Z",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	sameKeys(t, "reputation", r, `
.complete
.limit
.note
.path
.rows[]
.rows[].indicator
.rows[].observed
.rows[].source
.rows[].verdict
.truncated`)
	if fileHash(t, store) != before {
		t.Error("Reputation changed the file")
	}
}

func TestReputationFilters(t *testing.T) {
	cfg, _ := repConfig(t, repRows)
	ctx := t.Context()
	count := func(o ReputationOptions) int {
		o.Config = cfg
		r, err := Reputation(ctx, "", o)
		if err != nil {
			t.Fatal(err)
		}
		return len(r.Rows)
	}
	if n := count(ReputationOptions{Indicators: []string{"192.0.2.1"}}); n != 3 {
		t.Errorf("indicator: %d", n)
	}
	if n := count(ReputationOptions{Indicators: []string{" 192.0.2.2 ", "198.51.100.9", "192.0.2.2"}}); n != 2 {
		t.Errorf("two indicators: %d", n)
	}
	if n := count(ReputationOptions{Source: "dnsbl:zen.example.com"}); n != 1 {
		t.Errorf("source: %d", n)
	}
	if n := count(ReputationOptions{Since: repT0.Add(-30 * time.Minute)}); n != 3 { // 5, 10, 30 min old: inclusive
		t.Errorf("since: %d", n)
	}
	if n := count(ReputationOptions{Until: repT0.Add(-30 * time.Minute)}); n != 2 { // 60, 120 min old: exclusive
		t.Errorf("until: %d", n)
	}
	if n := count(ReputationOptions{Since: repT0.Add(-60 * time.Minute), Until: repT0.Add(-10 * time.Minute)}); n != 2 { // 60, 30
		t.Errorf("window: %d", n)
	}
	if n := count(ReputationOptions{Indicators: []string{"192.0.2.77"}}); n != 0 {
		t.Errorf("unknown indicator: %d", n)
	}
}

func TestReputationLatestIsNewestPerIndicatorAndFeed(t *testing.T) {
	cfg, _ := repConfig(t, repRows)
	r, err := Reputation(t.Context(), "", ReputationOptions{Config: cfg, Latest: true})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range r.Rows {
		got = append(got, x.Indicator+"|"+x.Source+"|"+x.Verdict)
	}
	want := "192.0.2.1|greynoise|malicious,192.0.2.1|dnsbl:zen.example.com|listed,192.0.2.2|greynoise|benign,198.51.100.9|greynoise|not_found"
	if strings.Join(got, ",") != want {
		t.Errorf("latest = %v", got)
	}
	r, err = Reputation(t.Context(), "", ReputationOptions{Config: cfg, Latest: true, Since: repT0.Add(-20 * time.Minute)})
	if err != nil || len(r.Rows) != 2 {
		t.Errorf("latest since: %v %+v", err, r)
	}
}

func TestReputationCapAndTruncated(t *testing.T) {
	var rows []core.Reputation
	for i := 0; i < 12; i++ {
		rows = append(rows, repRow(fmt.Sprintf("192.0.2.%d", i+1), "benign", "greynoise", i))
	}
	cfg, _ := repConfig(t, rows)
	ctx := t.Context()
	r, err := Reputation(ctx, "", ReputationOptions{Config: cfg, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 5 || !r.Truncated || r.Complete() || r.Limit != 5 {
		t.Errorf("cut: rows=%d truncated=%v complete=%v limit=%d", len(r.Rows), r.Truncated, r.Complete(), r.Limit)
	}
	var m map[string]any
	b, _ := json.Marshal(r)
	_ = json.Unmarshal(b, &m)
	if m["truncated"] != true || m["complete"] != false {
		t.Errorf("json = %s", b)
	}
	// Exactly at the cap is complete.
	r, _ = Reputation(ctx, "", ReputationOptions{Config: cfg, Limit: 12})
	if len(r.Rows) != 12 || r.Truncated || !r.Complete() {
		t.Errorf("at cap: rows=%d truncated=%v", len(r.Rows), r.Truncated)
	}
	r, _ = Reputation(ctx, "", ReputationOptions{Config: cfg})
	if r.Limit != 1000 {
		t.Errorf("default limit %d", r.Limit)
	}
	r, _ = Reputation(ctx, "", ReputationOptions{Config: cfg, Limit: MaxReputationRows})
	if r.Limit != 10000 {
		t.Errorf("max limit %d", r.Limit)
	}
}

func TestReputationUsageErrors(t *testing.T) {
	cfg, _ := repConfig(t, repRows)
	many := make([]string, 101)
	for i := range many {
		many[i] = fmt.Sprintf("192.0.2.%d", i%250)
	}
	cases := map[string]ReputationOptions{
		"not an ip":      {Config: cfg, Indicators: []string{"example.com"}},
		"empty ip":       {Config: cfg, Indicators: []string{""}},
		"101 indicators": {Config: cfg, Indicators: many},
		"negative limit": {Config: cfg, Limit: -1},
		"over max":       {Config: cfg, Limit: MaxReputationRows + 1},
		"since > until":  {Config: cfg, Since: repT0, Until: repT0.Add(-time.Hour)},
		"no config":      {},
	}
	for name, o := range cases {
		if _, err := Reputation(t.Context(), "", o); !IsUsage(err) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Reputation(t.Context(), "", ReputationOptions{Config: cfg, Indicators: many[:100]}); err != nil {
		t.Errorf("100 indicators: %v", err)
	}
}

// "When did this address change verdict": the observations of one address come back
// newest first, and Latest with Until gives the verdict as of that time.
func TestReputationShowsAVerdictChangeInOrder(t *testing.T) {
	cfg, _ := repConfig(t, []core.Reputation{
		repRow("192.0.2.5", "benign", "greynoise", 120),
		repRow("192.0.2.5", "malicious", "greynoise", 30),
		repRow("192.0.2.6", "benign", "greynoise", 30),
	})
	ind := []string{"192.0.2.5"}
	r, err := Reputation(t.Context(), "", ReputationOptions{Config: cfg, Indicators: ind})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 2 || r.Rows[0].Verdict != "malicious" || r.Rows[1].Verdict != "benign" || r.Rows[0].Observed <= r.Rows[1].Observed {
		t.Errorf("rows = %+v", r.Rows)
	}
	r, err = Reputation(t.Context(), "", ReputationOptions{Config: cfg, Indicators: ind, Latest: true, Until: repT0.Add(-time.Hour)})
	if err != nil || len(r.Rows) != 1 || r.Rows[0].Verdict != "benign" {
		t.Errorf("as of an hour ago: %v %+v", err, r)
	}
	r, _ = Reputation(t.Context(), "", ReputationOptions{Config: cfg, Indicators: ind, Latest: true, Since: repT0.Add(-3 * time.Hour), Until: repT0})
	if len(r.Rows) != 1 || r.Rows[0].Verdict != "malicious" {
		t.Errorf("latest in a window: %+v", r.Rows)
	}
}

func TestReputationNeverCreatesAStore(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "absent.duckdb")
	cfg := filepath.Join(dir, "jb.yaml")
	y := fmt.Sprintf("sources:\n  - type: kibana\n    url: https://kibana.example.com\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-auth-*\ndetectors:\n  - type: authspike\n    key_field: client_ip\n    status_field: status\nstore:\n  path: %s\n", store)
	if err := os.WriteFile(cfg, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Reputation(t.Context(), "", ReputationOptions{Config: cfg})
	if r != nil || err == nil || !strings.Contains(err.Error(), "no evidence database at") {
		t.Errorf("r=%v err=%v", r, err)
	}
	if _, err := os.Stat(store); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a store was created: %v", err)
	}
}

func TestReputationOnACaseUsesTheIntelConfig(t *testing.T) {
	dir := copyCase(t)
	store := filepath.Join(dir, "evidence", "jb.duckdb")
	appendRep(t, store, repRows)
	r, err := Reputation(t.Context(), dir, ReputationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Path != store || len(r.Rows) != 5 {
		t.Errorf("result = %+v", r)
	}
	if _, err := Reputation(t.Context(), dir, ReputationOptions{Config: "../outside.yaml"}); !IsUsage(err) {
		t.Errorf("config outside the case: %v", err)
	}
}

// TestRepHolderProcess is the child half of the lock test: it holds the store read-write.
func TestRepHolderProcess(t *testing.T) {
	path := os.Getenv("JB_TEST_REP_HOLD")
	if path == "" {
		t.Skip("child helper")
	}
	st, err := duckdb.Open(path, false)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	fmt.Println("HELD")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	st.Close()
	os.Exit(0)
}

// A writer process holding the store read-write is waited for, then refused with the
// holder named: the read does not fight for the lock, and does not create or change
// anything.
func TestReputationWhileAWriterProcessHoldsTheStore(t *testing.T) {
	cfg, store := repConfig(t, repRows)
	cmd := exec.Command(os.Args[0], "-test.run=^TestRepHolderProcess$")
	cmd.Env = append(os.Environ(), "JB_TEST_REP_HOLD="+store)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	if line, _ := bufio.NewReader(out).ReadString('\n'); strings.TrimSpace(line) != "HELD" {
		t.Fatalf("holder said %q", line)
	}
	t.Setenv(duckdb.EnvLockWait, "0")
	r, err := Reputation(t.Context(), "", ReputationOptions{Config: cfg})
	if r != nil || err == nil || !strings.Contains(err.Error(), "another process") {
		t.Errorf("held: r=%v err=%v", r, err)
	}
	// Once the writer lets go, the rows are all there.
	in.Close()
	_ = cmd.Wait()
	r, err = Reputation(t.Context(), "", ReputationOptions{Config: cfg})
	if err != nil || len(r.Rows) != 5 {
		t.Errorf("after release: %v %+v", err, r)
	}
}
