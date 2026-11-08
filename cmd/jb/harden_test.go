package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

// nginxKibana serves `good` parseable nginx access lines and `bad` documents the
// nginx_ingress mapper refuses, all inside the hour before fixedNow.
func nginxKibana(t *testing.T, good, bad int) *httptest.Server {
	t.Helper()
	var hits []map[string]any
	add := func(i int, msg string) {
		at := fixedNow.Add(-time.Duration(i+1) * time.Second)
		hits = append(hits, map[string]any{
			"_id": fmt.Sprintf("n%d", i), "sort": []any{at.UnixMilli(), fmt.Sprint(i)},
			"_source": map[string]any{"@timestamp": at.Format(time.RFC3339Nano), "message": msg},
		})
	}
	line := `192.0.2.10 - - [05/Nov/2026:11:59:00 +0000] "GET /home HTTP/1.1" 200 52 "-" "ExampleAgent/1.0" 310 0.004 [example-svc-80] [] 10.0.0.5:8080 52 0.004 200 req%04d`
	for i := range good {
		add(i, fmt.Sprintf(line, i))
	}
	for i := range bad {
		add(good+i, "not an access line")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{
			"hits": map[string]any{"total": map[string]any{"value": len(hits)}, "hits": hits},
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func nginxConfig(t *testing.T, url string) string {
	t.Helper()
	cfg := writeConfig(t, url)
	editFile(t, cfg, "index: logs-auth-*", "index: logs-auth-*\n    mapper: nginx_ingress")
	return cfg
}

func TestHuntShowsUnparsableDocuments(t *testing.T) {
	d := testDeps(huntEnv)
	for name, tc := range map[string]struct {
		good, bad int
		want      []string
		not       []string
	}{
		"all parsed":        {good: 30, bad: 0, not: []string{"UNPARSABLE"}},
		"a few unparsable":  {good: 95, bad: 5, want: []string{"UNPARSABLE: kibana:logs-auth-* received 5 document(s)", "5.0% of 100"}, not: []string{"HIGH"}},
		"mostly unparsable": {good: 25, bad: 75, want: []string{"received 75 document(s)", "75.0% of 100", "HIGH UNPARSABLE SHARE"}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := nginxConfig(t, nginxKibana(t, tc.good, tc.bad).URL)
			code, stdout, stderr := run(t, d, "hunt", "--config", cfg)
			if code != 0 {
				t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			for _, w := range tc.not {
				if strings.Contains(stdout, w) {
					t.Errorf("stdout has %q:\n%s", w, stdout)
				}
			}
			// The same facts are in the JSON output.
			_, js, _ := run(t, d, "hunt", "--config", cfg, "--output", "json")
			var got struct {
				Sources []struct {
					Unparsable     *int `json:"unparsable"`
					HighUnparsable bool `json:"high_unparsable"`
				} `json:"sources"`
			}
			if err := json.Unmarshal([]byte(js), &got); err != nil {
				t.Fatal(err)
			}
			if tc.bad == 0 && got.Sources[0].Unparsable != nil {
				t.Errorf("json reports unparsable for a clean source: %s", js)
			}
			if tc.bad > 0 && (got.Sources[0].Unparsable == nil || *got.Sources[0].Unparsable != tc.bad) {
				t.Errorf("json unparsable = %v, want %d", got.Sources[0].Unparsable, tc.bad)
			}
			if got.Sources[0].HighUnparsable != (tc.bad == 75) {
				t.Errorf("json high_unparsable = %t", got.Sources[0].HighUnparsable)
			}
		})
	}
}

// A window of nothing but garbage already fails the source; the count must still show.
func TestHuntAllUnparsableStillShowsTheCount(t *testing.T) {
	cfg := nginxConfig(t, nginxKibana(t, 0, 12).URL)
	code, stdout, _ := run(t, testDeps(huntEnv), "hunt", "--config", cfg)
	if code != exitFailure || !strings.Contains(stdout, "received 12 document(s)") || !strings.Contains(stdout, "HIGH UNPARSABLE SHARE") {
		t.Errorf("exit %d\n%s", code, stdout)
	}
}

func TestWatchCycleLineShowsUnparsableDocuments(t *testing.T) {
	dir := copyExampleCase(t, nginxKibana(t, 25, 75).URL)
	gitInit(t, dir)
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	editFile(t, filepath.Join(dir, "config", "hunt.yaml"), "index: logs-auth-*", "index: logs-auth-*\n    mapper: nginx_ingress")
	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once")
	if code != 0 {
		t.Fatalf("exit %d: unparsable documents are reported, they do not fail the cycle\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "75 unparsable document(s), 75.0%") || !strings.Contains(stdout, "HIGH") {
		t.Errorf("cycle line:\n%s", stdout)
	}
	if !strings.Contains(readEvidence(t, dir, "watch.log"), "75 unparsable") {
		t.Error("the watch log does not carry it")
	}
}

// ---- retention through the command ----

func seedWatchRun(t *testing.T, st *duckdb.Store, id string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	ev := core.Event{Time: fixedNow.Add(-age), Source: "s", Kind: "k", Fields: map[string]any{"n": float64(1)}}
	if err := st.SaveEvents(ctx, id+"/s", seqOf([]core.Event{ev})); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveFindings(ctx, id, []core.Finding{{Detector: "d", Tag: "t", Summary: "s"}}); err != nil {
		t.Fatal(err)
	}
}

func TestWatchPrunesOldWatchRunsAndReportsIt(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "evidence", "jb.duckdb")
	st, err := duckdb.Open(dbPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	seedWatchRun(t, st, "watch-20261101T000000Z", 0)
	seedWatchRun(t, st, "watch-20261101T010000Z", 0)
	seedWatchRun(t, st, "hunt-20261101T000000Z", 0) // not a watch run
	st.Close()
	age(t, dbPath, "watch-20261101T000000Z", 100*time.Hour)
	age(t, dbPath, "watch-20261101T010000Z", 99*time.Hour)
	age(t, dbPath, "hunt-20261101T000000Z", 900*time.Hour)

	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--keep", "48h")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "pruned 4 run(s), 2 event(s), 2 finding(s) older than 48h0m0s") {
		t.Errorf("the cycle line does not report what was pruned:\n%s", stdout)
	}
	ro, err := duckdb.Open(dbPath, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ro.Stats()
	ro.Close() // DuckDB refuses a second handle with another access mode
	if err != nil {
		t.Fatal(err)
	}
	// Left: the hunt run (1 event, 1 finding) and the cycle that just ran (150 events).
	if s.Findings < 2 || s.Events < 151 {
		t.Errorf("store after the prune: %+v", s)
	}
	for _, id := range []string{"watch-20261101T000000Z", "watch-20261101T010000Z"} {
		if n := countRuns(t, dbPath, id); n != 0 {
			t.Errorf("%s survived the prune (%d run records)", id, n)
		}
	}
	if n := countRuns(t, dbPath, "hunt-20261101T000000Z"); n != 2 {
		t.Errorf("a non-watch run was touched: %d run records, want 2", n)
	}
}

func TestWatchKeepFlagIsValidated(t *testing.T) {
	dir, served := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	for name, args := range map[string][]string{
		"zero keep":     {"watch", "--case", dir, "--once", "--keep", "0s"},
		"keep below 2x": {"watch", "--case", dir, "--once", "--keep", "90m"},
		"zero repeat":   {"watch", "--case", dir, "--once", "--repeat", "0s"},
		"negative keep": {"watch", "--case", dir, "--once", "--keep", "-5h"},
		"bad keep":      {"watch", "--case", dir, "--once", "--keep", "soon"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, stderr := run(t, d, args...); code != exitUsage {
				t.Errorf("exit %d, want 2: %s", code, stderr)
			}
		})
	}
	if served() != 0 {
		t.Errorf("a refused watch reached the source (%d requests)", served())
	}
	// A long window lifts the default keep instead of refusing it.
	if code, _, stderr := run(t, d, "watch", "--case", dir, "--once", "--every", "1h", "--window", "36h"); code == exitUsage {
		t.Errorf("the default keep was not raised for a 36h window: %s", stderr)
	}
}

// ---- outage alerts through the command ----

func TestWatchRepeatedOutageIsHeldBackButStillFailsTheCycle(t *testing.T) {
	dir, _ := watchCase(t, http.StatusBadGateway)
	d := testDeps(huntEnv)
	at := func(m int) { d.now = func() time.Time { return fixedNow.Add(time.Duration(m) * time.Minute) } }

	at(0)
	code, stdout, _ := run(t, d, "watch", "--case", dir, "--once")
	if code != exitFailure || strings.Count(stdout, "[c:watch-incomplete]") != 2 {
		t.Fatalf("first cycle: exit %d\n%s", code, stdout)
	}
	at(5)
	code, stdout, stderr := run(t, d, "watch", "--case", dir, "--once")
	if code != exitFailure {
		t.Fatalf("a held-back alert changed the exit code to %d, want 1", code)
	}
	if strings.Contains(stdout, "[c:watch-incomplete]") {
		t.Errorf("an identical outage alerted again after 5 minutes:\n%s", stdout)
	}
	if !strings.Contains(stdout, "CYCLE INCOMPLETE") || !strings.Contains(stdout, "still down") || !strings.Contains(stderr, "no clean result") {
		t.Errorf("the repeated cycle is not reported as failed:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
	at(31)
	if _, stdout, _ = run(t, d, "watch", "--case", dir, "--once"); strings.Count(stdout, "[c:watch-incomplete]") != 2 {
		t.Errorf("no repeat after 30 minutes:\n%s", stdout)
	}
	at(33)
	if _, stdout, _ = run(t, d, "watch", "--case", dir, "--once", "--repeat", "1m"); strings.Count(stdout, "[c:watch-incomplete]") != 2 {
		t.Errorf("--repeat 1m did not re-alert after 2 minutes:\n%s", stdout)
	}
	// The log is the record: three rounds of two alerts (source and detector), not four rounds.
	if n := strings.Count(readEvidence(t, dir, "watch.log"), "[c:watch-incomplete]"); n != 6 {
		t.Errorf("log holds %d outage alerts, want 6", n)
	}
	if !strings.Contains(readEvidence(t, dir, "watch-state.json"), `"health"`) {
		t.Error("the outage is not remembered in the state file, so a restart would repeat it")
	}
}

// rawDB opens the store file with the driver directly, the way a test may and a command
// may not, to age runs and count rows. The duckdb adapter registers the driver.
func rawDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", dbPath+"?access_mode=READ_WRITE")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// age makes a hunt look `by` old: both its findings run and its source run.
func age(t *testing.T, dbPath, id string, by time.Duration) {
	t.Helper()
	db := rawDB(t, dbPath)
	defer db.Close()
	if _, err := db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = ? OR starts_with(run_id, ?)`,
		fixedNow.Add(-by).Format(time.RFC3339), id, id+"/"); err != nil {
		t.Fatal(err)
	}
}

func countRuns(t *testing.T, dbPath, id string) int {
	t.Helper()
	db := rawDB(t, dbPath)
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM runs WHERE run_id = ? OR starts_with(run_id, ?)`, id, id+"/").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
