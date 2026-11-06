package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/config"
)

const secretKey = "s3cr3t-value-0123456789"

var fixedNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func testDeps(env map[string]string) deps {
	return deps{
		env: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		now: func() time.Time { return fixedNow },
	}
}

func run(t *testing.T, d deps, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = executeWith(context.Background(), d, args, &out, &errb)
	return code, out.String(), errb.String()
}

// fakeKibana serves synthetic auth events: 192.0.2.7 fails 40 of 50 requests in the
// current hour and 0 of 50 in the hour before; 192.0.2.99 never fails. status is the HTTP status the server
// answers with.
func fakeKibana(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv, _ := fakeKibanaCounted(t, status)
	return srv
}

// fakeKibanaCounted is fakeKibana plus the number of requests it has served, so a
// test can prove that a refused hunt never reached the network.
func fakeKibanaCounted(t *testing.T, status int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var served atomic.Int64
	type src = map[string]any
	var hits []map[string]any
	add := func(at time.Time, ip string, i, st int) {
		hits = append(hits, map[string]any{
			"_id": fmt.Sprintf("d%d-%s-%d", at.Unix(), ip, i), "sort": []any{at.UnixMilli(), fmt.Sprint(i)},
			"_source": src{"@timestamp": at.Format(time.RFC3339Nano), "client_ip": ip, "status": st, "path": "/token"},
		})
	}
	for i := range 50 {
		prev := fixedNow.Add(-2 * time.Hour).Add(time.Duration(i+1) * time.Minute)
		cur := fixedNow.Add(-time.Hour).Add(time.Duration(i+1) * time.Minute)
		st := 401
		if i >= 40 {
			st = 200
		}
		add(prev, "192.0.2.7", i, 200)
		add(cur, "192.0.2.7", i, st)
		// A healthy neighbour: the detector must see a key failing more than its population.
		add(prev, "192.0.2.99", i, 200)
		add(cur, "192.0.2.99", i, 200)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		if status != http.StatusOK {
			http.Error(w, "boom", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{
			"hits": map[string]any{"total": map[string]any{"value": len(hits)}, "hits": hits},
		}})
	}))
	t.Cleanup(srv.Close)
	return srv, &served
}

func writeConfig(t *testing.T, url string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "jb.yaml")
	y := fmt.Sprintf(`sources:
  - type: kibana
    url: %s
    api_key_env: JB_KIBANA_API_KEY
    index: logs-auth-*
detectors:
  - type: authspike
    key_field: client_ip
    status_field: status
store:
  path: %s
`, url, filepath.Join(dir, "jb.duckdb"))
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFlagsExist(t *testing.T) {
	hunt := newHuntCmd()
	for _, f := range []string{"config", "window", "output"} {
		if hunt.Flags().Lookup(f) == nil {
			t.Errorf("hunt has no --%s", f)
		}
	}
	if got := hunt.Flags().Lookup("window").DefValue; got != "1h0m0s" {
		t.Errorf("default window = %s", got)
	}
	root := newRootCmd()
	if !root.SilenceUsage || !root.SilenceErrors {
		t.Error("root must silence usage and errors; Execute prints once")
	}
	for _, path := range [][]string{{"hunt"}, {"version"}, {"db", "status"}} {
		if c, _, err := root.Find(path); err != nil || c.Name() != path[len(path)-1] {
			t.Errorf("command %v not found: %v", path, err)
		}
	}
	st, _, _ := root.Find([]string{"db", "status"})
	if st.Flags().Lookup("config") == nil {
		t.Error("db status has no --config")
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	cfg := writeConfig(t, "https://kibana.example.com")
	cases := map[string][]string{
		"hunt without config": {"hunt"},
		"zero window":         {"hunt", "--config", cfg, "--window", "0s"},
		"negative window":     {"hunt", "--config", cfg, "--window", "-5m"},
		"bad window":          {"hunt", "--config", cfg, "--window", "soon"},
		"bad output":          {"hunt", "--config", cfg, "--output", "xml"},
		"unknown flag":        {"hunt", "--config", cfg, "--nope"},
		"extra argument":      {"hunt", "--config", cfg, "extra"},
		"unknown command":     {"frobnicate"},
		"unknown root flag":   {"--nope"},
		"db status no config": {"db", "status"},
		"version with arg":    {"version", "x"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(nil), args...)
			if code != exitUsage {
				t.Errorf("exit = %d, want 2\nstderr: %s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("a usage error wrote to stdout: %q", stdout)
			}
			if strings.Count(stderr, "jb:") != 1 {
				t.Errorf("error should be printed exactly once, got %q", stderr)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, testDeps(nil), "version")
	if code != 0 || !strings.HasPrefix(out, "jb ") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestHuntMissingEnvVarNamedButValueNeverPrinted(t *testing.T) {
	cfg := writeConfig(t, "https://kibana.example.com")
	// Another variable holds a value; the one the config names is unset.
	code, stdout, stderr := run(t, testDeps(map[string]string{"UNRELATED": secretKey}), "hunt", "--config", cfg)
	if code != exitFailure {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "JB_KIBANA_API_KEY") {
		t.Errorf("error does not name the variable: %q", stderr)
	}
	if strings.Contains(stdout+stderr, secretKey) {
		t.Error("a credential value appeared in the output")
	}
}

func TestHuntRejectsUnknownYAMLKey(t *testing.T) {
	cfg := writeConfig(t, "https://kibana.example.com")
	b, _ := os.ReadFile(cfg)
	if err := os.WriteFile(cfg, append(b, []byte("surprise: 1\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey}), "hunt", "--config", cfg)
	if code != exitFailure || !strings.Contains(stderr, "surprise") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stderr, secretKey) {
		t.Error("credential in error")
	}
}

func TestHuntEndToEnd(t *testing.T) {
	srv := fakeKibana(t, http.StatusOK)
	cfg := writeConfig(t, srv.URL)
	d := testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey})

	code, stdout, stderr := run(t, d, "hunt", "--config", cfg, "--window", "60m")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"kibana:logs-auth-*", "authspike", "192.0.2.7"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "No findings") {
		t.Errorf("the failing key was not reported:\n%s", stdout)
	}
	if strings.Contains(stdout+stderr, secretKey) {
		t.Error("credential in output")
	}
	if strings.Contains(stdout, "hunting ") {
		t.Error("progress log leaked to stdout")
	}

	// The evidence is in the store, and db status sees it read-only.
	code, out, errb := run(t, d, "db", "status", "--config", cfg)
	if code != 0 {
		t.Fatalf("db status exit %d: %s", code, errb)
	}
	if !strings.Contains(out, "events") || !strings.Contains(out, "200") {
		t.Errorf("db status:\n%s", out)
	}

	// JSON output parses and says it is complete.
	code, stdout, stderr = run(t, d, "hunt", "--config", cfg, "--output", "json")
	if code != 0 {
		t.Fatalf("json hunt exit %d: %s", code, stderr)
	}
	var got struct {
		Complete bool `json:"complete"`
		Findings []struct {
			Tag      string `json:"tag"`
			Severity string `json:"severity"`
		} `json:"findings"`
		Sources []struct{ Status string }
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if !got.Complete || len(got.Findings) != 1 || got.Sources[0].Status != "ok" {
		t.Errorf("result = %+v", got)
	}
}

func TestHuntUnavailableSourceIsNeverACleanResult(t *testing.T) {
	srv := fakeKibana(t, http.StatusBadGateway)
	cfg := writeConfig(t, srv.URL)
	d := testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey})
	code, stdout, stderr := run(t, d, "hunt", "--config", cfg)
	if code != exitFailure {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"unavailable", "INCOMPLETE"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "every source and detector completed") {
		t.Errorf("an unavailable source was presented as clean:\n%s", stdout)
	}
	if !strings.Contains(stderr, "incomplete") {
		t.Errorf("stderr should say the hunt was incomplete: %q", stderr)
	}
	if strings.Contains(stdout+stderr, secretKey) {
		t.Error("credential in output")
	}
}

func TestDBStatusOnMissingDatabaseFails(t *testing.T) {
	cfg := writeConfig(t, "https://kibana.example.com")
	code, _, stderr := run(t, testDeps(nil), "db", "status", "--config", cfg)
	if code != exitFailure || !strings.Contains(stderr, "database") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfg), "jb.duckdb")); err == nil {
		t.Error("db status created the database file; it must be read-only")
	}
}

func TestExampleConfigStillBuilds(t *testing.T) {
	f, err := config.Load(filepath.Join("..", "..", "examples", "jb.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Build(testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey}).env); err != nil {
		t.Fatal(err)
	}
}
