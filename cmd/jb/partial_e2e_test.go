package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One behaviour detector, two rare actions. "device-code" fires. "admin-login" needs
// three events from one key, sees three keys once each and has max_keys 2, so it
// cannot be judged (RFC 0011). RFC 0012: the fired finding is kept and the run stays
// incomplete. Synthetic data only.
func partialCase(t *testing.T) string {
	t.Helper()
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "ExampleAgent/1.0", "/home", 200, "203.0.113.10", "x"),
		webDoc(cur(5), "ExampleAgent/1.0", "/oauth/device/code", 200, "203.0.113.55", "x"),
		webDoc(cur(6), "ExampleAgent/1.0", "/admin/login", 200, "198.51.100.1", "x"),
		webDoc(cur(7), "ExampleAgent/1.0", "/admin/login", 200, "198.51.100.2", "x"),
		webDoc(cur(8), "ExampleAgent/1.0", "/admin/login", 200, "198.51.100.3", "x"),
	})
	dir := searchCase(t, idx)
	body := `sources:
  - type: kibana
    url: ` + idx.srv.URL + `
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
detectors:
  - type: behaviour
    key_field: client_ip
    path_field: path
    method_field: method
    max_keys: 2
    actions:
      - {name: device-code, class: rare, path: /oauth/device/code, methods: [GET]}
      - {name: admin-login, class: rare, path: /admin/login, methods: [GET], min_events_per_key: 3}
store:
  path: ""
`
	if err := os.WriteFile(filepath.Join(dir, "config", "behaviour.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	editFile(t, filepath.Join(dir, "case.yaml"), "config:\n", "config:\n  - config/behaviour.yaml\n")
	return dir
}

func TestHuntReportsTheFindingOfAnIncompleteDetector(t *testing.T) {
	dir := partialCase(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--output", "json", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h")
	var out struct {
		Complete  bool `json:"complete"`
		Detectors []struct {
			Status   string `json:"status"`
			Findings *int   `json:"findings"`
			Error    string `json:"error"`
		} `json:"detectors"`
		Findings []struct {
			Tag string `json:"tag"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if code != 1 || out.Complete {
		t.Fatalf("exit %d complete %v: a hunt with an unjudged action must exit 1\n%s", code, out.Complete, stdout)
	}
	if len(out.Findings) != 1 || out.Findings[0].Tag != "behaviour:device-code" {
		t.Fatalf("findings %+v, want the device-code finding", out.Findings)
	}
	d := out.Detectors[0]
	if d.Status != "error" || d.Findings == nil || *d.Findings != 1 || !strings.Contains(d.Error, "admin-login") {
		t.Fatalf("detector %+v", d)
	}
}

func TestActivityIsActiveAndIncompleteForAnIncompleteDetectorWithAFinding(t *testing.T) {
	dir := partialCase(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "activity", "--output", "json", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h")
	var out struct {
		Verdict   string `json:"verdict"`
		Complete  bool   `json:"complete"`
		Detectors []struct {
			Status   string `json:"status"`
			Findings int    `json:"findings_before_stop"`
		} `json:"detectors"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if out.Verdict != "ACTIVE" || out.Complete || code != 1 {
		t.Fatalf("exit %d verdict %q complete %v\n%s", code, out.Verdict, out.Complete, stdout)
	}
	if d := out.Detectors[0]; d.Status != "error" || d.Findings != 1 {
		t.Fatalf("detector %+v", d)
	}
	_, table, _ := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h")
	if !strings.Contains(table, "1 finding(s) proved before the detector stopped") || !strings.Contains(table, "also incomplete") {
		t.Fatalf("table lacks the combined state:\n%s", table)
	}
}
