package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	edgeAddr    = "198.51.100.200" // a CDN edge, shared by many clients
	gatewayAddr = "198.51.100.7"   // listed in the example config's ignore_ips
)

type activityJSON struct {
	Run      string   `json:"run"`
	Verdict  string   `json:"verdict"`
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons"`
	Sources  []struct {
		Status string `json:"status"`
		Events *int64 `json:"events"`
	} `json:"sources"`
	Detectors []struct {
		Name     string `json:"name"`
		Status   string `json:"status"`
		Subjects []struct {
			Subject string     `json:"subject"`
			Active  bool       `json:"active"`
			Window  int        `json:"window_events"`
			Last    *time.Time `json:"last_genuine"`
		} `json:"subjects"`
	} `json:"detectors"`
	Current  int `json:"genuine_events_window"`
	Previous int `json:"genuine_events_preceding"`
}

func runActivityCmd(t *testing.T, dir string, args ...string) (code int, out activityJSON, stdout, stderr string) {
	t.Helper()
	all := append([]string{"activity", "--output", "json", "--case", dir, "--config", fpConfigRel, "--window", "1h"}, args...)
	code, stdout, stderr = run(t, testDeps(huntEnv), all...)
	_ = json.Unmarshal([]byte(stdout), &out)
	return
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func cur(m int) time.Time { return fixedNow.Add(-time.Hour).Add(time.Duration(m) * time.Minute) }

func TestActivityActiveWhenTheActorIsSeen(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(2), exampleUA, "/login", 200, "203.0.113.11", "x"),
		webDoc(cur(9), exampleUA, "/profile", 200, "203.0.113.11", "x"),
		webDoc(cur(30), exampleUA, "/wp-login.php", 200, "203.0.113.11", "x"), // later, but a sweep
		webDoc(cur(-30), exampleUA, "/login", 200, "203.0.113.11", "x"),       // preceding window
	})
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runActivityCmd(t, dir)
	if code != 0 || out.Verdict != "ACTIVE" {
		t.Fatalf("exit %d verdict %q\n%s\n%s", code, out.Verdict, stdout, stderr)
	}
	s := out.Detectors[0].Subjects[0]
	if !s.Active || s.Window != 2 || out.Current != 2 || out.Previous != 1 {
		t.Fatalf("subject %+v, counts %d/%d, want 2 in window and 1 before", s, out.Current, out.Previous)
	}
	if s.Last == nil || !s.Last.Equal(cur(9)) {
		t.Fatalf("last genuine = %v, want %v: the later wp-login sweep is noise", s.Last, cur(9))
	}
	if *out.Sources[0].Events != 5 {
		t.Fatalf("events fetched = %d, want the 5 the server returned", *out.Sources[0].Events)
	}

	// The table ends with the verdict line, which states the window, the sources and the counts.
	code, stdout, stderr = run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	last := lastLine(stdout)
	for _, want := range []string{
		"ACTIVE: window 2026-11-05T11:00:00Z to 2026-11-05T12:00:00Z (1h0m0s)",
		"sources read: kibana:logs-http-* (5 events fetched)",
		"judged: fingerprint read 4 events in the window, actor/rare-action events: 2 (window), 1 (preceding)",
		"last activity 2026-11-05T11:09:00Z (" + s.Subject + ", 51m ago)",
	} {
		if !strings.Contains(last, want) {
			t.Errorf("verdict line lacks %q:\n%s", want, last)
		}
	}
}

func TestActivityQuietOnlyWhenEverythingCompleted(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(2), "OtherClient/1.0", "/home", 200, "203.0.113.12", "x"),
	})
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runActivityCmd(t, dir)
	// The default fingerprint config reads a window with no actor event as a normal answer.
	if code != 0 || out.Verdict != "QUIET" || !out.Complete {
		t.Fatalf("exit %d verdict %q reasons %v\n%s\n%s", code, out.Verdict, out.Reasons, stdout, stderr)
	}
	_, stdout, _ = run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h")
	last := lastLine(stdout)
	if !strings.HasPrefix(last, "QUIET: window 2026-11-05T11:00:00Z") || !strings.Contains(last, "every source and detector completed") || !strings.Contains(last, "(2 events fetched)") {
		t.Errorf("verdict line:\n%s", last)
	}
}

func TestActivityNoiseAndInfrastructureAreNotTheActor(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(2), exampleUA, "/wp-login.php", 200, "203.0.113.11", "x"),
		webDoc(cur(3), exampleUA, "/", 404, "203.0.113.11", "x"),
		webDoc(cur(4), exampleUA, "/login", 200, gatewayAddr, "x"), // relayed by our gateway
	})
	dir := searchCase(t, idx)
	code, out, stdout, stderr := runActivityCmd(t, dir)
	if code != 0 || out.Verdict != "QUIET" {
		t.Fatalf("exit %d verdict %q\n%s\n%s", code, out.Verdict, stdout, stderr)
	}
	if s := out.Detectors[0].Subjects[0]; s.Active || s.Last != nil {
		t.Fatalf("subject %+v: noise or infrastructure became the actor", s)
	}
}

// A CDN edge is not a client: the actor behind an edge is found by what it sends, and
// the edge address is not printed as if it were the actor.
func TestActivityNeverNamesAnAddress(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, edgeAddr, "x"),
		webDoc(cur(2), exampleUA, "/login", 200, edgeAddr, "x"),
	})
	dir := searchCase(t, idx)
	for _, args := range [][]string{{"--output", "json"}, {"--output", "table"}} {
		_, stdout, stderr := run(t, testDeps(huntEnv), append([]string{"activity", "--case", dir, "--config", fpConfigRel, "--window", "1h"}, args...)...)
		if !strings.Contains(stdout, "ACTIVE") && !strings.Contains(stdout, `"ACTIVE"`) {
			t.Fatalf("%v: not active\n%s\n%s", args, stdout, stderr)
		}
		if strings.Contains(stdout, edgeAddr) || strings.Contains(stderr, edgeAddr) {
			t.Fatalf("%v: the edge address is in the output\n%s\n%s", args, stdout, stderr)
		}
	}
}

func TestActivityIsIncompleteNotQuietWhenSomethingDidNotFinish(t *testing.T) {
	for name, tc := range map[string]struct {
		docs   []doc
		status int
		want   string
	}{
		"source unreachable": {nil, 502, "source kibana:logs-http-* did not finish (unavailable)"},
		"index silent":       {nil, 200, "source kibana:logs-http-* did not finish (no_records)"},
		"mapper blind": { // every document lacks the fields the detector reads
			docs: []doc{
				{at: cur(1), fields: map[string]any{"message": "x"}},
				{at: cur(2), fields: map[string]any{"message": "y"}},
			},
			status: 200, want: "detector fingerprint did not finish (no_records)",
		},
		"a quarter of the events unreadable": {
			docs: []doc{
				webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
				webDoc(cur(2), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
				webDoc(cur(3), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
				{at: cur(4), fields: map[string]any{"message": "no fields"}},
			},
			status: 200, want: "could not judge 25%",
		},
	} {
		t.Run(name, func(t *testing.T) {
			idx := newFakeIndex(t, tc.docs)
			idx.status = tc.status
			dir := searchCase(t, idx)
			code, out, stdout, stderr := runActivityCmd(t, dir)
			if code != exitFailure || out.Verdict != "INCOMPLETE" || out.Complete {
				t.Fatalf("exit %d verdict %q\n%s\n%s", code, out.Verdict, stdout, stderr)
			}
			if got := strings.Join(out.Reasons, "; "); !strings.Contains(got, tc.want) {
				t.Fatalf("reasons %q lack %q", got, tc.want)
			}
			_, tbl, errOut := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h")
			if l := lastLine(tbl); !strings.HasPrefix(l, "INCOMPLETE:") || !strings.Contains(l, "this is not QUIET because") {
				t.Errorf("verdict line: %s", l)
			}
			if !strings.Contains(errOut, "activity incomplete, not QUIET") {
				t.Errorf("stderr = %q", errOut)
			}
		})
	}
}

// A positive stands even when a source failed; the output says the check was also incomplete.
func TestActivityActiveWithGapsExitsOne(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(2), exampleUA, "/login", 200, "203.0.113.11", "x"),
		{at: cur(3), fields: map[string]any{"message": "unreadable"}},
	})
	dir := searchCase(t, idx)
	code, out, stdout, _ := runActivityCmd(t, dir)
	if code != 1 || out.Verdict != "ACTIVE" || out.Complete {
		t.Fatalf("exit %d verdict %q complete %v\n%s", code, out.Verdict, out.Complete, stdout)
	}
	_, tbl, _ := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h")
	if !strings.Contains(tbl, "NOTE: ACTIVE stands, but the check is also incomplete") {
		t.Errorf("table:\n%s", tbl)
	}
}

// The filtered source is shown alive when nothing matches, and the fingerprint detector
// is configured to read an empty window as quiet: the one way QUIET is reachable with a
// server-side filter, through the sink that refuses an empty save.
func TestActivityQuietThroughAFilteredSourceThatMatchedNothing(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
	})
	dir := searchCase(t, idx)
	cfg := filepath.Join(dir, fpConfigRel)
	editFile(t, cfg, "    index: logs-http-*\n", "    index: logs-http-*\n    filter:\n      - match_phrase: {field: user_agent, value: \"ExampleBrowser\"}\n")
	editFile(t, cfg, "    actors: [example-actor.yaml]\n", "    actors: [example-actor.yaml]\n    empty_is_quiet: true\n")
	code, out, stdout, stderr := runActivityCmd(t, dir)
	if code != 0 || out.Verdict != "QUIET" || !out.Complete {
		t.Fatalf("exit %d verdict %q reasons %v\n%s\n%s", code, out.Verdict, out.Reasons, stdout, stderr)
	}
	// The same filtered source on a dead index must not be QUIET.
	idx2 := newFakeIndex(t, nil)
	dir2 := searchCase(t, idx2)
	cfg2 := filepath.Join(dir2, fpConfigRel)
	editFile(t, cfg2, "    index: logs-http-*\n", "    index: logs-http-*\n    filter:\n      - match_phrase: {field: user_agent, value: \"ExampleBrowser\"}\n")
	editFile(t, cfg2, "    actors: [example-actor.yaml]\n", "    actors: [example-actor.yaml]\n    empty_is_quiet: true\n")
	code, out, stdout, stderr = runActivityCmd(t, dir2)
	if code != exitFailure || out.Verdict != "INCOMPLETE" {
		t.Fatalf("dead index: exit %d verdict %q\n%s\n%s", code, out.Verdict, stdout, stderr)
	}
}

// A behaviour action is matched by what is done, so a client with an unknown user agent
// is found: "active from any client".
func TestActivityBehaviourFindsAnyClient(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(5), "curl/8.0", "/oauth/device/code", 200, "203.0.113.55", "x"),
		webDoc(cur(6), "gateway-http/1.0", "/oauth/device/code", 200, gatewayAddr, "x"),
	})
	dir := searchCase(t, idx)
	cfg := filepath.Join(dir, "config", "behaviour.yaml")
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
    status_field: status
    user_agent_field: user_agent
    ignore_keys: [` + gatewayAddr + `]
    actions:
      - {name: device-code, class: rare, path: /oauth/device/code, methods: [GET]}
store:
  path: ""
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	editFile(t, filepath.Join(dir, "case.yaml"), "config:\n", "config:\n  - config/behaviour.yaml\n")
	code, stdout, stderr := run(t, testDeps(huntEnv), "activity", "--output", "json", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h")
	var out activityJSON
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if code != 0 || out.Verdict != "ACTIVE" {
		t.Fatalf("exit %d verdict %q\n%s\n%s", code, out.Verdict, stdout, stderr)
	}
	s := out.Detectors[0].Subjects[0]
	if s.Subject != "device-code" || s.Window != 1 || s.Last == nil || !s.Last.Equal(cur(5)) {
		t.Fatalf("subject %+v: want the one curl request, not the gateway's", s)
	}
	if strings.Contains(stdout, "203.0.113.55") || strings.Contains(stdout, gatewayAddr) {
		t.Fatalf("an address is in the output:\n%s", stdout)
	}
}

func TestActivityUsageErrors(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	for name, args := range map[string][]string{
		"no case":              {"activity"},
		"zero window":          {"activity", "--case", dir, "--config", fpConfigRel, "--window", "0s"},
		"bad output":           {"activity", "--case", dir, "--config", fpConfigRel, "--output", "xml"},
		"stray arg":            {"activity", "--case", dir, "extra"},
		"no activity detector": {"activity", "--case", dir, "--config", "config/hunt.yaml"}, // authspike only
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(huntEnv), args...)
			if code != exitUsage {
				t.Fatalf("exit %d, want 2\n%s\n%s", code, stdout, stderr)
			}
		})
	}
	if n := len(idx.requests()); n != 0 {
		t.Fatalf("%d request(s) reached the server for refused input", n)
	}
}

func TestActivityRefusesAnUnguardedCase(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	unignore(t, dir)
	code, _, stderr := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel)
	if code != exitFailure || !strings.Contains(stderr, "refusing to hunt case") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if n := len(idx.requests()); n != 0 {
		t.Fatalf("%d request(s) went out before the guard refused", n)
	}
}

func TestActivityNamesSkippedDetectors(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	cfg := filepath.Join(dir, fpConfigRel)
	editFile(t, cfg, "store:\n", "  - type: authspike\n    key_field: client_ip\n    status_field: status\n\nstore:\n")
	_, _, stderr := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h")
	if !strings.Contains(stderr, "not an activity detector, skipped: authspike") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestActivityWithoutAnActivityDetectorSaysSo(t *testing.T) {
	idx := newFakeIndex(t, searchDocs())
	dir := searchCase(t, idx)
	code, _, stderr := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", "config/hunt.yaml")
	if code != exitUsage || !strings.Contains(stderr, "no fingerprint or behaviour detector") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

// behaviourCase writes a behaviour config with the given sources block and lists it in the case.
func behaviourCase(t *testing.T, idx *fakeIndex, sources string) (dir string) {
	t.Helper()
	dir = searchCase(t, idx)
	body := "sources:\n" + strings.ReplaceAll(sources, "URL", idx.srv.URL) + `detectors:
  - type: behaviour
    key_field: client_ip
    path_field: path
    method_field: method
    status_field: status
    user_agent_field: user_agent
    actions:
      - {name: device-code, class: rare, path: /oauth/device/code, methods: [GET]}
      - {name: login, class: common, path: /login, methods: [GET]}
store:
  path: ""
`
	if err := os.WriteFile(filepath.Join(dir, "config", "behaviour.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	editFile(t, filepath.Join(dir, "case.yaml"), "config:\n", "config:\n  - config/behaviour.yaml\n")
	return dir
}

const twoOverlappingSources = `  - type: kibana
    name: device-paths
    url: URL
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
    filter:
      - any_of:
          - match_phrase: {field: path, value: /oauth/device/code}
          - match_phrase: {field: path, value: /oauth/token}
  - type: kibana
    name: curl-clients
    url: URL
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
    filter:
      - match_phrase: {field: user_agent, value: curl}
`

// Two sources on one index with overlapping filters both return the curl device-code
// request. The detector must count it once, the sources are named in the output, and the
// duplicate is shown, not hidden.
func TestActivityOverlappingSourcesOnOneIndexCountOnce(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(5), "curl/8.0", "/oauth/device/code", 200, "203.0.113.55", "x"), // both filters match
		webDoc(cur(7), "OtherClient/1.0", "/oauth/token", 200, "203.0.113.56", "x"),
	})
	dir := behaviourCase(t, idx, twoOverlappingSources)
	code, stdout, stderr := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h", "--output", "json")
	var out struct {
		Verdict string `json:"verdict"`
		Sources []struct {
			Name       string `json:"name"`
			Events     int64  `json:"events"`
			Duplicates int64  `json:"duplicates"`
		} `json:"sources"`
		Detectors []struct {
			Subjects []struct {
				Subject string `json:"subject"`
				Window  int    `json:"window_events"`
			} `json:"subjects"`
		} `json:"detectors"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if code != 0 || out.Verdict != "ACTIVE" {
		t.Fatalf("exit %d verdict %q\n%s\n%s", code, out.Verdict, stdout, stderr)
	}
	names := map[string]bool{}
	var events, dups int64
	for _, s := range out.Sources {
		names[s.Name] = true
		events += s.Events
		dups += s.Duplicates
	}
	if !names["device-paths"] || !names["curl-clients"] {
		t.Fatalf("source names = %v, want the configured names", names)
	}
	// device-paths matches 2 documents, curl-clients matches 1 of them: 2 distinct, 1 duplicate.
	if events != 2 || dups != 1 {
		t.Fatalf("events %d duplicates %d, want 2 distinct documents and 1 duplicate\n%s", events, dups, stdout)
	}
	for _, s := range out.Detectors[0].Subjects {
		if s.Subject == "device-code" && s.Window != 1 {
			t.Fatalf("device-code counted %d times in the window, want 1: the overlapped document was double counted", s.Window)
		}
	}

	_, table, _ := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h")
	for _, want := range []string{"device-paths", "curl-clients", "already returned by another source"} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q:\n%s", want, table)
		}
	}
}

// A QUIET answer must not read as activity: routine traffic of a common action is not a
// "genuine event". The line states per detector what was read and judged and keeps the
// actor/rare-action count apart from common-action traffic.
func TestActivityQuietLineDoesNotCallRoutineTrafficGenuine(t *testing.T) {
	idx := newFakeIndex(t, []doc{
		webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x"),
		webDoc(cur(2), "OtherClient/1.0", "/login", 200, "203.0.113.11", "x"),
		webDoc(cur(3), "OtherClient/1.0", "/login", 200, "203.0.113.12", "x"),
		webDoc(cur(-3), "OtherClient/1.0", "/login", 200, "203.0.113.12", "x"),
	})
	dir := behaviourCase(t, idx, `  - type: kibana
    url: URL
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
`)
	code, stdout, stderr := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	last := lastLine(stdout)
	if !strings.HasPrefix(last, "QUIET:") {
		t.Fatalf("not QUIET:\n%s", stdout)
	}
	if strings.Contains(last, "genuine") {
		t.Errorf("a QUIET line calls traffic genuine:\n%s", last)
	}
	for _, want := range []string{
		"judged: behaviour read 3 events in the window, actor/rare-action events: 0 (window), 0 (preceding)",
		"common-action events (ordinary traffic): 3 (window), 1 (preceding)",
	} {
		if !strings.Contains(last, want) {
			t.Errorf("line lacks %q:\n%s", want, last)
		}
	}
}

func TestAgeTextCountsFromTheEndOfTheWindow(t *testing.T) {
	end := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		ago  time.Duration
		want string
	}{
		{18*time.Hour + 12*time.Minute + 40*time.Second, "18h12m ago"},
		{51 * time.Minute, "51m ago"},
		{2 * time.Hour, "2h0m ago"},
		{30 * time.Second, "under 1m ago"},
		{0, "under 1m ago"},
		{-5 * time.Minute, "under 1m ago"}, // a clock skew never prints a negative age
		{50 * time.Hour, "50h0m ago"},
	} {
		if got := ageText(end.Add(-c.ago), end); got != c.want {
			t.Errorf("ageText(%v before end) = %q, want %q", c.ago, got, c.want)
		}
	}
}

// The verdict line says which subject holds the newest time of any active subject, so a
// rare action's time cannot read as the actor's. The table keeps each subject's own time.
func TestVerdictLineNamesTheSubjectHoldingTheLastActivity(t *testing.T) {
	end := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	actor := core.ActivitySubject{Subject: "pago-actor", Kind: "actor", Current: 2, Active: true, Last: end.Add(-18 * time.Hour)}
	reset := core.ActivitySubject{Subject: "password-reset", Kind: "rare", Current: 1, Active: true, Last: end.Add(-2 * time.Hour)}
	mk := func(fp, beh []core.ActivitySubject) app.ActivityResult {
		return app.ActivityResult{
			Window:  core.Window{From: end.Add(-24 * time.Hour), To: end},
			Verdict: app.VerdictActive,
			Detectors: []app.ActivityDetector{
				{Name: "fingerprint", Status: app.StatusOK, Report: core.ActivityReport{Subjects: fp}},
				{Name: "behaviour", Status: app.StatusOK, Report: core.ActivityReport{Subjects: beh}},
			},
		}
	}
	line := verdictLine(mk([]core.ActivitySubject{actor}, nil))
	if want := "last activity 2026-11-05T18:00:00Z (pago-actor, 18h0m ago)"; !strings.Contains(line, want) {
		t.Errorf("actor only: line lacks %q:\n%s", want, line)
	}
	line = verdictLine(mk([]core.ActivitySubject{actor}, []core.ActivitySubject{reset}))
	if want := "last activity 2026-11-06T10:00:00Z (password-reset, rare action, 2h0m ago)"; !strings.Contains(line, want) {
		t.Errorf("a later rare action holds the newest time: line lacks %q:\n%s", want, line)
	}
}
