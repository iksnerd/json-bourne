package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
)

const gnKey = "SENTINEL-GN-KEY-0123456789abcdef"

type fakeGN struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string
	keys []string
}

func (f *fakeGN) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

// fakeGreyNoise answers per address: 192.0.2.7 is malicious, 192.0.2.99 was never seen
// (404), anything else answers with status other.
func fakeGreyNoise(t *testing.T, other int) *fakeGN {
	t.Helper()
	f := &fakeGN{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.URL.Path)
		f.keys = append(f.keys, r.Header.Get("key"))
		f.mu.Unlock()
		switch strings.TrimPrefix(r.URL.Path, "/v3/community/") {
		case "192.0.2.7":
			fmt.Fprint(w, `{"ip":"192.0.2.7","noise":true,"riot":false,"classification":"malicious","last_seen":"2026-11-03"}`)
		case "192.0.2.99":
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"IP not observed scanning the internet or contained in RIOT data set."}`)
		default:
			w.WriteHeader(other)
			fmt.Fprintf(w, "echo %s", gnKey) // a hostile body must not surface anywhere
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// intelCase is a ready case whose hunt config also names the fake feed.
func intelCase(t *testing.T, gn *fakeGN, extra string) string {
	t.Helper()
	dir, _ := readyCase(t)
	cfg := filepath.Join(dir, "config", "hunt.yaml")
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	add := fmt.Sprintf("\nfeeds:\n  - type: greynoise\n    base_url: %s\n    api_key_env: JB_GREYNOISE_API_KEY\n    min_interval: 0s\n%s", gn.srv.URL, extra)
	if err := os.WriteFile(cfg, append(b, []byte(add)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func intelDeps() deps {
	return testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey, "JB_GREYNOISE_API_KEY": gnKey})
}

func huntFirst(t *testing.T, dir string) {
	t.Helper()
	if code, out, errs := run(t, intelDeps(), "hunt", "--case", dir); code != 0 && !strings.Contains(out, "192.0.2.7") {
		t.Fatalf("hunt exit %d\n%s\n%s", code, out, errs)
	}
}

type intelJSON struct {
	Note     string `json:"note"`
	Run      string `json:"run"`
	Complete bool   `json:"complete"`
	Results  []struct {
		Indicator string `json:"indicator"`
		Feed      string `json:"feed"`
		Verdict   string `json:"verdict"`
		Observed  string `json:"observed"`
	} `json:"results"`
	Failures []struct {
		Indicator string `json:"indicator"`
		Feed      string `json:"feed"`
		Error     string `json:"error"`
	} `json:"failures"`
}

func storedReputation(t *testing.T, dir, ip string) int {
	t.Helper()
	st, err := duckdb.Open(filepath.Join(dir, "evidence", "jb.duckdb"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs, err := st.Reputation(context.Background(), ip)
	if err != nil {
		t.Fatal(err)
	}
	return len(rs)
}

func TestIntelLooksUpTheLatestRunAndStoresSnapshots(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	dir := intelCase(t, gn, "")
	huntFirst(t, dir)

	code, stdout, stderr := run(t, intelDeps(), "intel", "--case", dir, "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var got intelJSON
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if !got.Complete || len(got.Results) != 2 || len(got.Failures) != 0 || !strings.HasPrefix(got.Run, "hunt-") {
		t.Fatalf("%+v", got)
	}
	verdicts := map[string]string{}
	for _, r := range got.Results {
		verdicts[r.Indicator] = r.Verdict
		if r.Feed != "greynoise:community" || r.Observed == "" {
			t.Errorf("row %+v", r)
		}
	}
	if verdicts["192.0.2.7"] != "classification=malicious;noise=true;riot=false;last_seen=2026-11-03" || verdicts["192.0.2.99"] != "not_found" {
		t.Errorf("verdicts %v", verdicts)
	}
	for _, want := range []string{"context", "not attribution", "CDN"} {
		if !strings.Contains(got.Note, want) {
			t.Errorf("note lacks %q: %s", want, got.Note)
		}
	}
	if storedReputation(t, dir, "192.0.2.7") != 1 || storedReputation(t, dir, "192.0.2.99") != 1 {
		t.Error("snapshots not stored")
	}
	// Passive: only the feed's API path was requested, only for the two addresses.
	for _, p := range gn.paths() {
		if p != "/v3/community/192.0.2.7" && p != "/v3/community/192.0.2.99" {
			t.Errorf("unexpected request %q", p)
		}
	}
	// A second run appends: reputation is a time series.
	if code, _, _ := run(t, intelDeps(), "intel", "--case", dir); code != 0 {
		t.Fatal("second run failed")
	}
	if storedReputation(t, dir, "192.0.2.7") != 2 {
		t.Error("a second lookup must append, not replace")
	}
}

func TestIntelKeyNeverReachesOutputOrTheStore(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	dir := intelCase(t, gn, "")
	huntFirst(t, dir)
	_, o1, e1 := run(t, intelDeps(), "intel", "--case", dir, "192.0.2.7", "198.51.100.4") // second one fails with a hostile body
	_, o2, e2 := run(t, intelDeps(), "intel", "--case", dir, "--output", "json", "198.51.100.4")
	all := o1 + e1 + o2 + e2
	if strings.Contains(all, gnKey) {
		t.Fatalf("key in output:\n%s", all)
	}
	for _, k := range gn.keys {
		if k != gnKey {
			t.Errorf("feed received key %q", k)
		}
	}
	for _, name := range []string{"jb.duckdb", "jb.duckdb.wal"} {
		if b, err := os.ReadFile(filepath.Join(dir, "evidence", name)); err == nil && strings.Contains(string(b), gnKey) {
			t.Fatalf("key found in %s", name)
		}
	}
}

func TestIntelFailureIsIncompleteAndNeverStoredAsUnknown(t *testing.T) {
	for _, status := range []int{429, 500, 503} {
		gn := fakeGreyNoise(t, status)
		dir := intelCase(t, gn, "")
		code, stdout, stderr := run(t, intelDeps(), "intel", "--case", dir, "192.0.2.7", "198.51.100.4", "203.0.113.5")
		if code != exitFailure {
			t.Fatalf("status %d: exit %d, want 1\n%s", status, code, stdout)
		}
		if !strings.Contains(stdout, "INCOMPLETE") || strings.Contains(stdout, "No findings") {
			t.Errorf("status %d: stdout lacks INCOMPLETE:\n%s", status, stdout)
		}
		if !strings.Contains(stderr, "incomplete") {
			t.Errorf("status %d: stderr %q", status, stderr)
		}
		if storedReputation(t, dir, "198.51.100.4") != 0 || storedReputation(t, dir, "203.0.113.5") != 0 {
			t.Errorf("status %d: a failed lookup was stored", status)
		}
		if storedReputation(t, dir, "192.0.2.7") != 1 {
			t.Errorf("status %d: the answer that was obtained must be kept", status)
		}
		if status == 429 && len(gn.paths()) != 2 {
			t.Errorf("after a 429 the feed must not be asked again: %v", gn.paths())
		}
	}
}

func TestIntelJSONIncompleteSaysSo(t *testing.T) {
	gn := fakeGreyNoise(t, 503)
	dir := intelCase(t, gn, "")
	code, stdout, _ := run(t, intelDeps(), "intel", "--case", dir, "--output", "json", "198.51.100.4")
	var got intelJSON
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if code != exitFailure || got.Complete || len(got.Failures) != 1 || len(got.Results) != 0 {
		t.Fatalf("exit %d %+v", code, got)
	}
}

func TestIntelTableCarriesTheContextNote(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	dir := intelCase(t, gn, "")
	code, stdout, stderr := run(t, intelDeps(), "intel", "--case", dir, "192.0.2.7")
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	for _, want := range []string{"context, not attribution", "CDN", "192.0.2.7", "malicious", "greynoise:community"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestIntelOverTheIndicatorCapIsIncomplete(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	dir := intelCase(t, gn, "intel:\n  max_indicators: 1\n")
	huntFirst(t, dir)
	code, stdout, _ := run(t, intelDeps(), "intel", "--case", dir)
	if code != exitFailure || !strings.Contains(stdout, "INCOMPLETE") || len(gn.paths()) != 1 {
		t.Fatalf("exit %d, requests %v\n%s", code, gn.paths(), stdout)
	}
}

func TestIntelRefusals(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	dir := intelCase(t, gn, "")

	// No hunt has run: there is nothing to read, which is an error and not a clean result.
	if code, out, errs := run(t, intelDeps(), "intel", "--case", dir); code != exitFailure || strings.Contains(out, "No ") {
		t.Errorf("empty store: exit %d\n%s\n%s", code, out, errs)
	}
	// Not an address: a usage error, nothing sent.
	if code, _, errs := run(t, intelDeps(), "intel", "--case", dir, "example.com"); code != exitUsage || !strings.Contains(errs, "example.com") {
		t.Errorf("bad indicator: exit %d %s", code, errs)
	}
	// The key variable is named but unset: refuse; never fall back to keyless.
	d := testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey})
	code, _, errs := run(t, d, "intel", "--case", dir, "192.0.2.7")
	if code != exitFailure || !strings.Contains(errs, "JB_GREYNOISE_API_KEY") {
		t.Errorf("unset key: exit %d %s", code, errs)
	}
	// No flags.
	if code, _, _ := run(t, intelDeps(), "intel"); code != exitUsage {
		t.Errorf("no --config/--case: exit %d", code)
	}
	if n := len(gn.paths()); n != 0 {
		t.Errorf("refused runs reached the feed %d time(s)", n)
	}
}

func TestIntelWithoutAFeedInTheConfigIsAnError(t *testing.T) {
	dir, _ := readyCase(t)
	code, _, errs := run(t, intelDeps(), "intel", "--case", dir, "192.0.2.7")
	if code != exitFailure || !strings.Contains(errs, "feed") {
		t.Fatalf("exit %d %s", code, errs)
	}
}

// fakeISC answers 192.0.2.7 with reports, and anything else with HTTP 500.
func fakeISC(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/ip/192.0.2.7" {
			fmt.Fprint(w, `{"ip":{"number":"192.0.2.7","count":12,"attacks":3,"mindate":"2026-10-01","maxdate":"2026-11-03"}}`)
			return
		}
		w.WriteHeader(500)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func storedSources(t *testing.T, dir, ip string) []string {
	t.Helper()
	st, err := duckdb.Open(filepath.Join(dir, "evidence", "jb.duckdb"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rs, err := st.Reputation(context.Background(), ip)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rs {
		out = append(out, r.Source)
	}
	sort.Strings(out)
	return out
}

func TestIntelManyFeedsOneFailingIsIncompleteAndKeepsTheOthers(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	isc := fakeISC(t)
	dir := intelCase(t, gn, fmt.Sprintf("  - type: sans-isc\n    base_url: %s\n    min_interval: 0s\n  - type: dnsbl\n    zone: bl.example.test\n", isc.URL))
	code, stdout, stderr := run(t, intelDeps(), "intel", "--case", dir, "--output", "json", "192.0.2.7", "192.0.2.99")
	if code != exitFailure {
		t.Fatalf("exit %d, want 1\n%s\n%s", code, stdout, stderr)
	}
	var got intelJSON
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if got.Complete || len(got.Results) != 3 || len(got.Failures) != 1 {
		t.Fatalf("%+v", got)
	}
	if f := got.Failures[0]; f.Feed != "sans-isc" || f.Indicator != "192.0.2.99" || strings.Contains(f.Error, "SENTINEL") {
		t.Fatalf("failure %+v", f)
	}
	if s := storedSources(t, dir, "192.0.2.7"); strings.Join(s, ",") != "greynoise:community,sans-isc" {
		t.Errorf("192.0.2.7 sources %v", s)
	}
	if s := storedSources(t, dir, "192.0.2.99"); strings.Join(s, ",") != "greynoise:community" {
		t.Errorf("192.0.2.99 sources %v: the failed lookup must store nothing", s)
	}
	if !strings.Contains(stderr, "dnsbl:bl.example.test") || !strings.Contains(stderr, "not enabled") {
		t.Errorf("a disabled feed must be named on stderr, got %q", stderr)
	}
}

func TestIntelWithOnlyDisabledFeedsRefuses(t *testing.T) {
	dir, _ := readyCase(t)
	cfg := filepath.Join(dir, "config", "hunt.yaml")
	b, _ := os.ReadFile(cfg)
	if err := os.WriteFile(cfg, append(b, []byte("\nfeeds:\n  - type: dnsbl\n    zone: bl.example.test\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, intelDeps(), "intel", "--case", dir, "192.0.2.7")
	if code != exitFailure || !strings.Contains(stderr, "enabled: true") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}
