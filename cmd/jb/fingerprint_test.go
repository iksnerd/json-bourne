package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The example case lists config/fingerprint.yaml after config/hunt.yaml; each declares
// its commands, so no test passes --config to choose between them.
const fpConfigRel = "config/fingerprint.yaml"

const exampleUA = "ExampleBrowser/9.1 (Plan9; Win64; x64) InventedKit/537.36 (like Gecko) Chrome/9.1.0.0 Safari/537.36"

func TestCaseCheckReportsActors(t *testing.T) {
	code, stdout, stderr := run(t, testDeps(nil), "case", "check", "--case", exampleCase)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "actors") || !strings.Contains(stdout, "actor-a") || !strings.Contains(stdout, "actors") {
		t.Errorf("stdout lacks the actors line:\n%s", stdout)
	}

	code, stdout, _ = run(t, testDeps(nil), "case", "check", "--case", exampleCase, "--output", "json")
	var rep caseReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || code != 0 {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if rep.Actors == nil || !rep.Actors.OK || len(rep.Actors.IDs) != 1 || rep.Actors.IDs[0] != "actor-a" {
		t.Errorf("actors = %+v", rep.Actors)
	}
}

func TestCaseCheckFailsOnABrokenActorFile(t *testing.T) {
	dir := copyExampleCase(t, "")
	f, err := os.OpenFile(filepath.Join(dir, "actors", "example-actor.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("surprise: 1\n")
	f.Close()

	code, stdout, stderr := run(t, testDeps(nil), "case", "check", "--case", dir)
	if code != exitFailure {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "actors") || !strings.Contains(stdout, "FAIL") || !strings.Contains(stdout, "example-actor.yaml") || !strings.Contains(stdout, "surprise") {
		t.Errorf("stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "example-actor.yaml") || strings.Count(stderr, "jb:") != 1 {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCaseCheckValidatesTheFingerprintConfig(t *testing.T) {
	t.Run("example config is valid", func(t *testing.T) {
		dir := copyExampleCase(t, "")
		code, stdout, stderr := run(t, testDeps(nil), "case", "check", "--case", dir)
		if code != 0 || !strings.Contains(stdout, fpConfigRel+": OK") {
			t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
		}
	})
	t.Run("an actor file that is not there", func(t *testing.T) {
		dir := copyExampleCase(t, "")
		editFile(t, filepath.Join(dir, fpConfigRel), "example-actor.yaml", "missing-actor.yaml")
		code, stdout, stderr := run(t, testDeps(nil), "case", "check", "--case", dir)
		if code != exitFailure || !strings.Contains(stdout, fpConfigRel+": FAIL") || !strings.Contains(stdout, "missing-actor.yaml") {
			t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
		}
	})
}

// fakeHTTPKibana serves one hour of synthetic web events: the actor browsing, the actor's
// scanner twin on /wp-login.php, a customer on a near-miss UA, and one 2xx on the token path.
func fakeHTTPKibana(t *testing.T, withGrant bool) *httptest.Server {
	t.Helper()
	var hits []map[string]any
	n := 0
	add := func(at time.Time, ua, path string, status int) {
		n++
		hits = append(hits, map[string]any{
			"_id": fmt.Sprintf("h%d", n), "sort": []any{at.UnixMilli(), fmt.Sprint(n)},
			"_source": map[string]any{
				"@timestamp": at.Format(time.RFC3339Nano), "user_agent": ua, "path": path, "status": status,
				"client_ip": "198.51.100.200", "method": "GET",
			},
		})
	}
	cur := fixedNow.Add(-time.Hour)
	add(cur.Add(1*time.Minute), "OtherClient/1.0", "/login", 200)
	add(cur.Add(2*time.Minute), exampleUA, "/login", 200)
	add(cur.Add(3*time.Minute), exampleUA, "/wp-login.php", 200)
	add(cur.Add(4*time.Minute), exampleUA, "/?x=1", 404)
	add(cur.Add(5*time.Minute), strings.Replace(exampleUA, "Plan9", "Linux", 1), "/realms/example/protocol/openid-connect/token", 200)
	if withGrant {
		add(cur.Add(6*time.Minute), exampleUA, "/realms/example/protocol/openid-connect/token", 200)
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

func TestHuntCaseFingerprintEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name       string
		grant      bool
		wantTags   []string
		wantSev    map[string]string
		wantAbsent []string
	}{
		{"activity only", false, []string{"fingerprint:actor-a"}, map[string]string{"fingerprint:actor-a": "check"}, []string{"fingerprint:actor-a:grant"}},
		{"grant on the token path", true, []string{"fingerprint:actor-a", "fingerprint:actor-a:grant"}, map[string]string{"fingerprint:actor-a:grant": "critical"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeHTTPKibana(t, tc.grant)
			dir := copyExampleCase(t, srv.URL)
			gitInit(t, dir)
			// Same server for the fingerprint config's source.
			editFile(t, filepath.Join(dir, fpConfigRel), "https://kibana.example.com", srv.URL)
			editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")

			code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--output", "json", "--case", dir, "--config", fpConfigRel)
			var got struct {
				Complete bool `json:"complete"`
				Findings []struct {
					Tag      string `json:"tag"`
					Severity string `json:"severity"`
				} `json:"findings"`
			}
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("not JSON: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
			}
			if strings.Contains(stderr, "reads actor files from a case") {
				t.Fatalf("hunt --case did not hand the case to the config: %s", stderr)
			}
			// The window has no preceding events: the activity finding is one step down (check).
			sev := map[string]string{}
			for _, f := range got.Findings {
				sev[f.Tag] = f.Severity
			}
			for _, tag := range tc.wantTags {
				if _, ok := sev[tag]; !ok {
					t.Errorf("no finding %q in %v (exit %d)\n%s", tag, sev, code, stderr)
				}
			}
			for tag, want := range tc.wantSev {
				if sev[tag] != want {
					t.Errorf("%s severity = %q, want %q", tag, sev[tag], want)
				}
			}
			for _, tag := range tc.wantAbsent {
				if _, ok := sev[tag]; ok {
					t.Errorf("unexpected finding %q: the near-miss UA and the scanner must not raise it", tag)
				}
			}
		})
	}
}

func TestHuntWithoutCaseCannotUseFingerprint(t *testing.T) {
	srv := fakeHTTPKibana(t, false)
	dir := copyExampleCase(t, srv.URL)
	editFile(t, filepath.Join(dir, fpConfigRel), "https://kibana.example.com", srv.URL)
	code, _, stderr := run(t, testDeps(huntEnv), "hunt", "--config", filepath.Join(dir, fpConfigRel))
	if code != exitFailure || !strings.Contains(stderr, "reads actor files from a case") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
