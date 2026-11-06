package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite cmd/jb/testdata/golden/hunt-activity")

type goldenBuild func(t *testing.T) (d deps, args []string, dir string, urls []string)

// TestHuntAndActivityGolden pins the exit code, stdout and stderr (each on its own, so the
// order of the operator notes is held) of `jb hunt` and `jb activity` over the scenarios
// of the other tests. RFC 0013 moved the wiring of both commands into the library; the
// recorded text was taken before that and must pass unchanged after it.
func TestHuntAndActivityGolden(t *testing.T) {
	plain := func(cmd string, extra ...string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			idx := newFakeIndex(t, searchDocs())
			dir := searchCase(t, idx)
			args := append([]string{cmd, "--case", dir, "--config", fpConfigRel}, extra...)
			return testDeps(huntEnv), args, dir, []string{idx.srv.URL}
		}
	}
	withUntil := func(cmd string, extra ...string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			dir, idx := untilCase(t, pastDocs(), 0)
			args := append([]string{cmd, "--case", dir, "--config", fpConfigRel, "--window", "1h", "--until", untilArg}, extra...)
			return depsAt(fixedNow), args, dir, []string{idx.srv.URL}
		}
	}
	partial := func(cmd string, extra ...string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			dir := partialCase(t)
			args := append([]string{cmd, "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h"}, extra...)
			return testDeps(huntEnv), args, dir, nil
		}
	}
	notInGit := func(cmd string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			idx := newFakeIndex(t, searchDocs())
			dir := copyExampleCase(t, idx.srv.URL)
			editFile(t, filepath.Join(dir, fpConfigRel), "https://kibana.example.com", idx.srv.URL)
			args := []string{cmd, "--case", dir, "--config", fpConfigRel}
			if cmd == "activity" {
				args = append(args, "--window", "1h")
			}
			return testDeps(huntEnv), args, dir, []string{idx.srv.URL}
		}
	}
	// The same documents stored under two source labels: the second run renames the source.
	overlap := func(cmd string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			idx := newFakeIndex(t, []doc{
				webDoc(cur(5), "curl/8.0", "/oauth/device/code", 200, "203.0.113.55", "x"),
				webDoc(cur(7), "OtherClient/1.0", "/oauth/token", 200, "203.0.113.56", "x"),
			})
			src := "  - type: kibana\n    name: old-label\n    url: URL\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-http-*\n"
			dir := behaviourCase(t, idx, src)
			first := depsAt(fixedNow.Add(-time.Minute))
			if code, so, se := run(t, first, "activity", "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h"); code != 0 {
				t.Fatalf("first run exit %d\n%s\n%s", code, so, se)
			}
			editFile(t, filepath.Join(dir, "config", "behaviour.yaml"), "old-label", "new-label")
			args := []string{cmd, "--case", dir, "--config", "config/behaviour.yaml", "--window", "1h"}
			return testDeps(huntEnv), args, dir, []string{idx.srv.URL}
		}
	}
	down := func(cmd string, extra ...string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			idx := newFakeIndex(t, searchDocs())
			idx.status = 502
			dir := searchCase(t, idx)
			args := append([]string{cmd, "--case", dir, "--config", fpConfigRel, "--window", "1h"}, extra...)
			return testDeps(huntEnv), args, dir, []string{idx.srv.URL}
		}
	}
	noWindowCase := func(cmd string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			idx := newFakeIndex(t, searchDocs())
			dir := searchCase(t, idx)
			return testDeps(huntEnv), []string{cmd, "--case", dir, "--config", fpConfigRel}, dir, []string{idx.srv.URL}
		}
	}
	noCase := func(t *testing.T) (deps, []string, string, []string) {
		srv := fakeKibana(t, 200)
		cfg := writeConfig(t, srv.URL)
		dir := filepath.Dir(cfg)
		return testDeps(huntEnv), []string{"hunt", "--config", cfg, "--window", "1h"}, dir, []string{srv.URL}
	}
	storeOutside := func(cmd string) goldenBuild {
		return func(t *testing.T) (deps, []string, string, []string) {
			d, args, dir, urls := plain(cmd, "--window", "1h")(t)
			other := t.TempDir()
			editFile(t, filepath.Join(dir, fpConfigRel), `path: ""`, "path: "+filepath.Join(other, "elsewhere.duckdb"))
			return d, args, dir, append(urls, other)
		}
	}
	skipped := func(t *testing.T) (deps, []string, string, []string) {
		idx := newFakeIndex(t, searchDocs())
		dir := searchCase(t, idx)
		body := "sources:\n  - type: kibana\n    url: " + idx.srv.URL + "\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-http-*\n" +
			"detectors:\n  - type: behaviour\n    key_field: client_ip\n    path_field: path\n    method_field: method\n    status_field: status\n    actions:\n      - {name: login, class: common, path: /login, methods: [GET]}\n  - type: authspike\n    key_field: client_ip\n    status_field: status\nstore:\n  path: \"\"\n"
		if err := os.WriteFile(filepath.Join(dir, "config", "mixed.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		editFile(t, filepath.Join(dir, "case.yaml"), "config:\n", "config:\n  - config/mixed.yaml\n")
		return testDeps(huntEnv), []string{"activity", "--case", dir, "--config", "config/mixed.yaml", "--window", "1h"}, dir, []string{idx.srv.URL}
	}
	scenarios := []struct {
		name  string
		build goldenBuild
	}{
		{"hunt-table", plain("hunt", "--window", "1h")},
		{"hunt-json", plain("hunt", "--window", "1h", "--output", "json")},
		{"hunt-case-window", noWindowCase("hunt")},
		{"hunt-search-table", plain("hunt", "--search", "needle-token")},
		{"hunt-search-absent", plain("hunt", "--search", "no-such-term")},
		{"hunt-search-json", plain("hunt", "--search", "needle-token", "--search-field", "message", "--output", "json")},
		{"hunt-until-table", withUntil("hunt")},
		{"hunt-until-json", withUntil("hunt", "--output", "json")},
		{"hunt-no-store-table", plain("hunt", "--no-store")},
		{"hunt-no-store-json", plain("hunt", "--no-store", "--output", "json")},
		{"hunt-not-in-git", notInGit("hunt")},
		{"hunt-overlap", overlap("hunt")},
		{"hunt-incomplete-detector", partial("hunt")},
		{"hunt-incomplete-detector-json", partial("hunt", "--output", "json")},
		{"hunt-source-down", down("hunt")},
		{"hunt-no-case", noCase},
		{"hunt-store-outside-evidence", storeOutside("hunt")},
		{"activity-store-outside-evidence", storeOutside("activity")},
		{"activity-table", plain("activity", "--window", "1h")},
		{"activity-json", plain("activity", "--window", "1h", "--output", "json")},
		{"activity-default-window", noWindowCase("activity")},
		{"activity-until-table", withUntil("activity")},
		{"activity-until-json", withUntil("activity", "--output", "json")},
		{"activity-no-store", plain("activity", "--window", "1h", "--no-store")},
		{"activity-not-in-git", notInGit("activity")},
		{"activity-overlap", overlap("activity")},
		{"activity-active-with-gaps", partial("activity")},
		{"activity-active-with-gaps-json", partial("activity", "--output", "json")},
		{"activity-source-down", down("activity")},
		{"activity-skipped-detector", skipped},
	}
	dir := filepath.Join("testdata", "golden", "hunt-activity")
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tmp := scratchRoot(t)
			d, args, caseDir, urls := sc.build(t)
			code, stdout, stderr := run(t, d, args...)
			norm := func(s string) string {
				s = strings.ReplaceAll(s, caseDir, "<CASE>")
				s = strings.ReplaceAll(s, tmp, "<SCRATCH>")
				for _, u := range urls {
					s = strings.ReplaceAll(s, u, "<URL>")
				}
				return s
			}
			got := fmt.Sprintf("exit %d\n--- stdout\n%s--- stderr\n%s", code, norm(stdout), norm(stderr))
			path := filepath.Join(dir, sc.name+".golden")
			if *updateGolden {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("%s differs from the recorded output\n--- got\n%s\n--- want\n%s", sc.name, got, want)
			}
		})
	}
}
