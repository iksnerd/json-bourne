package main

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const exampleCase = "../../examples/case"

// copyExampleCase copies examples/case into a fresh temp directory, points its hunt
// config at kibanaURL, and returns the directory. The temp directory is not in a git
// work tree until a test runs gitInit.
func copyExampleCase(t *testing.T, kibanaURL string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(exampleCase, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(exampleCase, p)
		if e.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if kibanaURL != "" {
		editFile(t, filepath.Join(dst, "config", "hunt.yaml"), "https://kibana.example.com", kibanaURL)
	}
	return dst
}

// editFile replaces old with new once and fails if old is not there, so an edit that
// silently matched nothing cannot make a test pass for the wrong reason.
func editFile(t *testing.T, path, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s does not contain %q", path, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, new, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gitInit(t *testing.T, dir string) {
	t.Helper()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git init: %v: %s", err, out)
	}
}

// unignore removes the case's .gitignore, which leaves evidence/ exposed to git add.
func unignore(t *testing.T, dir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, ".gitignore")); err != nil {
		t.Fatal(err)
	}
}

func TestCaseCheckExample(t *testing.T) {
	// No environment at all: check must not need an API key.
	code, stdout, stderr := run(t, testDeps(nil), "case", "check", exampleCase)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"example-login-spray", "monitoring", "2026-11-01", "evidence: OK", "config/hunt.yaml: OK", "result"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if stderr != "" {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCaseCheckJSON(t *testing.T) {
	code, stdout, stderr := run(t, testDeps(nil), "case", "check", exampleCase, "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got caseReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if !got.OK || got.ID != "example-login-spray" || got.Status != "monitoring" || got.Opened != "2026-11-01" {
		t.Errorf("report = %+v", got)
	}
	if got.Guard == nil || !got.Guard.OK || got.Guard.Result == "" {
		t.Errorf("guard = %+v", got.Guard)
	}
	if len(got.Configs) != 1 || got.Configs[0].Path != "config/hunt.yaml" || !got.Configs[0].OK {
		t.Errorf("configs = %+v", got.Configs)
	}

	// A failing case is still valid JSON on stdout, with ok=false, and exits 1.
	bad := copyExampleCase(t, "")
	editFile(t, filepath.Join(bad, "case.yaml"), "passive_only: true", "passive_only: false")
	code, stdout, _ = run(t, testDeps(nil), "case", "check", bad, "--output", "json")
	if code != exitFailure {
		t.Fatalf("exit = %d, want 1", code)
	}
	var fail caseReport
	if err := json.Unmarshal([]byte(stdout), &fail); err != nil || fail.OK || !strings.Contains(fail.Error, "passive_only") {
		t.Errorf("failure report = %+v (%v)\n%s", fail, err, stdout)
	}
}

func TestCaseCheckGuardResultsAreDistinct(t *testing.T) {
	t.Run("not a git work tree", func(t *testing.T) {
		dir := copyExampleCase(t, "")
		code, stdout, stderr := run(t, testDeps(nil), "case", "check", dir)
		if code != 0 {
			t.Fatalf("exit %d: %s%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "(not a git work tree)") || strings.Contains(stdout, "(ignored)") {
			t.Errorf("stdout:\n%s", stdout)
		}
		if !strings.Contains(stdout, "run check again once the case is under git") {
			t.Errorf("no reminder that this is not a pass for later:\n%s", stdout)
		}
	})
	t.Run("ignored", func(t *testing.T) {
		dir := copyExampleCase(t, "")
		gitInit(t, dir)
		code, stdout, stderr := run(t, testDeps(nil), "case", "check", dir)
		if code != 0 {
			t.Fatalf("exit %d: %s%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "(ignored)") || strings.Contains(stdout, "not a git work tree") {
			t.Errorf("stdout:\n%s", stdout)
		}
	})
}

func TestCaseCheckFailures(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T) string
		wantStdout []string
		wantStderr string
	}{
		{"no case.yaml", func(t *testing.T) string { return t.TempDir() }, nil, "case.yaml"},
		{"no such directory", func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope") }, nil, "case directory"},
		{"passive_only false", func(t *testing.T) string {
			d := copyExampleCase(t, "")
			editFile(t, filepath.Join(d, "case.yaml"), "passive_only: true", "passive_only: false")
			return d
		}, nil, "passive_only"},
		{"evidence not ignored", func(t *testing.T) string {
			d := copyExampleCase(t, "")
			gitInit(t, d)
			unignore(t, d)
			return d
		}, []string{"evidence: FAIL", "not ignored", "result    FAIL"}, "not ignored"},
		{"config that does not load", func(t *testing.T) string {
			d := copyExampleCase(t, "")
			f, _ := os.OpenFile(filepath.Join(d, "config", "hunt.yaml"), os.O_APPEND|os.O_WRONLY, 0)
			defer f.Close()
			_, _ = f.WriteString("surprise: 1\n")
			return d
		}, []string{"config/hunt.yaml: FAIL", "surprise", "evidence: OK"}, "config/hunt.yaml"},
		{"config file missing", func(t *testing.T) string {
			d := copyExampleCase(t, "")
			if err := os.Remove(filepath.Join(d, "config", "hunt.yaml")); err != nil {
				t.Fatal(err)
			}
			return d
		}, nil, "config/hunt.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(nil), "case", "check", tc.setup(t))
			if code != exitFailure {
				t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			for _, w := range tc.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			if !strings.Contains(stderr, tc.wantStderr) || strings.Count(stderr, "jb:") != 1 {
				t.Errorf("stderr = %q, want it to contain %q once", stderr, tc.wantStderr)
			}
		})
	}
}

func TestCaseCheckNeverPrintsOrNeedsACredential(t *testing.T) {
	d := testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey})
	for _, out := range []string{"table", "json"} {
		code, stdout, stderr := run(t, d, "case", "check", exampleCase, "--output", out)
		if code != 0 || strings.Contains(stdout+stderr, secretKey) {
			t.Errorf("%s: code=%d, credential in output=%v", out, code, strings.Contains(stdout+stderr, secretKey))
		}
	}
}

func TestCaseUsageErrorsExitTwo(t *testing.T) {
	for name, args := range map[string][]string{
		"no directory":   {"case", "check"},
		"two directions": {"case", "check", "a", "b"},
		"bad output":     {"case", "check", exampleCase, "--output", "xml"},
		"unknown flag":   {"case", "check", exampleCase, "--nope"},
		"unknown sub":    {"case", "frobnicate"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(nil), args...)
			if code != exitUsage || stdout != "" || strings.Count(stderr, "jb:") != 1 {
				t.Errorf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// ---- jb hunt --case ----

var huntEnv = map[string]string{"JB_KIBANA_API_KEY": secretKey}

// readyCase is the example case, inside a git work tree that ignores evidence/,
// pointed at a fake Kibana.
func readyCase(t *testing.T) (dir string, served func() int64) {
	t.Helper()
	srv, n := fakeKibanaCounted(t, http.StatusOK)
	dir = copyExampleCase(t, srv.URL)
	gitInit(t, dir)
	return dir, n.Load
}

type huntJSON struct {
	Window   [2]time.Time `json:"window"`
	Complete bool         `json:"complete"`
	Findings []struct {
		Tag string `json:"tag"`
	} `json:"findings"`
}

func huntCase(t *testing.T, args ...string) (huntJSON, string, string, int) {
	t.Helper()
	code, stdout, stderr := run(t, testDeps(huntEnv), append([]string{"hunt", "--output", "json"}, args...)...)
	var got huntJSON
	if stdout != "" {
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
		}
	}
	if strings.Contains(stdout+stderr, secretKey) {
		t.Error("credential in output")
	}
	return got, stdout, stderr, code
}

func TestHuntCaseRefusesEvidenceNotIgnored(t *testing.T) {
	srv, served := fakeKibanaCounted(t, http.StatusOK)
	dir := copyExampleCase(t, srv.URL)
	gitInit(t, dir)
	unignore(t, dir)

	_, stdout, stderr, code := huntCase(t, "--case", dir)
	if code != exitFailure {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "refusing to hunt") || !strings.Contains(stderr, "not ignored") {
		t.Errorf("stderr = %q", stderr)
	}
	if served.Load() != 0 {
		t.Errorf("a refused hunt made %d request(s) to the source", served.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); err == nil {
		t.Error("a refused hunt created the store")
	}
	if stdout != "" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestHuntCaseRefusesAPassiveOnlyFalseCase(t *testing.T) {
	srv, served := fakeKibanaCounted(t, http.StatusOK)
	dir := copyExampleCase(t, srv.URL)
	gitInit(t, dir)
	editFile(t, filepath.Join(dir, "case.yaml"), "passive_only: true", "passive_only: false")

	_, _, stderr, code := huntCase(t, "--case", dir)
	if code != exitFailure || !strings.Contains(stderr, "passive_only") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if served.Load() != 0 {
		t.Errorf("a case with passive_only false reached the source (%d requests)", served.Load())
	}
}

func TestHuntCaseRunsWhenEvidenceIsIgnored(t *testing.T) {
	dir, served := readyCase(t)
	// The fake Kibana ignores the time filter and holds one hour of failures, so the
	// case's window is one hour to give the detector what it was built to see.
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	// A decoy default store: a case hunt must not use it.
	decoy := filepath.Join(t.TempDir(), "decoy.duckdb")
	t.Setenv("JB_DB", decoy)
	t.Setenv("HOME", t.TempDir())

	got, stdout, stderr, code := huntCase(t, "--case", dir)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !got.Complete || len(got.Findings) != 1 || !strings.Contains(got.Findings[0].Tag, "192.0.2.7") {
		t.Errorf("result = %+v", got)
	}
	if served() == 0 {
		t.Error("source was never queried")
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); err != nil {
		t.Errorf("store is not under the case's evidence directory: %v", err)
	}
	if _, err := os.Stat(decoy); err == nil {
		t.Error("JB_DB was used instead of the case's evidence directory")
	}
	if out, err := exec.Command("git", "-C", dir, "status", "--porcelain", "--ignored", "evidence").CombinedOutput(); err != nil || !strings.Contains(string(out), "!! evidence/") {
		t.Errorf("the store should show as ignored by git: %q (%v)", out, err)
	}
	// The table output is the plain hunt table.
	code, stdout, _ = run(t, testDeps(huntEnv), "hunt", "--case", dir)
	if code != 0 || !strings.Contains(stdout, "SOURCE") || !strings.Contains(stdout, "192.0.2.7") {
		t.Errorf("table output: code=%d\n%s", code, stdout)
	}
}

func TestHuntCaseWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		caseWin string // windows.default, "" keeps the example's 24h
		args    []string
		want    time.Duration
	}{
		{"from the case", "", nil, 24 * time.Hour},
		{"case in hours", "2h", nil, 2 * time.Hour},
		{"case in days", "7d", nil, 7 * 24 * time.Hour},
		{"explicit flag wins", "", []string{"--window", "90m"}, 90 * time.Minute},
		{"explicit flag wins over a long case window", "7d", []string{"--window", "30m"}, 30 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := readyCase(t)
			if tc.caseWin != "" {
				editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: "+tc.caseWin)
			}
			got, _, stderr, _ := huntCase(t, append([]string{"--case", dir}, tc.args...)...)
			if span := got.Window[1].Sub(got.Window[0]); span != tc.want {
				t.Errorf("window = %s, want %s\nstderr: %s", span, tc.want, stderr)
			}
			if !got.Window[1].Equal(fixedNow) {
				t.Errorf("window ends %s, want now (%s)", got.Window[1], fixedNow)
			}
		})
	}
}

func TestHuntCaseWithoutDefaultWindowKeepsFlagDefault(t *testing.T) {
	dir, _ := readyCase(t)
	editFile(t, filepath.Join(dir, "case.yaml"), "  default: 24h\n", "")
	got, _, _, _ := huntCase(t, "--case", dir)
	if span := got.Window[1].Sub(got.Window[0]); span != time.Hour {
		t.Errorf("window = %s, want the 1h flag default", span)
	}
}

func TestHuntCaseStorePath(t *testing.T) {
	t.Run("relative path is relative to the case, not the cwd", func(t *testing.T) {
		dir, _ := readyCase(t)
		editFile(t, filepath.Join(dir, "config", "hunt.yaml"), `path: ""`, `path: "evidence/custom.duckdb"`)
		elsewhere := t.TempDir()
		t.Chdir(elsewhere)
		_, stdout, stderr, code := huntCase(t, "--case", dir)
		if code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
		}
		if _, err := os.Stat(filepath.Join(dir, "evidence", "custom.duckdb")); err != nil {
			t.Errorf("store not under the case directory: %v", err)
		}
		if _, err := os.Stat(filepath.Join(elsewhere, "evidence")); err == nil {
			t.Error("store was resolved against the working directory")
		}
		if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); err == nil {
			t.Error("the evidence default was used although the config set a path")
		}
		if strings.Contains(stderr, "outside the case's evidence directory") {
			t.Errorf("unexpected warning for a store inside evidence/: %q", stderr)
		}
	})
	t.Run("a store outside evidence/ is used and flagged", func(t *testing.T) {
		dir, _ := readyCase(t)
		editFile(t, filepath.Join(dir, "config", "hunt.yaml"), `path: ""`, `path: "scratch/jb.duckdb"`)
		_, _, stderr, code := huntCase(t, "--case", dir)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if _, err := os.Stat(filepath.Join(dir, "scratch", "jb.duckdb")); err != nil {
			t.Error(err)
		}
		if !strings.Contains(stderr, "outside the case's evidence directory") {
			t.Errorf("no warning that git ignore is unchecked for this store: %q", stderr)
		}
	})
}

func TestHuntCaseConfigSelection(t *testing.T) {
	second := func(t *testing.T, dir string) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, "config", "hunt.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config", "second.yaml"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		editFile(t, filepath.Join(dir, "case.yaml"), "  - config/hunt.yaml\n", "  - config/hunt.yaml\n  - config/second.yaml\n")
	}

	t.Run("several configs and none chosen is a usage error that lists them", func(t *testing.T) {
		dir, served := readyCase(t)
		second(t, dir)
		_, stdout, stderr, code := huntCase(t, "--case", dir)
		if code != exitUsage || stdout != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "config/hunt.yaml") || !strings.Contains(stderr, "config/second.yaml") {
			t.Errorf("stderr does not list the choices: %q", stderr)
		}
		if served() != 0 {
			t.Error("an ambiguous hunt reached the source")
		}
	})
	t.Run("a listed config can be chosen", func(t *testing.T) {
		dir, _ := readyCase(t)
		second(t, dir)
		_, _, stderr, code := huntCase(t, "--case", dir, "--config", "config/second.yaml")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})
	t.Run("a file inside the case but not listed can be chosen", func(t *testing.T) {
		dir, _ := readyCase(t)
		b, _ := os.ReadFile(filepath.Join(dir, "config", "hunt.yaml"))
		extra := filepath.Join(dir, "notes", "adhoc.yaml")
		if err := os.WriteFile(extra, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, stderr, code := huntCase(t, "--case", dir, "--config", extra)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})
	t.Run("a relative path is relative to the case, from any working directory", func(t *testing.T) {
		dir, _ := readyCase(t)
		b, _ := os.ReadFile(filepath.Join(dir, "config", "hunt.yaml"))
		draft := filepath.Join(dir, "config", "drafts", "x.yaml")
		if err := os.MkdirAll(filepath.Dir(draft), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(draft, b, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Chdir(t.TempDir())
		_, _, stderr, code := huntCase(t, "--case", dir, "--config", "config/drafts/x.yaml")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})
	t.Run("a relative path that leaves the case is refused", func(t *testing.T) {
		dir, served := readyCase(t)
		t.Chdir(t.TempDir())
		_, _, stderr, code := huntCase(t, "--case", dir, "--config", "../hunt.yaml")
		if code != exitUsage {
			t.Errorf("code=%d stderr=%q", code, stderr)
		}
		if served() != 0 {
			t.Error("reached the source")
		}
	})
	t.Run("a config outside the case is refused", func(t *testing.T) {
		dir, served := readyCase(t)
		outside := writeConfig(t, "https://kibana.example.com")
		_, _, stderr, code := huntCase(t, "--case", dir, "--config", outside)
		if code != exitUsage || !strings.Contains(stderr, "outside the case directory") {
			t.Errorf("code=%d stderr=%q", code, stderr)
		}
		if served() != 0 {
			t.Error("reached the source")
		}
	})
	t.Run("a missing file is a usage error", func(t *testing.T) {
		dir, _ := readyCase(t)
		_, _, stderr, code := huntCase(t, "--case", dir, "--config", "config/nope.yaml")
		if code != exitUsage || !strings.Contains(stderr, "not one of the case's configs") {
			t.Errorf("code=%d stderr=%q", code, stderr)
		}
	})
}

func TestHuntCaseBadCaseIsNotAUsageError(t *testing.T) {
	_, _, stderr, code := huntCase(t, "--case", t.TempDir())
	if code != exitFailure || !strings.Contains(stderr, "case.yaml") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

// Without --case, hunt behaves exactly as before.
func TestHuntPlainConfigUnchanged(t *testing.T) {
	if f := newHuntCmd().Flags().Lookup("case"); f == nil || f.DefValue != "" {
		t.Fatalf("--case flag = %+v", f)
	}
	srv := fakeKibana(t, http.StatusOK)
	cfg := writeConfig(t, srv.URL)
	// The relative store path of a plain hunt is relative to the working directory.
	editFile(t, cfg, "path: "+filepath.Join(filepath.Dir(cfg), "jb.duckdb"), "path: rel/plain.duckdb")
	cwd := t.TempDir()
	t.Chdir(cwd)

	got, _, stderr, code := huntCase(t, "--config", cfg)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if span := got.Window[1].Sub(got.Window[0]); span != time.Hour {
		t.Errorf("default window = %s, want 1h", span)
	}
	if _, err := os.Stat(filepath.Join(cwd, "rel", "plain.duckdb")); err != nil {
		t.Errorf("plain --config store is no longer cwd-relative: %v", err)
	}
	if strings.Contains(stderr, "note:") || strings.Contains(stderr, "from the case") {
		t.Errorf("case messages in a plain hunt: %q", stderr)
	}
	// A plain hunt never runs the git guard: it works from a directory with no case.
	if code, _, _ := run(t, testDeps(huntEnv), "hunt", "--config", cfg, "--window", "60m"); code != 0 {
		t.Errorf("explicit --window: exit %d", code)
	}
}

func TestCaseCheckReportsEstate(t *testing.T) {
	code, stdout, stderr := run(t, testDeps(nil), "case", "check", exampleCase)
	if code != 0 || !strings.Contains(stdout, "estate") || !strings.Contains(stdout, "example-estate") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	_, js, _ := run(t, testDeps(nil), "case", "check", exampleCase, "--output", "json")
	var got caseReport
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatal(err)
	}
	if got.Estate == nil || !got.Estate.OK || len(got.Estate.IDs) != 1 || got.Estate.IDs[0] != "example-estate" {
		t.Errorf("estate = %+v", got.Estate)
	}
}

func TestCaseCheckFailsOnABrokenEstateFile(t *testing.T) {
	for name, edit := range map[string][2]string{
		"missing method": {"    method: \"GET https://rdap.example.com/ip/192.0.2.10\"\n    observed: 2026-11-06T10:00:01Z\nedges:", "    observed: 2026-11-06T10:00:01Z\nedges:"},
		"active source":  {"source: rdap\n    method: \"GET https://rdap.example.com/ip/192.0.2.10\"\n    observed: 2026-11-06T10:00:01Z\nedges:", "source: nmap\n    method: \"-sV\"\n    observed: 2026-11-06T10:00:01Z\nedges:"},
		"empty caveat":   {"", ""},
		"dangling edge":  {"    to: network:net-192-0-2-0-1\n", "    to: network:gone\n"},
	} {
		t.Run(name, func(t *testing.T) {
			d := copyExampleCase(t, "")
			if name == "empty caveat" {
				editFile(t, filepath.Join(d, "estate", "example-estate.yaml"), "caveat: This map shows infrastructure ownership and relationships as public registries and DNS describe them. It does not show who typed the commands, and a CDN edge address says nothing about the visitor behind it.", "caveat: \"\"")
			} else {
				editFile(t, filepath.Join(d, "estate", "example-estate.yaml"), edit[0], edit[1])
			}
			code, stdout, stderr := run(t, testDeps(nil), "case", "check", d)
			if code != exitFailure || !strings.Contains(stdout, "estate") || !strings.Contains(stdout, "FAIL") || !strings.Contains(stderr, "example-estate.yaml") {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
		})
	}
}
