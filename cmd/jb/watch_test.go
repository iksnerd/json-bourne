package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// watchCase is a ready case whose window is the one hour the fake Kibana holds.
func watchCase(t *testing.T, status int) (dir string, served func() int64) {
	t.Helper()
	srv, n := fakeKibanaCounted(t, status)
	dir = copyExampleCase(t, srv.URL)
	gitInit(t, dir)
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	return dir, n.Load
}

func readEvidence(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "evidence", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWatchOnceSurfacesThenDedupes(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)

	code, stdout, stderr := run(t, d, "watch", "--case", dir, "--once")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"ALERT [", "192.0.2.7", "CYCLE FINDINGS: 1 new"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout+stderr, secretKey) {
		t.Error("credential in output")
	}
	if !strings.Contains(readEvidence(t, dir, "watch.log"), "192.0.2.7") || !strings.Contains(readEvidence(t, dir, "watch-state.json"), "192.0.2.7") {
		t.Error("log or state missing the finding")
	}

	// Same condition, a minute later: held back, and the cycle says it was quiet.
	d.now = func() time.Time { return fixedNow.Add(time.Minute) }
	code, stdout, stderr = run(t, d, "watch", "--case", dir, "--once")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.Contains(stdout, "ALERT [") || !strings.Contains(stdout, "CYCLE QUIET") || !strings.Contains(stdout, "1 held back by ttl") {
		t.Errorf("second cycle:\n%s", stdout)
	}
	if n := strings.Count(readEvidence(t, dir, "watch.log"), "ALERT ["); n != 1 {
		t.Errorf("log holds %d alerts, want 1", n)
	}
}

// A source that cannot be reached must not look like a quiet network: not in the
// output, not in the log and not in the exit code.
func TestWatchOnceUnavailableSourceIsIncompleteNotQuiet(t *testing.T) {
	dir, _ := watchCase(t, http.StatusBadGateway)
	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once")
	if code != exitFailure {
		t.Fatalf("exit %d, want 1\nstdout: %s", code, stdout)
	}
	if !strings.Contains(stdout, "CYCLE INCOMPLETE") || strings.Contains(stdout, "QUIET") {
		t.Errorf("stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[c:watch-incomplete]") || !strings.Contains(readEvidence(t, dir, "watch.log"), "watch-incomplete") {
		t.Errorf("no incomplete alert on stdout and in the log:\n%s", stdout)
	}
	if !strings.Contains(stderr, "no clean result") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestWatchOnceCorruptStateStillWatches(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence", "watch-state.json"), []byte(`{"version":1,"seen":{},"junk":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once")
	if code != exitFailure {
		t.Fatalf("exit %d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "watch-state-load") || !strings.Contains(stdout, "192.0.2.7") {
		t.Errorf("a corrupt state must be reported and the hunt still run:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "watch-state.json.corrupt")); err != nil {
		t.Errorf("corrupt state not kept: %v", err)
	}
}

func TestWatchUsageErrors(t *testing.T) {
	dir, served := watchCase(t, http.StatusOK)
	d := testDeps(huntEnv)
	for name, args := range map[string][]string{
		"no case":                 {"watch", "--once"},
		"window below interval":   {"watch", "--case", dir, "--once", "--every", "10m", "--window", "5m"},
		"case window below every": {"watch", "--case", dir, "--once", "--every", "2h"},
		"zero interval":           {"watch", "--case", dir, "--every", "0s"},
		"stray argument":          {"watch", "--case", dir, "extra"},
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
}

func TestWatchLoopRunsUntilInterruptedAndExitsClean(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	code := executeWith(ctx, testDeps(huntEnv), []string{"watch", "--case", dir, "--every", "1h"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if strings.Count(out.String(), "CYCLE FINDINGS") != 1 {
		t.Errorf("expected exactly one cycle before the interrupt:\n%s", out.String())
	}
}
