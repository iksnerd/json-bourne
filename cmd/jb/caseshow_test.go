package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaseShowExampleJSON(t *testing.T) {
	d := testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey})
	code, stdout, stderr := run(t, d, "case", "show", "--case", exampleCase, "--config", "config/hunt.yaml", "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.Contains(stdout+stderr, secretKey) {
		t.Fatal("a credential value reached the output")
	}
	var got struct {
		Case, Config string
		Sources      []struct {
			Type, Name, URL, Index string
			CredentialEnv          string `json:"credential_env"`
		}
		Detectors []struct {
			Type    string
			Options map[string]any
		}
		Store struct{ Path string }
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if got.Case != "example-login-spray" || got.Config != "config/hunt.yaml" {
		t.Errorf("case/config = %q %q", got.Case, got.Config)
	}
	if len(got.Sources) != 1 || got.Sources[0].CredentialEnv != "JB_KIBANA_API_KEY" || got.Sources[0].Index != "logs-auth-*" {
		t.Errorf("sources = %+v", got.Sources)
	}
	if len(got.Detectors) != 1 || got.Detectors[0].Type != "authspike" || got.Detectors[0].Options["min_events"] != float64(20) {
		t.Errorf("detectors = %+v", got.Detectors)
	}
	if want := filepath.Join("examples", "case", "evidence", "jb.duckdb"); !filepath.IsAbs(got.Store.Path) || !strings.HasSuffix(got.Store.Path, want) {
		t.Errorf("store = %q, want an absolute path ending %q", got.Store.Path, want)
	}
}

func TestCaseShowTable(t *testing.T) {
	code, stdout, stderr := run(t, testDeps(nil), "case", "show", "--case", exampleCase, "--config", "config/hunt.yaml")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"example-login-spray", "kibana:logs-auth-*", "JB_KIBANA_API_KEY", "authspike", "min_events", "jb.duckdb"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestCaseShowUsageAndFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"no case":      {[]string{"case", "show"}, exitUsage},
		"positional":   {[]string{"case", "show", exampleCase}, exitUsage},
		"bad output":   {[]string{"case", "show", "--case", exampleCase, "--output", "xml"}, exitUsage},
		"unknown conf": {[]string{"case", "show", "--case", exampleCase, "--config", "nope.yaml"}, exitUsage},
		"missing case": {[]string{"case", "show", "--case", filepath.Join(t.TempDir(), "absent")}, exitFailure},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, testDeps(nil), tc.args...)
			if code != tc.code || stdout != "" || strings.Count(stderr, "jb:") != 1 {
				t.Errorf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCaseShowNeedsAConfigWhenSeveralAreListed(t *testing.T) {
	dir := copyExampleCase(t, "")
	editFile(t, filepath.Join(dir, "case.yaml"), "  - config/hunt.yaml", "  - config/hunt.yaml\n  - config/fingerprint.yaml")
	code, _, stderr := run(t, testDeps(nil), "case", "show", "--case", dir)
	if code != exitUsage || !strings.Contains(stderr, "--config") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr = run(t, testDeps(nil), "case", "show", "--case", dir, "--config", "config/fingerprint.yaml"); code != 0 {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}
