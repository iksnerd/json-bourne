package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const secret = "s3cr3t-value-0123456789"

func envOf(m map[string]string) Env {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

const valid = `
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-auth-*
detectors:
  - type: authspike
    key_field: client_ip
    status_field: status
store:
  path: /tmp/jb-test.duckdb
`

func TestExampleFileLoadsAndBuilds(t *testing.T) {
	f, err := Load(filepath.Join("..", "..", "examples", "jb.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Sources) != 1 || len(f.Detectors) != 1 {
		t.Fatalf("sources=%d detectors=%d", len(f.Sources), len(f.Detectors))
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	var _ core.Source = rt.Sources[0]
	if got := rt.Sources[0].Name(); got != "kibana:logs-auth-*" {
		t.Errorf("source name = %q", got)
	}
	if got := rt.Detectors[0].Name(); got != "authspike" {
		t.Errorf("detector name = %q", got)
	}
}

func TestExampleFileHoldsNoRealLookingValues(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "jb.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "http") && !strings.Contains(line, "example.com") {
			t.Errorf("non-placeholder URL: %q", line)
		}
	}
}

func TestBuildFailsWhenEnvVarMissingAndNeverEchoesValue(t *testing.T) {
	f, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]Env{
		"unset": envOf(nil),
		"empty": envOf(map[string]string{"JB_KIBANA_API_KEY": ""}),
	} {
		t.Run(name, func(t *testing.T) {
			rt, err := f.Build(env)
			if err == nil {
				t.Fatalf("Build succeeded without a key: %+v", rt)
			}
			if !strings.Contains(err.Error(), "JB_KIBANA_API_KEY") {
				t.Errorf("error does not name the variable: %v", err)
			}
		})
	}
	// Set under a different name: still missing, and the other value stays out of the error.
	_, err = f.Build(envOf(map[string]string{"OTHER": secret}))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("err = %v", err)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"unknown top-level key": valid + "extra: 1\n",
		"unknown source key":    strings.Replace(valid, "index: logs-auth-*", "index: logs-auth-*\n    api_key: "+secret, 1),
		"unknown detector key":  strings.Replace(valid, "key_field: client_ip", "key_field: client_ip\n    kye_field: x", 1),
		"unknown source type":   strings.Replace(valid, "type: kibana", "type: splunk", 1),
		"unknown detector type": strings.Replace(valid, "type: authspike", "type: magic", 1),
		"missing type":          strings.Replace(valid, "  - type: kibana\n", "  - {}\n", 1),
		"http url":              strings.Replace(valid, "https://kibana.example.com", "http://kibana.example.com", 1),
		"url credentials":       strings.Replace(valid, "https://kibana.example.com", "https://user:pw@kibana.example.com", 1),
		"key pasted as env":     strings.Replace(valid, "JB_KIBANA_API_KEY", "abc123SecretKey==", 1),
		"no index":              strings.Replace(valid, "    index: logs-auth-*\n", "", 1),
		"bad detector option":   strings.Replace(valid, "status_field: status", "status_field: status\n    min_failure_share_rise: 7", 1),
		"no sources":            "detectors:\n  - type: authspike\n    key_field: a\n    status_field: b\n",
		"no detectors":          strings.SplitN(valid, "detectors:", 2)[0],
		"empty":                 "",
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(y))
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error echoes the pasted value: %v", err)
			}
		})
	}
}

func TestParseUnknownTypeListsKnownOnes(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(valid, "type: kibana", "type: splunk", 1)))
	if err == nil || !strings.Contains(err.Error(), "kibana") || !strings.Contains(err.Error(), "splunk") {
		t.Errorf("err = %v", err)
	}
}

func TestLoopbackHTTPAllowed(t *testing.T) {
	y := strings.Replace(valid, "https://kibana.example.com", "http://127.0.0.1:5601", 1)
	if _, err := Parse([]byte(y)); err != nil {
		t.Errorf("loopback http refused: %v", err)
	}
}

func TestStorePath(t *testing.T) {
	f, _ := Parse([]byte(valid))
	if f.StorePath() != "/tmp/jb-test.duckdb" {
		t.Errorf("StorePath = %q", f.StorePath())
	}
	t.Setenv("JB_DB", "/tmp/from-env.duckdb")
	f, _ = Parse([]byte(strings.Replace(valid, "path: /tmp/jb-test.duckdb", "path: \"\"", 1)))
	if f.StorePath() != "/tmp/from-env.duckdb" {
		t.Errorf("default StorePath = %q", f.StorePath())
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected an error")
	}
}
