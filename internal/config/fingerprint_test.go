package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

const fpHead = `
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
detectors:
`

func fpConfig(detector string) string { return fpHead + detector }

const fpValid = `  - type: fingerprint
    actors: [example-actor.yaml]
    ignore_ips: [198.51.100.7, 198.51.100.64/28]
`

func exampleCase(t *testing.T) *casefile.Case {
	t.Helper()
	c, err := casefile.Load(filepath.Join("..", "..", "examples", "case"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFingerprintLoadsAndBuildsInACase(t *testing.T) {
	f, err := Parse([]byte(fpConfig(fpValid)))
	if err != nil {
		t.Fatal(err)
	}
	f.UseCase(exampleCase(t))
	ds, err := f.BuildDetectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 || ds[0].Name() != "fingerprint" {
		t.Fatalf("%v", ds)
	}
	// Build needs the environment for the source; the detector side must not change that.
	if _, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret})); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintNeedsACase(t *testing.T) {
	f, err := Parse([]byte(fpConfig(fpValid)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.BuildDetectors()
	if err == nil || !strings.Contains(err.Error(), "case") {
		t.Fatalf("an actors file lives in a case: got %v", err)
	}
}

func TestFingerprintRejectsAtLoad(t *testing.T) {
	for name, tc := range map[string]struct{ det, want string }{
		"unknown key":   {"  - type: fingerprint\n    actors: [a.yaml]\n    user_agent: x\n", "user_agent"},
		"no actors":     {"  - type: fingerprint\n", "actors"},
		"empty actors":  {"  - type: fingerprint\n    actors: []\n", "actors"},
		"dotdot":        {"  - type: fingerprint\n    actors: [../case.yaml]\n", "'..'"},
		"absolute":      {"  - type: fingerprint\n    actors: [/etc/passwd.yaml]\n", "absolute"},
		"not yaml":      {"  - type: fingerprint\n    actors: [a.txt]\n", ".yaml"},
		"twice":         {"  - type: fingerprint\n    actors: [a.yaml, a.yaml]\n", "twice"},
		"bad ignore ip": {"  - type: fingerprint\n    actors: [a.yaml]\n    ignore_ips: [edge]\n", "ignore_ips"},
		"bad name":      {"  - type: fingerprint\n    name: Has Space\n    actors: [a.yaml]\n", "name"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(fpConfig(tc.det)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestFingerprintBuildReportsBrokenActorFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"),
		[]byte("apiVersion: jb.case/v1\nid: t\ntitle: t\nstatus: open\nopened: 2026-11-01\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "actors"), 0o750); err != nil {
		t.Fatal(err)
	}
	// Valid as an actor file, but the detector refuses it: the grant path holds a noise marker.
	doc := `apiVersion: jb.actor/v1
id: actor-x
label: X
confidence: low
indicators:
  - kind: user_agent
    value: InventedAgent/1.0
detection:
  noise_paths: ["/token"]
  grant_paths: ["/realms/x/token"]
`
	if err := os.WriteFile(filepath.Join(dir, "actors", "x.yaml"), []byte(doc), 0o640); err != nil {
		t.Fatal(err)
	}
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse([]byte(fpConfig("  - type: fingerprint\n    actors: [x.yaml]\n")))
	if err != nil {
		t.Fatal(err)
	}
	f.UseCase(c)
	if _, err := f.BuildDetectors(); err == nil || !strings.Contains(err.Error(), "noise marker") {
		t.Fatalf("got %v", err)
	}
	// A missing file is an error naming the file.
	f, _ = Parse([]byte(fpConfig("  - type: fingerprint\n    actors: [missing.yaml]\n")))
	f.UseCase(c)
	if _, err := f.BuildDetectors(); err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("got %v", err)
	}
}

func TestFingerprintActorWithoutUserAgentIsRefused(t *testing.T) {
	// An actor with only an ip indicator would match nothing: a detector that can never
	// fire reads as a clean network.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"),
		[]byte("apiVersion: jb.case/v1\nid: t\ntitle: t\nstatus: open\nopened: 2026-11-01\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "actors"), 0o750); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: jb.actor/v1\nid: ip-only\nlabel: L\nconfidence: low\nindicators:\n  - kind: ip\n    value: 192.0.2.1\n"
	if err := os.WriteFile(filepath.Join(dir, "actors", "ip.yaml"), []byte(doc), 0o640); err != nil {
		t.Fatal(err)
	}
	c, _ := casefile.Load(dir)
	f, _ := Parse([]byte(fpConfig("  - type: fingerprint\n    actors: [ip.yaml]\n")))
	f.UseCase(c)
	if _, err := f.BuildDetectors(); err == nil || !strings.Contains(err.Error(), "user agent") {
		t.Fatalf("got %v", err)
	}
}
