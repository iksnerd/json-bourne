package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// profileCfg is a hunt config with two sources and two detectors on the case's synthetic
// fake Kibana: one of each is on, one of each is switched off. The off source points at a
// second fake that counts requests, and names an API key variable that is never set, so a
// source that was built or asked anyway would fail loudly.
//
//	%[1]s  URL of the live fake      %[2]s  URL of the fake that must stay untouched
const profileCfg = `
sources:
  - type: kibana
    name: live
    url: %[1]s
    api_key_env: JB_KIBANA_API_KEY
    index: logs-auth-*
  - type: kibana
    name: standby
    enabled: false
    url: %[2]s
    api_key_env: JB_STANDBY_KEY_NEVER_SET
    index: logs-standby-*
detectors:
  - type: authspike
    name: spike
    key_field: client_ip
    status_field: status
    fail_statuses: [401, 403]
    min_events: 20
    min_failure_share_rise: 0.20
  - type: authspike
    name: spike-standby
    enabled: false
    key_field: client_ip
    status_field: status
    fail_statuses: [401, 403]
    min_events: 20
    min_failure_share_rise: 0.20
`

const profileRel = "config/profile.yaml"

// profileCase is a ready case with profileCfg as config/profile.yaml. live and off count
// the requests each fake Kibana served.
func profileCase(t *testing.T) (dir string, live, off func() int64) {
	t.Helper()
	srvA, a := fakeKibanaCounted(t, http.StatusOK)
	srvB, b := fakeKibanaCounted(t, http.StatusOK)
	dir = copyExampleCase(t, srvA.URL)
	gitInit(t, dir)
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	attack := fmt.Sprintf(profileCfg, srvA.URL, srvB.URL)
	writeProfile(t, dir, profileRel, attack)
	// health: the standby source on, the live one off, the other detector on.
	writeProfile(t, dir, healthRel, strings.NewReplacer(
		"    name: live\n", "    name: live\n    enabled: false\n",
		"    name: standby\n    enabled: false\n", "    name: standby\n",
		"    name: spike\n", "    name: spike\n    enabled: false\n",
		"    name: spike-standby\n    enabled: false\n", "    name: spike-standby\n",
	).Replace(attack))
	// A case with two configs asks for --config on every run, which is how profiles are chosen.
	editFile(t, filepath.Join(dir, "case.yaml"), "  - config/hunt.yaml\n", "  - "+profileRel+"\n  - "+healthRel+"\n")
	return dir, a.Load, b.Load
}

const healthRel = "config/health.yaml"

func writeProfile(t *testing.T, dir, rel, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const disabledLine = "DISABLED: source standby, detector spike-standby"

func TestHuntNeverContactsADisabledSourceAndListsWhatItSkipped(t *testing.T) {
	dir, live, off := profileCase(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", profileRel)
	if code != 0 {
		t.Fatalf("exit %d (a disabled source's unset key must not matter)\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if off() != 0 {
		t.Fatalf("the disabled source's server was asked %d time(s); it must never be contacted", off())
	}
	if live() == 0 {
		t.Fatal("the enabled source was never asked: the test proves nothing")
	}
	for name, out := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if !strings.Contains(out, disabledLine) {
			t.Errorf("%s does not list the disabled components (%q):\n%s", name, disabledLine, out)
		}
	}
	// Not a row, so never a status: a disabled source must not read as ok or quiet.
	if regexp.MustCompile(`(?m)^(standby|spike-standby)\s`).MatchString(stdout) {
		t.Errorf("a disabled component has a result row:\n%s", stdout)
	}
	if !strings.Contains(stdout, "192.0.2.7") {
		t.Errorf("the enabled detector did not run:\n%s", stdout)
	}
}

// The strongest form of "never contacted": the disabled source's credential is set and its
// server is up and full of data, and it is still not asked.
func TestDisabledSourceIsNotAskedEvenWithItsCredentialSet(t *testing.T) {
	dir, _, off := profileCase(t)
	env := map[string]string{"JB_KIBANA_API_KEY": secretKey, "JB_STANDBY_KEY_NEVER_SET": secretKey}
	for _, args := range [][]string{
		{"hunt", "--case", dir, "--config", profileRel},
		{"watch", "--case", dir, "--config", profileRel, "--once"},
	} {
		if code, stdout, stderr := run(t, testDeps(env), args...); code != 0 {
			t.Fatalf("%v: exit %d\n%s\n%s", args, code, stdout, stderr)
		}
	}
	if off() != 0 {
		t.Fatalf("the disabled source's server was asked %d time(s)", off())
	}
}

func TestHuntJSONListsDisabled(t *testing.T) {
	dir, _, off := profileCase(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--config", profileRel, "--output", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var out struct {
		Sources   []struct{ Name string }
		Detectors []struct{ Name string }
		Disabled  []struct{ Kind, Name string }
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sources) != 1 || len(out.Detectors) != 1 {
		t.Errorf("components = %d sources, %d detectors, want 1 and 1 (only the enabled ones)", len(out.Sources), len(out.Detectors))
	}
	want := []struct{ Kind, Name string }{{"source", "standby"}, {"detector", "spike-standby"}}
	if len(out.Disabled) != 2 || out.Disabled[0] != want[0] || out.Disabled[1] != want[1] {
		t.Errorf("disabled = %v, want %v", out.Disabled, want)
	}
	if off() != 0 {
		t.Errorf("disabled source contacted %d time(s)", off())
	}
}

// With nothing switched off the JSON has no "disabled" key at all: existing consumers see
// exactly what they saw before.
func TestHuntJSONHasNoDisabledKeyWhenNothingIsOff(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	_, stdout, stderr := run(t, testDeps(huntEnv), "hunt", "--case", dir, "--output", "json")
	if strings.Contains(stdout, "disabled") || strings.Contains(stderr, "DISABLED") {
		t.Errorf("output mentions disabled components though none are:\n%s\n%s", stdout, stderr)
	}
}

func TestWatchCycleLineAndBannerListDisabled(t *testing.T) {
	dir, _, off := profileCase(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--config", profileRel, "--once")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var cycle string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.Contains(l, " CYCLE ") {
			cycle = l
		}
	}
	if !strings.Contains(cycle, disabledLine) || !strings.Contains(cycle, "every enabled source and detector completed") {
		t.Errorf("cycle line does not state what was not read:\n%s", cycle)
	}
	if !strings.Contains(stderr, disabledLine) || !strings.Contains(stderr, "1 source(s), 1 detector(s)") {
		t.Errorf("banner does not list the disabled components or counts them in:\n%s", stderr)
	}
	if !strings.Contains(readEvidence(t, dir, "watch.log"), disabledLine) {
		t.Error("watch.log, the source of truth, lacks the DISABLED statement")
	}
	if off() != 0 {
		t.Errorf("disabled source contacted %d time(s) by watch", off())
	}
}

func TestActivityListsDisabledAndNeverAsksThem(t *testing.T) {
	idxLive := newFakeIndex(t, []doc{webDoc(cur(1), "OtherClient/1.0", "/login", 200, "203.0.113.10", "x")})
	idxOff := newFakeIndex(t, nil)
	dir := searchCase(t, idxLive)
	cfg := filepath.Join(dir, fpConfigRel)
	body, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	extra := fmt.Sprintf(`  - type: kibana
    name: standby
    enabled: false
    url: %s
    api_key_env: JB_STANDBY_KEY_NEVER_SET
    index: logs-standby-*
`, idxOff.srv.URL)
	s := strings.Replace(string(body), "\ndetectors:", "\n"+strings.TrimSuffix(extra, "\n")+"\n\ndetectors:", 1)
	if s == string(body) {
		t.Fatal("could not edit the fingerprint config")
	}
	if err := os.WriteFile(cfg, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	last := lastLine(stdout)
	if !strings.HasPrefix(last, "QUIET:") || !strings.Contains(last, "DISABLED: source standby") || !strings.Contains(last, "every enabled source and detector completed") {
		t.Errorf("the verdict line must say QUIET is about the enabled components only:\n%s", last)
	}
	if !strings.Contains(stderr, "DISABLED: source standby") {
		t.Errorf("stderr lacks the DISABLED line:\n%s", stderr)
	}
	if n := len(idxOff.requests()); n != 0 {
		t.Errorf("the disabled source was asked %d time(s)", n)
	}
	_, js, _ := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "1h", "--output", "json")
	if !strings.Contains(js, `"disabled"`) || !strings.Contains(js, `"standby"`) {
		t.Errorf("activity JSON lacks the disabled list:\n%s", js)
	}
}

func TestDoctorListsDisabledAndDoesNotRequireTheirKey(t *testing.T) {
	dir, _, off := profileCase(t)
	code, stdout, stderr := run(t, testDeps(huntEnv), "doctor", "--case", dir, "--config", profileRel)
	if code != 0 {
		t.Fatalf("exit %d (an unset key of a disabled source must not fail doctor)\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"source standby", "detector spike-standby", "DISABLED: enabled: false", "DISABLED  source standby"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("doctor output lacks %q:\n%s", want, stdout)
		}
	}
	if off() != 0 {
		t.Errorf("doctor contacted the disabled source %d time(s)", off())
	}
}

func TestCaseCheckReportsDisabledAsNotesNotFailures(t *testing.T) {
	dir, _, _ := profileCase(t)
	code, stdout, stderr := run(t, testDeps(nil), "case", "check", dir)
	if code != 0 {
		t.Fatalf("exit %d: a disabled entry is a note, not a failure\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{profileRel + ": OK", healthRel + ": OK", "note: DISABLED: source standby", "note: DISABLED: detector spike-standby", "note: DISABLED: source live"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("case check lacks %q:\n%s", want, stdout)
		}
	}
	_, js, _ := run(t, testDeps(nil), "case", "check", dir, "--output", "json")
	if !strings.Contains(js, `"notes"`) {
		t.Errorf("JSON lacks notes:\n%s", js)
	}
}

// The two profiles of one case: switching a source and a detector over is the only
// difference between them, and each run says what it left out.
func TestAttackAndHealthProfilesOnOneCase(t *testing.T) {
	dir, liveA, _ := profileCase(t)
	// the health profile's standby source needs a key: it is enabled now.
	env := map[string]string{"JB_KIBANA_API_KEY": secretKey, "JB_STANDBY_KEY_NEVER_SET": secretKey}
	before := liveA()
	code, stdout, stderr := run(t, testDeps(env), "hunt", "--case", dir, "--config", healthRel)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if liveA() != before {
		t.Errorf("health profile asked the attack profile's source %d time(s)", liveA()-before)
	}
	if !strings.Contains(stdout, "DISABLED: source live, detector spike") {
		t.Errorf("health profile does not list what it left out:\n%s", stdout)
	}
}
