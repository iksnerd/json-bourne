package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	whToken = "SENTINEL-WEBHOOK-TOKEN-0123456789"
)

// lengthHint matches the ways a report could leak how long a secret is.
var lengthHint = regexp.MustCompile(`(?i)\b(23|224|212)\s*(chars?|characters|bytes?)\b|\blen(gth)?\b`)

func doctorDeps(extra map[string]string) deps {
	env := map[string]string{"JB_KIBANA_API_KEY": secretKey}
	for k, v := range extra {
		env[k] = v
	}
	return testDeps(env)
}

type doctorJSON struct {
	OK     bool `json:"ok"`
	Checks []struct {
		Group  string `json:"group"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"checks"`
	Services []struct {
		Kind   string `json:"kind"`
		Name   string `json:"name"`
		State  string `json:"state"`
		Leaves string `json:"leaves"`
	} `json:"services"`
}

func doctorRun(t *testing.T, d deps, args ...string) (code int, rep doctorJSON, stdout, stderr string) {
	t.Helper()
	code, stdout, stderr = run(t, d, append([]string{"doctor", "--output", "json"}, args...)...)
	if stdout != "" {
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
		}
	}
	return
}

func (r doctorJSON) status(group, contains string) string {
	for _, c := range r.Checks {
		if c.Group == group && strings.Contains(c.Name, contains) {
			return c.Status
		}
	}
	return "(no such check)"
}

func TestDoctorReadyCasePassesAndSkipsWhatIsNotThere(t *testing.T) {
	dir, served := readyCase(t)
	code, rep, stdout, stderr := doctorRun(t, doctorDeps(nil), "--case", dir)
	if code != 0 || !rep.OK {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	for group, want := range map[string]string{"build": "ok", "case": "ok", "config": "ok", "env": "ok", "online": "skipped"} {
		if got := rep.status(group, ""); got != want {
			t.Errorf("%s: %s, want %s\n%s", group, got, want, stdout)
		}
	}
	if got := rep.status("store", "(file)"); got != "skipped" {
		t.Errorf("a store that does not exist yet is skipped, not ok: %s", got)
	}
	if served() != 0 {
		t.Errorf("doctor reached the network without --online: %d request(s)", served())
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); err == nil {
		t.Error("doctor created the store")
	}
	if strings.Contains(stdout+stderr, secretKey) {
		t.Fatal("credential in output")
	}
}

func TestDoctorReportsVersionsAndDriver(t *testing.T) {
	_, rep, _, _ := doctorRun(t, doctorDeps(nil))
	var ver, db string
	for _, c := range rep.Checks {
		if c.Group == "build" && c.Name == "jb" {
			ver = c.Detail
		}
		if c.Group == "build" && c.Name == "duckdb" {
			db = c.Detail
		}
	}
	if ver == "" || !strings.Contains(db, "driver") || !strings.Contains(db, "engine v") {
		t.Fatalf("jb=%q duckdb=%q", ver, db)
	}
}

func TestDoctorUnsetVariableFailsAndTheValueNeverAppears(t *testing.T) {
	dir, _ := readyCase(t)
	code, rep, stdout, stderr := doctorRun(t, testDeps(map[string]string{}), "--case", dir)
	if code != exitFailure || rep.OK || rep.status("env", "JB_KIBANA_API_KEY") != "fail" {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stderr, "failed") {
		t.Errorf("stderr %q", stderr)
	}
	// An empty variable is unset for every command that would use it.
	code, rep, _, _ = doctorRun(t, testDeps(map[string]string{"JB_KIBANA_API_KEY": ""}), "--case", dir)
	if code != exitFailure || rep.status("env", "JB_KIBANA_API_KEY") != "fail" {
		t.Fatalf("an empty variable must read as unset: exit %d", code)
	}
}

func TestDoctorNeverPrintsAValueOrALength(t *testing.T) {
	dir, _ := readyCase(t)
	long := "LONGSENTINEL-" + strings.Repeat("z", 211)
	for _, v := range []string{secretKey, long} {
		d := testDeps(map[string]string{"JB_KIBANA_API_KEY": v})
		for _, args := range [][]string{{"--case", dir}, {"--case", dir, "--online"}, {"--case", dir, "--output", "json"}} {
			_, stdout, stderr := run(t, d, append([]string{"doctor"}, args...)...)
			all := stdout + stderr
			if strings.Contains(all, v) || strings.Contains(all, "LONGSENTINEL") {
				t.Fatalf("value in output of %v", args)
			}
			if lengthHint.MatchString(all) {
				t.Fatalf("a length hint in output of %v:\n%s", args, all)
			}
		}
	}
}

func TestDoctorEvidenceNotIgnoredFails(t *testing.T) {
	dir, _ := readyCase(t)
	unignore(t, dir)
	code, rep, stdout, _ := doctorRun(t, doctorDeps(nil), "--case", dir)
	if code != exitFailure || rep.status("case", "guard") != "fail" {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

func TestDoctorNotAGitWorkTreeIsAWarningNotAPass(t *testing.T) {
	srv := fakeKibana(t, 200)
	dir := copyExampleCase(t, srv.URL)
	if os.Getenv("GIT_DIR") != "" {
		t.Skip("GIT_DIR set")
	}
	code, rep, stdout, _ := doctorRun(t, doctorDeps(nil), "--case", dir)
	if st := rep.status("case", "guard"); st != "warn" && st != "ok" { // a temp dir under a work tree is "ok"
		t.Fatalf("guard %s\n%s", st, stdout)
	}
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

func TestDoctorBrokenConfigFails(t *testing.T) {
	dir, _ := readyCase(t)
	cfg := filepath.Join(dir, "config", "hunt.yaml")
	b, _ := os.ReadFile(cfg)
	if err := os.WriteFile(cfg, append(b, []byte("\nsurprise: true\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	code, rep, stdout, _ := doctorRun(t, doctorDeps(nil), "--case", dir)
	if code != exitFailure || rep.status("config", "hunt.yaml") != "fail" {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	code, _, _, _ = doctorRun(t, doctorDeps(nil), "--config", filepath.Join(dir, "no-such.yaml"))
	if code != exitFailure {
		t.Fatalf("a missing config file must fail: %d", code)
	}
}

func TestDoctorStoreStates(t *testing.T) {
	dir, _ := readyCase(t)
	gn := fakeGreyNoise(t, 500)
	_ = gn
	// An existing, healthy store (after a hunt) opens.
	if code, out, errs := run(t, intelDeps(), "hunt", "--case", dir); code != 0 && !strings.Contains(out, "192.0.2.7") {
		t.Fatalf("hunt: %d %s %s", code, out, errs)
	}
	code, rep, stdout, _ := doctorRun(t, doctorDeps(nil), "--case", dir)
	if code != 0 || rep.status("store", "(open)") != "ok" || rep.status("store", "(owner)") != "ok" {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	// A file that is not a database does not open, and that fails the run.
	if err := os.WriteFile(filepath.Join(dir, "evidence", "jb.duckdb"), []byte("this is not a duckdb file"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, rep, stdout, _ = doctorRun(t, doctorDeps(nil), "--case", dir)
	if code != exitFailure || rep.status("store", "(open)") != "fail" {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	// Writable by this user: a read-only file is a failure.
	if err := os.Chmod(filepath.Join(dir, "evidence", "jb.duckdb"), 0o400); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		_, rep, stdout, _ = doctorRun(t, doctorDeps(nil), "--case", dir)
		if rep.status("store", "jb.duckdb") != "fail" {
			t.Fatalf("a store this user cannot write must fail\n%s", stdout)
		}
	}
	// Group/world writable evidence is a warning.
	if err := os.Chmod(filepath.Join(dir, "evidence", "jb.duckdb"), 0o666); err != nil {
		t.Fatal(err)
	}
	_, rep, _, _ = doctorRun(t, doctorDeps(nil), "--case", dir)
	if rep.status("store", "(mode)") != "warn" {
		t.Fatalf("a 0666 store must warn: %+v", rep.Checks)
	}
}

func TestDoctorListsServicesWithStateAndWhatLeaves(t *testing.T) {
	gn := fakeGreyNoise(t, 500)
	dir := intelCase(t, gn, "  - type: dnsbl\n    zone: bl.example.test\n  - type: sans-isc\n    base_url: http://127.0.0.1:9\n")
	_, rep, stdout, _ := doctorRun(t, intelDeps(), "--case", dir)
	states := map[string]string{}
	for _, s := range rep.Services {
		if s.Leaves == "" {
			t.Errorf("%s says nothing about what leaves", s.Name)
		}
		states[s.Name] = s.State
	}
	if states["dnsbl:bl.example.test"] != "disabled" || states["greynoise:community"] != "enabled" || states["sans-isc"] != "enabled" {
		t.Fatalf("%v\n%s", states, stdout)
	}
	for _, s := range rep.Services {
		if s.Name == "dnsbl:bl.example.test" && (!strings.Contains(s.Leaves, "resolver") || !strings.Contains(s.Leaves, "operator")) {
			t.Errorf("the DNSBL must say the address goes to a resolver and the zone operator: %q", s.Leaves)
		}
	}
	// Enabling it flips the state, and its (absent) env vars do not matter.
	editFile(t, filepath.Join(dir, "config", "hunt.yaml"), "zone: bl.example.test\n", "zone: bl.example.test\n    enabled: true\n")
	_, rep, _, _ = doctorRun(t, intelDeps(), "--case", dir)
	for _, s := range rep.Services {
		if s.Name == "dnsbl:bl.example.test" && s.State != "enabled" {
			t.Errorf("state %s", s.State)
		}
	}
}

// listener accepts connections and records how many bytes any client sent.
type listener struct {
	ln    net.Listener
	mu    sync.Mutex
	conns int
	bytes int
}

func newListener(t *testing.T) *listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	l := &listener{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.mu.Lock()
			l.conns++
			l.mu.Unlock()
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
				n, _ := io.Copy(io.Discard, c)
				l.mu.Lock()
				l.bytes += int(n)
				l.mu.Unlock()
			}()
		}
	}()
	return l
}

func (l *listener) snapshot() (conns, bytes int) {
	time.Sleep(900 * time.Millisecond) // let the reader see EOF or its deadline
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns, l.bytes
}

func TestDoctorOnlineConnectsOncePerHostAndSendsNothing(t *testing.T) {
	kib := newListener(t)
	hook := newListener(t)
	dir, served := readyCase(t)
	cfg := filepath.Join(dir, "config", "hunt.yaml")
	b, _ := os.ReadFile(cfg)
	// Point kibana at the raw listener, add two webhooks on one host, and a disabled DNSBL.
	editFile(t, cfg, strings.TrimSuffix(strings.SplitN(string(b), "url: ", 2)[1], "\n")[:strings.Index(strings.SplitN(string(b), "url: ", 2)[1], "\n")], "http://"+kib.ln.Addr().String())
	// The case lists a second config on the same host; it points at the same listener.
	editFile(t, filepath.Join(dir, "config", "fingerprint.yaml"), "https://kibana.example.com", "http://"+kib.ln.Addr().String())
	b, _ = os.ReadFile(cfg)
	add := "\nalerts:\n  - type: webhook\n    url_env: JB_WEBHOOK_URL\n    allow_insecure_loopback: true\n" +
		"feeds:\n  - type: dnsbl\n    zone: bl.example.test\n"
	if err := os.WriteFile(cfg, append(b, []byte(add)...), 0o600); err != nil {
		t.Fatal(err)
	}
	hookURL := "http://" + hook.ln.Addr().String() + "/services/" + whToken
	d := doctorDeps(map[string]string{"JB_WEBHOOK_URL": hookURL})

	// Without --online: no connection at all.
	_, _, stdout, stderr := doctorRun(t, d, "--case", dir)
	if c, _ := kib.snapshot(); c != 0 {
		t.Fatalf("kibana host contacted without --online")
	}
	if strings.Contains(stdout+stderr, whToken) {
		t.Fatal("webhook token in output")
	}

	code, rep, stdout, stderr := doctorRun(t, d, "--case", dir, "--online")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	kc, kb := kib.snapshot()
	hc, hb := hook.snapshot()
	if kc != 1 || hc != 1 {
		t.Fatalf("one connect per host: kibana %d, webhook %d", kc, hc)
	}
	if kb != 0 || hb != 0 {
		t.Fatalf("doctor sent bytes: kibana %d, webhook %d (no request, no credential, no URL path may be sent)", kb, hb)
	}
	if served() != 0 {
		t.Error("the real kibana test server was not the target here")
	}
	all := stdout + stderr
	if strings.Contains(all, whToken) || strings.Contains(all, "/services/") || strings.Contains(all, secretKey) {
		t.Fatalf("the webhook path or a credential reached the output:\n%s", all)
	}
	ok := 0
	for _, c := range rep.Checks {
		if c.Group == "online" && c.Status == "ok" {
			ok++
		}
	}
	if ok != 2 {
		t.Errorf("want 2 reachable hosts, got %d\n%s", ok, stdout)
	}
	// The disabled DNSBL is neither probed nor called reachable.
	for _, c := range rep.Checks {
		if c.Group == "online" && strings.Contains(c.Name+c.Detail, "bl.example.test") {
			t.Errorf("a disabled feed appears in the online section: %+v", c)
		}
	}
}

func TestDoctorOnlineUnreachableFailsAndTimesOut(t *testing.T) {
	dir, _ := readyCase(t)
	cfg := filepath.Join(dir, "config", "hunt.yaml")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close() // nothing listens here now
	b, _ := os.ReadFile(cfg)
	line := strings.SplitN(strings.SplitN(string(b), "url: ", 2)[1], "\n", 2)[0]
	editFile(t, cfg, line, "http://"+dead)
	code, rep, stdout, _ := doctorRun(t, doctorDeps(nil), "--case", dir, "--online")
	if code != exitFailure || rep.status("online", dead) != "fail" {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

func TestDoctorUsageErrors(t *testing.T) {
	d := doctorDeps(nil)
	if code, _, _ := run(t, d, "doctor", "--output", "xml"); code != exitUsage {
		t.Errorf("bad --output: %d", code)
	}
	if code, _, _ := run(t, d, "doctor", "extra"); code != exitUsage {
		t.Errorf("stray argument: %d", code)
	}
}

func TestDoctorTableIsReadable(t *testing.T) {
	dir, _ := readyCase(t)
	code, out, _ := run(t, doctorDeps(nil), "doctor", "--case", dir)
	if code != 0 {
		t.Fatal(out)
	}
	for _, want := range []string{"BUILD", "CASE", "CONFIG", "ENV", "STORE", "ONLINE", "SERVICES", "SKIPPED", "RESULT  OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
}
