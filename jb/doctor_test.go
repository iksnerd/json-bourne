package jb

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const doctorSecret = "s3cr3t-value-0123456789"

func envOf(m map[string]string) Env {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// doctorCase is a case whose configs point at a local server that counts requests.
func doctorCase(t *testing.T) (dir string, requests *atomic.Int64, host string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // no operator plugin allowlist
	t.Setenv("JB_PLUGINS_FILE", filepath.Join(t.TempDir(), "absent.yaml"))
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { n.Add(1) }))
	t.Cleanup(srv.Close)
	dir = copyCase(t)
	for _, f := range []string{"config/hunt.yaml", "config/fingerprint.yaml"} {
		p := filepath.Join(dir, f)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(b), "https://kibana.example.com", srv.URL)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitInit(t, dir)
	return dir, &n, strings.TrimPrefix(srv.URL, "http://")
}

func (r *DoctorResult) status(group, contains string) CheckStatus {
	for _, c := range r.Checks {
		if c.Group == group && strings.Contains(c.Name, contains) {
			return c.Status
		}
	}
	return "(none)"
}

func TestDoctorChecksACaseAndSaysWhatItDidNotCheck(t *testing.T) {
	dir, served, _ := doctorCase(t)
	r, err := Doctor(context.Background(), DoctorOptions{Case: dir, Env: envOf(map[string]string{"JB_KIBANA_API_KEY": doctorSecret})})
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() || r.Failed() != 0 {
		t.Fatalf("checks = %+v", r.Checks)
	}
	for group, want := range map[string]CheckStatus{"build": CheckOK, "case": CheckOK, "config": CheckOK, "env": CheckOK, "online": CheckSkipped} {
		if got := r.status(group, ""); got != want {
			t.Errorf("%s = %s, want %s", group, got, want)
		}
	}
	if r.Complete() || r.Skipped() == 0 {
		t.Errorf("online and the store file were not checked, so the result is not complete: skipped %d", r.Skipped())
	}
	if served.Load() != 0 {
		t.Errorf("doctor reached the network without Online: %d request(s)", served.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "jb.duckdb")); err == nil {
		t.Error("doctor created the store")
	}
	out, _ := json.Marshal(r)
	if strings.Contains(string(out), doctorSecret) {
		t.Fatal("credential in the result")
	}
}

func TestDoctorFailsOnAnUnsetVariable(t *testing.T) {
	dir, _, _ := doctorCase(t)
	r, err := Doctor(context.Background(), DoctorOptions{Case: dir, Env: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if r.OK() || r.Failed() == 0 || r.status("env", "JB_KIBANA_API_KEY") != CheckFail || r.Complete() {
		t.Fatalf("checks = %+v", r.Checks)
	}
}

func TestDoctorOnlineConnectsAndSendsNothing(t *testing.T) {
	dir, served, host := doctorCase(t)
	env := envOf(map[string]string{"JB_KIBANA_API_KEY": doctorSecret})
	r, err := Doctor(context.Background(), DoctorOptions{Case: dir, Config: "config/hunt.yaml", Online: true, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.status("online", host); got != CheckOK {
		t.Fatalf("online %s = %s\n%+v", host, got, r.Checks)
	}
	if served.Load() != 0 {
		t.Errorf("a request reached the server, doctor must send no bytes: %d", served.Load())
	}
}

func TestDoctorOnlineFailsOnAHostThatDoesNotAnswer(t *testing.T) {
	dir, _, host := doctorCase(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	l.Close()
	p := filepath.Join(dir, "config", "hunt.yaml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(b), host, dead)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envOf(map[string]string{"JB_KIBANA_API_KEY": doctorSecret})
	r, err := Doctor(context.Background(), DoctorOptions{Case: dir, Config: "config/hunt.yaml", Online: true, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	if r.OK() || r.status("online", dead) != CheckFail {
		t.Fatalf("checks = %+v", r.Checks)
	}
}

func TestDoctorWithNothingToCheckIsNotComplete(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("JB_PLUGINS_FILE", filepath.Join(t.TempDir(), "absent.yaml"))
	r, err := Doctor(context.Background(), DoctorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() || r.Complete() {
		t.Errorf("no case and no config: nothing failed, but not everything was checked: %+v", r.Checks)
	}
}

func TestDoctorReturnsTheContextErrorWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Doctor(ctx, DoctorOptions{})
	if err == nil || r == nil {
		t.Fatalf("a canceled doctor must say so: %v %v", r, err)
	}
}

func TestDoctorResultHealthMethods(t *testing.T) {
	r := DoctorResult{Checks: []DoctorCheck{{Status: CheckOK}, {Status: CheckWarn}}}
	if !r.OK() || !r.Complete() || r.Failed() != 0 || r.Skipped() != 0 {
		t.Errorf("ok and warn: %+v", r)
	}
	r.Checks = append(r.Checks, DoctorCheck{Status: CheckSkipped})
	if !r.OK() || r.Complete() || r.Skipped() != 1 {
		t.Errorf("a skip is not a fail and not complete: %+v", r)
	}
	r.Checks = append(r.Checks, DoctorCheck{Status: CheckFail})
	if r.OK() || r.Failed() != 1 {
		t.Errorf("a fail: %+v", r)
	}
}

func TestDoctorResultMarshalsWithOKAndNeverNull(t *testing.T) {
	out, err := json.Marshal(DoctorResult{})
	if err != nil || string(out) != `{"ok":true,"checks":[],"services":[]}` {
		t.Errorf("%s %v", out, err)
	}
}
