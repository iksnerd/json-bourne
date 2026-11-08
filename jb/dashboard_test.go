package jb_test

import (
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/jb"
)

// dashCase copies the example case into a temp dir.
func dashCase(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir("../examples/case", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("../examples/case", p)
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
	if out, err := exec.Command("git", "-C", dst, "init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git init: %v: %s", err, out)
	}
	return dst
}

func seedDash(t *testing.T, dir string) {
	t.Helper()
	st, err := duckdb.Open(filepath.Join(dir, "evidence", "jb.duckdb"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveFindings(context.Background(), "watch-1", []core.Finding{{Detector: "authspike", Tag: "spray:192.0.2.7",
		Severity: core.SevHigh, Summary: `192.0.2.7 <script>alert(1)</script>`}}); err != nil {
		t.Fatal(err)
	}
}

// writerCanOpen proves no reader holds the store: a read-write open succeeds.
func writerCanOpen(t *testing.T, dir string) {
	t.Helper()
	st, err := duckdb.Open(filepath.Join(dir, "evidence", "jb.duckdb"), false)
	if err != nil {
		t.Fatalf("a writer cannot open the store, so a handle is still open: %v", err)
	}
	st.Close()
}

func do(t *testing.T, h http.Handler, method, target, host string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func assertSecure(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("%s: CSP %q lacks %q", what, csp, want)
		}
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s: security headers missing: %v", what, rec.Header())
	}
}

func TestDashboardHandlerCarriesTheSecurityModel(t *testing.T) {
	dir := dashCase(t)
	seedDash(t, dir)
	h, info, err := jb.DashboardHandler(jb.DashboardOptions{Case: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(info.Store, "jb.duckdb") || info.Evidence != filepath.Join(dir, "evidence") {
		t.Errorf("info = %+v", info)
	}
	rec := do(t, h, "GET", "/findings", "localhost:8090")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "&lt;script&gt;") || strings.Contains(rec.Body.String(), "<script>alert") {
		t.Fatalf("findings: %d %s", rec.Code, rec.Body)
	}
	assertSecure(t, rec, "GET")
	if rec := do(t, h, "POST", "/findings", "localhost:8090"); rec.Code != 405 || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST: %d %v", rec.Code, rec.Header())
	} else {
		assertSecure(t, rec, "POST")
	}
	if rec := do(t, h, "GET", "/", "evil.example.com"); rec.Code != 421 {
		t.Errorf("foreign Host: %d", rec.Code)
	} else {
		assertSecure(t, rec, "foreign host")
	}
	writerCanOpen(t, dir) // every request closed its handle
}

// The v2 example estate (facts and an assessment) renders through the real handler, and
// the assessment is marked as opinion.
func TestDashboardRendersTheV2EstateFactsAndAssessments(t *testing.T) {
	dir := dashCase(t)
	seedDash(t, dir)
	h, _, err := jb.DashboardHandler(jb.DashboardOptions{Case: dir})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "GET", "/estate/node?g=example-estate&id=ip:192.0.2.10", "localhost:8090")
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, body)
	}
	for _, want := range []string{"tls.cn", "port.open", "scan-cache", "Assessments (opinion)", "example-analyst", "watch"} {
		if !strings.Contains(body, want) {
			t.Errorf("node record lacks %q:\n%s", want, body)
		}
	}
}

func TestDashboardHandlerKeepsItsRulesWhenMounted(t *testing.T) {
	dir := dashCase(t)
	seedDash(t, dir)
	h, _, err := jb.DashboardHandler(jb.DashboardOptions{Case: dir})
	if err != nil {
		t.Fatal(err)
	}
	outer := http.NewServeMux()
	outer.Handle("/jb/", http.StripPrefix("/jb", h))
	outer.HandleFunc("/other", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "app") })

	rec := do(t, outer, "GET", "/jb/findings", "127.0.0.1:9000")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "spray:192.0.2.7") {
		t.Fatalf("mounted GET: %d %s", rec.Code, rec.Body)
	}
	assertSecure(t, rec, "mounted GET")
	if rec := do(t, outer, "DELETE", "/jb/findings", "127.0.0.1:9000"); rec.Code != 405 {
		t.Errorf("mounted DELETE: %d", rec.Code)
	}
	if rec := do(t, outer, "GET", "/jb/", "evil.example.com"); rec.Code != 421 {
		t.Errorf("mounted foreign Host: %d", rec.Code)
	}
	writerCanOpen(t, dir)
}

func TestDashboardHandlerOnAMissingStoreFailsVisiblyAndHoldsNoHandle(t *testing.T) {
	dir := dashCase(t) // no store seeded
	h, _, err := jb.DashboardHandler(jb.DashboardOptions{Case: dir})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "GET", "/", "localhost")
	assertSecure(t, rec, "missing store")
	if rec.Code == 200 && !strings.Contains(strings.ToLower(rec.Body.String()), "no evidence database") {
		t.Errorf("a missing store looks clean: %d %s", rec.Code, rec.Body)
	}
	writerCanOpen(t, dir) // creating the store still works: the failed request left nothing open
}

func TestDashboardHandlerRefusesBadInput(t *testing.T) {
	dir := dashCase(t)
	if _, _, err := jb.DashboardHandler(jb.DashboardOptions{}); !jb.IsUsage(err) {
		t.Errorf("neither case nor config: %v is not a usage error", err)
	}
	if _, _, err := jb.DashboardHandler(jb.DashboardOptions{Case: dir, Config: "nope.yaml"}); err == nil {
		t.Error("unknown config accepted")
	}
}

func TestServeRefusesANonLoopbackBind(t *testing.T) {
	dir := dashCase(t)
	for _, a := range []string{"0.0.0.0:0", ":0", "192.0.2.1:8090", "[::]:0"} {
		called := false
		err := jb.Serve(context.Background(), jb.ServeOptions{Dashboard: jb.DashboardOptions{Case: dir}, Addr: a,
			Ready: func(jb.ServeInfo) { called = true }})
		if !jb.IsUsage(err) || called {
			t.Errorf("%s: err=%v ready=%v", a, err, called)
		}
	}
}

func TestServeRunsOnLoopbackUntilTheContextEnds(t *testing.T) {
	dir := dashCase(t)
	seedDash(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan jb.ServeInfo, 1)
	done := make(chan error, 1)
	go func() {
		done <- jb.Serve(ctx, jb.ServeOptions{Dashboard: jb.DashboardOptions{Case: dir}, Addr: "localhost:0",
			Ready: func(i jb.ServeInfo) { ready <- i }})
	}()
	var info jb.ServeInfo
	select {
	case info = <-ready:
	case err := <-done:
		t.Fatalf("Serve returned early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("never ready")
	}
	host, port, err := net.SplitHostPort(info.Addr)
	if err != nil || host != "127.0.0.1" || port == "0" || info.Remote {
		t.Fatalf("info = %+v", info)
	}
	resp, err := http.Get("http://" + info.Addr + "/findings")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "spray:192.0.2.7") || resp.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("GET: %d %s", resp.StatusCode, b)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil on a context end", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not stop")
	}
	writerCanOpen(t, dir)
}

func TestServeAllowRemoteReportsRemote(t *testing.T) {
	dir := dashCase(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan jb.ServeInfo, 1)
	done := make(chan error, 1)
	go func() {
		done <- jb.Serve(ctx, jb.ServeOptions{Dashboard: jb.DashboardOptions{Case: dir}, Addr: "0.0.0.0:0", AllowRemote: true,
			Ready: func(i jb.ServeInfo) { ready <- i }})
	}()
	select {
	case i := <-ready:
		if !i.Remote {
			t.Errorf("Remote not set: %+v", i)
		}
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("never ready")
	}
	cancel()
	<-done
}
