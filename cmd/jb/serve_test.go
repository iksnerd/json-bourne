package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

var listenRE = regexp.MustCompile(`listening on (http://[^/ ]+)/`)

// startServe runs `jb serve args...` and returns its base URL and a stop function that
// returns the exit code.
func startServe(t *testing.T, d deps, args ...string) (base string, stderr *syncBuf, stop func() int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out, errb := &syncBuf{}, &syncBuf{}
	done := make(chan int, 1)
	go func() { done <- executeWith(ctx, d, append([]string{"serve"}, args...), out, errb) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := listenRE.FindStringSubmatch(out.String()); m != nil {
			base = m[1]
			break
		}
		select {
		case code := <-done:
			cancel()
			t.Fatalf("serve exited %d before listening\nstdout: %s\nstderr: %s", code, out, errb)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if base == "" {
		cancel()
		t.Fatalf("serve never listened\nstderr: %s", errb)
	}
	var once sync.Once
	var code int
	stop = func() int {
		once.Do(func() {
			cancel()
			select {
			case code = <-done:
			case <-time.After(10 * time.Second):
				t.Error("serve did not stop on context cancel")
				code = -1
			}
		})
		return code
	}
	t.Cleanup(func() { stop() })
	return base, errb, stop
}

func fetch(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const hostilePath = `/x"onmouseover="alert(1)<script>alert(1)</script>?token=1`

func seedStore(t *testing.T, dir string) {
	t.Helper()
	st, err := duckdb.Open(filepath.Join(dir, "evidence", "jb.duckdb"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)
	ev := func(i int, path string) core.Event {
		return core.Event{Time: at.Add(time.Duration(i) * time.Second), Source: "kibana:logs-auth-*", Kind: "request",
			Fields: map[string]any{"path": path, "status": float64(401), "client_ip": "192.0.2.7", "user_agent": `UA "onmouseover="x <script>`}}
	}
	ctx := context.Background()
	evs := []core.Event{ev(0, hostilePath), ev(1, "/token?a=1"), ev(2, "/token?a=2")}
	if err := st.SaveEvents(ctx, "watch-1/kibana:logs-auth-*", func(y func(core.Event, error) bool) {
		for _, e := range evs {
			if !y(e, nil) {
				return
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveFindings(ctx, "watch-1", []core.Finding{{Detector: "authspike", Tag: "spray:192.0.2.7", Severity: core.SevHigh,
		Summary: `192.0.2.7 <script>alert(1)</script> "onmouseover="x`}}); err != nil {
		t.Fatal(err)
	}
}

func serveCase(t *testing.T) string {
	t.Helper()
	dir := copyExampleCase(t, "https://kibana.example.com")
	gitInit(t, dir)
	return dir
}

func TestServeRequiresASourceAndRefusesNonLoopback(t *testing.T) {
	d := testDeps(nil)
	if code, _, stderr := run(t, d, "serve"); code != exitUsage || !strings.Contains(stderr, "--case") {
		t.Errorf("no source: exit %d, %s", code, stderr)
	}
	dir := serveCase(t)
	for _, a := range []string{"0.0.0.0:8090", ":8090", "192.0.2.1:8090", "[::]:8090"} {
		code, stdout, stderr := run(t, d, "serve", "--case", dir, "--addr", a)
		if code != exitUsage || !strings.Contains(stderr, "--allow-remote") || strings.Contains(stdout, "listening") {
			t.Errorf("--addr %s: exit %d\nstdout %s\nstderr %s", a, code, stdout, stderr)
		}
	}
}

func TestServeAllowRemoteWarnsLoudly(t *testing.T) {
	dir := serveCase(t)
	_, stderr, stop := startServe(t, testDeps(nil), "--case", dir, "--addr", "0.0.0.0:0", "--allow-remote")
	if !strings.Contains(stderr.String(), "WARNING") || !strings.Contains(stderr.String(), "NO authentication") {
		t.Errorf("remote bind without a loud warning: %s", stderr)
	}
	if code := stop(); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

func TestServeCaseEndToEnd(t *testing.T) {
	dir := serveCase(t)
	// The example config names JB_KIBANA_API_KEY; give it a value to prove neither
	// the name nor the value can reach a page.
	d := testDeps(map[string]string{"JB_KIBANA_API_KEY": secretKey})
	base, _, stop := startServe(t, d, "--case", dir, "--addr", "127.0.0.1:0")
	dbPath := filepath.Join(dir, "evidence", "jb.duckdb")

	// 1. No database yet: say so, and never create it.
	code, body := fetch(t, base+"/")
	if code != 200 || !strings.Contains(body, "no evidence database") {
		t.Fatalf("absent store: %d\n%s", code, body)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Fatal("serve created the database")
	}

	// 2. Seed it while the server runs: the handle is per request, so a writer is never locked out.
	seedStore(t, dir)
	pages := []string{"/", "/run?id=watch-1", "/findings", "/reputation", "/watch", "/estate",
		"/estate/node?g=example-estate&id=ip:192.0.2.10", "/estate/edge?g=example-estate&i=0"}
	bodies := map[string]string{}
	for _, p := range pages {
		code, b := fetch(t, base+p)
		if code != 200 {
			t.Fatalf("%s = %d\n%s", p, code, b)
		}
		bodies[p] = b
		for _, bad := range []string{"<script", `"onmouseover=`, secretKey, "JB_KIBANA_API_KEY", "api_key"} {
			if strings.Contains(b, bad) {
				t.Errorf("%s contains %q", p, bad)
			}
		}
	}
	if !strings.Contains(bodies["/"], "watch-1") {
		t.Errorf("runs page lacks the seeded run:\n%s", bodies["/"])
	}
	run := bodies["/run?id=watch-1"]
	if !strings.Contains(run, "<td>/token</td><td>2</td>") || !strings.Contains(run, "&lt;script&gt;") {
		t.Errorf("run page: top paths must be grouped without the query string and the hostile path shown escaped:\n%s", run)
	}
	if !strings.Contains(bodies["/estate"], "192.0.2.10") || !strings.Contains(bodies["/estate"], "rdns") {
		t.Errorf("estate:\n%s", bodies["/estate"])
	}
	if !strings.Contains(bodies["/watch"], "no alert log") {
		t.Errorf("no watch has run in this case, the page must say so:\n%s", bodies["/watch"])
	}

	// 3. A request that tries to carry SQL is just an unknown id, and the data is intact.
	for _, q := range []string{"/run?id=x%27%3B+DROP+TABLE+events%3B--", "/run?id=watch-1%27+OR+1%3D1", "/run?sql=DROP+TABLE+events&id=watch-1"} {
		fetch(t, base+q)
	}
	if code, b := fetch(t, base+"/run?id=x%27%3B+DROP+TABLE+events%3B--"); code != 404 {
		t.Errorf("injection id = %d\n%s", code, b)
	}
	resp, err := http.Post(base+"/run?id=watch-1", "text/plain", strings.NewReader("DROP TABLE events"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", resp.StatusCode)
	}
	// 4. The writer can open the file between requests, and every row is still there.
	rw, err := duckdb.Open(dbPath, false)
	if err != nil {
		t.Fatalf("a writer could not open the file while serve is running: %v", err)
	}
	stats, err := rw.Stats()
	rw.Close()
	if err != nil || stats.Events != 3 || stats.Findings != 1 {
		t.Errorf("stats after the attack attempts = %+v, %v", stats, err)
	}
	if stop() != exitOK {
		t.Error("serve did not exit cleanly")
	}
}

func TestServeWatchLogAndStateAreShown(t *testing.T) {
	dir := serveCase(t)
	seedStore(t, dir)
	line := "2026-11-05T12:00:00Z CYCLE watch-1 CYCLE INCOMPLETE: 1 component(s) did not finish [kibana:x], gap=false; this is not a quiet result (0 new findings)\n"
	os.WriteFile(filepath.Join(dir, "evidence", "watch.log"), []byte(line), 0o600)
	os.WriteFile(filepath.Join(dir, "evidence", "watch-state.json"), []byte(`{"version":1,"seen":{}}`+"\ngarbage"), 0o600)
	base, _, _ := startServe(t, testDeps(nil), "--case", dir, "--addr", "127.0.0.1:0")
	_, w := fetch(t, base+"/watch")
	if !strings.Contains(w, "CYCLE INCOMPLETE") || !strings.Contains(w, "not healthy") || !strings.Contains(w, "corrupt") {
		t.Errorf("watch page:\n%s", w)
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "watch-state.json")); err != nil {
		t.Errorf("serve touched the corrupt state file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence", "watch-state.json.corrupt")); err == nil {
		t.Error("serve moved the state file aside: that is the watcher's decision")
	}
}

func TestServeConfigModeHasNoEstateAndNeedsNoCredential(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "jb.duckdb")
	cfg := writeConfig(t, "https://kibana.example.com")
	editFile(t, cfg, "path: ", "path: "+db+" #")
	st, err := duckdb.Open(db, false)
	if err != nil {
		t.Fatal(err)
	}
	st.Migrate()
	st.Close()
	base, _, _ := startServe(t, testDeps(nil), "--config", cfg, "--addr", "127.0.0.1:0")
	if code, b := fetch(t, base+"/estate"); code != 200 || !strings.Contains(b, "estate is not available") {
		t.Errorf("estate: %d\n%s", code, b)
	}
	if code, b := fetch(t, base+"/"); code != 200 || !strings.Contains(b, "no runs yet") {
		t.Errorf("runs: %d\n%s", code, b)
	}
}

func TestServeIsListedInHelp(t *testing.T) {
	_, stdout, _ := run(t, testDeps(nil), "serve", "--help")
	for _, w := range []string{"--allow-remote", "--addr", "NO authentication", defaultServeAddr} {
		if !strings.Contains(stdout, w) {
			t.Errorf("help lacks %q", w)
		}
	}
	_ = fmt.Sprint
}
