//go:build unix

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
)

// envRunMain makes the test binary run the real main() with these arguments (joined by
// a unit separator) instead of the tests. That gives the signal tests a real jb
// process, with the real signal.NotifyContext in main(), without a `go build`.
const envRunMain = "JB_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if a := os.Getenv(envRunMain); a != "" {
		os.Args = append([]string{"jb"}, strings.Split(a, "\x1f")...)
		main() // exits
		return
	}
	code := m.Run()
	cleanupPluginBins()
	os.Exit(code)
}

// recentKibana serves synthetic events dated around the real clock (the subprocess
// uses it), shaped like fakeKibana: 192.0.2.7 fails 40 of 50 requests in the last hour and none in the hour
// before. When hold is non-nil each request first signals started, then blocks until
// the client goes away or hold closes.
func recentKibana(t *testing.T, hold chan struct{}, started chan struct{}) *httptest.Server {
	t.Helper()
	now := time.Now().UTC()
	var hits []map[string]any
	add := func(at time.Time, ip string, i, st int) {
		hits = append(hits, map[string]any{
			"_id": fmt.Sprintf("d%d-%s-%d", at.UnixNano(), ip, i), "sort": []any{at.UnixMilli(), fmt.Sprint(i)},
			"_source": map[string]any{"@timestamp": at.Format(time.RFC3339Nano), "client_ip": ip, "status": st, "path": "/token"},
		})
	}
	for i := range 50 {
		st := 401
		if i >= 40 {
			st = 200
		}
		prev, cur := now.Add(-2*time.Hour+time.Duration(i+2)*time.Minute), now.Add(-time.Hour+time.Duration(i+2)*time.Minute)
		add(prev, "192.0.2.7", i, 200)
		add(cur, "192.0.2.7", i, st)
		add(prev, "192.0.2.99", i, 200) // a healthy neighbour: the detector needs a population to compare with
		add(cur, "192.0.2.99", i, 200)
	}
	var once atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hold != nil {
			// Read the request body first: the server notices a client that went away
			// only once the body is consumed, and r.Context() would never end otherwise.
			_, _ = io.Copy(io.Discard, r.Body)
			if once.CompareAndSwap(false, true) {
				close(started)
			}
			select {
			case <-r.Context().Done():
				return
			case <-hold:
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rawResponse": map[string]any{
			"hits": map[string]any{"total": map[string]any{"value": len(hits)}, "hits": hits},
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startJB starts the real jb as a subprocess and streams its stdout lines to a channel.
func startJB(t *testing.T, args ...string) (*exec.Cmd, <-chan string, *strings.Builder) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), envRunMain+"="+strings.Join(args, "\x1f"), "JB_KIBANA_API_KEY="+secretKey)
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd, lines, stderr
}

func waitLine(t *testing.T, lines <-chan string, contains string) []string {
	t.Helper()
	var seen []string
	deadline := time.After(30 * time.Second)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("jb exited before printing %q; output so far: %q", contains, seen)
			}
			seen = append(seen, l)
			if strings.Contains(l, contains) {
				return seen
			}
		case <-deadline:
			t.Fatalf("no %q within 30s; output so far: %q", contains, seen)
		}
	}
}

// exitCode waits for the process; a hung shutdown fails the test instead of the run.
func exitCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode() // -1 when killed by a signal
		}
		t.Fatal(err)
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("jb did not exit within 20s of the signal")
	}
	return -2
}

var logLine = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z (ALERT \[[a-z]+\] \[c:.*\]|CYCLE) `)

// assertEvidenceIntact is what "not corrupted" means after an interrupted watch: the
// state file is absent or strictly valid, no half-written temp file is left, the log
// holds whole alert lines only, and the store still opens and holds a schema.
func assertEvidenceIntact(t *testing.T, dir string) {
	t.Helper()
	ev := filepath.Join(dir, "evidence")
	if _, err := (watchstate.Store{Path: filepath.Join(ev, watchStateFile)}).Load(context.Background()); err != nil {
		t.Errorf("watch state after the signal: %v", err)
	}
	if m, _ := filepath.Glob(filepath.Join(ev, "*.tmp-*")); len(m) > 0 {
		t.Errorf("temporary state files left behind: %v", m)
	}
	if m, _ := filepath.Glob(filepath.Join(ev, "*.corrupt")); len(m) > 0 {
		t.Errorf("state was moved aside as corrupt: %v", m)
	}
	if b, err := os.ReadFile(filepath.Join(ev, watchLogFile)); err == nil {
		if len(b) > 0 && b[len(b)-1] != '\n' {
			t.Errorf("watch.log ends mid-line: %q", b[max(0, len(b)-80):])
		}
		for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if l != "" && !logLine.MatchString(l) {
				t.Errorf("malformed watch.log line: %q", l)
			}
		}
	}
	st, err := duckdb.Open(filepath.Join(ev, "jb.duckdb"), true)
	if err != nil {
		t.Errorf("the store does not open after the signal: %v", err)
		return
	}
	defer st.Close()
	if _, err := st.Stats(); err != nil {
		t.Errorf("store stats: %v", err)
	}
}

func signalCase(t *testing.T, kibanaURL string) string {
	t.Helper()
	dir := copyExampleCase(t, kibanaURL)
	gitInit(t, dir)
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	return dir
}

// Between cycles: one cycle has completed and the loop sleeps for an hour. The signal
// must end it at once, with exit 0 and everything on disk whole.
func TestWatchSignalBetweenCyclesExitsCleanly(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"SIGINT": syscall.SIGINT, "SIGTERM": syscall.SIGTERM} {
		t.Run(name, func(t *testing.T) {
			dir := signalCase(t, recentKibana(t, nil, nil).URL)
			cmd, lines, stderr := startJB(t, "watch", "--case", dir, "--every", "1h")
			waitLine(t, lines, "CYCLE FINDINGS")
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if code := exitCode(t, cmd); code != 0 {
				t.Fatalf("exit %d after %s, want 0\nstderr: %s", code, name, stderr)
			}
			if strings.Contains(stderr.String(), "jb:") {
				t.Errorf("a clean shutdown printed an error: %q", stderr)
			}
			assertEvidenceIntact(t, dir)
			state, _ := os.ReadFile(filepath.Join(dir, "evidence", watchStateFile))
			if !strings.Contains(string(state), "192.0.2.7") {
				t.Errorf("the completed cycle's state was lost:\n%s", state)
			}
			// The same case watches again: nothing the shutdown left behind blocks it.
			if code, out, errb := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--every", "1h"); code == exitUsage || strings.Contains(errb, "database") {
				t.Errorf("watch after the signal: exit %d\n%s\n%s", code, out, errb)
			}
		})
	}
}

// Mid-cycle: the source is slow and the signal arrives while the hunt is fetching.
// The cycle is abandoned without a verdict: exit 0, no half-written file.
func TestWatchSignalDuringAHuntExitsCleanly(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"SIGINT": syscall.SIGINT, "SIGTERM": syscall.SIGTERM} {
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			hold := make(chan struct{})
			srv := recentKibana(t, hold, started)
			t.Cleanup(func() { // runs before srv.Close: a handler still waiting must not block it
				select {
				case <-hold:
				default:
					close(hold)
				}
			})
			dir := signalCase(t, srv.URL)
			cmd, lines, stderr := startJB(t, "watch", "--case", dir, "--every", "1h")
			select {
			case <-started:
			case <-time.After(30 * time.Second):
				t.Fatalf("the hunt never reached the source\nstderr: %s", stderr)
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if code := exitCode(t, cmd); code != 0 {
				t.Fatalf("exit %d after %s during a hunt, want 0\nstderr: %s", code, name, stderr)
			}
			for l := range lines {
				if strings.Contains(l, "CYCLE ") || strings.Contains(l, "ALERT [") {
					t.Errorf("an interrupted cycle reported a verdict or an alert: %q", l)
				}
			}
			assertEvidenceIntact(t, dir)
		})
	}
}
