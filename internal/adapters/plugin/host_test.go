package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func pidOf(t *testing.T, dir, name string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, err := strconv.Atoi(strings.TrimSpace(readFile(dir, name))); err == nil {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s file appeared", name)
	return 0
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if !alive(pid) {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("process %d is still alive", pid)
}

func mustFail(t *testing.T, h *Host, n int, want string) error {
	t.Helper()
	res, err := h.MapBatch(context.Background(), docs(n))
	if err == nil {
		t.Fatalf("expected an error containing %q, got %d results", want, len(res))
	}
	if res != nil {
		t.Errorf("a failed call returned results (%d): a partial answer is a quiet pass", len(res))
	}
	if !errors.Is(err, ErrPlugin) {
		t.Errorf("error does not wrap ErrPlugin: %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err, want)
	}
	return err
}

func TestHappyPathOneResultPerDocument(t *testing.T) {
	e := install(t, "ok")
	h := newHost(t, e, Limits{}, map[string]any{"k": "v"})
	in := docs(3)
	in[1]["bad"] = true
	res, err := h.MapBatch(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || !res[1].Unparsable || res[0].Unparsable || res[2].Unparsable {
		t.Fatalf("results = %+v", res)
	}
	if got := res[0].Event.Fields["status"]; got != 401 {
		t.Errorf("status = %#v (%T), want int 401", got, got)
	}
	if res[2].Event.Fields["cfg"] != "v" || res[2].Event.Fields["x"] != 2 {
		t.Errorf("config or doc did not reach the plugin: %v", res[2].Event.Fields)
	}
	if res[0].Event.Time.Year() != 2026 {
		t.Errorf("time = %v", res[0].Event.Time)
	}
	if m := h.Manifest(); m.Name != "fake" || m.Role != "mapper" {
		t.Errorf("manifest = %+v", m)
	}
}

func TestBatchesAreCappedAtMaxDocs(t *testing.T) {
	h := newHost(t, install(t, "ok"), Limits{MaxDocs: 200}, nil)
	res, err := h.MapBatch(context.Background(), docs(450))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 450 {
		t.Fatalf("got %d results for 450 docs", len(res))
	}
	// The fake reports which request each document rode in: 200 + 200 + 50.
	for i, want := range map[int]int{0: 1, 199: 1, 200: 2, 399: 2, 400: 3, 449: 3} {
		if got := res[i].Event.Fields["req"]; got != want {
			t.Errorf("doc %d rode request %v, want %d", i, got, want)
		}
	}
}

func TestChildEnvironmentIsEmptyPlusFour(t *testing.T) {
	const secret = "sentinel-do-not-leak-7f3a"
	t.Setenv("JB_KIBANA_API_KEY", secret)
	t.Setenv("GREYNOISE_API_KEY", secret)
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("HOME", "/home/example")
	t.Setenv("LANG", "C")
	t.Setenv("TMPDIR", "/tmp")
	h := newHost(t, install(t, "printenv"), Limits{}, nil)
	res, err := h.MapBatch(context.Background(), docs(1))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := res[0].Event.Fields["env"].([]any)
	if len(env) == 0 {
		t.Fatal("child reported no environment at all; the PATH/HOME/LANG/TMPDIR contract is untested")
	}
	for _, kv := range env {
		s := fmt.Sprint(kv)
		if strings.Contains(s, secret) {
			t.Fatalf("a secret from the host environment reached the child: %q", s)
		}
		k, _, _ := strings.Cut(s, "=")
		switch k {
		case "PATH", "HOME", "LANG", "TMPDIR":
		default:
			t.Errorf("child received %s: only PATH, HOME, LANG and TMPDIR may be passed", k)
		}
	}
}

func TestChildRunsInThePluginsOwnDirectory(t *testing.T) {
	e := install(t, "cwd")
	h := newHost(t, e, Limits{}, nil)
	res, err := h.MapBatch(context.Background(), docs(1))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := res[0].Event.Fields["cwd"].(string)
	got, _ = filepath.EvalSymlinks(got)
	if want := filepath.Dir(e.Path); got != want {
		t.Errorf("cwd = %q, want %q", got, want)
	}
}

func TestDeadlineKillsTheWholeProcessGroup(t *testing.T) {
	e := install(t, "slow")
	dir := filepath.Dir(e.Path)
	h := newHost(t, e, Limits{Deadline: 2 * time.Second}, nil)
	start := time.Now()
	mustFail(t, h, 1, "request: no answer within")
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("took %s to give up on a 2s deadline", d)
	}
	waitDead(t, pidOf(t, dir, "pid"))
	waitDead(t, pidOf(t, dir, "child.pid")) // the grandchild: only a group kill reaches it
}

func TestOversizedResponseIsABreak(t *testing.T) {
	h := newHost(t, install(t, "huge"), Limits{MaxResponseBytes: 1 << 20}, nil)
	mustFail(t, h, 1, "larger than")
}

func TestUnterminatedFloodIsBoundedAndKilled(t *testing.T) {
	e := install(t, "unterminated")
	h := newHost(t, e, Limits{MaxResponseBytes: 1 << 20}, nil)
	mustFail(t, h, 1, "larger than")
	waitDead(t, pidOf(t, filepath.Dir(e.Path), "pid"))
}

func TestInvalidJSONIsABreak(t *testing.T) {
	mustFail(t, newHost(t, install(t, "badjson"), Limits{}, nil), 2, "not valid JSON")
}

func TestWrongResultCountIsABreak(t *testing.T) {
	mustFail(t, newHost(t, install(t, "wrongcount"), Limits{}, nil), 3, "2 result slots for 3 documents")
}

func TestNullSlotNotListedUnparsableIsABreak(t *testing.T) {
	mustFail(t, newHost(t, install(t, "nullskip"), Limits{}, nil), 2, "skipped document")
}

func TestUnparsableListIsValidated(t *testing.T) {
	mustFail(t, newHost(t, install(t, "doublecount"), Limits{}, nil), 2, "repeated index")
	mustFail(t, newHost(t, install(t, "eventandunparsable"), Limits{}, nil), 2, "also listed as unparsable")
}

func TestBadEventTimestampIsABreak(t *testing.T) {
	mustFail(t, newHost(t, install(t, "badts"), Limits{}, nil), 1, "ts is missing or not RFC 3339")
}

func TestResponseForAnotherRequestIsABreak(t *testing.T) {
	mustFail(t, newHost(t, install(t, "wrongid"), Limits{}, nil), 1, "does not match request id")
}

func TestPluginReportedErrorFailsAndIsScrubbed(t *testing.T) {
	err := mustFail(t, newHost(t, install(t, "errorresp"), Limits{}, nil), 1, "reported an error")
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("error text leaks a credential-looking value or a terminal escape: %q", err)
	}
}

func TestCrashMidStreamFailsTheCallAndNoPartialAnswer(t *testing.T) {
	h := newHost(t, install(t, "crash"), Limits{}, nil)
	if _, err := h.MapBatch(context.Background(), docs(2)); err != nil {
		t.Fatalf("first request should succeed: %v", err)
	}
	mustFail(t, h, 2, "stdout closed")
}

func TestExitZeroWithoutHandshakeIsABreak(t *testing.T) {
	mustFail(t, newHost(t, install(t, "nohandshake"), Limits{}, nil), 1, "handshake")
}

func TestHandshakeDeadline(t *testing.T) {
	mustFail(t, newHost(t, install(t, "slowhandshake"), Limits{Deadline: 300 * time.Millisecond}, nil), 1, "handshake: no answer")
}

func TestHandshakeRoleAndVersionAreChecked(t *testing.T) {
	mustFail(t, newHost(t, install(t, "badrole"), Limits{}, nil), 1, "role")
	mustFail(t, newHost(t, install(t, "badversion"), Limits{}, nil), 1, "protocol version 2")
}

func TestUnknownFieldsAreIgnored(t *testing.T) {
	h := newHost(t, install(t, "extra"), Limits{}, nil)
	res, err := h.MapBatch(context.Background(), docs(2))
	if err != nil || len(res) != 2 {
		t.Fatalf("res=%d err=%v: unknown fields in the manifest, the response and an event must not break a v1 host", len(res), err)
	}
}

func TestBreakerOpensAfterThreeBreaksInARow(t *testing.T) {
	e := install(t, "badjson")
	h := newHost(t, e, Limits{}, nil)
	for i := 1; i <= 3; i++ {
		mustFail(t, h, 1, "not valid JSON")
		if h.Breaks() != i {
			t.Fatalf("after break %d the count is %d", i, h.Breaks())
		}
	}
	_, err := h.MapBatch(context.Background(), docs(1))
	if !errors.Is(err, ErrBreakerOpen) || !errors.Is(err, ErrPlugin) {
		t.Fatalf("fourth call = %v, want ErrBreakerOpen wrapping ErrPlugin", err)
	}
	launches := strings.Count(readFile(filepath.Dir(e.Path), "launches"), "\n")
	if launches != 3 {
		t.Errorf("plugin launched %d times; the open breaker must not launch it again (want 3)", launches)
	}
}

func TestSuccessResetsTheBreakerCount(t *testing.T) {
	h := newHost(t, install(t, "crashonce"), Limits{}, nil)
	mustFail(t, h, 1, "stdout closed")
	if h.Breaks() != 1 {
		t.Fatalf("breaks = %d", h.Breaks())
	}
	if _, err := h.MapBatch(context.Background(), docs(1)); err != nil {
		t.Fatalf("a relaunch after one break should work: %v", err)
	}
	if h.Breaks() != 0 {
		t.Errorf("breaks = %d after a success, want 0", h.Breaks())
	}
}

func TestStderrIsBoundedAndScrubbed(t *testing.T) {
	h := newHost(t, install(t, "stderrflood"), Limits{StderrBytes: 2048}, nil)
	if _, err := h.MapBatch(context.Background(), docs(1)); err != nil {
		t.Fatal(err)
	}
	// Force a failure so the tail is put in an error.
	h2 := newHost(t, install(t, "stderrflood"), Limits{StderrBytes: 2048, MaxResponseBytes: 200}, nil)
	err := mustFail(t, h2, 8, "larger than")
	msg := err.Error()
	if !strings.Contains(msg, "LASTLINE") {
		t.Fatalf("the stderr tail is not in the error, so the scrub assertions below prove nothing: %q", msg)
	}
	if len(msg) > 2000 {
		t.Errorf("error is %d bytes: stderr in an error must be bounded", len(msg))
	}
	if strings.Contains(msg, strings.Repeat("S", 40)) || strings.Contains(msg, "abc123") || strings.Contains(msg, "deadbeefdeadbeef") || strings.Contains(msg, "\x1b") {
		t.Errorf("stderr tail leaks a credential-looking value or an escape: %q", msg)
	}
}

func TestCloseStopsTheChildAndIsIdempotent(t *testing.T) {
	e := install(t, "ok")
	h := newHost(t, e, Limits{}, nil)
	if _, err := h.MapBatch(context.Background(), docs(1)); err != nil {
		t.Fatal(err)
	}
	pid := pidOf(t, filepath.Dir(e.Path), "pid")
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	waitDead(t, pid)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.MapBatch(context.Background(), docs(1)); !errors.Is(err, ErrPlugin) {
		t.Errorf("a closed host answered: %v", err)
	}
}

func TestCloseKillsAChildThatIgnoresEndOfInput(t *testing.T) {
	e := install(t, "ignoreeof")
	h := newHost(t, e, Limits{}, nil)
	if _, err := h.MapBatch(context.Background(), docs(1)); err != nil {
		t.Fatal(err)
	}
	pid := pidOf(t, filepath.Dir(e.Path), "pid")
	start := time.Now()
	h.Close()
	waitDead(t, pid)
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("Close took %s", d)
	}
}

func TestCancelledContextKillsTheChildAndIsNotABreak(t *testing.T) {
	e := install(t, "slow")
	h := newHost(t, e, Limits{Deadline: 30 * time.Second}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel once the child is running (it has written its pid), not after a fixed
	// time: on a loaded machine the child may start later than any fixed delay, and
	// then there is no pid file to check.
	go func() {
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			if _, err := strconv.Atoi(strings.TrimSpace(readFile(filepath.Dir(e.Path), "pid"))); err == nil {
				break
			}
		}
		cancel()
	}()
	_, err := h.MapBatch(ctx, docs(1))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if h.Breaks() != 0 {
		t.Errorf("an operator interrupt counted as a plugin break (%d)", h.Breaks())
	}
	waitDead(t, pidOf(t, filepath.Dir(e.Path), "pid"))
}

func TestOneDocumentOverTheRequestLimitFailsInsteadOfBeingSkipped(t *testing.T) {
	h := newHost(t, install(t, "ok"), Limits{MaxRequestBytes: 1024}, nil)
	in := docs(2)
	in[1]["big"] = strings.Repeat("a", 4096)
	_, err := h.MapBatch(context.Background(), in)
	if err == nil || !strings.Contains(err.Error(), "request limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestPinIsCheckedBeforeEveryLaunch(t *testing.T) {
	e := install(t, "badjson") // breaks every call, so every call relaunches
	e.SHA256 = sum(t, e.Path)
	h := newHost(t, e, Limits{}, nil)
	mustFail(t, h, 1, "not valid JSON") // launched: the pin matched
	if err := os.WriteFile(e.Path, append(mustRead(t, e.Path), '\n'), 0o755); err != nil {
		t.Fatal(err)
	}
	mustFail(t, h, 1, "pinned sha256 does not match")
	if n := strings.Count(readFile(filepath.Dir(e.Path), "launches"), "\n"); n != 1 {
		t.Errorf("launched %d times; the changed file must not run again", n)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
