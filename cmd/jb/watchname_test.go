//go:build unix

package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/adapters/runlock"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/core"
)

// goldenAlert and goldenCycle are what an unnamed `jb watch --once` wrote before --name
// existed, character for character. The test below must stay green on a build that
// predates --name; if it needs editing, the unnamed watcher changed.
const (
	goldenAlert = `2026-11-05T12:00:00Z ALERT [high] [c:authspike:192.0.2.7] authspike: failure share for "192.0.2.7" rose from 0.0% (0/50) to 80.0% (40/50)`
	goldenCycle = `2026-11-05T12:00:00Z CYCLE watch-20261105T120000Z CYCLE FINDINGS: 1 new, 0 held back by ttl; every source and detector completed; pruned 0 run(s), 0 event(s), 0 finding(s) older than 48h0m0s`
	goldenState = `{
  "version": 1,
  "seen": {
    "authspike:192.0.2.7": {
      "at": "2026-11-05T12:00:00Z",
      "severity": "high"
    }
  }
}
`
	goldenBanner = "watching case example-login-spray every 5m0s over a 1h0m0s window, ttl 3h0m0s, keep 48h0m0s, repeat 30m0s, 1 source(s), 1 detector(s), 0 webhook(s)\n"
)

func TestUnnamedWatchIsByteIdenticalToBeforeNames(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	wantOut := goldenAlert + "\n" + goldenCycle + "\n"
	if stdout != wantOut {
		t.Errorf("stdout changed:\n got: %q\nwant: %q", stdout, wantOut)
	}
	if !strings.HasSuffix(stderr, goldenBanner) {
		t.Errorf("banner changed:\n got: %q\nwant suffix: %q", stderr, goldenBanner)
	}
	if got := readEvidence(t, dir, "watch.log"); got != wantOut {
		t.Errorf("watch.log changed:\n got: %q\nwant: %q", got, wantOut)
	}
	if got := readEvidence(t, dir, "watch-state.json"); got != goldenState {
		t.Errorf("watch-state.json changed:\n got: %q\nwant: %q", got, goldenState)
	}
}

// evidenceFiles lists the watcher files in the case's evidence directory.
func evidenceFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "watch") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func TestUnnamedWatcherKeepsItsFileNamesAndTakesItsLock(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	if code, _, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := []string{"watch-state.json", "watch-status.json", "watch.lock", "watch.log"}
	if got := evidenceFiles(t, dir); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("evidence holds %v, want %v", got, want)
	}
}

func TestNamedWatchersUseTheirOwnFilesAndRunIDs(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	code, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--name", "attack")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := []string{"watch-state.attack.json", "watch-status.attack.json", "watch.attack.lock", "watch.attack.log"}
	sort.Strings(want)
	if got := evidenceFiles(t, dir); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("evidence holds %v, want %v and none of the unnamed watcher's", got, want)
	}
	if !strings.Contains(stderr, "watching case example-login-spray (watcher attack) every 5m0s") {
		t.Errorf("banner lacks the name:\n%s", stderr)
	}
	for _, l := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if !strings.Contains(l, " [w:attack]") && !strings.Contains(l, " [w:attack]") {
			t.Errorf("line is not attributable to its watcher: %q", l)
		}
	}
	if !strings.Contains(stdout, "ALERT [high] [c:authspike:192.0.2.7] [w:attack] authspike:") {
		t.Errorf("alert line lacks [w:attack]:\n%s", stdout)
	}
	if !strings.Contains(stdout, "CYCLE watch-attack-20261105T120000Z [w:attack] CYCLE FINDINGS") {
		t.Errorf("cycle line lacks the run id or the name:\n%s", stdout)
	}
	if got := readEvidence(t, dir, "watch.attack.log"); got != stdout {
		t.Errorf("the named log differs from stdout:\n%q\n%q", got, stdout)
	}
	st, err := watchstate.Store{Path: filepath.Join(dir, "evidence", "watch-state.attack.json")}.Load(context.Background())
	if err != nil || len(st.Seen) != 1 {
		t.Errorf("named state: %+v, %v", st, err)
	}
}

func TestInvalidWatchNamesAreUsageErrors(t *testing.T) {
	dir, served := watchCase(t, http.StatusOK)
	for _, name := range []string{"A", "1a", "a b", "a/b", "../x", "a.b", "-a", "_a", strings.Repeat("a", 33), "é"} {
		if code, _, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--name", name); code != exitUsage {
			t.Errorf("--name %q: exit %d, want 2: %s", name, code, stderr)
		}
	}
	if served() != 0 {
		t.Errorf("a refused name reached the source (%d)", served())
	}
	for _, name := range []string{"a", "attack-1", "health_check", strings.Repeat("a", 32)} {
		d := testDeps(huntEnv)
		if code, _, stderr := run(t, d, "watch", "--case", dir, "--once", "--name", name); code != 0 {
			t.Errorf("--name %q: exit %d: %s", name, code, stderr)
		}
	}
}

// The same finding alerts once per watcher: their state files, and so their dedupe tags,
// are separate. That is documented behaviour; this keeps it from changing by accident.
func TestTheSameFindingAlertsOncePerWatcher(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	for _, name := range []string{"a", "b"} {
		_, stdout, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--name", name)
		if !strings.Contains(stdout, "ALERT [") {
			t.Fatalf("watcher %s did not alert on a finding the other already alerted:\n%s\n%s", name, stdout, stderr)
		}
	}
	// A second cycle of one watcher is held back by its own state.
	_, stdout, _ := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--name", "a")
	if strings.Contains(stdout, "ALERT [") || !strings.Contains(stdout, "1 held back by ttl") {
		t.Errorf("watcher a repeated itself:\n%s", stdout)
	}
}

// holdLock takes the lock file as another watcher would, and returns the release.
func holdLock(t *testing.T, dir, file string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := runlock.Acquire(filepath.Join(dir, "evidence", file))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Release() })
}

func TestSecondWatcherWithTheSameNameIsRefusedAndNamesTheHolder(t *testing.T) {
	for _, tc := range []struct {
		name, lock string
		args       []string
	}{
		{"named", "watch.a.lock", []string{"--name", "a"}},
		{"unnamed", "watch.lock", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, served := watchCase(t, http.StatusOK)
			holdLock(t, dir, tc.lock)
			args := append([]string{"watch", "--case", dir, "--once"}, tc.args...)
			code, stdout, stderr := run(t, testDeps(huntEnv), args...)
			if code != exitFailure {
				t.Fatalf("exit %d, want 1\n%s\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, fmt.Sprintf("held by PID %d", os.Getpid())) || !strings.Contains(stderr, "already running") {
				t.Errorf("the refusal does not name the holder's PID:\n%s", stderr)
			}
			if served() != 0 || stdout != "" {
				t.Errorf("a refused watcher still ran: %d request(s), stdout %q", served(), stdout)
			}
			if _, err := os.Stat(filepath.Join(dir, "evidence", "watch.log")); err == nil {
				t.Error("a refused watcher wrote a log")
			}
		})
	}
}

func TestWatchersWithDifferentNamesDoNotBlockEachOther(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	holdLock(t, dir, "watch.a.lock")
	for _, args := range [][]string{{"--name", "b"}, {}} {
		if code, _, stderr := run(t, testDeps(huntEnv), append([]string{"watch", "--case", dir, "--once"}, args...)...); code != 0 {
			t.Errorf("watch %v blocked by another name's lock: exit %d: %s", args, code, stderr)
		}
	}
}

// A finished watcher frees its lock: the next one with the same name runs.
func TestLockIsFreedWhenTheWatcherEnds(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	for i := range 2 {
		if code, _, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--name", "a"); code != 0 {
			t.Fatalf("run %d: exit %d: %s", i, code, stderr)
		}
	}
}

// seedWatchRun stores one finished watch hunt as `watch` does and ages it.
func seedAgedWatchRun(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, "evidence", "jb.duckdb")
	st, err := duckdb.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveFindings(context.Background(), id, []core.Finding{{Detector: "d", Tag: id, Summary: "s"}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	db, err := sql.Open("duckdb", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE runs SET created_at = CAST('2026-10-01T00:00:00Z' AS TIMESTAMPTZ) WHERE run_id = ?`, id); err != nil {
		t.Fatal(err)
	}
}

func storedRuns(t *testing.T, dir string) []string {
	t.Helper()
	st, err := duckdb.Open(filepath.Join(dir, "evidence", "jb.duckdb"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("duckdb", filepath.Join(dir, "evidence", "jb.duckdb")+"?access_mode=READ_ONLY")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT run_id FROM runs WHERE starts_with(run_id, 'watch-') AND run_id LIKE '%Z' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// Retention of one watcher touches only its own old runs: not another name's, not a
// name that merely starts the same way, and not the unnamed watcher's; and the unnamed
// watcher in turn leaves every named watcher's runs alone.
func TestWatchRetentionPrunesOnlyTheWatchersOwnRuns(t *testing.T) {
	dir, _ := watchCase(t, http.StatusOK)
	// Create the store, then add old runs of four watchers, all long past --keep.
	if code, _, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--name", "zz-bootstrap"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	old := map[string]string{
		"unnamed": "watch-20261001T000000Z", "a": "watch-a-20261001T000000Z",
		"ab": "watch-ab-20261001T000000Z", "a-b": "watch-a-b-20261001T000000Z",
	}
	for _, id := range old {
		seedAgedWatchRun(t, dir, id)
	}

	has := func(id string) bool {
		for _, r := range storedRuns(t, dir) {
			if r == id {
				return true
			}
		}
		return false
	}
	// watcher "a" cycles: its own old run goes, every other old run stays.
	if code, _, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once", "--name", "a"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if has(old["a"]) {
		t.Errorf("watcher a did not prune its own old run: %v", storedRuns(t, dir))
	}
	for _, k := range []string{"unnamed", "ab", "a-b"} {
		if !has(old[k]) {
			t.Errorf("watcher a pruned the run of %q (%s)", k, old[k])
		}
	}
	// the unnamed watcher cycles: its own old run goes, the named ones stay.
	if code, _, stderr := run(t, testDeps(huntEnv), "watch", "--case", dir, "--once"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if has(old["unnamed"]) {
		t.Errorf("the unnamed watcher did not prune its own old run: %v", storedRuns(t, dir))
	}
	for _, k := range []string{"ab", "a-b"} {
		if !has(old[k]) {
			t.Errorf("the unnamed watcher pruned a named watcher's run %q (%s)", k, old[k])
		}
	}
}

// twoWatcherCase is a case with two configs, each on its own fake Kibana dated around the
// real clock, because the watchers below are real jb processes (the test binary running
// main()) and a process cannot be given the tests' fixed clock.
func twoWatcherCase(t *testing.T) (dir string, cfgs [2]string) {
	t.Helper()
	srvA, srvB := recentKibana(t, nil, nil), recentKibana(t, nil, nil)
	dir = copyExampleCase(t, srvA.URL)
	gitInit(t, dir)
	editFile(t, filepath.Join(dir, "case.yaml"), "default: 24h", "default: 1h")
	body, err := os.ReadFile(filepath.Join(dir, "config", "hunt.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeProfile(t, dir, "config/second.yaml", regexp.MustCompile(`url: \S+`).ReplaceAllString(string(body), "url: "+srvB.URL))
	editFile(t, filepath.Join(dir, "case.yaml"), "  - config/hunt.yaml\n", "  - config/hunt.yaml\n  - config/second.yaml\n")
	return dir, [2]string{"config/hunt.yaml", "config/second.yaml"}
}

// assertNamedEvidenceIntact is what "neither watcher damaged the other" means: each
// named state file is strictly valid and holds the one finding, each log holds whole
// lines of its own watcher only, nothing was moved aside or left half-written, and the
// shared store opens.
func assertNamedEvidenceIntact(t *testing.T, dir string, names []string) {
	t.Helper()
	ev := filepath.Join(dir, "evidence")
	for _, name := range names {
		st, err := watchstate.Store{Path: filepath.Join(ev, "watch-state."+name+".json")}.Load(context.Background())
		if err != nil || len(st.Seen) != 1 {
			t.Errorf("%s: state %+v, %v", name, st, err)
		}
		b, err := os.ReadFile(filepath.Join(ev, "watch."+name+".log"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(b) > 0 && b[len(b)-1] != '\n' {
			t.Errorf("%s: log ends mid-line", name)
		}
		for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if !logLine.MatchString(l) {
				t.Errorf("%s: malformed log line %q", name, l)
			}
			if !strings.Contains(l, " [w:"+name+"]") && !strings.Contains(l, "watch-"+name+"-") {
				t.Errorf("%s: a line that is not its own: %q", name, l)
			}
		}
		if n := strings.Count(string(b), "ALERT [high] [c:authspike:192.0.2.7]"); n != 1 {
			t.Errorf("%s: the finding alerted %d times in its log, want once (its own dedupe)", name, n)
		}
		if strings.Contains(string(b), "CYCLE FAILED") || strings.Contains(string(b), "CYCLE INCOMPLETE") {
			t.Errorf("%s had a bad cycle:\n%s", name, b)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(ev, "*.tmp-*")); len(m) > 0 {
		t.Errorf("temporary state files left behind: %v", m)
	}
	if m, _ := filepath.Glob(filepath.Join(ev, "*.corrupt")); len(m) > 0 {
		t.Errorf("state moved aside as corrupt: %v", m)
	}
	st, err := duckdb.Open(filepath.Join(ev, "jb.duckdb"), true)
	if err != nil {
		t.Fatalf("the shared store does not open: %v", err)
	}
	defer st.Close()
}

// Two watchers with different names and different configs on one case, cycling at the
// same time in separate processes: they share only the DuckDB file, which each opens for
// one hunt at a time and waits for when the other has it. Several rounds, each started
// together, so the two keep colliding on the store.
func TestConcurrentNamedWatchersDoNotCorruptEachOther(t *testing.T) {
	dir, cfgs := twoWatcherCase(t)
	names := []string{"first", "second"}
	const rounds = 4
	for round := range rounds {
		var cmds [2]*exec.Cmd
		var errs [2]*strings.Builder
		for i := range cmds {
			cmds[i], _, errs[i] = startJB(t, "watch", "--case", dir, "--config", cfgs[i], "--name", names[i], "--once")
		}
		for i, c := range cmds {
			if code := exitCode(t, c); code != 0 {
				t.Errorf("round %d, %s: exit %d: %s", round, names[i], code, errs[i])
			}
		}
	}
	assertNamedEvidenceIntact(t, dir, names)
	for _, name := range names {
		b := readEvidence(t, dir, "watch."+name+".log")
		if n := strings.Count(b, " CYCLE watch-"+name+"-"); n != rounds {
			t.Errorf("%s: %d cycle lines, want %d", name, n, rounds)
		}
	}
}

// The long-running loop, not just --once: two named watchers cycle every second for a
// few seconds at the same time, then both are interrupted and must exit cleanly.
func TestConcurrentNamedWatcherLoops(t *testing.T) {
	dir, cfgs := twoWatcherCase(t)
	names := []string{"attack", "health"}
	var cmds [2]*exec.Cmd
	var lines [2]<-chan string
	var errs [2]*strings.Builder
	for i := range cmds {
		cmds[i], lines[i], errs[i] = startJB(t, "watch", "--case", dir, "--config", cfgs[i], "--name", names[i], "--every", "1s")
	}
	for i := range cmds {
		// the first cycle, then two more: three cycles each, started together.
		seen := 0
		for seen < 3 {
			waitLine(t, lines[i], " CYCLE ")
			seen++
		}
	}
	for i := range cmds {
		_ = cmds[i].Process.Signal(syscall.SIGTERM)
	}
	for i, c := range cmds {
		if code := exitCode(t, c); code != 0 {
			t.Errorf("%s: exit %d after SIGTERM: %s", names[i], code, errs[i])
		}
	}
	assertNamedEvidenceIntact(t, dir, names)
}

// A real second process with the same name, started while the first is running, is
// refused with the first's PID; the first is undisturbed.
func TestSecondRealProcessWithTheSameNameIsRefused(t *testing.T) {
	dir, cfgs := twoWatcherCase(t)
	first, lines, _ := startJB(t, "watch", "--case", dir, "--config", cfgs[0], "--name", "dup", "--every", "1s")
	waitLine(t, lines, " CYCLE ")

	second, _, errb := startJB(t, "watch", "--case", dir, "--config", cfgs[1], "--name", "dup", "--once")
	if code := exitCode(t, second); code != exitFailure {
		t.Fatalf("the second watcher named dup exited %d, want 1: %s", code, errb)
	}
	if want := fmt.Sprintf("held by PID %d", first.Process.Pid); !strings.Contains(errb.String(), want) {
		t.Errorf("the refusal does not name the first process (%s):\n%s", want, errb)
	}
	// ... and the same name with the unnamed watcher's lock is a different lock.
	other, _, errb2 := startJB(t, "watch", "--case", dir, "--config", cfgs[1], "--once")
	if code := exitCode(t, other); code != 0 {
		t.Errorf("the unnamed watcher was blocked by a named one: exit %d: %s", code, errb2)
	}
	waitLine(t, lines, " CYCLE ") // the first is still cycling
	_ = first.Process.Signal(syscall.SIGTERM)
	if code := exitCode(t, first); code != 0 {
		t.Errorf("first exit %d", code)
	}
}
