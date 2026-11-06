package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jb "github.com/iksnerd/json-bourne"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

const defaultLabel = "kibana:logs-auth-*"

var storeBase = fixedNow.Add(-30 * time.Minute)

func labelled(source string, from, n int) []core.Event {
	var out []core.Event
	for i := from; i < from+n; i++ {
		out = append(out, core.Event{
			Time: storeBase.Add(time.Duration(i) * time.Second), Source: source, Kind: "request",
			Fields: map[string]any{"n": float64(i)}, Raw: []byte(fmt.Sprintf(`192.0.2.7 GET /item/%d`, i)),
		})
	}
	return out
}

func seqOf(evs []core.Event) func(func(core.Event, error) bool) {
	return func(yield func(core.Event, error) bool) {
		for _, e := range evs {
			if !yield(e, nil) {
				return
			}
		}
	}
}

// seedTwoLabels writes the config's store with the same n documents under the default
// label and under an explicit name, and returns the config path and the store path.
func seedTwoLabels(t *testing.T, n int) (cfg, store string) {
	t.Helper()
	cfg = writeConfig(t, "https://kibana.example.com")
	store = filepath.Join(filepath.Dir(cfg), "jb.duckdb")
	st, err := duckdb.Open(store, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	for run, src := range map[string]string{"hunt-1/" + defaultLabel: defaultLabel, "hunt-2/ingress": "ingress"} {
		if err := st.SaveEvents(context.Background(), run, seqOf(labelled(src, 0, n))); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, store
}

func countsBySource(t *testing.T, store string) map[string]int {
	t.Helper()
	st, err := duckdb.Open(store, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := map[string]int{}
	for ev, err := range st.Events(context.Background(), core.Window{From: storeBase.Add(-time.Hour), To: fixedNow}) {
		if err != nil {
			t.Fatal(err)
		}
		m[ev.Source]++
	}
	return m
}

func TestRenameSourceCLIDryRunIsTheDefaultAndChangesNothing(t *testing.T) {
	cfg, store := seedTwoLabels(t, 12)
	code, out, errs := run(t, testDeps(nil), "db", "rename-source", "--config", cfg, defaultLabel, "ingress", "--merge")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"dry run", "events under " + defaultLabel, "12 in 1 run(s)", "documents under both", "would be relabelled", "Add --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if got := countsBySource(t, store); got[defaultLabel] != 12 || got["ingress"] != 12 {
		t.Fatalf("a dry run changed the store: %v", got)
	}
}

func TestRenameSourceCLIRefusesOverlapWithoutMergeEvenWithApply(t *testing.T) {
	cfg, store := seedTwoLabels(t, 12)
	for _, extra := range [][]string{nil, {"--apply"}} {
		args := append([]string{"db", "rename-source", "--config", cfg, defaultLabel, "ingress"}, extra...)
		code, out, errs := run(t, testDeps(nil), args...)
		if code != 1 || !strings.Contains(errs, "refused") || !strings.Contains(errs, "--merge") {
			t.Fatalf("%v: exit %d\nout %s\nerr %s", extra, code, out, errs)
		}
		if !strings.Contains(out, "documents under both") {
			t.Errorf("the refusal should still print the counts:\n%s", out)
		}
		if got := countsBySource(t, store); got[defaultLabel] != 12 || got["ingress"] != 12 {
			t.Fatalf("%v: a refused rename changed the store: %v", extra, got)
		}
	}
}

func TestRenameSourceCLIApplyMerge(t *testing.T) {
	cfg, store := seedTwoLabels(t, 12)
	code, out, errs := run(t, testDeps(nil), "db", "rename-source", "--config", cfg, "--apply", "--merge", defaultLabel, "ingress")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "(apply)") || !strings.Contains(out, "dropped from "+defaultLabel) {
		t.Errorf("output:\n%s", out)
	}
	if got := countsBySource(t, store); len(got) != 1 || got["ingress"] != 12 {
		t.Fatalf("after the rename: %v, want 12 under ingress only", got)
	}
	// The overlap warning's own fix is gone.
	code, _, _ = run(t, testDeps(nil), "db", "rename-source", "--config", cfg, defaultLabel, "ingress")
	if code != 1 {
		t.Errorf("renaming a label that no longer exists should fail, got exit %d", code)
	}
}

func TestRenameSourceCLIUsageErrorsExitTwo(t *testing.T) {
	cfg, _ := seedTwoLabels(t, 2)
	for name, args := range map[string][]string{
		"no config":        {"db", "rename-source", "a", "b"},
		"one label":        {"db", "rename-source", "--config", cfg, "a"},
		"invalid new name": {"db", "rename-source", "--config", cfg, "old", "Not A Name"},
		"upper-case new":   {"db", "rename-source", "--config", cfg, "old", "Ingress"},
		"glob in new":      {"db", "rename-source", "--config", cfg, "old", "kibana:x-*"},
		"invalid old":      {"db", "rename-source", "--config", cfg, "Old Label", "new"},
		"same":             {"db", "rename-source", "--config", cfg, "same", "same"},
	} {
		if code, _, errs := run(t, testDeps(nil), args...); code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, code, errs)
		}
	}
}

func TestRenameSourceCLIDoesNotCreateAMissingStore(t *testing.T) {
	cfg := writeConfig(t, "https://kibana.example.com")
	store := filepath.Join(filepath.Dir(cfg), "jb.duckdb")
	code, _, errs := run(t, testDeps(nil), "db", "rename-source", "--config", cfg, "--apply", "a", "b")
	if code != 1 || !strings.Contains(errs, "no evidence database") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if _, err := os.Stat(store); err == nil {
		t.Fatal("rename-source created the store")
	}
}

// The warning is advice. The same hunt, with and without one set of documents stored
// under two labels, exits the same way and prints the fix on stderr only in the second.
func TestHuntWarnsOfDuplicateLabelsWithoutChangingTheExitCode(t *testing.T) {
	dir, _ := untilCase(t, searchDocs(), 0)
	code1, _, _, err1 := runSearchHunt(t, dir)
	if strings.Contains(err1, "WARNING") {
		t.Fatalf("a single label produced a warning:\n%s", err1)
	}

	// Store the same documents again under an explicit name, as an earlier config did.
	store, err := storePathFor(nopWriter{}, dir, fpConfigRel)
	if err != nil {
		t.Fatal(err)
	}
	st, err := duckdb.Open(store, false)
	if err != nil {
		t.Fatal(err)
	}
	var copies []core.Event
	for ev, err := range st.Events(context.Background(), core.Window{From: fixedNow.Add(-3 * time.Hour), To: fixedNow}) {
		if err != nil {
			t.Fatal(err)
		}
		ev.Source = "ingress"
		copies = append(copies, ev)
	}
	if len(copies) == 0 {
		t.Fatal("the first hunt stored nothing to copy")
	}
	if err := st.SaveEvents(context.Background(), "hunt-old/ingress", seqOf(copies)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	code2, _, _, err2 := runSearchHunt(t, dir)
	if code2 != code1 {
		t.Fatalf("the warning changed the exit code: %d -> %d", code1, code2)
	}
	for _, want := range []string{"WARNING", "two source labels", `"ingress"`, "jb db rename-source --case ", " --merge"} {
		if !strings.Contains(err2, want) {
			t.Errorf("stderr lacks %q:\n%s", want, err2)
		}
	}
	// activity warns the same way.
	_, _, errAct := run(t, testDeps(huntEnv), "activity", "--case", dir, "--config", fpConfigRel, "--window", "3h")
	if !strings.Contains(errAct, "WARNING") || !strings.Contains(errAct, "jb db rename-source") {
		t.Errorf("activity stderr lacks the warning:\n%s", errAct)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestHolderProcessCmd is the child half of the lock tests: it holds the store read-write.
func TestHolderProcessCmd(t *testing.T) {
	path := os.Getenv("JB_TEST_HOLD")
	if path == "" {
		t.Skip("child helper")
	}
	st, err := duckdb.Open(path, false)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	fmt.Println("HELD")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	st.Close()
	os.Exit(0)
}

func holdStore(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHolderProcessCmd$")
	cmd.Env = append(os.Environ(), "JB_TEST_HOLD="+path)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "HELD" {
		t.Fatalf("holder said %q", line)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
}

func TestLockedStoreIsWaitedForThenReportedWithTheHolder(t *testing.T) {
	cfg, store := seedTwoLabels(t, 3)
	holdStore(t, store)
	t.Setenv(duckdb.EnvLockWait, "500ms")

	start := time.Now()
	code, _, errs := run(t, testDeps(nil), "db", "status", "--config", cfg)
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	if el := time.Since(start); el < 400*time.Millisecond {
		t.Errorf("gave up after %v, before the 500ms budget", el)
	}
	for _, want := range []string{store, "another process", "PID", "Wait for it", duckdb.EnvLockWait} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}

	// JB_DB_LOCK_WAIT=0 disables the retry: it fails at once.
	t.Setenv(duckdb.EnvLockWait, "0")
	start = time.Now()
	if code, _, errs = run(t, testDeps(nil), "db", "status", "--config", cfg); code != 1 || time.Since(start) > 400*time.Millisecond || !strings.Contains(errs, "retry is off") {
		t.Errorf("no-wait: exit %d after %v\n%s", code, time.Since(start), errs)
	}
	// A malformed value is refused, not ignored.
	t.Setenv(duckdb.EnvLockWait, "forever")
	if code, _, errs = run(t, testDeps(nil), "db", "status", "--config", cfg); code != 1 || !strings.Contains(errs, duckdb.EnvLockWait) {
		t.Errorf("bad value: exit %d\n%s", code, errs)
	}
}

func TestDoctorReportsAHeldLockAsFailAfterTheShortBudgetAndNamesTheHolder(t *testing.T) {
	cfg, store := seedTwoLabels(t, 3)
	holdStore(t, store)
	start := time.Now()
	code, rep, stdout, stderr := doctorRun(t, doctorDeps(nil), "--config", cfg)
	el := time.Since(start)
	if code != 1 || rep.OK {
		t.Fatalf("exit %d, ok=%v\n%s\n%s", code, rep.OK, stdout, stderr)
	}
	if el < jb.DoctorLockWait-200*time.Millisecond || el > jb.DoctorLockWait+4*time.Second {
		t.Errorf("doctor took %v, want about its %v budget", el, jb.DoctorLockWait)
	}
	var detail string
	for _, c := range rep.Checks {
		if c.Group == "store" && strings.Contains(c.Name, "(open)") {
			if c.Status != "fail" {
				t.Errorf("status %s, want fail", c.Status)
			}
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, "PID") || !strings.Contains(detail, "another process") {
		t.Errorf("detail does not say who holds it: %q", detail)
	}
}

func TestDoctorWarnsOfDuplicateLabelsAndStillPasses(t *testing.T) {
	cfg, _ := seedTwoLabels(t, 6)
	d := doctorDeps(nil)
	d.now = func() time.Time { return fixedNow }
	code, rep, stdout, stderr := doctorRun(t, d, "--config", cfg)
	if code != 0 || !rep.OK {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	found := false
	for _, c := range rep.Checks {
		if strings.Contains(c.Name, "(source labels)") {
			found = true
			if c.Status != "warn" || !strings.Contains(c.Detail, "jb db rename-source --config") {
				t.Errorf("%+v", c)
			}
		}
	}
	if !found {
		t.Errorf("no source-label check in the report:\n%s", stdout)
	}
}

func TestWatchCycleWarnsOfDuplicateLabelsWithoutChangingTheOutcome(t *testing.T) {
	dir, _ := watchCase(t, 200)
	d := testDeps(huntEnv)
	code1, _, err1 := run(t, d, "watch", "--case", dir, "--once")
	if code1 != 0 || strings.Contains(err1, "WARNING") {
		t.Fatalf("first cycle: exit %d\n%s", code1, err1)
	}
	store, err := storePathFor(nopWriter{}, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := duckdb.Open(store, false)
	if err != nil {
		t.Fatal(err)
	}
	var copies []core.Event
	for ev, err := range st.Events(context.Background(), core.Window{From: fixedNow.Add(-3 * time.Hour), To: fixedNow.Add(time.Hour)}) {
		if err != nil {
			t.Fatal(err)
		}
		ev.Source = "ingress"
		copies = append(copies, ev)
	}
	if len(copies) == 0 {
		t.Fatal("the first cycle stored nothing")
	}
	if err := st.SaveEvents(context.Background(), "watch-old/ingress", seqOf(copies)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	code2, _, err2 := run(t, d, "watch", "--case", dir, "--once")
	if code2 != code1 {
		t.Fatalf("the warning changed the exit code: %d -> %d", code1, code2)
	}
	if !strings.Contains(err2, "WARNING") || !strings.Contains(err2, "jb db rename-source --case ") {
		t.Errorf("watch stderr lacks the warning:\n%s", err2)
	}
}
