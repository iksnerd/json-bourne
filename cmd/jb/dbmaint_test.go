package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

type maintHunt struct {
	id    string
	n     int
	ageH  int
	label string
}

// seedMaint writes a store beside a config (synthetic, example.com / RFC 5737 only).
// Every event's raw text holds an address and a path that must never be printed.
func seedMaint(t *testing.T, hunts []maintHunt) (cfg, store string) {
	t.Helper()
	cfg = writeConfig(t, "https://kibana.example.com")
	store = filepath.Join(filepath.Dir(cfg), "jb.duckdb")
	st, err := duckdb.Open(store, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, h := range hunts {
		lab := h.label
		if lab == "" {
			lab = "ingress"
		}
		if err := st.SaveEvents(ctx, h.id+"/"+lab, seqOf(labelled(lab, 0, h.n))); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveFindings(ctx, h.id, []core.Finding{{Detector: "d", Tag: "t-" + h.id, Summary: "s"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.AppendReputation(ctx, []core.Reputation{{Indicator: "192.0.2.1", Verdict: "benign", Observed: fixedNow, Source: "feed.example.com"}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	db, err := sql.Open("duckdb", store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, h := range hunts {
		if _, err := db.Exec(`UPDATE runs SET created_at = CAST(? AS TIMESTAMPTZ) WHERE run_id = ? OR starts_with(run_id, ?)`,
			fixedNow.Add(-time.Duration(h.ageH)*time.Hour).Format(time.RFC3339), h.id, h.id+"/"); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, store
}

var standardHunts = []maintHunt{
	{"hunt-20261001T000000Z", 4, 500, ""},
	{"hunt-20261002T000000Z", 3, 400, ""},
	{"hunt-20261105T100000Z", 2, 2, ""},
	{"hunt-until-20261001T000000Z-w86400s", 5, 450, ""},
	{"activity-20261001T000000Z", 6, 300, ""},
	{"watch-20261001T000000Z", 7, 900, ""},
}

func hashOf(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func noLeak(t *testing.T, outs ...string) {
	t.Helper()
	for _, o := range outs {
		for _, bad := range []string{"192.0.2.7", "/item/", "GET "} {
			if strings.Contains(o, bad) {
				t.Errorf("output contains stored document text %q:\n%s", bad, o)
			}
		}
	}
}

func TestDBUsageReportsKindsLabelsAndSizes(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	before := hashOf(t, store)
	code, out, errs := run(t, testDeps(nil), "db", "usage", "--config", cfg)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{"RUN KIND", "hunt-until", "activity", "watch (unnamed)", "SOURCE LABEL", "ingress", "file on disk", "uncompressed", "none"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q:\n%s", want, out)
		}
	}
	noLeak(t, out, errs)
	if hashOf(t, store) != before {
		t.Error("usage changed the file")
	}

	code, out, errs = run(t, testDeps(nil), "db", "usage", "--config", cfg, "--output", "json")
	if code != 0 {
		t.Fatalf("json exit %d\n%s", code, errs)
	}
	var rep struct {
		Events int64 `json:"events"`
		Kinds  []struct {
			Kind   string `json:"kind"`
			Runs   int64  `json:"runs"`
			Events int64  `json:"events"`
		} `json:"kinds"`
		Labels []struct {
			Label  string `json:"label"`
			Events int64  `json:"events"`
		} `json:"labels"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := map[string][2]int64{"hunt": {3, 9}, "hunt-until": {1, 5}, "activity": {1, 6}, "watch": {1, 7}}
	for _, k := range rep.Kinds {
		if w := want[k.Kind]; k.Runs != w[0] || k.Events != w[1] {
			t.Errorf("kind %s: %d runs %d events, want %v", k.Kind, k.Runs, k.Events, w)
		}
	}
	if rep.Events != 27 || len(rep.Labels) != 1 || rep.Labels[0].Events != 27 {
		t.Errorf("totals: %+v", rep)
	}
	if code, _, errs := run(t, testDeps(nil), "db", "usage", "--config", cfg, "--output", "yaml"); code != 2 || !strings.Contains(errs, "--output") {
		t.Errorf("bad --output: exit %d\n%s", code, errs)
	}
}

func TestDBUsageNeedsAStoreAndNeverCreatesOne(t *testing.T) {
	cfg := writeConfig(t, "https://kibana.example.com")
	store := filepath.Join(filepath.Dir(cfg), "jb.duckdb")
	for _, args := range [][]string{{"usage", "--config", cfg}, {"prune", "--config", cfg, "--kind", "hunt", "--older-than", "1d", "--apply"}, {"compact", "--config", cfg, "--to", store + ".new", "--apply"}} {
		code, _, errs := run(t, testDeps(nil), append([]string{"db"}, args...)...)
		if code != 1 || !strings.Contains(errs, "no evidence database") {
			t.Errorf("%v: exit %d\n%s", args, code, errs)
		}
	}
	if _, err := os.Stat(store); err == nil {
		t.Fatal("a maintenance command created the store")
	}
	if code, _, _ := run(t, testDeps(nil), "db", "usage"); code != 2 {
		t.Errorf("no --config/--case: exit %d, want 2", code)
	}
}

func TestDBPruneIsADryRunByDefault(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	before := hashOf(t, store)
	code, out, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--kind", "hunt,activity", "--older-than", "7d")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{"(dry run)", "dry run: nothing was changed", "would delete: 2 hunt(s)", "7 events", "keep (latest of its kind)  hunt-20261105T100000Z", "keep (latest of its kind)  activity-20261001T000000Z", "prune  hunt-20261001T000000Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	noLeak(t, out, errs)
	if hashOf(t, store) != before {
		t.Error("a dry run changed the file")
	}
}

func TestDBPruneRefusesWatchWildcardAndMissingFlags(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	before := hashOf(t, store)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"watch":              {[]string{"--kind", "watch", "--older-than", "1d"}, "jb watch --keep"},
		"watch among others": {[]string{"--kind", "hunt,watch", "--older-than", "1d"}, "jb watch --keep"},
		"watch id":           {[]string{"--kind", "watch-20261001T000000Z", "--older-than", "1d"}, "jb watch --keep"},
		"named watcher":      {[]string{"--kind", "watch-a", "--older-than", "1d"}, "jb watch --keep"},
		"all":                {[]string{"--kind", "all", "--older-than", "1d"}, "no wildcard"},
		"star":               {[]string{"--kind", "*", "--older-than", "1d"}, "no wildcard"},
		"unknown":            {[]string{"--kind", "other", "--older-than", "1d"}, "not a prunable"},
		"no kind":            {[]string{"--older-than", "1d"}, "--kind is required"},
		"no age":             {[]string{"--kind", "hunt"}, "--older-than is required"},
		"bad age":            {[]string{"--kind", "hunt", "--older-than", "soon"}, "--older-than"},
		"zero age":           {[]string{"--kind", "hunt", "--older-than", "0s"}, "positive"},
		"negative keep":      {[]string{"--kind", "hunt", "--older-than", "1d", "--keep-latest", "-1"}, "--keep-latest"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errs := run(t, testDeps(nil), append([]string{"db", "prune", "--config", cfg, "--apply"}, tc.args...)...)
			if code != 2 || !strings.Contains(errs, tc.want) {
				t.Errorf("exit %d (want 2), stderr:\n%s\nstdout:\n%s", code, errs, out)
			}
		})
	}
	if hashOf(t, store) != before {
		t.Error("a refused prune changed the file")
	}
}

func TestDBPruneApplyDeletesEventsKeepsFindingsAndSaysSo(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	code, out, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--kind", "hunt", "--older-than", "7d", "--apply")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{"(apply)", "deleted: 7 events", "4 run record(s) marked pruned", "findings kept", "equal to the plan", "jb db compact"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply lacks %q:\n%s", want, out)
		}
	}
	noLeak(t, out, errs)
	st, err := duckdb.Open(store, true)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := st.Stats()
	st.Close()
	if s.Events != 27-7 || s.Findings != 6 || s.Reputation != 1 || s.Version != duckdb.Version {
		t.Errorf("after prune: %+v", s)
	}
	code, out, _ = run(t, testDeps(nil), "db", "usage", "--config", cfg)
	if code != 0 || !strings.Contains(out, "EVENTS PRUNED") {
		t.Fatalf("usage after prune: %d\n%s", code, out)
	}
	var hunt string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "hunt ") {
			hunt = l
		}
	}
	if f := strings.Fields(hunt); len(f) < 3 || f[1] != "3" || f[2] != "2" {
		t.Errorf("usage hunt row should say 3 runs, 2 pruned: %q", hunt)
	}
	// --drop-findings removes the findings and records of what is left to prune.
	code, out, errs = run(t, testDeps(nil), "db", "prune", "--config", cfg, "--kind", "hunt", "--older-than", "7d", "--drop-findings", "--apply")
	if code != 0 || !strings.Contains(out, "2 findings, 4 run records") {
		t.Fatalf("drop-findings: exit %d\n%s\n%s", code, out, errs)
	}
}

func TestDBPruneKeepLatestZeroNeedsTheExplicitFlag(t *testing.T) {
	cfg, _ := seedMaint(t, []maintHunt{{"activity-20261001T000000Z", 3, 300, ""}})
	// By omission the newest activity stays.
	code, out, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--kind", "activity", "--older-than", "1d")
	if code != 0 || !strings.Contains(out, "would delete: 0 hunt(s)") || !strings.Contains(out, "keep (latest of its kind)") {
		t.Fatalf("default keep: %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run(t, testDeps(nil), "db", "prune", "--config", cfg, "--kind", "activity", "--older-than", "1d", "--keep-latest", "0")
	if code != 0 || !strings.Contains(out, "would delete: 1 hunt(s)") {
		t.Fatalf("explicit 0: %d\n%s\n%s", code, out, errs)
	}
}

func TestDBPruneAndCompactAreRefusedWhileAnotherProcessHoldsTheStore(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	before := hashOf(t, store)
	holdStore(t, store)
	t.Setenv(duckdb.EnvLockWait, "400ms")
	for _, args := range [][]string{
		{"prune", "--config", cfg, "--kind", "hunt", "--older-than", "7d", "--apply"},
		{"prune", "--config", cfg, "--kind", "hunt", "--older-than", "7d"},
		{"compact", "--config", cfg, "--to", store + ".new", "--apply"},
		{"usage", "--config", cfg},
	} {
		start := time.Now()
		code, out, errs := run(t, testDeps(nil), append([]string{"db"}, args...)...)
		if code != 1 || !strings.Contains(errs, "refusing") || !strings.Contains(errs, "PID") || !strings.Contains(errs, "another process") {
			t.Errorf("%v: exit %d\nstdout %s\nstderr %s", args, code, out, errs)
		}
		if time.Since(start) < 300*time.Millisecond {
			t.Errorf("%v: gave up before the lock wait", args)
		}
	}
	if _, err := os.Stat(store + ".new"); err == nil {
		t.Error("a refused compact wrote a file")
	}
	_ = before
}

// TestHolderProcessROCmd holds the store read-only: other readers may share it, a writer may not.
func TestHolderProcessROCmd(t *testing.T) {
	path := os.Getenv("JB_TEST_HOLD_RO")
	if path == "" {
		t.Skip("child helper")
	}
	st, err := duckdb.Open(path, true)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	fmt.Println("HELD")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	st.Close()
	os.Exit(0)
}

func TestDBCompactApplyIsRefusedWhileAReaderHoldsTheStore(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHolderProcessROCmd$")
	cmd.Env = append(os.Environ(), "JB_TEST_HOLD_RO="+store)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	if line, _ := bufio.NewReader(out).ReadString('\n'); strings.TrimSpace(line) != "HELD" {
		t.Fatalf("holder said %q", line)
	}
	t.Setenv(duckdb.EnvLockWait, "400ms")
	// A dry run only reads and may share the file; the apply needs it alone.
	if code, _, errs := run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", store+".new"); code != 0 {
		t.Errorf("dry run beside a reader: exit %d\n%s", code, errs)
	}
	// Likewise usage and a prune dry run are read-only and share the file with a reader.
	for _, args := range [][]string{{"usage", "--config", cfg}, {"prune", "--config", cfg, "--kind", "hunt", "--older-than", "7d"}} {
		if code, _, errs := run(t, testDeps(nil), append([]string{"db"}, args...)...); code != 0 {
			t.Errorf("%v beside a reader: exit %d\n%s", args, code, errs)
		}
	}
	if code, _, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--kind", "hunt", "--older-than", "7d", "--apply"); code != 1 || !strings.Contains(errs, "refusing") {
		t.Errorf("prune apply beside a reader: exit %d\n%s", code, errs)
	}
	code, _, errs := run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", store+".new", "--apply")
	if code != 1 || !strings.Contains(errs, "refusing") || !strings.Contains(errs, "PID") {
		t.Errorf("apply beside a reader: exit %d\n%s", code, errs)
	}
}

func TestDBCompactTargetRules(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	dir := filepath.Dir(store)
	outsideDir := t.TempDir()

	// Existing target: refused, untouched.
	existing := filepath.Join(dir, "exists.duckdb")
	if err := os.WriteFile(existing, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", existing, "--apply")
	if code != 1 || !strings.Contains(errs, "already exists") {
		t.Errorf("existing: exit %d\n%s", code, errs)
	}
	if b, _ := os.ReadFile(existing); string(b) != "precious" {
		t.Error("an existing file was changed")
	}
	// The store itself.
	if code, _, errs = run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", store, "--apply"); code != 1 || !strings.Contains(errs, "already exists") {
		t.Errorf("store as target: exit %d\n%s", code, errs)
	}
	// Outside the evidence directory.
	outside := filepath.Join(outsideDir, "copy.duckdb")
	code, _, errs = run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", outside, "--apply")
	if code != 1 || !strings.Contains(errs, "outside the evidence directory") || !strings.Contains(errs, "--allow-outside-evidence") {
		t.Errorf("outside: exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Error("a refused compact wrote outside the evidence directory")
	}
	// A missing directory is not created.
	if code, _, errs = run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", filepath.Join(dir, "nope", "c.duckdb"), "--apply"); code != 1 || !strings.Contains(errs, "does not exist") {
		t.Errorf("missing dir: exit %d\n%s", code, errs)
	}
	if code, _, errs = run(t, testDeps(nil), "db", "compact", "--config", cfg, "--apply"); code != 2 || !strings.Contains(errs, "--to") {
		t.Errorf("no --to: exit %d\n%s", code, errs)
	}
	// The override works.
	code, out, errs := run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", outside, "--apply", "--allow-outside-evidence")
	if code != 0 {
		t.Fatalf("override: exit %d\n%s", code, errs)
	}
	if fi, err := os.Stat(outside); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("copy: %v %v", fi, err)
	}
	_ = out
}

func TestDBCompactWritesAVerifiedCopyAndLeavesTheOriginalAlone(t *testing.T) {
	cfg, store := seedMaint(t, standardHunts)
	if code, _, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--kind", "hunt,activity", "--older-than", "7d", "--keep-latest", "0", "--apply"); code != 0 {
		t.Fatalf("prune: %s", errs)
	}
	before := hashOf(t, store)
	target := filepath.Join(filepath.Dir(store), "compacted.duckdb")

	code, out, errs := run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", target)
	if code != 0 || !strings.Contains(out, "dry run: nothing was written") || !strings.Contains(out, "estimated copy") {
		t.Fatalf("dry run: exit %d\n%s\n%s", code, out, errs)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("a dry run wrote the target")
	}

	code, out, errs = run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", target, "--apply")
	if code != 0 {
		t.Fatalf("apply: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"verified:", "mode 0600", "was not changed", "STOP EVERY `jb watch`", "mv ", ".before-compact", "rows: events"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply output lacks %q:\n%s", want, out)
		}
	}
	noLeak(t, out, errs)
	if hashOf(t, store) != before {
		t.Error("compact changed the original")
	}
	a, err := duckdb.Open(store, true)
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := a.Stats()
	a.Close()
	b, err := duckdb.Open(target, true)
	if err != nil {
		t.Fatalf("the copy does not open: %v", err)
	}
	sb, _ := b.Stats()
	b.Close()
	sa.Path, sb.Path = "", ""
	if sa != sb || sb.Version != duckdb.Version {
		t.Errorf("copy stats differ:\n%+v\n%+v", sa, sb)
	}
	// Second apply to the same target is refused: it exists now.
	if code, _, errs = run(t, testDeps(nil), "db", "compact", "--config", cfg, "--to", target, "--apply"); code != 1 || !strings.Contains(errs, "already exists") {
		t.Errorf("second compact: exit %d\n%s", code, errs)
	}
}

func TestDBMaintenanceWithACase(t *testing.T) {
	dir, _ := untilCase(t, searchDocs(), 0)
	if code, _, _, errs := runSearchHunt(t, dir); code == 2 {
		t.Fatalf("hunt: %s", errs)
	}
	code, out, errs := run(t, testDeps(nil), "db", "usage", "--case", dir, "--config", fpConfigRel)
	if code != 0 || !strings.Contains(out, "hunt ") {
		t.Fatalf("usage --case: exit %d\n%s\n%s", code, out, errs)
	}
	ev := filepath.Join(dir, "evidence")
	target := filepath.Join(ev, "copy.duckdb")
	if code, out, errs = run(t, testDeps(nil), "db", "compact", "--case", dir, "--config", fpConfigRel, "--to", target, "--apply"); code != 0 {
		t.Fatalf("compact --case: exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "--case") {
		t.Errorf("swap steps do not name the case:\n%s", out)
	}
	if code, _, errs = run(t, testDeps(nil), "db", "compact", "--case", dir, "--config", fpConfigRel, "--to", filepath.Join(t.TempDir(), "x.duckdb"), "--apply"); code != 1 || !strings.Contains(errs, "outside the evidence directory") {
		t.Errorf("outside evidence: exit %d\n%s", code, errs)
	}
}
