package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
)

// runIDHunts adds two search-until runs whose ids are a prefix of each other.
var runIDHunts = append(append([]maintHunt{}, standardHunts...),
	maintHunt{"search-until-20261001T000000Z-w60s", 8, 300, ""},
	maintHunt{"search-until-20261001T000000Z-w600s", 9, 300, ""},
)

func eventsOf(t *testing.T, store string) map[string]int {
	t.Helper()
	db, err := sql.Open("duckdb", store)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT split_part(run_id, '/', 1), count(*) FROM events GROUP BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			t.Fatal(err)
		}
		m[id] = n
	}
	return m
}

func TestDBPruneRunDryRunListsExactlyTheNamedRunsAndChangesNothing(t *testing.T) {
	cfg, store := seedMaint(t, runIDHunts)
	before := hashOf(t, store)
	code, out, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--run", "hunt-20261001T000000Z", "--run", "hunt-20261105T100000Z")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{"(dry run)", "named with --run", "prune  hunt-20261001T000000Z (hunt)", "4 events", "prune  hunt-20261105T100000Z (hunt)", "would delete: 2 hunt(s)", "6 events", "dry run: nothing was changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunt-20261002T000000Z") || strings.Contains(out, "keep (latest") {
		t.Errorf("an unnamed run is listed:\n%s", out)
	}
	noLeak(t, out, errs)
	if hashOf(t, store) != before {
		t.Error("a dry run changed the file")
	}
	code, out, errs = run(t, testDeps(nil), "db", "prune", "--config", cfg, "--run", "hunt-20261001T000000Z", "--output", "json")
	if code != 0 {
		t.Fatalf("json exit %d\n%s", code, errs)
	}
	var got struct {
		ByRunID bool `json:"by_run_id"`
		Runs    []struct {
			ID     string `json:"id"`
			Action string `json:"action"`
			Events int    `json:"events"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !got.ByRunID || len(got.Runs) != 1 || got.Runs[0].ID != "hunt-20261001T000000Z" || got.Runs[0].Action != "prune" || got.Runs[0].Events != 4 {
		t.Errorf("json = %+v", got)
	}
}

func TestDBPruneRunApplyRemovesOnlyTheNamedRunNewerAndOlderStay(t *testing.T) {
	cfg, store := seedMaint(t, runIDHunts)
	// hunt-20261002 (400h old) is named, twice; the older (500h) and the newer (2h) hunt stay.
	code, out, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--run", "hunt-20261002T000000Z", "--run", "hunt-20261002T000000Z", "--apply")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	for _, want := range []string{"(apply)", "deleted: 3 events", "2 run record(s) marked pruned", "findings kept", "jb db compact"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply lacks %q:\n%s", want, out)
		}
	}
	noLeak(t, out, errs)
	ev := eventsOf(t, store)
	if _, still := ev["hunt-20261002T000000Z"]; still {
		t.Error("the named run kept its events")
	}
	for id, n := range map[string]int{"hunt-20261001T000000Z": 4, "hunt-20261105T100000Z": 2, "activity-20261001T000000Z": 6, "watch-20261001T000000Z": 7} {
		if ev[id] != n {
			t.Errorf("events of %s = %d, want %d", id, ev[id], n)
		}
	}
	st, err := duckdb.Open(store, true)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := st.Stats()
	st.Close()
	if int(s.Findings) != len(runIDHunts) || s.Reputation != 1 {
		t.Errorf("findings/reputation changed: %+v", s)
	}
	// --drop-findings takes the findings and records of the named run only.
	code, out, errs = run(t, testDeps(nil), "db", "prune", "--config", cfg, "--run", "hunt-20261001T000000Z", "--drop-findings", "--apply")
	if code != 0 || !strings.Contains(out, "1 findings, 2 run records") {
		t.Fatalf("drop-findings: exit %d\n%s\n%s", code, out, errs)
	}
}

func TestDBPruneRunMatchesTheExactIDNotAPrefix(t *testing.T) {
	cfg, store := seedMaint(t, runIDHunts)
	code, out, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--run", "search-until-20261001T000000Z-w60s", "--apply")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	ev := eventsOf(t, store)
	if ev["search-until-20261001T000000Z-w600s"] != 9 || ev["search-until-20261001T000000Z-w60s"] != 0 {
		t.Errorf("events = %v", ev)
	}
}

func TestDBPruneRunUnknownIDFailsAndDeletesNothing(t *testing.T) {
	cfg, store := seedMaint(t, runIDHunts)
	before := hashOf(t, store)
	code, out, errs := run(t, testDeps(nil), "db", "prune", "--config", cfg, "--run", "hunt-20261001T000000Z", "--run", "hunt-20261001T000099Z", "--apply")
	if code == 0 || !strings.Contains(errs, "hunt-20261001T000099Z") || !strings.Contains(errs, "nothing was changed") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	if hashOf(t, store) != before {
		t.Error("a failed prune changed the file")
	}
}

func TestDBPruneRunRefusals(t *testing.T) {
	cfg, store := seedMaint(t, runIDHunts)
	before := hashOf(t, store)
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, "--run", fmt.Sprintf("hunt-20260101T0000%02dZ", i))
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"watch":       {[]string{"--run", "watch-20261001T000000Z"}, "jb watch --keep"},
		"with kind":   {[]string{"--run", "hunt-20261001T000000Z", "--kind", "hunt"}, "cannot be combined with --kind"},
		"with age":    {[]string{"--run", "hunt-20261001T000000Z", "--older-than", "1d"}, "cannot be combined with --older-than"},
		"with keep":   {[]string{"--run", "hunt-20261001T000000Z", "--keep-latest", "1"}, "cannot be combined with --keep-latest"},
		"with keep 0": {[]string{"--run", "hunt-20261001T000000Z", "--keep-latest", "0"}, "cannot be combined with --keep-latest"},
		"too many":    {many, "at most 20"},
		"wildcard":    {[]string{"--run", "hunt-*"}, "no wildcard"},
		"empty":       {[]string{"--run", ""}, "empty run id"},
		"source run":  {[]string{"--run", "hunt-20261001T000000Z/ingress"}, "hunt id"},
		"not a hunt":  {[]string{"--run", "custom"}, "not a hunt, activity or search"},
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
	// 20 ids is the limit and is accepted by the parser (none exist here, so the store says so).
	code, _, errs := run(t, testDeps(nil), append([]string{"db", "prune", "--config", cfg}, many[:40]...)...)
	if code == 2 || !strings.Contains(errs, "no such run") {
		t.Errorf("20 ids: exit %d\n%s", code, errs)
	}
}
