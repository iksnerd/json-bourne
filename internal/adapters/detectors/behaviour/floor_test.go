package behaviour

import (
	"errors"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
)

func floorCfg(mut func(*Action)) Config {
	c := cfg()
	a := Action{Name: "admin-console-login", Class: ClassRare, Path: "/admin/login", Methods: []string{"POST"}}
	if mut != nil {
		mut(&a)
	}
	c.Actions = []Action{a}
	return c
}

func adminEvents(key string, n int) ev {
	return ev{key: key, path: "/admin/login", method: "POST", n: n}
}

func TestMinSeverityRaisesRareFinding(t *testing.T) {
	c := floorCfg(func(a *Action) { a.MinSeverity, a.Note = "critical", "admin console is never used from outside" })
	cur := events(win, noise(), adminEvents(c1, 1))
	fs, err := detect(t, c, cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	f := fs[0]
	if f.Severity != core.SevCritical || f.Tag != "behaviour:admin-console-login" {
		t.Errorf("severity %v tag %s", f.Severity, f.Tag)
	}
	if f.Detail["min_severity"] != "critical" || f.Detail["note"] != "admin console is never used from outside" {
		t.Errorf("detail %+v", f.Detail)
	}
}

func TestMinSeverityIsAFloorAppliedAfterBaselineDrop(t *testing.T) {
	c := floorCfg(func(a *Action) { a.MinSeverity = "activity" })
	// Empty baseline: computed check, the floor lifts it to activity, baseline_empty still shown.
	fs, err := detect(t, c, events(win, adminEvents(c1, 1)), nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	if fs[0].Severity != core.SevActivity || fs[0].Detail["baseline_empty"] != true || fs[0].Detail["min_severity"] != "activity" {
		t.Errorf("%v %+v", fs[0].Severity, fs[0].Detail)
	}
	// A floor at the computed result changes nothing and is not shown.
	fs, _ = detect(t, c, events(win, noise(), adminEvents(c1, 1)), events(win.Previous(), noise()))
	if fs[0].Severity != core.SevActivity {
		t.Errorf("severity %v", fs[0].Severity)
	}
	if _, ok := fs[0].Detail["min_severity"]; ok {
		t.Errorf("min_severity shown though it raised nothing: %+v", fs[0].Detail)
	}
}

func TestMinSeverityAndNoteRefusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Action)
		want string
	}{
		{"info", func(a *Action) { a.MinSeverity = "info" }, "min_severity"},
		{"check", func(a *Action) { a.MinSeverity = "check" }, "min_severity"},
		{"unknown", func(a *Action) { a.MinSeverity = "urgent" }, "min_severity"},
		{"critical needs note", func(a *Action) { a.MinSeverity = "critical" }, "note"},
		{"critical blank note", func(a *Action) { a.MinSeverity, a.Note = "critical", "  " }, "note"},
		{"common min_severity", func(a *Action) { a.Class, a.MinSeverity = ClassCommon, "high" }, "rare"},
		{"common note", func(a *Action) { a.Class, a.Note = ClassCommon, "x" }, "rare"},
	}
	for _, tc := range cases {
		_, err := New(floorCfg(tc.mut))
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "admin-console-login") {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

func TestMinEventsPerKeyRefusals(t *testing.T) {
	for name, mut := range map[string]func(*Action){
		"negative": func(a *Action) { a.MinEventsPerKey = -1 },
		"common":   func(a *Action) { a.Class, a.MinEventsPerKey = ClassCommon, 2 },
	} {
		if _, err := New(floorCfg(mut)); err == nil || !strings.Contains(err.Error(), "min_events_per_key") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func perKey(n int) Config { return floorCfg(func(a *Action) { a.MinEventsPerKey = n }) }

func TestMinEventsPerKeyBoundary(t *testing.T) {
	prev := events(win.Previous(), noise())
	// N-1 from one key: quiet.
	fs, err := detect(t, perKey(3), events(win, noise(), adminEvents(c1, 2)), prev)
	if err != nil || len(fs) != 0 {
		t.Fatalf("N-1: fs=%v err=%v", fs, err)
	}
	// N from one key: fires and names the key.
	fs, err = detect(t, perKey(3), events(win, noise(), adminEvents(c1, 3)), prev)
	if err != nil || len(fs) != 1 {
		t.Fatalf("N: fs=%v err=%v", fs, err)
	}
	if fs[0].Detail["hot_key"] != c1 || fs[0].Detail["hot_key_events"] != 3 {
		t.Errorf("detail %+v", fs[0].Detail)
	}
	// N spread over N distinct keys: quiet.
	fs, err = detect(t, perKey(3), events(win, noise(), adminEvents("198.51.100.1", 1), adminEvents("198.51.100.2", 1), adminEvents("198.51.100.3", 1)), prev)
	if err != nil || len(fs) != 0 {
		t.Fatalf("spread: fs=%v err=%v", fs, err)
	}
}

func TestMinEventsPerKeyCombinesWithMinEvents(t *testing.T) {
	c := floorCfg(func(a *Action) { a.MinEvents, a.MinEventsPerKey = 5, 2 })
	prev := events(win.Previous(), noise())
	fs, _ := detect(t, c, events(win, noise(), adminEvents(c1, 4)), prev)
	if len(fs) != 0 {
		t.Errorf("total below min_events fired: %v", fs)
	}
	fs, _ = detect(t, c, events(win, noise(), adminEvents(c1, 5)), prev)
	if len(fs) != 1 {
		t.Errorf("both hold, quiet: %v", fs)
	}
}

func TestHotKeyIsHashedWithHashKeys(t *testing.T) {
	c := perKey(2)
	c.KeyField, c.HashKeys, c.IgnoreKeys = "email", true, nil
	cur := events(win, noise(), ev{path: "/admin/login", method: "POST", n: 2, extra: map[string]any{"email": sentinelEmail}})
	fs, err := detect(t, c, cur, events(win.Previous(), noise()))
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	if fs[0].Detail["hot_key"] != piiguard.Hash(sentinelEmail) || strings.Contains(fs[0].Summary, "sentinel") {
		t.Errorf("hot_key %v summary %s", fs[0].Detail["hot_key"], fs[0].Summary)
	}
}

func truncCfg(n int) Config {
	c := perKey(n)
	c.MaxKeys = 2
	return c
}

func TestTruncatedWithoutHotKeyIsIncompleteNotQuiet(t *testing.T) {
	prev := events(win.Previous(), noise())
	cur := events(win, noise(), adminEvents("198.51.100.1", 1), adminEvents("198.51.100.2", 1), adminEvents("198.51.100.3", 1))
	fs, err := detect(t, truncCfg(3), cur, prev)
	if err == nil || errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want an incomplete error", err)
	}
	for _, w := range []string{"admin-console-login", "max_keys"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q lacks %q", err, w)
		}
	}
	if len(fs) != 0 {
		t.Errorf("findings %v", fs)
	}
	if _, aerr := activityOf(t, truncCfg(3), cur, prev); aerr == nil {
		t.Error("Activity answered cleanly for an action that could not be judged")
	}
}

func TestTruncatedWithHotKeyStillFires(t *testing.T) {
	prev := events(win.Previous(), noise())
	cur := events(win, noise(), adminEvents("198.51.100.1", 3), adminEvents("198.51.100.2", 1), adminEvents("198.51.100.3", 1))
	fs, err := detect(t, truncCfg(3), cur, prev)
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	if fs[0].Detail["keys_truncated"] != true || fs[0].Detail["hot_key"] != "198.51.100.1" {
		t.Errorf("detail %+v", fs[0].Detail)
	}
}

func TestTruncationDoesNotMatterWithoutPerKey(t *testing.T) {
	c := truncCfg(0)
	cur := events(win, noise(), adminEvents("198.51.100.1", 1), adminEvents("198.51.100.2", 1), adminEvents("198.51.100.3", 1))
	if fs, err := detect(t, c, cur, events(win.Previous(), noise())); err != nil || len(fs) != 1 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
}
