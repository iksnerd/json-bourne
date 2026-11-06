package authspike

import (
	"fmt"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const wantNoSuccessNote = "no successful events were logged in this window; the failure share is not meaningful"

// A deployment that logs errors but not successes (Keycloak logs LOGIN at DEBUG and
// LOGIN_ERROR at WARN by default) shows only failures: every key, and the population,
// is at 100%. The failure share says nothing then, so the finding is annotated and one
// step lower, and it is never dropped to a clean result.
func TestFailValuesWindowWithoutAnySuccessIsAnnotatedAndLowered(t *testing.T) {
	var cur, prev []core.Event
	for i := 10; i < 15; i++ {
		cur = append(cur, kcEvents(fmt.Sprintf("192.0.2.%d", i), 20, 0, 0)...)
		prev = append(prev, kcEvents(fmt.Sprintf("192.0.2.%d", i), 20, 0, 0)...)
	}
	cur = append(cur, kcEvents(attacker, 50, 0, 0)...)
	prev = append(prev, kcEvents(attacker, 2, 28, 0)...)
	fs, err := run(t, kcCfg(), cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Detail["key"] != attacker {
		t.Fatalf("findings = %+v; want the attacker annotated, not a clean result", fs)
	}
	f := fs[0]
	if f.Severity != core.SevHigh-1 {
		t.Errorf("severity = %v, want one step below %v", f.Severity, core.SevHigh)
	}
	if f.Detail["success_events_cur"] != 0 {
		t.Errorf("success_events_cur = %v, want 0 counted from the events", f.Detail["success_events_cur"])
	}
	if !strings.Contains(f.Summary, wantNoSuccessNote) {
		t.Errorf("summary = %q, want it to say %q", f.Summary, wantNoSuccessNote)
	}
}

// With successes in the window nothing changes: same severity, same summary, and the
// count is reported.
func TestFailValuesMixedWindowIsUnchangedByTheNoSuccessGuard(t *testing.T) {
	cur := append(population(), kcEvents(attacker, 45, 5, 0)...)
	prev := append(population(), kcEvents(attacker, 2, 28, 0)...)
	fs, err := run(t, kcCfg(), cur, prev)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	f := fs[0]
	if f.Severity != core.SevHigh {
		t.Errorf("severity = %v, want %v", f.Severity, core.SevHigh)
	}
	if want := 5*19 + 5; f.Detail["success_events_cur"] != want {
		t.Errorf("success_events_cur = %v, want %d", f.Detail["success_events_cur"], want)
	}
	if strings.Contains(f.Summary, "no successful") {
		t.Errorf("summary = %q carries the no-success note in a window with successes", f.Summary)
	}
}

// With HTTP statuses an all-failure window is an outage and stays quiet (pinned by
// TestDetect); the success count is still reported when a finding is raised.
func TestFailStatusesFindingReportsSuccessCount(t *testing.T) {
	c := Config{Name: "st", KeyField: "client_ip", StatusField: "status"}
	mk := func(key string, fail, ok int) []core.Event {
		var out []core.Event
		for i := 0; i < fail; i++ {
			out = append(out, core.Event{Fields: map[string]any{"status": 401, "client_ip": key}})
		}
		for i := 0; i < ok; i++ {
			out = append(out, core.Event{Fields: map[string]any{"status": 200, "client_ip": key}})
		}
		return out
	}
	cur := append(mk("192.0.2.10", 2, 48), mk(attacker, 50, 10)...)
	prev := append(mk("192.0.2.10", 2, 48), mk(attacker, 2, 28)...)
	fs, err := run(t, c, cur, prev)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	if fs[0].Severity != core.SevHigh || fs[0].Detail["success_events_cur"] != 58 || strings.Contains(fs[0].Summary, "no successful") {
		t.Errorf("finding = %+v", fs[0])
	}
}
