package authspike

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Keycloak-shaped events: an outcome string, no HTTP status.
func kcEvents(key string, fail, ok, noOutcome int) []core.Event {
	var out []core.Event
	add := func(f map[string]any) { out = append(out, core.Event{Fields: f}) }
	for i := 0; i < fail; i++ {
		add(map[string]any{"outcome": "error", "event_type": "LOGIN_ERROR", "client_ip": key, "username": key})
	}
	for i := 0; i < ok; i++ {
		add(map[string]any{"outcome": "success", "event_type": "LOGIN", "client_ip": key, "username": key})
	}
	for i := 0; i < noOutcome; i++ {
		add(map[string]any{"event_type": "LOGIN", "client_ip": key})
	}
	return out
}

func kcCfg() Config {
	return Config{Name: "kc", KeyField: "client_ip", StatusField: "outcome", FailValues: []string{"error"}, PathField: "event_type", PathContains: "LOGIN"}
}

func run(t *testing.T, c Config, cur, prev []core.Event) ([]core.Finding, error) {
	t.Helper()
	return mustNew(t, c).Detect(t.Context(), fakeReader{evs: cur}, fakeReader{evs: prev}, win)
}

func population() []core.Event {
	var evs []core.Event
	for i := 10; i < 15; i++ {
		evs = append(evs, kcEvents(fmt.Sprintf("192.0.2.%d", i), 1, 19, 0)...)
	}
	return evs
}

func TestFailValuesJudgeAStringOutcomeByFailureShare(t *testing.T) {
	cur := append(population(), kcEvents(attacker, 45, 5, 0)...)
	prev := append(population(), kcEvents(attacker, 2, 28, 0)...)
	fs, err := run(t, kcCfg(), cur, prev)
	if err != nil || len(fs) != 1 || fs[0].Tag != "kc:"+attacker {
		t.Fatalf("findings = %+v, err %v; want one rising finding for the attacker", fs, err)
	}
	if got := fs[0].Detail["key_cur_failures"]; got != 45 {
		t.Errorf("key_cur_failures = %v, want 45 counted from the events", got)
	}
}

// A volume spike with no failures is a busy platform, in text mode as in numeric.
func TestFailValuesBusyPlatformIsNotASpray(t *testing.T) {
	cur := append(population(), kcEvents(attacker, 0, 200, 0)...)
	prev := append(population(), kcEvents(attacker, 0, 20, 0)...)
	fs, err := run(t, kcCfg(), cur, prev)
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings = %+v, err %v; want none", fs, err)
	}
}

func TestFailValuesMissingOrNonTextIsUnparsableNotSuccess(t *testing.T) {
	cur := append(population(), kcEvents(attacker, 0, 0, 30)...)
	cur = append(cur, core.Event{Fields: map[string]any{"outcome": 401, "event_type": "LOGIN", "client_ip": attacker}})
	fs, err := run(t, kcCfg(), cur, population())
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	// All of them unreadable is no records, never a clean window.
	_, err = run(t, kcCfg(), kcEvents(attacker, 0, 0, 40), nil)
	if !errors.Is(err, core.ErrNoRecords) || !strings.Contains(err.Error(), "unparsable") {
		t.Fatalf("err = %v, want core.ErrNoRecords naming the unparsable events", err)
	}
}

func TestFailStatusesAndFailValuesAreExclusive(t *testing.T) {
	c := kcCfg()
	c.FailStatuses = []int{401}
	if _, err := New(c); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	c = kcCfg()
	c.FailValues = []string{"error", " "}
	if _, err := New(c); err == nil {
		t.Fatal("a blank fail value was accepted")
	}
	d := mustNew(t, kcCfg())
	if len(d.fail) != 0 {
		t.Errorf("text mode must not inherit the 401/403 default: %v", d.fail)
	}
}

const sentinel = "sentinel.person@example.com"

func TestPersonalKeyNeverAppearsInAFinding(t *testing.T) {
	c := Config{Name: "kc", KeyField: "username", StatusField: "outcome", FailValues: []string{"error"}, HashKeys: true}
	mk := func(fail, ok int) []core.Event {
		var out []core.Event
		for i := 0; i < fail; i++ {
			out = append(out, core.Event{Fields: map[string]any{"outcome": "error", "username": sentinel}})
		}
		for i := 0; i < ok; i++ {
			out = append(out, core.Event{Fields: map[string]any{"outcome": "success", "username": sentinel}})
		}
		return out
	}
	other := func() []core.Event {
		var out []core.Event
		for i := 0; i < 100; i++ {
			out = append(out, core.Event{Fields: map[string]any{"outcome": "success", "username": fmt.Sprintf("u%d@example.com", i%10)}})
		}
		return out
	}
	fs, err := run(t, c, append(other(), mk(45, 5)...), append(other(), mk(2, 28)...))
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	b, _ := json.Marshal(fs[0])
	for _, part := range []string{sentinel, "sentinel.person", "@example.com"} {
		if strings.Contains(string(b), part) || strings.Contains(fs[0].Tag, part) || strings.Contains(fs[0].Summary, part) {
			t.Errorf("finding leaks %q: %s", part, b)
		}
	}
	if !strings.HasPrefix(fs[0].Tag, "kc:h:") {
		t.Errorf("tag = %q, want a digest", fs[0].Tag)
	}
	// The tag is stable, so one ongoing condition still dedupes across runs.
	fs2, _ := run(t, c, append(other(), mk(45, 5)...), append(other(), mk(2, 28)...))
	if fs2[0].Tag != fs[0].Tag {
		t.Errorf("tag changed between runs: %q vs %q", fs[0].Tag, fs2[0].Tag)
	}
}

func TestPersonalKeyFieldWithoutHashingIsRefused(t *testing.T) {
	for _, f := range []string{"username", "Email", "user_id"} {
		c := kcCfg()
		c.KeyField = f
		if _, err := New(c); err == nil || !strings.Contains(err.Error(), "personal data") {
			t.Errorf("key_field %q: err = %v, want a refusal", f, err)
		}
	}
}
