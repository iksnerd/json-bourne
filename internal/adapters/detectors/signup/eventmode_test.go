package signup

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func evCfg() Config {
	return Config{EventField: "event_type", CreateValues: []string{"REGISTER"}, AttemptValues: []string{"REGISTER_ERROR"}}
}

func ev(typ string, n int, email string) []core.Event {
	var out []core.Event
	for i := 0; i < n; i++ {
		f := map[string]any{"event_type": typ}
		if email != "" {
			f["email"] = fmt.Sprintf("u%d@%s", i, email)
		}
		out = append(out, core.Event{Fields: f})
	}
	return out
}

func cat(parts ...[]core.Event) []core.Event {
	var out []core.Event
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The event that creates the account is REGISTER. REGISTER_ERROR is an attempt.
func TestEventModeCountsRegisterNotRegisterError(t *testing.T) {
	cur := cat(ev("REGISTER", 12, ""), ev("REGISTER_ERROR", 40, ""), ev("LOGIN", 100, ""))
	prev := cat(ev("REGISTER", 2, ""), ev("REGISTER_ERROR", 3, ""))
	fs, err := detect(t, evCfg(), cur, prev)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	d := fs[0].Detail
	if d["creations_cur"] != 12 || d["attempts_cur"] != 52 || d["creations_prev"] != 2 {
		t.Errorf("detail = %v, want 12 creations of 52 attempts against 2", d)
	}
	// Forty failed attempts and no creation is attempts, not a burst of accounts.
	fs, err = detect(t, evCfg(), cat(ev("REGISTER_ERROR", 40, ""), ev("REGISTER", 1, "")), prev)
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings = %+v, err %v; failed attempts must not be counted as accounts", fs, err)
	}
}

func TestEventModeNoRegisterEventsIsNoRecords(t *testing.T) {
	_, err := detect(t, evCfg(), ev("LOGIN", 50, ""), nil)
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
	_, err = detect(t, evCfg(), []core.Event{{Fields: map[string]any{"event_type": 7}}, {Fields: map[string]any{}}}, nil)
	if !errors.Is(err, core.ErrNoRecords) || !strings.Contains(err.Error(), "2 with an unparsable") {
		t.Fatalf("err = %v, want no records counting the 2 unreadable events", err)
	}
}

func TestEventModeIsStrictlyAlternativeToPathMode(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"paths":            func(c *Config) { c.CreatePaths = []string{"/x"} },
		"status":           func(c *Config) { c.StatusField = "status" },
		"success":          func(c *Config) { c.SuccessStatuses = []int{200} },
		"method":           func(c *Config) { c.MethodField = "method" },
		"no create values": func(c *Config) { c.CreateValues = nil },
		"overlap":          func(c *Config) { c.AttemptValues = []string{"REGISTER"} },
		"blank":            func(c *Config) { c.CreateValues = []string{" "} },
	} {
		c := evCfg()
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	// Path mode is unchanged.
	if _, err := New(baseCfg()); err != nil {
		t.Fatal(err)
	}
}

func TestEventModeFindingsNeverCarryAnAddress(t *testing.T) {
	c := evCfg()
	c.AddressField, c.DisposableDomains = "email", []string{"mail.example"}
	sent := "sentinel.person@mail.example"
	cur := cat(ev("REGISTER", 8, "mail.example"), []core.Event{{Fields: map[string]any{"event_type": "REGISTER", "email": sent}}})
	fs, err := detect(t, c, cur, ev("REGISTER", 1, ""))
	if err != nil || len(fs) < 2 {
		t.Fatalf("findings = %+v, err %v; want a burst and a disposable finding", fs, err)
	}
	b, _ := json.Marshal(fs)
	for _, part := range []string{sent, "sentinel.person", "u0@"} {
		if strings.Contains(string(b), part) {
			t.Errorf("findings leak %q: %s", part, b)
		}
	}
}
