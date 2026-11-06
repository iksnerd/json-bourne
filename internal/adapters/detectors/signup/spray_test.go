package signup

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

func sprayPath() Config {
	c := baseCfg()
	c.MinAttempts = 10
	return c
}

func sprayEvent() Config {
	c := evCfg()
	c.MinAttempts = 10
	return c
}

// A spray is many failed attempts and few creations: below min_creations, so the
// creation rule says nothing, and the attempt rule has to speak.
func TestSprayBothMetPathMode(t *testing.T) {
	fs, err := detect(t, sprayPath(), evs(rejected(30), created(2)), evs(rejected(5), created(1)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	f := fs[0]
	if f.Tag != "signup:attempts" || f.Severity != core.SevActivity {
		t.Errorf("tag %q severity %v", f.Tag, f.Severity)
	}
	d := f.Detail
	if d["failed_attempts_cur"] != 30 || d["failed_attempts_prev"] != 5 || d["creations_cur"] != 2 || d["creations_prev"] != 1 {
		t.Errorf("detail = %v", d)
	}
	if got := d["failure_share_cur"].(float64); got < 0.9374 || got > 0.9376 {
		t.Errorf("failure share = %v, want 30/32", got)
	}
	for _, want := range []string{"30 failed", "2 accounts created", "93.8%", "5 failed attempts and 1 created"} {
		if !strings.Contains(f.Summary, want) {
			t.Errorf("summary %q lacks %q", f.Summary, want)
		}
	}
}

func TestSprayBothMetEventMode(t *testing.T) {
	cur := cat(ev("REGISTER_ERROR", 30, ""), ev("REGISTER", 2, ""), ev("LOGIN", 80, ""))
	prev := cat(ev("REGISTER_ERROR", 5, ""), ev("REGISTER", 1, ""))
	fs, err := detect(t, sprayEvent(), cur, prev)
	if err != nil || len(fs) != 1 || fs[0].Tag != "signup:attempts" {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	if fs[0].Detail["failed_attempts_cur"] != 30 || fs[0].Detail["creations_cur"] != 2 {
		t.Errorf("detail = %v", fs[0].Detail)
	}
}

func TestSprayBelowMinAttemptsIsQuiet(t *testing.T) {
	fs, err := detect(t, sprayPath(), evs(rejected(9), created(1)), evs(rejected(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings = %+v, err %v; 9 < min_attempts 10 must not raise", fs, err)
	}
}

func TestSprayNoRiseIsQuiet(t *testing.T) {
	// 40 failed against 20 is 2x, under attempt_factor 3: a steady busy form.
	fs, err := detect(t, sprayPath(), evs(rejected(40)), evs(rejected(20)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings = %+v, err %v; no rise must not raise", fs, err)
	}
	// Exactly 3x is raised (inclusive).
	fs, err = detect(t, sprayPath(), evs(rejected(60)), evs(rejected(20)))
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v; 3x must raise", fs, err)
	}
}

func TestSprayAttemptFactorIsConfigurable(t *testing.T) {
	c := sprayPath()
	c.AttemptFactor = 1.5
	fs, err := detect(t, c, evs(rejected(40)), evs(rejected(20)))
	if err != nil || len(fs) != 1 || fs[0].Detail["attempt_factor"] != 1.5 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
}

func TestSprayBaselineEmptyLowersSeverity(t *testing.T) {
	fs, err := detect(t, sprayPath(), evs(rejected(30), created(1)), nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	f := fs[0]
	if f.Severity != core.SevCheck || f.Detail["baseline_empty"] != true {
		t.Errorf("severity %v baseline_empty %v, want check/true", f.Severity, f.Detail["baseline_empty"])
	}
	if !strings.Contains(f.Summary, "no preceding window") {
		t.Errorf("summary %q should say there is nothing to compare", f.Summary)
	}
}

// A preceding window that holds only creations is a real baseline of zero failed
// attempts, not an empty one.
func TestSprayPrevWithOnlyCreationsIsRealBaseline(t *testing.T) {
	fs, err := detect(t, sprayPath(), evs(rejected(12)), evs(created(3)))
	if err != nil || len(fs) != 1 || fs[0].Severity != core.SevActivity || fs[0].Detail["baseline_empty"] != false {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
}

func TestSprayCreationsStillBehaveAsBefore(t *testing.T) {
	// Creation burst with the spray rule on and not met: exactly the old finding.
	c := sprayPath()
	fs, err := detect(t, c, evs(created(12), rejected(2)), evs(created(2)))
	if err != nil || len(fs) != 1 || fs[0].Tag != "signup" {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	// Both rules met: two findings, distinct tags.
	fs, err = detect(t, c, evs(created(12), rejected(30)), evs(created(2), rejected(2)))
	if err != nil || len(fs) != 2 || byTag(fs, "signup") == nil || byTag(fs, "signup:attempts") == nil {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
}

func TestSprayOffByDefault(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(rejected(500), created(1)), evs(rejected(1)))
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings = %+v, err %v; min_attempts 0 must leave the rule off", fs, err)
	}
	fs, err = detect(t, evCfg(), cat(ev("REGISTER_ERROR", 500, ""), ev("REGISTER", 1, "")), ev("REGISTER_ERROR", 1, ""))
	if err != nil || len(fs) != 0 {
		t.Fatalf("event mode: findings = %+v, err %v", fs, err)
	}
}

func TestSprayEmptyWindowStillNoRecords(t *testing.T) {
	_, err := detect(t, sprayEvent(), ev("LOGIN", 50, ""), ev("REGISTER_ERROR", 50, ""))
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("err = %v, want core.ErrNoRecords", err)
	}
	_, err = detect(t, sprayPath(), evs(otherForm(50), formRender(5)), evs(rejected(50)))
	if !errors.Is(err, core.ErrNoRecords) {
		t.Fatalf("path mode: err = %v, want core.ErrNoRecords", err)
	}
}

func TestSprayNeverPutsAnAddressInAFinding(t *testing.T) {
	const sentinel = "sentinel.person"
	c := sprayEvent()
	c.AddressField, c.DisposableDomains = "email", []string{"tempmail.example"}
	cur := cat(ev("REGISTER_ERROR", 30, sentinel+".example.com"), ev("REGISTER", 2, "tempmail.example"))
	fs, err := detect(t, c, cur, nil)
	if err != nil || byTag(fs, "signup:attempts") == nil {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	for _, f := range fs {
		if s := fmt.Sprint(f.Tag, f.Summary, f.Detail); strings.Contains(s, sentinel) || strings.Contains(s, "@") {
			t.Errorf("finding leaks an address: %s", s)
		}
	}
}

func TestSprayValidation(t *testing.T) {
	bad := map[string]func(*Config){
		"negative min_attempts":      func(c *Config) { c.MinAttempts = -1 },
		"attempt_factor 1":           func(c *Config) { c.AttemptFactor = 1 },
		"attempt_factor below 1":     func(c *Config) { c.AttemptFactor = 0.5 },
		"attempt_factor negative":    func(c *Config) { c.AttemptFactor = -3 },
		"attempt_factor without min": func(c *Config) { c.MinAttempts = 0; c.AttemptFactor = 4 },
	}
	for name, mut := range bad {
		c := sprayPath()
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	d, err := New(sprayPath())
	if err != nil || d.cfg.AttemptFactor != 3 {
		t.Fatalf("default attempt_factor: %v, %v", d, err)
	}
}
