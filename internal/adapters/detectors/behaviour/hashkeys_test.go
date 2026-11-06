package behaviour

import (
	"fmt"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/piiguard"
)

const sentinelEmail = "sentinel.person@example.com"

func TestPersonalKeyFieldWithoutHashingIsRefused(t *testing.T) {
	for _, f := range []string{"username", "email", "user_id", "USER_EMAIL"} {
		c := cfg()
		c.KeyField = f
		if _, err := New(c); err == nil || !strings.Contains(err.Error(), "personal data") {
			t.Errorf("key_field %q: err = %v, want a personal data refusal", f, err)
		}
		c.HashKeys = true
		if _, err := New(c); err != nil {
			t.Errorf("key_field %q with hash_keys: %v", f, err)
		}
	}
	if _, err := New(cfg()); err != nil {
		t.Fatal(err)
	}
}

func TestHashedSoleKeyNeverAppearsInAFinding(t *testing.T) {
	c := cfg()
	c.KeyField, c.HashKeys, c.IgnoreKeys = "email", true, nil
	cur := events(win, ev{path: "/oauth/device/code", method: "POST", n: 3, extra: map[string]any{"email": sentinelEmail}}, noise())
	for i := range cur {
		delete(cur[i].Fields, "client")
	}
	fs, err := detect(t, c, cur, events(win.Previous(), noise()))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := byTag(fs)["behaviour:device-code"]
	if !ok {
		t.Fatalf("findings = %+v", fs)
	}
	if s := fmt.Sprint(f.Tag, "|", f.Summary, "|", f.Detail); strings.Contains(s, "sentinel") || strings.Contains(s, "@") {
		t.Fatalf("finding leaks the key: %s", s)
	}
	if f.Detail["sole_key"] != piiguard.Hash(sentinelEmail) {
		t.Errorf("sole_key = %v, want %s", f.Detail["sole_key"], piiguard.Hash(sentinelEmail))
	}
}

func TestPlainSoleKeyUnchangedWithoutHashKeys(t *testing.T) {
	cur := events(win, ev{key: c1, path: "/oauth/device/code", method: "POST", n: 3}, noise())
	fs, err := detect(t, cfg(), cur, events(win.Previous(), noise()))
	if err != nil {
		t.Fatal(err)
	}
	if f := byTag(fs)["behaviour:device-code"]; f.Detail["sole_key"] != c1 {
		t.Errorf("sole_key = %v, want %s", f.Detail["sole_key"], c1)
	}
}
