package newkey

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
)

const sentinelEmail = "sentinel.person@example.com"

func TestPersonalKeyFieldWithoutHashingIsRefused(t *testing.T) {
	for _, f := range []string{"username", "email", "user_id", "Email"} {
		c := baseCfg()
		c.KeyField = f
		if _, err := New(c); err == nil || !strings.Contains(err.Error(), "personal data") {
			t.Errorf("key_field %q: err = %v, want a personal data refusal", f, err)
		}
		c.HashKeys = true
		if _, err := New(c); err != nil {
			t.Errorf("key_field %q with hash_keys: %v", f, err)
		}
	}
	c := baseCfg() // client: not personal, no hashing needed
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
}

func TestHashedKeyNeverAppearsInAFinding(t *testing.T) {
	c := Config{KeyField: "email", PathField: "path", SensitivePaths: []string{"/secret/"}, HashKeys: true}
	cur := evsKey("email", hit{key: sentinelEmail, path: "/v1/secret/ops", n: 4}, hit{key: "known@example.com", path: "/v1/home", n: 3})
	prev := evsKey("email", hit{key: "known@example.com", path: "/v1/home", n: 3})
	fs, err := detect(t, c, cur, prev)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
	f := fs[0]
	if s := fmt.Sprint(f.Tag, "|", f.Summary, "|", f.Detail); strings.Contains(s, "sentinel") || strings.Contains(s, "@") {
		t.Fatalf("finding leaks the key: %s", s)
	}
	h := piiguard.Hash(sentinelEmail)
	if f.Tag != "newkey:"+h || f.Detail["key"] != h || !strings.Contains(f.Summary, h) {
		t.Errorf("tag %q key %v summary %q, want the digest %s", f.Tag, f.Detail["key"], f.Summary, h)
	}
	if !regexp.MustCompile(`^newkey:h:[0-9a-f]{12}$`).MatchString(f.Tag) {
		t.Errorf("tag %q has the wrong shape", f.Tag)
	}
	// Stable: a second run yields the same tag, so dedupe still works.
	fs2, _ := detect(t, c, cur, prev)
	if len(fs2) != 1 || fs2[0].Tag != f.Tag {
		t.Errorf("tag not stable: %v vs %v", fs2, f.Tag)
	}
}

func TestBaselineEmptySummaryHashesToo(t *testing.T) {
	c := Config{KeyField: "email", PathField: "path", SensitivePaths: []string{"/secret/"}, HashKeys: true}
	fs, err := detect(t, c, evsKey("email", hit{key: sentinelEmail, path: "/secret/x", n: 4}), nil)
	if err != nil || len(fs) != 1 || strings.Contains(fs[0].Summary, "sentinel") {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
}

// Without hash_keys on a non-personal field the key is shown as before.
func TestPlainKeyUnchangedWithoutHashKeys(t *testing.T) {
	fs, err := detect(t, baseCfg(), evs(sens(newcomer, 4), plain(regular, 3)), evs(plain(regular, 3)))
	if err != nil || len(fs) != 1 || fs[0].Tag != "newkey:"+newcomer || fs[0].Detail["key"] != newcomer {
		t.Fatalf("findings = %+v, err %v", fs, err)
	}
}

func evsKey(field string, hs ...hit) []core.Event {
	out := evs(hs...)
	for i := range out {
		out[i].Fields[field] = out[i].Fields["client"]
		delete(out[i].Fields, "client")
	}
	return out
}
