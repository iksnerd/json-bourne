package piiguard

import (
	"regexp"
	"strings"
	"testing"
)

func TestPersonalFields(t *testing.T) {
	for _, n := range []string{"username", "User_Name", " email ", "user_email", "USER_ID", "userid"} {
		if !Personal(n) {
			t.Errorf("Personal(%q) = false", n)
		}
	}
	for _, n := range []string{"client_ip", "session", "", "emailed"} {
		if Personal(n) {
			t.Errorf("Personal(%q) = true", n)
		}
	}
}

func TestHashShapeStableAndHidesKey(t *testing.T) {
	k := "alice@example.com"
	h := Hash(k)
	if !regexp.MustCompile(`^h:[0-9a-f]{12}$`).MatchString(h) {
		t.Fatalf("Hash = %q, want h: and 12 hex digits", h)
	}
	if h != Hash(k) || h == Hash("bob@example.com") {
		t.Errorf("Hash not stable or collides: %q", h)
	}
	if strings.Contains(h, "alice") {
		t.Errorf("Hash %q leaks the key", h)
	}
	// Known vector: sha256("abc") begins ba7816bf8f01.
	if got := Hash("abc"); got != "h:ba7816bf8f01" {
		t.Errorf("Hash(abc) = %q", got)
	}
}

func TestShown(t *testing.T) {
	if Shown("k", false) != "k" || Shown("k", true) != Hash("k") {
		t.Error("Shown does not follow the flag")
	}
}
