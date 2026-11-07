package casefile

import (
	"fmt"
	"strings"
	"testing"
)

// The apiVersion strings are part of the supported file formats (RFC 0018). Each loader
// reads exactly one version and refuses any other with the documented message. The
// strings below are written out, not taken from the constants, so changing a constant
// fails the test.
func TestEachLoaderReadsOnlyItsOwnAPIVersion(t *testing.T) {
	yaml := func(v string) []byte { return []byte("apiVersion: " + v + "\n") }
	jsonDoc := func(v string) []byte { return []byte(fmt.Sprintf(`{"apiVersion":%q}`, v)) }
	rows := []struct {
		format string
		accept string
		other  string // an older or foreign version that must be refused
		parse  func([]byte) error
		doc    func(string) []byte
		// hint is text the refusal of `other` must also contain, when the format has a
		// documented migration.
		hint string
	}{
		{"case", "jb.case/v1", "jb.case/v2", func(b []byte) error { _, err := Parse(b); return err }, yaml, ""},
		{"actor", "jb.actor/v1", "jb.actor/v2", func(b []byte) error { _, err := ParseActor(b); return err }, yaml, ""},
		{"estate", "jb.estate/v2", "jb.estate/v1", func(b []byte) error { _, err := ParseEstate(b); return err }, yaml, "that edit is the whole migration"},
		{"estate snapshot", "jb.estate-snapshot/v2", "jb.estate-snapshot/v1", func(b []byte) error { _, err := ParseEstateSnapshot(b); return err }, yaml, "jb estate refresh"},
		{"estate facts", "jb.estate-facts/v1", "jb.estate-facts/v2", func(b []byte) error { _, err := ParseFactsImport(b); return err }, jsonDoc, ""},
	}
	for _, r := range rows {
		t.Run(r.format, func(t *testing.T) {
			// The accepted version gets past the version check (it may fail on other keys).
			if err := r.parse(r.doc(r.accept)); err != nil && (strings.Contains(err.Error(), "unsupported apiVersion") || strings.Contains(err.Error(), "apiVersion is required")) {
				t.Errorf("%s refused its own version: %v", r.accept, err)
			}
			for _, other := range []string{r.other, "jb.other/v1", "v1"} {
				err := r.parse(r.doc(other))
				if err == nil {
					t.Fatalf("%q was accepted", other)
				}
				want := fmt.Sprintf("unsupported apiVersion %q", other)
				if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "this build reads only "+r.accept) {
					t.Errorf("%q: message %q lacks %q and the version this build reads (%s)", other, err, want, r.accept)
				}
			}
			if r.hint != "" {
				if err := r.parse(r.doc(r.other)); err == nil || !strings.Contains(err.Error(), r.hint) {
					t.Errorf("refusal of %s lacks the migration hint %q: %v", r.other, r.hint, err)
				}
			}
			if err := r.parse(r.doc("")); err == nil || !strings.Contains(err.Error(), "apiVersion is required (this build reads "+r.accept+")") {
				t.Errorf("a missing apiVersion: %v", err)
			}
		})
	}
}
