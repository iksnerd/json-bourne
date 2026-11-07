package plugin

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestDecodeRefusesDeeplyNestedLineFast: a plugin is untrusted. A response line nested a
// million arrays deep must come back as an ErrPlugin at once, without a stack overflow.
func TestDecodeRefusesDeeplyNestedLineFast(t *testing.T) {
	const depth = 1_000_000
	deepArr := strings.Repeat("[", depth) + strings.Repeat("]", depth)
	deepObj := strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth)
	lines := map[string]string{
		"bare_arrays":   deepArr,
		"bare_objects":  deepObj,
		"in_events":     `{"id":1,"events":[` + deepArr + `]}`,
		"in_fields":     `{"id":1,"events":[{"ts":"2026-11-05T12:00:00Z","fields":{"a":` + deepArr + `}}]}`,
		"fields_object": `{"id":1,"events":[{"ts":"2026-11-05T12:00:00Z","fields":` + deepObj + `}]}`,
		"in_error":      `{"id":1,"error":` + deepArr + `}`,
		"in_unparsable": `{"id":1,"events":[null],"unparsable":` + deepArr + `}`,
	}
	for name, line := range lines {
		t.Run(name, func(t *testing.T) {
			h := &Host{entry: Entry{Name: "deep"}}
			start := time.Now()
			_, err := h.decode(nil, []byte(line), 1, 1)
			if d := time.Since(start); d > time.Second {
				t.Errorf("took %v, want well under a second", d)
			}
			if err == nil {
				t.Fatal("a line nested past the decoder limit must be refused")
			}
			if !errors.Is(err, ErrPlugin) {
				t.Errorf("refusal is not an ErrPlugin: %v", err)
			}
		})
	}
}
