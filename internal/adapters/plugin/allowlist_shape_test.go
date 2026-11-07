package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hugeMapping returns one YAML mapping with as many short keys as fit in size bytes.
func hugeMapping(size int) []byte {
	var b strings.Builder
	for i := 0; b.Len() < size-16; i++ {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	return []byte(b.String())
}

// TestAllowlistRefusesHugeMappingFast: yaml.v3 decodes a mapping in time quadratic in
// its keys, so an allowlist at the 1 MiB cap made of one mapping stalled the loader for
// tens of seconds. It must be refused at once, like the case-file loaders do.
func TestAllowlistRefusesHugeMappingFast(t *testing.T) {
	data := hugeMapping(maxAllowlistBytes)
	path := filepath.Join(t.TempDir(), "plugins.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := LoadAllowlist(path)
	if err == nil || !strings.Contains(err.Error(), "keys per mapping") {
		t.Fatalf("one huge mapping must be refused by the shape limit, got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("refusal took %v, want well under a second", d)
	}
}
