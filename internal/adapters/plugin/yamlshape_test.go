package plugin

import (
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

// The plugin package cannot import casefile (archtest scans non-test imports), so its
// mapping limit is a copy. A test may import casefile, and keeps the two equal.
func TestMaxMappingKeysMatchesCasefile(t *testing.T) {
	if maxMappingKeys != casefile.MaxMappingKeys {
		t.Fatalf("maxMappingKeys = %d, casefile.MaxMappingKeys = %d; keep them equal", maxMappingKeys, casefile.MaxMappingKeys)
	}
}
