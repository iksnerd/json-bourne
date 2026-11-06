package casefile_test

import (
	"path/filepath"
	"testing"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
)

// The shipped example must load, guard its evidence directory, and name hunt configs
// that internal/config accepts. This is the test file that imports config; the
// package itself does not.
func TestExampleCase(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "case")
	c, err := casefile.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := casefile.Guard(c.EvidenceDir())
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	t.Logf("guard: %v", st)
	for _, f := range c.Config {
		if _, err := config.Load(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
