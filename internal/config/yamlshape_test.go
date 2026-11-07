package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A 1 MiB config with one mapping of ~100,000 keys took tens of seconds in yaml.v3. Parse
// and LoadCommands now refuse it at once, naming the limit.
func TestConfigRefusesHugeMappingFast(t *testing.T) {
	var b strings.Builder
	for i := 0; b.Len() < maxFileSize; i++ {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	data := []byte(b.String())

	start := time.Now()
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "keys per mapping") || !strings.Contains(err.Error(), "config") {
		t.Fatalf("Parse must refuse a huge mapping with the shape error, got %v", err)
	}
	path := filepath.Join(t.TempDir(), "jb.yaml")
	if werr := os.WriteFile(path, data, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "keys per mapping") {
		t.Fatalf("Load: %v", err)
	}
	if _, err := LoadCommands(path); err == nil || !strings.Contains(err.Error(), "keys per mapping") {
		t.Fatalf("LoadCommands: %v", err)
	}
	if d := time.Since(start); d > 60*time.Second { // was 40s+ per call; race builds are slow
		t.Errorf("three refusals took %v, want well under a minute", d)
	}
}
