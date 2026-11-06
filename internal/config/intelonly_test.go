package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/core"
)

const intelOnlyFeeds = "feeds:\n  - type: sans-isc\nintel:\n  max_indicators: 5\n"

const noSourceMsg = "sources: at least one source is required"

func TestParseIntelOnlyConfigNeedsNoSourcesOrDetectors(t *testing.T) {
	f, err := Parse([]byte("commands: [intel]\n" + intelOnlyFeeds))
	if err != nil {
		t.Fatalf("an intel-only config must load: %v", err)
	}
	if !f.IntelOnly() || len(f.Feeds) != 1 {
		t.Errorf("IntelOnly = %v, feeds = %d", f.IntelOnly(), len(f.Feeds))
	}
	if _, err := Parse([]byte("commands: [intel]\nstore:\n  path: x.duckdb\n" + intelOnlyFeeds)); err != nil {
		t.Errorf("store beside feeds: %v", err)
	}
}

func TestParseWithoutIntelOnlyStillRequiresSourcesWithTheSameMessage(t *testing.T) {
	for name, head := range map[string]string{
		"no commands key":  "",
		"commands hunt":    "commands: [hunt]\n",
		"intel and hunt":   "commands: [intel, hunt]\n",
		"intel and estate": "commands: [estate, intel]\n",
		"empty commands":   "commands: []\n",
	} {
		_, err := Parse([]byte(head + intelOnlyFeeds))
		if err == nil || err.Error() != noSourceMsg {
			t.Errorf("%s: got %v, want exactly %q", name, err, noSourceMsg)
		}
	}
}

func TestParseIntelOnlyStillNeedsAFeedAndKeepsOtherChecks(t *testing.T) {
	if _, err := Parse([]byte("commands: [intel]\nstore:\n  path: x.duckdb\n")); err == nil || !strings.Contains(err.Error(), "feeds") {
		t.Errorf("an intel-only config with no feed would pass check and fail at run time: %v", err)
	}
	if _, err := Parse([]byte("commands: [intel]\nfeeds:\n  - type: sans-isc\nintel:\n  max_indicators: 0\n")); err == nil {
		t.Error("intel validation must still run")
	}
	// A config that does list sources keeps today's rules (detectors required).
	y := "commands: [intel]\n" + intelOnlyFeeds + "sources:\n  - type: kibana\n    url: https://kibana.example.com\n    api_key_env: JB_KIBANA_API_KEY\n    index: logs-*\n"
	if _, err := Parse([]byte(y)); err == nil || err.Error() != "detectors: at least one detector is required" {
		t.Errorf("sources without detectors: %v", err)
	}
}

func TestBuildRefusesAnIntelOnlyConfigAsAUsageError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "intel.yaml")
	if err := os.WriteFile(p, []byte("commands: [intel]\n"+intelOnlyFeeds), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(nil)
	if rt != nil || !core.IsUsage(err) || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "commands: [intel]") {
		t.Errorf("want a usage error naming the config, got %v, %v", rt, err)
	}
}
