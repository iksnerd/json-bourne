package jb

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// intelOnlyCase copies the example case, adds config/intel.yaml with feeds only
// (commands: [intel]; no sources, no detectors) pointed at a fake greynoise server,
// and lists it in case.yaml next to the two existing configs.
func intelOnlyCase(t *testing.T) (dir string, hits func() int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		fmt.Fprint(w, `{"ip":"192.0.2.7","noise":true,"riot":false,"classification":"malicious","last_seen":"2026-11-03"}`)
	}))
	t.Cleanup(srv.Close)
	dir = copyCase(t)
	y := fmt.Sprintf("commands: [intel]\nfeeds:\n  - type: greynoise\n    base_url: %s\n    api_key_env: JB_GREYNOISE_API_KEY\n    min_interval: 0s\nintel:\n  max_indicators: 5\n", srv.URL)
	if err := os.WriteFile(filepath.Join(dir, "config", "intel.yaml"), []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "case.yaml")
	b, _ := os.ReadFile(p)
	s := strings.Replace(string(b), "  - config/fingerprint.yaml\n", "  - config/fingerprint.yaml\n  - config/intel.yaml\n", 1)
	if s == string(b) {
		t.Fatal("case.yaml did not list the config")
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, func() int { return n }
}

func TestCaseCheckPassesAFeedsOnlyIntelConfig(t *testing.T) {
	dir, _ := intelOnlyCase(t)
	r, err := CaseCheck(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || len(r.Configs) != 3 || r.Configs[2].Path != "config/intel.yaml" || !r.Configs[2].OK {
		t.Fatalf("result = %+v", r)
	}
}

func TestIntelRunsEndToEndThroughAFeedsOnlyConfig(t *testing.T) {
	dir, hits := intelOnlyCase(t)
	res, err := Intel(t.Context(), dir, []string{"192.0.2.7"}, IntelOptions{Config: "config/intel.yaml", Env: intelEnv})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || len(res.Results) != 1 || res.Results[0].Indicator != "192.0.2.7" || hits() != 1 {
		t.Fatalf("result = %+v, feed hits = %d", res, hits())
	}
}

func TestHuntWatchActivityAndActorRefuseAFeedsOnlyConfig(t *testing.T) {
	dir, hits := intelOnlyCase(t)
	cfg := "config/intel.yaml"
	for name, run := range map[string]func() error{
		"hunt": func() error {
			_, err := HuntCase(t.Context(), dir, CaseHuntOptions{Config: cfg, HuntOptions: HuntOptions{Env: intelEnv}})
			return err
		},
		"watch": func() error {
			_, err := Watch(t.Context(), dir, WatchOptions{Config: cfg, Env: intelEnv})
			return err
		},
		"activity": func() error {
			_, err := Activity(t.Context(), dir, ActivityOptions{Config: cfg, Env: intelEnv})
			return err
		},
		"actor": func() error {
			_, err := ActorStatus(t.Context(), dir, ActorStatusOptions{Config: cfg})
			return err
		},
	} {
		err := run()
		if !IsUsage(err) || !strings.Contains(err.Error(), "intel.yaml") || !strings.Contains(err.Error(), "jb "+name) {
			t.Errorf("%s: want a usage error naming the config and the command, got %v", name, err)
		}
	}
	if hits() != 0 {
		t.Errorf("a refused run reached the feed %d time(s)", hits())
	}
}
