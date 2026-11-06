package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenCasePlacesTheStoreInTheCaseAndBuildsTheAdapters(t *testing.T) {
	dir := copyExampleCase(t, "https://kibana.example.com")
	gitInit(t, dir)
	plan, err := planCase(io.Discard, dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg, rt, err := openCase(io.Discard, testDeps(huntEnv).env, plan.configPath, plan)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(plan.c.EvidenceDir(), "jb.duckdb"); cfg.StorePath() != want {
		t.Errorf("store = %s, want %s", cfg.StorePath(), want)
	}
	if len(rt.Sources) != 1 || len(rt.Detectors) != 1 {
		t.Errorf("runtime = %d sources, %d detectors", len(rt.Sources), len(rt.Detectors))
	}
}

func TestOpenCaseWithoutAPlanUsesTheConfigAsWritten(t *testing.T) {
	cfgPath := writeConfig(t, "https://kibana.example.com")
	cfg, _, err := openCase(io.Discard, testDeps(huntEnv).env, cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(filepath.Dir(cfgPath), "jb.duckdb"); cfg.StorePath() != want {
		t.Errorf("store = %s, want %s", cfg.StorePath(), want)
	}
}

// The credential is read last, by Build: a config that does not load never gets that far.
func TestOpenCaseErrors(t *testing.T) {
	cfgPath := writeConfig(t, "https://kibana.example.com")
	if _, _, err := openCase(io.Discard, testDeps(nil).env, cfgPath, nil); err == nil || !strings.Contains(err.Error(), "JB_KIBANA_API_KEY") {
		t.Errorf("missing credential: err = %v", err)
	}
	if _, _, err := openCase(io.Discard, testDeps(huntEnv).env, filepath.Join(t.TempDir(), "none.yaml"), nil); err == nil {
		t.Error("a missing config was accepted")
	}
}
