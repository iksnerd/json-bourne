package config

import (
	"strings"
	"testing"

	"github.com/iksnerd/json-bourne/internal/adapters/kibana"
	"github.com/iksnerd/json-bourne/internal/core"
)

const historySource = `
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-web-*
    key_match:
      field: message
      mode: phrase
detectors:
`

const historyNewkey = `  - type: newkey
    key_field: client_ip
    path_field: path
    sensitive_paths: [/admin/]
    min_hits: 3
    history:
      lookback: 168h
      min_events: 50
      max_candidates: 50
`

func TestHistoryParsesAndBuildsWithNoNetworkAndNoEnvironment(t *testing.T) {
	f, err := Parse([]byte(historySource + historyNewkey))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := f.BuildDetectors() // what `jb case check` runs: no env, no network
	if err != nil || len(ds) != 1 {
		t.Fatalf("detectors %v err %v", ds, err)
	}
	if _, ok := ds[0].(core.HistoryDetector); !ok {
		t.Error("the newkey detector is not a core.HistoryDetector")
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	src, ok := rt.Sources[0].(*kibana.Source)
	if !ok || src.KeyMatch == nil || src.KeyMatch.Field != "message" || src.KeyMatch.Mode != kibana.ModePhrase {
		t.Fatalf("source %#v lost its key_match", rt.Sources[0])
	}
}

func TestHistoryNeedsAKibanaSourceWithKeyMatchWhichNeedsNoFilter(t *testing.T) {
	noMatch := strings.Replace(historySource, "    key_match:\n      field: message\n      mode: phrase\n", "", 1)
	if _, err := Parse([]byte(noMatch + historyNewkey)); err == nil || !strings.Contains(err.Error(), "key_match") || !strings.Contains(err.Error(), "kibana:logs-web-*") {
		t.Errorf("a source without key_match: %v", err)
	}
	if _, err := Parse([]byte(historySource + historyNewkey)); err != nil {
		t.Errorf("key_match without a filter must pass: %v", err)
	}
	// Every source the detector reads must qualify; one that it does not read may not.
	two := strings.Replace(historySource, "detectors:\n", `  - type: kibana
    name: plain
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-other-*
detectors:
`, 1)
	if _, err := Parse([]byte(two + historyNewkey)); err == nil || !strings.Contains(err.Error(), `"plain"`) {
		t.Errorf("unscoped detector over a source without key_match: %v", err)
	}
	scoped := strings.Replace(historyNewkey, "    min_hits: 3\n", "    min_hits: 3\n    sources: [kibana:logs-web-*]\n", 1)
	if _, err := Parse([]byte(two + scoped)); err != nil {
		t.Errorf("scoped to the source that has key_match: %v", err)
	}
	// A disabled source is not read.
	off := strings.Replace(two, "    name: plain\n", "    name: plain\n    enabled: false\n", 1)
	if _, err := Parse([]byte(off + historyNewkey)); err != nil {
		t.Errorf("a disabled source vetoed history: %v", err)
	}
}

type fakeSourceSpec struct{}

func (fakeSourceSpec) build(Env) (core.Source, error) { return nil, nil }
func (fakeSourceSpec) describe() ServiceInfo {
	return ServiceInfo{Kind: "source", Type: "other", Name: "other"}
}

func TestHistoryRefusesASourceTypeWithoutThePort(t *testing.T) {
	f, err := Parse([]byte(historySource + historyNewkey))
	if err != nil {
		t.Fatal(err)
	}
	f.Sources = append(f.Sources, SourceEntry{Type: "other", spec: fakeSourceSpec{}})
	err = f.checkHistorySources()
	if err == nil || !strings.Contains(err.Error(), `"other"`) || !strings.Contains(err.Error(), "history") {
		t.Errorf("err = %v, want a refusal naming the source", err)
	}
}

func TestHistoryBlockRangesAreRefusedAtLoad(t *testing.T) {
	cases := map[string]string{
		"no lookback":     strings.Replace(historyNewkey, "      lookback: 168h\n", "", 1),
		"lookback 32d":    strings.Replace(historyNewkey, "168h", "768h", 1),
		"lookback zero":   strings.Replace(historyNewkey, "168h", "0s", 1),
		"no min_events":   strings.Replace(historyNewkey, "      min_events: 50\n", "", 1),
		"min_events 0":    strings.Replace(historyNewkey, "min_events: 50", "min_events: 0", 1),
		"max 101":         strings.Replace(historyNewkey, "max_candidates: 50", "max_candidates: 101", 1),
		"unknown key":     strings.Replace(historyNewkey, "max_candidates: 50", "max_candidates: 50\n      lookbak: 1h", 1),
		"lookback is bad": strings.Replace(historyNewkey, "168h", "a week", 1),
	}
	for name, nk := range cases {
		if _, err := Parse([]byte(historySource + nk)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(historySource + strings.Replace(historyNewkey, "      max_candidates: 50\n", "", 1))); err != nil {
		t.Errorf("max_candidates has a default: %v", err)
	}
}

func TestKeyMatchModeHasNoDefaultAndIsValidated(t *testing.T) {
	cases := map[string]string{
		"no mode":     strings.Replace(historySource, "      mode: phrase\n", "", 1),
		"bad mode":    strings.Replace(historySource, "mode: phrase", "mode: regex", 1),
		"no field":    strings.Replace(historySource, "      field: message\n", "", 1),
		"bad field":   strings.Replace(historySource, "field: message", `field: "mess age"`, 1),
		"unknown key": strings.Replace(historySource, "mode: phrase", "mode: phrase\n      analyzer: x", 1),
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src + historyNewkey)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, m := range []string{"term", "phrase"} {
		if _, err := Parse([]byte(strings.Replace(historySource, "mode: phrase", "mode: "+m, 1) + historyNewkey)); err != nil {
			t.Errorf("mode %s: %v", m, err)
		}
	}
}

func TestDescribeSaysCandidateKeysAreSentToTheIndex(t *testing.T) {
	f, err := Parse([]byte(historySource + historyNewkey))
	if err != nil {
		t.Fatal(err)
	}
	var leaves string
	for _, s := range f.Services() {
		if s.Kind == "source" {
			leaves = s.Leaves
		}
	}
	if !strings.Contains(leaves, "candidate keys") || !strings.Contains(leaves, "kibana.example.com") {
		t.Errorf("Leaves = %q", leaves)
	}
	plain := strings.Replace(historySource, "    key_match:\n      field: message\n      mode: phrase\n", "", 1)
	f, err = Parse([]byte(plain + strings.Replace(historyNewkey, "    history:\n      lookback: 168h\n      min_events: 50\n      max_candidates: 50\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range f.Services() {
		if s.Kind == "source" && strings.Contains(s.Leaves, "candidate keys") {
			t.Errorf("a source without key_match claims keys leave: %q", s.Leaves)
		}
	}
}
