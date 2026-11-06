package config

import (
	"reflect"
	"strings"
	"testing"
)

const enabledHead = `
sources:
  - {type: kibana, name: ingress, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: ingress-*, mapper: nginx_ingress, filter: [{match_phrase: {field: message, value: token}}]}
  - {type: kibana, name: kc, url: 'https://kibana.example.com', api_key_env: JB_KC_KEY, index: kc-*, mapper: keycloak%s}
detectors:
`

func enabledCfg(kcExtra, detectors string) string {
	return strings.Replace(enabledHead, "%s", kcExtra, 1) + detectors
}

const (
	spikeOn  = "  - {type: authspike, name: spike, key_field: client_ip, status_field: status%s}\n"
	signupKC = "  - {type: signup, name: kc-signup, event_field: event_type, create_values: [REGISTER], attempt_values: [REGISTER_ERROR]%s}\n"
)

func with(tmpl, extra string) string { return strings.Replace(tmpl, "%s", extra, 1) }

func TestEnabledDefaultsToTrueAndAcceptsBothBooleans(t *testing.T) {
	for name, extra := range map[string]string{"absent": "", "true": ", enabled: true"} {
		f, err := Parse([]byte(enabledCfg(extra, with(spikeOn, extra))))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(f.DisabledSources()) != 0 || len(f.DisabledDetectors()) != 0 {
			t.Errorf("%s: disabled = %v %v, want none", name, f.DisabledSources(), f.DisabledDetectors())
		}
	}
	f, err := Parse([]byte(enabledCfg(", enabled: false", with(spikeOn, "")+with(signupKC, ", enabled: false"))))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.DisabledSources(); !reflect.DeepEqual(got, []string{"kc"}) {
		t.Errorf("DisabledSources = %v", got)
	}
	if got := f.DisabledDetectors(); !reflect.DeepEqual(got, []string{"kc-signup"}) {
		t.Errorf("DisabledDetectors = %v", got)
	}
}

func TestEnabledMustBeARealBoolean(t *testing.T) {
	for name, v := range map[string]string{
		"quoted false": `"false"`, "quoted true": `'true'`, "number": "0", "one": "1",
		"word": "off", "empty": "~", "list": "[false]", "map": "{a: b}",
	} {
		_, err := Parse([]byte(enabledCfg(", enabled: "+v, with(spikeOn, ""))))
		if err == nil || !strings.Contains(err.Error(), "enabled must be the YAML boolean") {
			t.Errorf("source, %s: err = %v", name, err)
		}
		_, err = Parse([]byte(enabledCfg("", with(spikeOn, ", enabled: "+v))))
		if err == nil || !strings.Contains(err.Error(), "enabled must be the YAML boolean") {
			t.Errorf("detector, %s: err = %v", name, err)
		}
	}
}

// A disabled entry is still a checked entry: a typo in it must not wait for the day it is
// switched on.
func TestDisabledEntriesAreStillValidated(t *testing.T) {
	if _, err := Parse([]byte(enabledCfg(", enabled: false, typo_key: 1", with(spikeOn, "")))); err == nil || !strings.Contains(err.Error(), "typo_key") {
		t.Errorf("unknown key in a disabled source: %v", err)
	}
	if _, err := Parse([]byte(enabledCfg("", with(spikeOn, "")+with(signupKC, ", enabled: false, typo_key: 1")))); err == nil || !strings.Contains(err.Error(), "typo_key") {
		t.Errorf("unknown key in a disabled detector: %v", err)
	}
}

func TestDisabledSourceIsNeverBuiltAndNeedsNoCredential(t *testing.T) {
	f, err := Parse([]byte(enabledCfg(", enabled: false", with(spikeOn, ", sources: [ingress]")+with(signupKC, ", enabled: false"))))
	if err != nil {
		t.Fatal(err)
	}
	// JB_KC_KEY, the disabled source's variable, is not set: building it would fail.
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": "k"}))
	if err != nil {
		t.Fatalf("a disabled source was built (or its credential required): %v", err)
	}
	defer rt.Close()
	if len(rt.Sources) != 1 || rt.Sources[0].Name() != "ingress" {
		t.Errorf("sources = %d, want just ingress", len(rt.Sources))
	}
	if len(rt.Detectors) != 1 || rt.Detectors[0].Name() != "spike" {
		t.Errorf("detectors = %d, want just spike (the disabled one is not built)", len(rt.Detectors))
	}
	if !reflect.DeepEqual(rt.DisabledSources, []string{"kc"}) || !reflect.DeepEqual(rt.DisabledDetectors, []string{"kc-signup"}) {
		t.Errorf("runtime lists %v / %v as disabled", rt.DisabledSources, rt.DisabledDetectors)
	}
	// BuildDetectors (jb case check) skips the disabled one too.
	ds, err := f.BuildDetectors()
	if err != nil || len(ds) != 1 {
		t.Errorf("BuildDetectors = %d, %v", len(ds), err)
	}
}

func TestEnabledDetectorScopedToADisabledSourceIsRefused(t *testing.T) {
	_, err := Parse([]byte(enabledCfg(", enabled: false", with(spikeOn, "")+with(signupKC, ", sources: [kc]"))))
	if err == nil {
		t.Fatal("a detector scoped to a disabled source was accepted: it would read nothing and say quiet")
	}
	for _, want := range []string{"kc-signup", `"kc"`, "disabled", "sources[1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	// Scoped to the enabled source, or to a disabled source but itself disabled: fine.
	for name, cfg := range map[string]string{
		"scoped to the enabled one": enabledCfg(", enabled: false", with(spikeOn, ", sources: [ingress]")),
		"both off":                  enabledCfg(", enabled: false", with(spikeOn, "")+with(signupKC, ", sources: [kc], enabled: false")),
	} {
		if _, err := Parse([]byte(cfg)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNothingToRunIsRefused(t *testing.T) {
	allSources := `
sources:
  - {type: kibana, name: a, enabled: false, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: a-*}
  - {type: kibana, name: b, enabled: false, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: b-*}
detectors:
  - {type: authspike, name: spike, key_field: client_ip, status_field: status}
`
	if _, err := Parse([]byte(allSources)); err == nil || !strings.Contains(err.Error(), "nothing to run") || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("every source disabled: err = %v", err)
	}
	_, err := Parse([]byte(enabledCfg("", with(spikeOn, ", enabled: false")+with(signupKC, ", enabled: false"))))
	if err == nil || !strings.Contains(err.Error(), "nothing to run") || !strings.Contains(err.Error(), "spike, kc-signup") {
		t.Errorf("every detector disabled: err = %v", err)
	}
}

// empty_is_quiet needs every source the detector reads to be filtered. A disabled source
// is not read, so it does not count: an unfiltered source switched off cannot veto the
// detector, and an unfiltered source switched on still does.
func TestEmptyIsQuietOnlyConsidersEnabledSources(t *testing.T) {
	cfg := func(unfilteredExtra string) string {
		return `
sources:
  - {type: kibana, name: filtered, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: f-*, mapper: keycloak, filter: [{match_phrase: {field: message, value: REGISTER}}]}
  - {type: kibana, name: unfiltered, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: u-*` + unfilteredExtra + `}
detectors:
  - {type: signup, name: s, empty_is_quiet: true, event_field: event_type, create_values: [REGISTER], attempt_values: [REGISTER_ERROR]}
`
	}
	if _, err := Parse([]byte(cfg(""))); err == nil || !strings.Contains(err.Error(), "empty_is_quiet") {
		t.Errorf("an enabled unfiltered source must still veto empty_is_quiet: %v", err)
	}
	if _, err := Parse([]byte(cfg(", enabled: false"))); err != nil {
		t.Errorf("a disabled unfiltered source vetoed empty_is_quiet: %v", err)
	}
}

func TestSearchSkipsDisabledSources(t *testing.T) {
	f, err := Parse([]byte(enabledCfg(", enabled: false", with(spikeOn, ", sources: [ingress]"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WithSearch([]string{"needle"}, ""); err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	rt.Close()
}

func TestServicesReportsADisabledSourceAsDisabled(t *testing.T) {
	f, err := Parse([]byte(enabledCfg(", enabled: false", with(spikeOn, ", sources: [ingress]"))))
	if err != nil {
		t.Fatal(err)
	}
	var on, off int
	for _, s := range f.Services() {
		if s.Kind != "source" {
			continue
		}
		if s.Enabled {
			on++
		} else {
			off++
			if s.Name != "kc" || !strings.Contains(s.Leaves, "nothing") {
				t.Errorf("disabled service %+v", s)
			}
		}
	}
	if on != 1 || off != 1 {
		t.Errorf("services: %d enabled, %d disabled, want 1 and 1", on, off)
	}
}
