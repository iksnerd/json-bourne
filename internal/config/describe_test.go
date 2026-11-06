package config

import (
	"encoding/json"
	"strings"
	"testing"
)

const describeYAML = `
sources:
  - type: kibana
    url: https://kibana.example.com:5601/base?token=sekrit-query
    api_key_env: JB_TEST_API_KEY
    index: logs-auth-*
    page_size: 500
    filter:
      - term: {field: host, value: portal.example.com}
  - type: kibana
    name: standby
    enabled: false
    url: https://standby.example.com
    api_key_env: JB_TEST_STANDBY_KEY
    index: logs-other-*
detectors:
  - type: authspike
    name: login-spray
    sources: [kibana:logs-auth-*]
    key_field: client_ip
    status_field: status
    fail_statuses: [401, 403]
    min_events: 20
    min_failure_share_rise: 0.2
  - type: authspike
    name: parked
    enabled: false
    key_field: client_ip
    status_field: status
    fail_statuses: [401]
store:
  path: data/jb.duckdb
alerts:
  - type: webhook
    url_env: JB_TEST_HOOK_URL
    min_severity: critical
`

func mustParse(t *testing.T, y string) *File {
	t.Helper()
	f, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDescribeShowsTheEffectiveConfig(t *testing.T) {
	d := mustParse(t, describeYAML).Describe()

	if len(d.Sources) != 2 {
		t.Fatalf("sources = %+v", d.Sources)
	}
	s := d.Sources[0]
	if s.Type != "kibana" || s.Name != "kibana:logs-auth-*" || !s.Enabled || s.Index != "logs-auth-*" ||
		s.CredentialEnv != "JB_TEST_API_KEY" || s.URL != "https://kibana.example.com:5601/base" {
		t.Errorf("source 0 = %+v", s)
	}
	if s.Options["page_size"] != 500 {
		t.Errorf("page_size = %v", s.Options["page_size"])
	}
	if _, ok := s.Options["filter"]; !ok {
		t.Errorf("filter missing: %v", s.Options)
	}
	if d.Sources[1].Enabled || d.Sources[1].Name != "standby" {
		t.Errorf("source 1 = %+v", d.Sources[1])
	}

	if len(d.Detectors) != 2 {
		t.Fatalf("detectors = %+v", d.Detectors)
	}
	a := d.Detectors[0]
	if a.Type != "authspike" || a.Name != "login-spray" || !a.Enabled {
		t.Errorf("detector 0 = %+v", a)
	}
	if got := strings.Join(a.Sources, ","); got != "kibana:logs-auth-*" {
		t.Errorf("scope = %q", got)
	}
	if got := strings.Join(a.Reads, ","); got != "kibana:logs-auth-*" {
		t.Errorf("reads = %q", got)
	}
	if a.Options["min_events"] != 20 || a.Options["min_failure_share_rise"] != 0.2 || a.Options["key_field"] != "client_ip" {
		t.Errorf("options = %v", a.Options)
	}
	if _, dup := a.Options["name"]; dup {
		t.Errorf("name is repeated in options: %v", a.Options)
	}
	p := d.Detectors[1]
	if p.Enabled || p.Name != "parked" || p.Reads != nil || p.Sources != nil {
		t.Errorf("detector 1 = %+v", p)
	}

	if d.Store.Path != "data/jb.duckdb" || d.Store.Default {
		t.Errorf("store = %+v", d.Store)
	}
	if len(d.Alerts) != 1 || d.Alerts[0].Type != "webhook" || d.Alerts[0].CredentialEnv != "JB_TEST_HOOK_URL" || d.Alerts[0].Options["min_severity"] != "critical" {
		t.Errorf("alerts = %+v", d.Alerts)
	}
}

func TestDescribeNeverCarriesAValueOrAURLQuery(t *testing.T) {
	t.Setenv("JB_TEST_API_KEY", "value-of-the-api-key")
	t.Setenv("JB_TEST_HOOK_URL", "https://hooks.example.com/secret-path-token")
	t.Setenv("JB_DB", "/should/not/be/read.duckdb")
	d := mustParse(t, strings.Replace(describeYAML, "path: data/jb.duckdb", "path: \"\"", 1)).Describe()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"value-of-the-api-key", "secret-path-token", "hooks.example.com", "sekrit-query", "/should/not/be/read.duckdb"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("description contains %q:\n%s", leak, b)
		}
	}
	if !d.Store.Default || d.Store.Path != "" {
		t.Errorf("an empty store.path must read as the default, not as a resolved path: %+v", d.Store)
	}
}

// Every registered detector type must describe its options. The count fails when a
// type is added to the registry and not here, so a new detector cannot print empty.
func TestEveryDetectorSpecDescribesItsOptions(t *testing.T) {
	specs := []detectorSpec{authspikeSpec{}, fingerprintSpec{}, signupSpec{}, newkeySpec{}, behaviourSpec{}, signatureSpec{}}
	if len(specs) != len(detectorTypes()) {
		t.Fatalf("%d registered detector types, %d covered here: add the new one", len(detectorTypes()), len(specs))
	}
	for _, s := range specs {
		if _, ok := s.(optioner); !ok {
			t.Errorf("%T has no options() method", s)
		}
	}
}

func TestDescribeFingerprintAndSignatureOptions(t *testing.T) {
	y := `
sources:
  - {type: kibana, url: "https://k.example.com", api_key_env: JB_X, index: i}
detectors:
  - type: fingerprint
    name: fp
    actors: [actor-a.yaml]
    ignore_ips: [192.0.2.1]
  - type: signature
    name: sig
    field: user_agent
    present: true
    key_field: client_ip
`
	d := mustParse(t, y).Describe()
	if got := d.Detectors[0].Options["actors"]; got == nil {
		t.Errorf("fingerprint options = %v", d.Detectors[0].Options)
	}
	if d.Detectors[1].Options["field"] != "user_agent" || d.Detectors[1].Options["present"] != true {
		t.Errorf("signature options = %v", d.Detectors[1].Options)
	}
}
