package config

import (
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/greynoise"
)

const hunt = `
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-*
detectors:
  - type: authspike
    key_field: client_ip
    status_field: status
`

func parseFeeds(t *testing.T, tail string) (*File, error) {
	t.Helper()
	return Parse([]byte(hunt + tail))
}

func TestFeedsAreOptionalAndAbsentByDefault(t *testing.T) {
	f, err := parseFeeds(t, "")
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := f.BuildFeeds(envOf(nil))
	if err != nil || len(feeds) != 0 {
		t.Fatalf("%v %v", feeds, err)
	}
	if got := f.IntelOptions(); len(got.IPFields) != 1 || got.IPFields[0] != "client_ip" || got.MaxIndicators != 10 {
		t.Fatalf("defaults: %+v", got)
	}
}

func TestGreyNoiseFeedDefaultsAndBuild(t *testing.T) {
	f, err := parseFeeds(t, `
feeds:
  - type: greynoise
    api_key_env: JB_GREYNOISE_API_KEY
`)
	if err != nil {
		t.Fatal(err)
	}
	feeds, err := f.BuildFeeds(envOf(map[string]string{"JB_GREYNOISE_API_KEY": secret}))
	if err != nil || len(feeds) != 1 {
		t.Fatal(feeds, err)
	}
	g := feeds[0].(*greynoise.Feed)
	if g.BaseURL != greynoise.DefaultBaseURL || g.Key != secret || g.MaxLookups != 10 ||
		g.MinInterval != time.Second || g.Timeout != 10*time.Second || g.MaxBody != 65536 {
		t.Fatalf("%v", g)
	}
	f2, _ := parseFeeds(t, "\nfeeds:\n  - type: greynoise\n")
	feeds, err = f2.BuildFeeds(envOf(nil))
	if err != nil || feeds[0].(*greynoise.Feed).Key != "" {
		t.Fatalf("a keyless feed needs no variable: %v", err)
	}
}

func TestFeedWithNamedKeyVariableRefusesToRunKeylessWhenUnset(t *testing.T) {
	f, err := parseFeeds(t, "\nfeeds:\n  - type: greynoise\n    api_key_env: JB_GREYNOISE_API_KEY\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.BuildFeeds(envOf(nil))
	if err == nil || !strings.Contains(err.Error(), "JB_GREYNOISE_API_KEY") {
		t.Fatalf("err = %v", err)
	}
	_, err = f.BuildFeeds(envOf(map[string]string{"JB_GREYNOISE_API_KEY": ""}))
	if err == nil {
		t.Fatal("an empty variable must be refused, not downgraded to the keyless quota")
	}
}

func TestFeedValidation(t *testing.T) {
	bad := map[string]string{
		"pasted key":   "    api_key_env: abcDEF123=secret\n",
		"http remote":  "    base_url: http://feed.example.com\n",
		"credentials":  "    base_url: https://u:p@feed.example.com\n",
		"path in base": "    base_url: https://feed.example.com/v3\n",
		"no host":      "    base_url: https:///x\n",
		"zero lookups": "    max_lookups: 0\n",
		"huge lookups": "    max_lookups: 100000\n",
		"negative gap": "    min_interval: -1s\n",
		"zero timeout": "    timeout: 0s\n",
		"long timeout": "    timeout: 5m\n",
		"huge body":    "    max_response_bytes: 999999999\n",
		"tiny body":    "    max_response_bytes: 10\n",
		"unknown key":  "    api_key: oops\n",
	}
	for name, body := range bad {
		if _, err := parseFeeds(t, "\nfeeds:\n  - type: greynoise\n"+body); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "abcDEF123") {
			t.Errorf("%s: the error echoed the pasted value: %v", name, err)
		}
	}
	if _, err := parseFeeds(t, "\nfeeds:\n  - type: nope\n"); err == nil || !strings.Contains(err.Error(), "greynoise") {
		t.Errorf("unknown feed type: %v", err)
	}
	if _, err := parseFeeds(t, "\nfeeds:\n  - type: greynoise\n    base_url: http://127.0.0.1:9999\n"); err != nil {
		t.Errorf("loopback http must be accepted: %v", err)
	}
}

func TestIntelOptions(t *testing.T) {
	f, err := parseFeeds(t, "\nintel:\n  ip_fields: [client_ip, forwarded_for]\n  max_indicators: 25\n")
	if err != nil {
		t.Fatal(err)
	}
	if o := f.IntelOptions(); len(o.IPFields) != 2 || o.MaxIndicators != 25 {
		t.Fatalf("%+v", o)
	}
	for _, tail := range []string{
		"\nintel:\n  ip_fields: ['a\"b']\n", "\nintel:\n  max_indicators: 0\n", "\nintel:\n  max_indicators: 5000\n",
		"\nintel:\n  ip_fields: []\n", "\nintel:\n  surprise: 1\n",
	} {
		if _, err := parseFeeds(t, tail); err == nil {
			t.Errorf("accepted %q", tail)
		}
	}
}
