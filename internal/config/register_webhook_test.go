package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const hookToken = "T0K3N-sentinel-config-5e4d3c"
const hookURL = "https://hooks.example.test/services/" + hookToken

func TestAlertsAreOptionalAndAbsentByDefault(t *testing.T) {
	f, err := parseFeeds(t, "")
	if err != nil {
		t.Fatal(err)
	}
	sinks, err := f.BuildAlerts(envOf(nil))
	if err != nil || len(sinks) != 0 {
		t.Fatalf("%v %v", sinks, err)
	}
}

func TestWebhookBuildsFromTheNamedVariable(t *testing.T) {
	f, err := parseFeeds(t, `
alerts:
  - type: webhook
    url_env: JB_ALERT_WEBHOOK_URL
    min_severity: high
    timeout: 10s
    max_per_cycle: 5
`)
	if err != nil {
		t.Fatal(err)
	}
	sinks, err := f.BuildAlerts(envOf(map[string]string{"JB_ALERT_WEBHOOK_URL": hookURL}))
	if err != nil || len(sinks) != 1 {
		t.Fatal(sinks, err)
	}
	if s := strings.Join([]string{sprint(sinks[0])}, ""); strings.Contains(s, hookToken) || !strings.Contains(s, "max_per_cycle:5") {
		t.Errorf("sink prints as %s", s)
	}
}

func TestWebhookURLPastedIntoUrlEnvIsRefusedWithoutEchoing(t *testing.T) {
	for _, pasted := range []string{hookURL, "http://127.0.0.1/" + hookToken, hookToken, "jb_alert_url", "JB ALERT", "JB-ALERT"} {
		_, err := parseFeeds(t, "\nalerts:\n  - type: webhook\n    url_env: \""+pasted+"\"\n")
		if err == nil {
			t.Errorf("accepted url_env %q", pasted[:6])
			continue
		}
		if strings.Contains(err.Error(), hookToken) || strings.Contains(err.Error(), "hooks.example") {
			t.Errorf("error echoes the value: %v", err)
		}
		if !strings.Contains(err.Error(), "url_env") {
			t.Errorf("error does not name the key: %v", err)
		}
	}
	if _, err := parseFeeds(t, "\nalerts:\n  - type: webhook\n"); err == nil {
		t.Error("a webhook with no url_env was accepted")
	}
}

func TestWebhookBuildErrorsNameTheVariableNeverTheValue(t *testing.T) {
	f, err := parseFeeds(t, "\nalerts:\n  - type: webhook\n    url_env: JB_ALERT_WEBHOOK_URL\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []map[string]string{nil, {"JB_ALERT_WEBHOOK_URL": ""}} {
		if _, err := f.BuildAlerts(envOf(v)); err == nil || !strings.Contains(err.Error(), "JB_ALERT_WEBHOOK_URL") {
			t.Errorf("unset or empty variable: %v", err)
		}
	}
	for _, bad := range []string{
		"http://hooks.example.test/services/" + hookToken, // not https
		"https://user:" + hookToken + "@hooks.example.test",
		"https://%zz/" + hookToken,
		"hooks.example.test/" + hookToken,
		"http://127.0.0.1/" + hookToken, // loopback http without the test flag
	} {
		_, err := f.BuildAlerts(envOf(map[string]string{"JB_ALERT_WEBHOOK_URL": bad}))
		if err == nil {
			t.Errorf("accepted a bad URL %q", bad[:8])
			continue
		}
		if strings.Contains(err.Error(), hookToken) || strings.Contains(err.Error(), "hooks.example") {
			t.Errorf("error echoes the URL: %v", err)
		}
	}
}

func TestWebhookInsecureLoopbackIsOptInAndLoopbackOnly(t *testing.T) {
	f, err := parseFeeds(t, "\nalerts:\n  - type: webhook\n    url_env: JB_ALERT_WEBHOOK_URL\n    allow_insecure_loopback: true\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.BuildAlerts(envOf(map[string]string{"JB_ALERT_WEBHOOK_URL": "http://127.0.0.1:9/" + hookToken})); err != nil {
		t.Errorf("loopback http refused with the flag: %v", err)
	}
	if _, err := f.BuildAlerts(envOf(map[string]string{"JB_ALERT_WEBHOOK_URL": "http://198.51.100.7/" + hookToken})); err == nil {
		t.Error("the flag let plain http reach a non-loopback address")
	}
}

func TestWebhookOptionsAreBounded(t *testing.T) {
	for name, line := range map[string]string{
		"unknown severity": "min_severity: urgent",
		"zero cap":         "max_per_cycle: 0",
		"huge cap":         "max_per_cycle: 100000",
		"zero timeout":     "timeout: 0s",
		"long timeout":     "timeout: 1h",
		"negative gap":     "min_interval: -1s",
		"tiny response":    "max_response_bytes: 1",
		"unknown key":      "url: https://x.example.test",
		"inline secret":    "token: abc",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFeeds(t, "\nalerts:\n  - type: webhook\n    url_env: JB_ALERT_WEBHOOK_URL\n    "+line+"\n"); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := parseFeeds(t, "\nalerts:\n  - type: carrier-pigeon\n"); err == nil || !strings.Contains(err.Error(), "webhook") {
		t.Errorf("unknown type: %v", err)
	}
}

func TestWebhookDefaultsAndSeverityMapping(t *testing.T) {
	s := webhookSpec{URLEnv: "X"}
	if s.severity() != core.SevHigh {
		t.Errorf("default severity = %v", s.severity())
	}
	s.MinSeverity = "critical"
	if s.severity() != core.SevCritical {
		t.Errorf("critical = %v", s.severity())
	}
	zero := time.Duration(0)
	s.MinInterval = &zero
	if _, err := s.build(envOf(map[string]string{"X": hookURL})); err != nil {
		t.Fatal(err)
	}
}

func sprint(v any) string { return fmt.Sprintf("%v %+v %#v", v, v, v) }
