package config

import (
	"strings"
	"testing"
)

// A credential that is not set must tell the operator where jb looks (the process
// environment, never the config file) and where to read how to supply it. It must name
// the variable and never a value.
func TestUnsetCredentialErrorsSayWhereTheVariableIsRead(t *testing.T) {
	unset := envOf(nil)
	_, kerr := kibanaSpec{APIKeyEnv: "JB_TEST_KIBANA_KEY"}.build(unset)
	_, werr := webhookSpec{URLEnv: "JB_TEST_WEBHOOK_URL"}.build(unset)
	_, gerr := greynoiseSpec{APIKeyEnv: "JB_TEST_GREYNOISE_KEY"}.build(unset)
	for name, c := range map[string]struct {
		err  error
		vars string
	}{
		"kibana":    {kerr, "JB_TEST_KIBANA_KEY"},
		"webhook":   {werr, "JB_TEST_WEBHOOK_URL"},
		"greynoise": {gerr, "JB_TEST_GREYNOISE_KEY"},
	} {
		if c.err == nil {
			t.Errorf("%s: no error for an unset variable", name)
			continue
		}
		for _, want := range []string{c.vars, "is not set", "process environment", "docs/CONFIG.md", "Supplying credentials"} {
			if !strings.Contains(c.err.Error(), want) {
				t.Errorf("%s: error %q lacks %q", name, c.err, want)
			}
		}
	}
}

// An empty value is as missing as an unset one, and the error never prints a value.
func TestEmptyCredentialIsMissingAndNeverPrinted(t *testing.T) {
	_, err := kibanaSpec{APIKeyEnv: "JB_TEST_KIBANA_KEY"}.build(envOf(map[string]string{"JB_TEST_KIBANA_KEY": ""}))
	if err == nil || !strings.Contains(err.Error(), "Supplying credentials") {
		t.Errorf("empty value: %v", err)
	}
}
