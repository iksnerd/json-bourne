package jb_test

import (
	"strings"
	"testing"

	jb "github.com/iksnerd/json-bourne"
)

func TestCaseShowDescribesTheExampleCase(t *testing.T) {
	t.Setenv("JB_KIBANA_API_KEY", "value-that-must-not-appear")
	got, err := jb.CaseShow("examples/case", jb.CaseShowOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Case != "example-login-spray" || got.Config != "config/hunt.yaml" {
		t.Errorf("got %q %q", got.Case, got.Config)
	}
	if len(got.Sources) != 1 || got.Sources[0].CredentialEnv != "JB_KIBANA_API_KEY" {
		t.Errorf("sources = %+v", got.Sources)
	}
	if len(got.Detectors) != 1 || got.Detectors[0].Type != "authspike" {
		t.Errorf("detectors = %+v", got.Detectors)
	}
}

func TestCaseShowRefusesAnUnknownConfig(t *testing.T) {
	_, err := jb.CaseShow("examples/case", jb.CaseShowOptions{Config: "nope.yaml"})
	if err == nil || !strings.Contains(err.Error(), "nope.yaml") {
		t.Errorf("err = %v", err)
	}
}
