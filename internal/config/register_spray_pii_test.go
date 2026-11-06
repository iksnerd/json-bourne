package config

import (
	"strings"
	"testing"
)

func TestSignupAttemptRuleLoadsAndIsStrict(t *testing.T) {
	ok := strings.Replace(signupOK, "factor: 3", "factor: 3\n    min_attempts: 10\n    attempt_factor: 4", 1)
	if _, err := Parse([]byte(kibanaHead + ok)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"attempt_factor without min_attempts": strings.Replace(signupOK, "factor: 3", "factor: 3\n    attempt_factor: 4", 1),
		"negative min_attempts":               strings.Replace(signupOK, "factor: 3", "factor: 3\n    min_attempts: -1", 1),
		"attempt_factor 1":                    strings.Replace(signupOK, "factor: 3", "factor: 3\n    min_attempts: 10\n    attempt_factor: 1", 1),
		"misspelt key":                        strings.Replace(signupOK, "factor: 3", "factor: 3\n    min_attempt: 10", 1),
	}
	for name, body := range bad {
		if _, err := Parse([]byte(kibanaHead + body)); err == nil {
			t.Errorf("%s: accepted at load", name)
		}
	}
}

func TestPersonalKeyFieldNeedsHashKeysAtLoadForEveryKeyedDetector(t *testing.T) {
	newkeyPII := strings.Replace(newkeyOK, "key_field: client_ip", "key_field: email", 1)
	behaviourPII := strings.Replace(behaviourOK, "key_field: client_ip", "key_field: username", 1)
	for name, body := range map[string]string{"newkey": newkeyPII, "behaviour": behaviourPII} {
		_, err := Parse([]byte(kibanaHead + body))
		if err == nil || !strings.Contains(err.Error(), "hash_keys") {
			t.Errorf("%s: err = %v, want a refusal that names hash_keys", name, err)
		}
		withHash := strings.Replace(body, "    path_field: path\n", "    path_field: path\n    hash_keys: true\n", 1)
		if _, err := Parse([]byte(kibanaHead + withHash)); err != nil {
			t.Errorf("%s with hash_keys: %v", name, err)
		}
	}
}
