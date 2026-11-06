package config

import (
	"strings"
	"testing"
)

const kibanaHead = `
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-web-*
detectors:
`

const signupOK = `  - type: signup
    create_paths: [/account/create]
    path_field: path
    status_field: status
    method_field: method
    min_creations: 5
    factor: 3
    address_field: email
    disposable_domains: [mail.example]
`

const newkeyOK = `  - type: newkey
    key_field: client_ip
    path_field: path
    sensitive_paths: [/admin/]
    min_hits: 3
    ignore_keys: [192.0.2.1]
`

func TestSignupAndNewkeyParseAndBuild(t *testing.T) {
	f, err := Parse([]byte(kibanaHead + signupOK + newkeyOK))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.Build(envOf(map[string]string{"JB_KIBANA_API_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.Detectors) != 2 || rt.Detectors[0].Name() != "signup" || rt.Detectors[1].Name() != "newkey" {
		t.Fatalf("detectors %v", rt.Detectors)
	}
}

func TestSignupAndNewkeyRejectBadInputAtLoad(t *testing.T) {
	cases := map[string]string{
		"signup unknown key":    strings.Replace(signupOK, "factor: 3", "factor: 3\n    facter: 2", 1),
		"signup no create path": strings.Replace(signupOK, "    create_paths: [/account/create]\n", "", 1),
		"signup factor 1":       strings.Replace(signupOK, "factor: 3", "factor: 1", 1),
		"signup list no field":  strings.Replace(signupOK, "    address_field: email\n", "", 1),
		"signup bad status":     strings.Replace(signupOK, "factor: 3", "factor: 3\n    success_statuses: [42]", 1),
		"newkey unknown key":    strings.Replace(newkeyOK, "min_hits: 3", "min_hits: 3\n    min_hit: 2", 1),
		"newkey no sensitive":   strings.Replace(newkeyOK, "    sensitive_paths: [/admin/]\n", "", 1),
		"newkey negative hits":  strings.Replace(newkeyOK, "min_hits: 3", "min_hits: -1", 1),
		"newkey no key field":   strings.Replace(newkeyOK, "    key_field: client_ip\n", "", 1),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(kibanaHead + d)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
