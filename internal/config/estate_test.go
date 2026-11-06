package config

import (
	"os"
	"strings"
	"testing"
)

func exampleHunt(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../examples/case/config/hunt.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEstateServicesAreOffByDefault(t *testing.T) {
	f, err := Parse([]byte(exampleHunt(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range EstateServices {
		if f.EstateEnabled(s) {
			t.Errorf("%s is enabled with no estate section: nothing may leave the machine until the operator says so", s)
		}
	}
}

func TestEstateExternalEnablesOnlyWhatItNames(t *testing.T) {
	f, err := Parse([]byte(exampleHunt(t) + "\nestate:\n  external: [crt.sh]\n  crtsh_url: https://ct.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !f.EstateEnabled(EstateCrtsh) || f.EstateEnabled(EstateBGP) || f.EstateEnabled(EstateDNS) {
		t.Errorf("%+v", f.Estate)
	}
	if f.Estate.CrtshURL != "https://ct.example.com" {
		t.Errorf("url %q", f.Estate.CrtshURL)
	}
}

func TestEstateSectionIsStrict(t *testing.T) {
	for name, tail := range map[string]string{
		"unknown service": "estate:\n  external: [whois]\n",
		"typo in a key":   "estate:\n  externl: [bgp]\n",
		"duplicate":       "estate:\n  external: [bgp, bgp]\n",
		"not a list":      "estate:\n  external: bgp\n",
	} {
		_, err := Parse([]byte(exampleHunt(t) + "\n" + tail))
		if err == nil {
			t.Errorf("%s accepted: a typo must not silently turn the switch off or on", name)
		} else if name == "unknown service" && !strings.Contains(err.Error(), "known: bgp, crt.sh, dns") {
			t.Errorf("error does not list the known services: %v", err)
		}
	}
}
