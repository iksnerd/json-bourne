package config

import (
	"fmt"
	"slices"
	"strings"
)

// Estate services. Each one sends the question (a domain name, an AS number, an
// address) to something that is not the operator's own machine, so each is off until
// the operator names it in estate.external.
const (
	EstateBGP   = "bgp"
	EstateCrtsh = "crt.sh"
	EstateDNS   = "dns"
)

// EstateServices is the closed list estate.external may name. It equals the sources of
// the estate collectors that leave the machine; the existing rdns and rdap lookups of
// `jb estate IP` are not switched by it.
var EstateServices = []string{EstateBGP, EstateCrtsh, EstateDNS}

// EstateConfig is the `estate:` section: which external services `jb estate asn|dns|ct`
// may ask, and where.
type EstateConfig struct {
	// External lists the enabled services. Empty (the default) enables none.
	External []string `yaml:"external"`
	// BGPURL is the base URL of a RIPEstat-style BGP data API. Empty means the public one.
	BGPURL string `yaml:"bgp_url"`
	// CrtshURL is the base URL of a crt.sh-style CT search. Empty means the public one.
	CrtshURL string `yaml:"crtsh_url"`
}

func (e EstateConfig) validate() error {
	seen := map[string]bool{}
	for i, s := range e.External {
		if !slices.Contains(EstateServices, s) {
			return fmt.Errorf("estate.external[%d]: unknown service %q (known: %s)", i, s, strings.Join(EstateServices, ", "))
		}
		if seen[s] {
			return fmt.Errorf("estate.external[%d]: %q is listed twice", i, s)
		}
		seen[s] = true
	}
	return nil
}

// EstateEnabled reports whether the operator enabled an external estate service.
func (f *File) EstateEnabled(service string) bool {
	return slices.Contains(f.Estate.External, service)
}
