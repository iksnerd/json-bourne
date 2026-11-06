package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/dnsbl"
	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	defaultDNSBLInterval = 250 * time.Millisecond
	defaultDNSBLTimeout  = 5 * time.Second
	maxDNSBLCodes        = 64
	maxDNSBLErrorCodes   = 16
)

var dnsblLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,40}$`)

// dnsblSpec is one DNSBL zone. A lookup sends the address, as a DNS name, to a resolver
// and to the zone's operator, so the feed does nothing until enabled: true.
type dnsblSpec struct {
	Enabled     bool              `yaml:"enabled"`
	Zone        string            `yaml:"zone"`
	Resolver    string            `yaml:"resolver"`
	ReturnCodes map[string]string `yaml:"return_codes"`
	ErrorCodes  []string          `yaml:"error_codes"`
	IPv6        bool              `yaml:"ipv6"`
	MaxLookups  *int              `yaml:"max_lookups"`
	MinInterval *time.Duration    `yaml:"min_interval"`
	Timeout     *time.Duration    `yaml:"timeout"`
}

func registerDNSBL(m map[string]func(*yaml.Node) (feedSpec, error)) {
	m["dnsbl"] = func(n *yaml.Node) (feedSpec, error) {
		var s dnsblSpec
		if err := decodeNode(n, &s); err != nil {
			return nil, err
		}
		if err := s.validate(); err != nil {
			return nil, err
		}
		return s, nil
	}
}

func parseCode(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !a.IsLoopback() {
		return netip.Addr{}, fmt.Errorf("%q is not an address in 127.0.0.0/8", s)
	}
	if a.As4()[1] == 255 && a.As4()[2] == 255 {
		return netip.Addr{}, fmt.Errorf("%s is in 127.255.255.0/24, which jb always treats as a refusal of service; it cannot be a listing", s)
	}
	return a, nil
}

// resolverAddr returns the host:port a resolver setting names, or "" for the system one.
func (s dnsblSpec) resolverAddr() (string, error) {
	if s.Resolver == "" {
		return "", nil
	}
	if ap, err := netip.ParseAddrPort(s.Resolver); err == nil {
		if ap.Port() == 0 {
			return "", errors.New("resolver port must be 1..65535")
		}
		return ap.String(), nil
	}
	if a, err := netip.ParseAddr(s.Resolver); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	return "", errors.New("resolver must be an IP address or IP:port (a name would need resolving first); omit it to use the system resolver")
}

func (s dnsblSpec) validate() error {
	if err := dnsbl.ValidZone(s.Zone); err != nil {
		return fmt.Errorf("zone: %w", err)
	}
	if _, err := s.resolverAddr(); err != nil {
		return err
	}
	if len(s.ReturnCodes) > maxDNSBLCodes {
		return fmt.Errorf("return_codes: at most %d entries", maxDNSBLCodes)
	}
	for k, v := range s.ReturnCodes {
		if _, err := parseCode(k); err != nil {
			return fmt.Errorf("return_codes: %w", err)
		}
		if !dnsblLabel.MatchString(v) {
			return errors.New("return_codes: a label is 1-40 characters of letters, digits, _ . -")
		}
	}
	if len(s.ErrorCodes) > maxDNSBLErrorCodes {
		return fmt.Errorf("error_codes: at most %d entries", maxDNSBLErrorCodes)
	}
	for _, c := range s.ErrorCodes {
		a, err := netip.ParseAddr(c)
		if err != nil || !a.Is4() || !a.IsLoopback() {
			return fmt.Errorf("error_codes: %q is not an address in 127.0.0.0/8", c)
		}
	}
	return validateFeedLimits(s.MaxLookups, s.MinInterval, s.Timeout, nil)
}

func (s dnsblSpec) feedName() string { return "dnsbl:" + s.Zone }
func (s dnsblSpec) enabled() bool    { return s.Enabled }

func (s dnsblSpec) describe() ServiceInfo {
	addr, _ := s.resolverAddr()
	via := "the system resolver"
	if addr != "" {
		via = "the resolver " + addr
	}
	return ServiceInfo{Kind: "feed", Type: "dnsbl", Name: s.feedName(), Enabled: s.Enabled, Host: addr, Resolver: true,
		Leaves: "each IP address looked up, as a DNS name under " + s.Zone + ", to " + via + " and, through it, to the operator of " + s.Zone}
}

func (s dnsblSpec) build(Env) (core.Feed, error) {
	f := &dnsbl.Feed{Zone: s.Zone, IPv6: s.IPv6, MaxLookups: defaultFeedLookups,
		MinInterval: defaultDNSBLInterval, Timeout: defaultDNSBLTimeout}
	if s.MaxLookups != nil {
		f.MaxLookups = *s.MaxLookups
	}
	if s.MinInterval != nil {
		f.MinInterval = *s.MinInterval
	}
	if s.Timeout != nil {
		f.Timeout = *s.Timeout
	}
	if len(s.ReturnCodes) > 0 {
		f.Codes = map[netip.Addr]string{}
		for k, v := range s.ReturnCodes {
			a, _ := parseCode(k) // validated at load
			f.Codes[a] = v
		}
	}
	for _, c := range s.ErrorCodes {
		a, _ := netip.ParseAddr(c)
		f.ErrorCodes = append(f.ErrorCodes, a)
	}
	// PreferGo: the cgo resolver cannot tell NXDOMAIN from SERVFAIL, and "not listed"
	// must never be a guess.
	r := &net.Resolver{PreferGo: true}
	if addr, _ := s.resolverAddr(); addr != "" {
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	f.Resolver = r
	return f, nil
}
