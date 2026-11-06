package config

import (
	"net"
	"net/url"

	"github.com/iksnerd/json-bourne/internal/adapters/bgp"
	"github.com/iksnerd/json-bourne/internal/adapters/crtsh"
)

// ServiceInfo describes one outbound service a config names, for `jb doctor`. It
// carries names and flags only: never a credential, never the value of an environment
// variable, never a webhook URL.
type ServiceInfo struct {
	Kind    string   // source, feed, alert or estate
	Type    string   // kibana, greynoise, sans-isc, dnsbl, webhook, bgp, crt.sh, dns
	Name    string   // what the service is called in output (a feed's source column, an estate service)
	Enabled bool     // false: listed or available, but switched off; nothing is sent
	EnvVars []string // names of the environment variables the config requires
	Host    string   // host[:port] to reach, "" when not known from the file
	HostEnv string   // the variable whose URL value holds the host (webhook); the path is a secret
	// Resolver is true when the service is reached through the system DNS resolver.
	Resolver bool
	Leaves   string // what would leave the machine, in words
}

// hostPort is host:port with the scheme's default port filled in: what a TCP connect needs.
func hostPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return ""
}

// Services lists every outbound service the file names: sources, feeds, alert sinks
// and the three estate collectors that leave the machine, each with its enabled state.
func (f *File) Services() []ServiceInfo {
	var out []ServiceInfo
	for _, e := range f.Sources {
		info := e.spec.describe()
		if e.Disabled {
			info.Enabled = false
			info.Leaves = "nothing: enabled: false in the config, so the source is never built or asked"
		}
		out = append(out, info)
	}
	for _, e := range f.Feeds {
		out = append(out, e.spec.describe())
	}
	for _, e := range f.Alerts {
		out = append(out, e.spec.describe())
	}
	bgpURL, crtURL := f.Estate.BGPURL, f.Estate.CrtshURL
	if bgpURL == "" {
		bgpURL = bgp.DefaultBaseURL
	}
	if crtURL == "" {
		crtURL = crtsh.DefaultBaseURL
	}
	out = append(out,
		ServiceInfo{Kind: "estate", Type: EstateBGP, Name: EstateBGP, Enabled: f.EstateEnabled(EstateBGP), Host: hostPort(bgpURL),
			Leaves: "AS numbers and addresses asked about by `jb estate asn`, to " + hostOf(bgpURL)},
		ServiceInfo{Kind: "estate", Type: EstateCrtsh, Name: EstateCrtsh, Enabled: f.EstateEnabled(EstateCrtsh), Host: hostPort(crtURL),
			Leaves: "domain names asked about by `jb estate ct`, to " + hostOf(crtURL)},
		ServiceInfo{Kind: "estate", Type: EstateDNS, Name: EstateDNS, Enabled: f.EstateEnabled(EstateDNS), Resolver: true,
			Leaves: "domain names asked about by `jb estate dns`, to the system DNS resolver and the domain's name servers"},
	)
	return out
}
