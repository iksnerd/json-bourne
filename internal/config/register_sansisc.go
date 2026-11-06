package config

import (
	"net/url"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/sansisc"
	"github.com/iksnerd/json-bourne/internal/core"
)

// sansiscSpec is the SANS ISC IP API feed. It has no key, so it has no api_key_env:
// naming one is an unknown key and fails at load.
type sansiscSpec struct {
	BaseURL     string         `yaml:"base_url"`
	MaxLookups  *int           `yaml:"max_lookups"`
	MinInterval *time.Duration `yaml:"min_interval"`
	Timeout     *time.Duration `yaml:"timeout"`
	MaxBody     *int64         `yaml:"max_response_bytes"`
}

func registerSansISC(m map[string]func(*yaml.Node) (feedSpec, error)) {
	m["sans-isc"] = func(n *yaml.Node) (feedSpec, error) {
		var s sansiscSpec
		if err := decodeNode(n, &s); err != nil {
			return nil, err
		}
		if err := validateFeedBase(s.baseURL(), "/api/ip/<ip>?json"); err != nil {
			return nil, err
		}
		if err := validateFeedLimits(s.MaxLookups, s.MinInterval, s.Timeout, s.MaxBody); err != nil {
			return nil, err
		}
		return s, nil
	}
}

func (s sansiscSpec) baseURL() string {
	if s.BaseURL == "" {
		return sansisc.DefaultBaseURL
	}
	return s.BaseURL
}

func (s sansiscSpec) feedName() string { return sansisc.SourceName }
func (s sansiscSpec) enabled() bool    { return true }

func (s sansiscSpec) describe() ServiceInfo {
	host := ""
	if u, err := url.Parse(s.baseURL()); err == nil {
		host = u.Host
	}
	return ServiceInfo{Kind: "feed", Type: "sans-isc", Name: sansisc.SourceName, Enabled: true, Host: hostPort(s.baseURL()),
		Leaves: "each IP address looked up, in the request path, to " + host + " (no credential)"}
}

func (s sansiscSpec) build(Env) (core.Feed, error) {
	f := &sansisc.Feed{BaseURL: s.baseURL(), MaxLookups: defaultFeedLookups, MinInterval: defaultFeedInterval,
		Timeout: defaultFeedTimeout, MaxBody: defaultFeedBody}
	if s.MaxLookups != nil {
		f.MaxLookups = *s.MaxLookups
	}
	if s.MinInterval != nil {
		f.MinInterval = *s.MinInterval
	}
	if s.Timeout != nil {
		f.Timeout = *s.Timeout
	}
	if s.MaxBody != nil {
		f.MaxBody = *s.MaxBody
	}
	return f, nil
}
