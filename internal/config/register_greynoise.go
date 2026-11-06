package config

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/greynoise"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Limits on a feed. Defaults are conservative on purpose: the free community API
// allows very few lookups, and a lookup is a request to a third party.
const (
	defaultFeedLookups   = 10
	maxFeedLookups       = 1000
	defaultFeedInterval  = time.Second
	maxFeedInterval      = time.Hour
	defaultFeedTimeout   = 10 * time.Second
	maxFeedTimeout       = time.Minute
	defaultFeedBody      = 64 << 10
	minFeedBody          = 512
	maxFeedBody          = 1 << 20
	defaultMaxIndicators = 10
	maxMaxIndicators     = 1000
	defaultIntelIPField  = "client_ip"
	maxIntelIPFields     = 8
)

type greynoiseSpec struct {
	BaseURL     string         `yaml:"base_url"`
	APIKeyEnv   string         `yaml:"api_key_env"`
	MaxLookups  *int           `yaml:"max_lookups"`
	MinInterval *time.Duration `yaml:"min_interval"`
	Timeout     *time.Duration `yaml:"timeout"`
	MaxBody     *int64         `yaml:"max_response_bytes"`
}

func registerGreyNoise(m map[string]func(*yaml.Node) (feedSpec, error)) {
	m["greynoise"] = func(n *yaml.Node) (feedSpec, error) {
		var s greynoiseSpec
		if err := decodeNode(n, &s); err != nil {
			return nil, err
		}
		if err := s.validate(); err != nil {
			return nil, err
		}
		return s, nil
	}
}

func (s greynoiseSpec) baseURL() string {
	if s.BaseURL == "" {
		return greynoise.DefaultBaseURL
	}
	return s.BaseURL
}

func (s greynoiseSpec) validate() error {
	if s.APIKeyEnv != "" && !envName.MatchString(s.APIKeyEnv) {
		return errors.New("api_key_env must name an environment variable (upper-case letters, digits, underscore); put the variable's name here, never the key")
	}
	if err := validateFeedBase(s.baseURL(), "/v3/community/<ip>"); err != nil {
		return err
	}
	return validateFeedLimits(s.MaxLookups, s.MinInterval, s.Timeout, s.MaxBody)
}

func (s greynoiseSpec) feedName() string { return greynoise.SourceName }
func (s greynoiseSpec) enabled() bool    { return true }

// validateFeedBase checks the base_url of an HTTP feed: https (http for loopback only),
// no credentials, no path, no query.
func validateFeedBase(raw, adds string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("base_url must be an absolute https URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return errors.New("base_url must use https (http is allowed for loopback only)")
	}
	if u.User != nil {
		return errors.New("base_url must not carry credentials")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("base_url must be scheme://host[:port] only; jb adds %s", adds)
	}
	return nil
}

// validateFeedLimits checks the bounds every feed shares.
func validateFeedLimits(maxLookups *int, minInterval, timeout *time.Duration, maxBody *int64) error {
	if maxLookups != nil && (*maxLookups < 1 || *maxLookups > maxFeedLookups) {
		return fmt.Errorf("max_lookups %d outside 1..%d", *maxLookups, maxFeedLookups)
	}
	if minInterval != nil && (*minInterval < 0 || *minInterval > maxFeedInterval) {
		return fmt.Errorf("min_interval %s outside 0..%s", *minInterval, maxFeedInterval)
	}
	if timeout != nil && (*timeout <= 0 || *timeout > maxFeedTimeout) {
		return fmt.Errorf("timeout %s outside (0, %s]", *timeout, maxFeedTimeout)
	}
	if maxBody != nil && (*maxBody < minFeedBody || *maxBody > maxFeedBody) {
		return fmt.Errorf("max_response_bytes %d outside %d..%d", *maxBody, minFeedBody, maxFeedBody)
	}
	return nil
}

func (s greynoiseSpec) build(env Env) (core.Feed, error) {
	f := &greynoise.Feed{
		BaseURL: s.baseURL(), MaxLookups: defaultFeedLookups, MinInterval: defaultFeedInterval,
		Timeout: defaultFeedTimeout, MaxBody: defaultFeedBody,
	}
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
	if s.APIKeyEnv != "" {
		// A named variable that is unset or empty is an error. Running keyless instead
		// would silently fall to the much smaller community quota.
		key, ok := env(s.APIKeyEnv)
		if !ok || key == "" {
			return nil, fmt.Errorf("environment variable %s is not set", s.APIKeyEnv)
		}
		f.Key = key
	}
	return f, nil
}

func (s greynoiseSpec) describe() ServiceInfo {
	host := hostOf(s.baseURL())
	in := ServiceInfo{Kind: "feed", Type: "greynoise", Name: greynoise.SourceName, Enabled: true, Host: hostPort(s.baseURL())}
	in.Leaves = "each IP address looked up, in the request path, to " + host
	if s.APIKeyEnv != "" {
		in.EnvVars = []string{s.APIKeyEnv}
		in.Leaves += ", with the API key in a header"
	}
	return in
}
