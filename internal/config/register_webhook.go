package config

import (
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/webhook"
	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	defaultAlertSeverity = "high"
	maxAlertTimeout      = time.Minute
	maxAlertsPerCycle    = 100
	maxAlertInterval     = time.Hour
)

// AlertEntry is one element of `alerts:`: a delivery in addition to the local log.
type AlertEntry struct {
	Type string
	spec alertSpec
}

type alertSpec interface {
	build(env Env) (core.AlertSink, error)
	describe() ServiceInfo
}

// UnmarshalYAML picks the builder by `type:` and strictly decodes the rest.
func (e *AlertEntry) UnmarshalYAML(n *yaml.Node) error {
	t, spec, err := decodeTyped("alert", n, alertTypes())
	if err != nil {
		return err
	}
	e.Type, e.spec = t, spec
	return nil
}

// BuildAlerts constructs the extra alert sinks, reading each webhook URL from its
// environment variable. They are optional sinks: the local log is always written first
// and stays the source of truth. An error never contains a URL.
func (f *File) BuildAlerts(env Env) ([]core.AlertSink, error) {
	if env == nil {
		env = OSEnv
	}
	var out []core.AlertSink
	var errs []error
	for i, e := range f.Alerts {
		s, err := e.spec.build(env)
		if err != nil {
			errs = append(errs, fmt.Errorf("alerts[%d] (%s): %w", i, e.Type, err))
			continue
		}
		out = append(out, s)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

func alertTypes() map[string]func(*yaml.Node) (alertSpec, error) {
	m := map[string]func(*yaml.Node) (alertSpec, error){}
	registerWebhook(m)
	return m
}

type webhookSpec struct {
	URLEnv      string         `yaml:"url_env"`
	MinSeverity string         `yaml:"min_severity"`
	Timeout     *time.Duration `yaml:"timeout"`
	MaxPerCycle *int           `yaml:"max_per_cycle"`
	MinInterval *time.Duration `yaml:"min_interval"`
	MaxResponse *int64         `yaml:"max_response_bytes"`
	// Insecure is for tests: it lets the URL be plain http to a loopback host.
	Insecure bool `yaml:"allow_insecure_loopback"`
}

func registerWebhook(m map[string]func(*yaml.Node) (alertSpec, error)) {
	m["webhook"] = func(n *yaml.Node) (alertSpec, error) {
		var s webhookSpec
		if err := decodeNode(n, &s); err != nil {
			return nil, err
		}
		if err := s.validate(); err != nil {
			return nil, err
		}
		return s, nil
	}
}

func (s webhookSpec) severity() core.Severity {
	name := s.MinSeverity
	if name == "" {
		name = defaultAlertSeverity
	}
	sev, _ := core.ParseSeverity(name)
	return sev
}

func (s webhookSpec) validate() error {
	// The message never quotes the value: a pasted URL is a leaked secret.
	if !envName.MatchString(s.URLEnv) {
		return errors.New("url_env must name an environment variable (upper-case letters, digits, underscore) that holds the webhook URL; put the variable's name here, never the URL, which carries a token")
	}
	if s.MinSeverity != "" {
		if _, ok := core.ParseSeverity(s.MinSeverity); !ok {
			return errors.New("min_severity must be one of info, check, activity, high, critical")
		}
	}
	if s.Timeout != nil && (*s.Timeout <= 0 || *s.Timeout > maxAlertTimeout) {
		return fmt.Errorf("timeout %s outside (0, %s]", *s.Timeout, maxAlertTimeout)
	}
	if s.MaxPerCycle != nil && (*s.MaxPerCycle < 1 || *s.MaxPerCycle > maxAlertsPerCycle) {
		return fmt.Errorf("max_per_cycle %d outside 1..%d", *s.MaxPerCycle, maxAlertsPerCycle)
	}
	if s.MinInterval != nil && (*s.MinInterval < 0 || *s.MinInterval > maxAlertInterval) {
		return fmt.Errorf("min_interval %s outside 0..%s", *s.MinInterval, maxAlertInterval)
	}
	if s.MaxResponse != nil && (*s.MaxResponse < 16 || *s.MaxResponse > maxFeedBody) {
		return fmt.Errorf("max_response_bytes %d outside 16..%d", *s.MaxResponse, maxFeedBody)
	}
	return nil
}

func (s webhookSpec) build(env Env) (core.AlertSink, error) {
	raw, ok := env(s.URLEnv)
	if !ok || raw == "" {
		return nil, errEnvNotSet(s.URLEnv)
	}
	cfg := webhook.Config{URL: webhook.Secret(raw), MinSeverity: s.severity(), AllowInsecureLoopback: s.Insecure}
	if s.Timeout != nil {
		cfg.Timeout = *s.Timeout
	}
	if s.MaxPerCycle != nil {
		cfg.MaxPerCycle = *s.MaxPerCycle
	}
	if s.MinInterval != nil {
		cfg.MinInterval = *s.MinInterval
		if *s.MinInterval == 0 {
			cfg.MinInterval = -1 // zero in the file means no pause
		}
	}
	if s.MaxResponse != nil {
		cfg.MaxResponse = *s.MaxResponse
	}
	sink, err := webhook.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("the URL in %s is not usable: %w", s.URLEnv, err)
	}
	return sink, nil
}

func (s webhookSpec) describe() ServiceInfo {
	return ServiceInfo{Kind: "alert", Type: "webhook", Name: "webhook", Enabled: true, EnvVars: []string{s.URLEnv}, HostEnv: s.URLEnv,
		Leaves: "a short summary of each alerted finding, to the host of the URL in " + s.URLEnv}
}
