package config

import (
	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/detectors/signup"
	"github.com/iksnerd/json-bourne/internal/core"
)

type signupSpec struct{ cfg signup.Config }

func registerSignup(m map[string]func(*yaml.Node) (detectorSpec, error)) {
	m["signup"] = func(n *yaml.Node) (detectorSpec, error) {
		var s signupSpec
		if err := decodeNode(n, &s.cfg); err != nil {
			return nil, err
		}
		// Validate now, so a bad threshold fails at Load rather than mid-incident.
		if _, err := signup.New(s.cfg); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// needsFilteredSources is read by Parse: see checkQuietNeedsFilters.
func (s signupSpec) needsFilteredSources() bool { return s.cfg.EmptyIsQuiet }

func (s signupSpec) build(buildCtx) (core.Detector, error) { return signup.New(s.cfg) }
