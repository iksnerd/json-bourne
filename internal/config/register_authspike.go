package config

import (
	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/detectors/authspike"
	"github.com/iksnerd/json-bourne/internal/core"
)

type authspikeSpec struct{ cfg authspike.Config }

func registerAuthspike(m map[string]func(*yaml.Node) (detectorSpec, error)) {
	m["authspike"] = func(n *yaml.Node) (detectorSpec, error) {
		var s authspikeSpec
		if err := decodeNode(n, &s.cfg); err != nil {
			return nil, err
		}
		// Validate now, so a bad threshold fails at Load rather than mid-incident.
		if _, err := authspike.New(s.cfg); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// needsFilteredSources is read by Parse: see checkQuietNeedsFilters.
func (s authspikeSpec) needsFilteredSources() bool { return s.cfg.EmptyIsQuiet }

func (s authspikeSpec) build(buildCtx) (core.Detector, error) { return authspike.New(s.cfg) }
