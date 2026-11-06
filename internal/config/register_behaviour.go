package config

import (
	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/detectors/behaviour"
	"github.com/iksnerd/json-bourne/internal/core"
)

type behaviourSpec struct{ cfg behaviour.Config }

func registerBehaviour(m map[string]func(*yaml.Node) (detectorSpec, error)) {
	m["behaviour"] = func(n *yaml.Node) (detectorSpec, error) {
		var s behaviourSpec
		if err := decodeNode(n, &s.cfg); err != nil {
			return nil, err
		}
		// Validate now, so a bad threshold fails at Load rather than mid-incident.
		if _, err := behaviour.New(s.cfg); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// needsFilteredSources is read by Parse: see checkQuietNeedsFilters.
func (s behaviourSpec) needsFilteredSources() bool { return s.cfg.EmptyIsQuiet }

func (s behaviourSpec) build(buildCtx) (core.Detector, error) { return behaviour.New(s.cfg) }
