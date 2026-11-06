package config

import (
	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/detectors/newkey"
	"github.com/iksnerd/json-bourne/internal/core"
)

type newkeySpec struct{ cfg newkey.Config }

func registerNewkey(m map[string]func(*yaml.Node) (detectorSpec, error)) {
	m["newkey"] = func(n *yaml.Node) (detectorSpec, error) {
		var s newkeySpec
		if err := decodeNode(n, &s.cfg); err != nil {
			return nil, err
		}
		// Validate now, so a bad value fails at Load rather than mid-incident.
		if _, err := newkey.New(s.cfg); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// needsFilteredSources is read by Parse: see checkQuietNeedsFilters.
func (s newkeySpec) needsFilteredSources() bool { return s.cfg.EmptyIsQuiet }

func (s newkeySpec) build(buildCtx) (core.Detector, error) { return newkey.New(s.cfg) }
