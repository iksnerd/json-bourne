package config

import (
	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/detectors/signature"
	"github.com/iksnerd/json-bourne/internal/core"
)

type signatureSpec struct{ cfg signature.Config }

func registerSignature(m map[string]func(*yaml.Node) (detectorSpec, error)) {
	m["signature"] = func(n *yaml.Node) (detectorSpec, error) {
		var s signatureSpec
		if err := decodeNode(n, &s.cfg); err != nil {
			return nil, err
		}
		// Validate now, so a bad value fails at Load rather than mid-incident.
		if _, err := signature.New(s.cfg); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// needsFilteredSources is read by Parse: see checkQuietNeedsFilters.
func (s signatureSpec) needsFilteredSources() bool { return s.cfg.EmptyIsQuiet }

// readsField is read by Parse: see checkFieldsAreEmitted.
func (s signatureSpec) readsField() string { return s.cfg.Field }

func (s signatureSpec) build(buildCtx) (core.Detector, error) { return signature.New(s.cfg) }
