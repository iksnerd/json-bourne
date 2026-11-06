package config

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/iksnerd/json-bourne/internal/adapters/detectors/fingerprint"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// fingerprintSpec holds the options. The indicators are not here: they live in the
// actor files of the case, named by Actors, so an incident's data stays in the case.
type fingerprintSpec struct {
	Name      string   `yaml:"name"`
	Actors    []string `yaml:"actors"`
	IgnoreIPs []string `yaml:"ignore_ips"`
	// EmptyIsQuiet makes "no matching event in the window" a quiet answer instead of
	// core.ErrNoRecords. It is only sound when every source filters on the server and
	// proves its index alive; Parse refuses it otherwise.
	EmptyIsQuiet bool `yaml:"empty_is_quiet"`
}

// needsFilteredSources is read by Parse: see EmptyIsQuiet.
func (s fingerprintSpec) needsFilteredSources() bool { return s.EmptyIsQuiet }

func registerFingerprint(m map[string]func(*yaml.Node) (detectorSpec, error)) {
	m["fingerprint"] = func(n *yaml.Node) (detectorSpec, error) {
		var s fingerprintSpec
		if err := decodeNode(n, &s); err != nil {
			return nil, err
		}
		// Everything that needs no file is checked now, so a bad value fails at Load.
		var errs []error
		if len(s.Actors) == 0 {
			errs = append(errs, errors.New("actors: at least one actor file name is required"))
		}
		seen := map[string]bool{}
		for _, a := range s.Actors {
			if err := casefile.ValidActorName(a); err != nil {
				errs = append(errs, fmt.Errorf("actors: %w", err))
			}
			if seen[a] {
				errs = append(errs, fmt.Errorf("actors: %q listed twice", a))
			}
			seen[a] = true
		}
		if err := fingerprint.ValidateName(s.Name); err != nil {
			errs = append(errs, err)
		}
		if _, err := fingerprint.ParseIgnoreIPs(s.IgnoreIPs); err != nil {
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// build reads the actor files from the case, so it needs one.
func (s fingerprintSpec) build(bc buildCtx) (core.Detector, error) {
	if bc.c == nil {
		return nil, errors.New("fingerprint reads actor files from a case: run it with `jb hunt --case DIR` (an actor file is case data, not config)")
	}
	cfg := fingerprint.Config{Name: s.Name, IgnoreIPs: s.IgnoreIPs, EmptyIsQuiet: s.EmptyIsQuiet}
	var errs []error
	for _, name := range s.Actors {
		a, err := casefile.LoadActorFile(bc.c, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cfg.Actors = append(cfg.Actors, fingerprint.Actor{
			ID:               a.ID,
			Label:            a.Label,
			UserAgents:       a.UserAgents(),
			NoisePaths:       a.Detection.NoisePaths,
			BareRoot4xxNoise: a.BareRoot4xxIsNoise(),
			GrantPaths:       a.Detection.GrantPaths,
		})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return fingerprint.New(cfg)
}
