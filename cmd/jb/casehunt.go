package main

import (
	"fmt"
	"io"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
)

// casePlan is what `jb hunt --case` takes from a case once it has passed the checks.
// The logic lives in internal/config so the Go package jb shares it.
type casePlan struct {
	c          *casefile.Case
	configPath string        // absolute path of the chosen hunt config
	window     time.Duration // zero: the case gave none, keep the flag's value
}

// planCase loads the case, refuses when the evidence guard fails, and chooses the
// config and the default window. Nothing here reads the environment or evidence/.
func planCase(stderr io.Writer, dir, cfgFlag string, windowSet bool) (*casePlan, error) {
	p, err := config.PlanCase(dir, cfgFlag, windowSet)
	if err != nil {
		return nil, err
	}
	for _, n := range p.Notes {
		fmt.Fprintln(stderr, n)
	}
	return &casePlan{c: p.Case, configPath: p.ConfigPath, window: p.Window}, nil
}

// chooseCaseConfig returns the absolute path of the hunt config to use.
func chooseCaseConfig(c *casefile.Case, flag string) (string, error) {
	p, err := config.ChooseCaseConfig(c, flag)
	return p, err
}

// placeStore decides where the evidence database goes (config.PlaceCaseStore).
func (p *casePlan) placeStore(stderr io.Writer, cfg *config.File) {
	if note := config.PlaceCaseStore(p.c, cfg); note != "" {
		fmt.Fprintln(stderr, note)
	}
}

func insideDir(dir, p string) bool { return config.InsideDir(dir, p) }
