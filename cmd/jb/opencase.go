package main

import (
	"io"

	"github.com/iksnerd/json-bourne/internal/config"
)

// openCase loads the hunt config at cfgPath and builds its adapters. It is the one
// sequence `jb hunt` and `jb watch` share. With a plan (--case) the store is placed
// under the case's evidence directory and the detectors are given the case, so they
// can read its data files; without one (hunt --config) the config is used as written.
// The environment is read only by Build, after the config and the store have been
// settled, so a refused case never touches a credential.
func openCase(stderr io.Writer, env config.Env, cfgPath string, plan *casePlan) (*config.File, *config.Runtime, error) {
	return openCaseSearch(stderr, env, cfgPath, plan, nil, "")
}

// openCaseSearch is openCase with the ad-hoc search of one run applied to every source
// before the adapters are built. No terms means no search.
func openCaseSearch(stderr io.Writer, env config.Env, cfgPath string, plan *casePlan, search []string, searchField string) (*config.File, *config.Runtime, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if len(search) > 0 {
		if err := cfg.WithSearch(search, searchField); err != nil {
			return nil, nil, usageErrorf("%v", err)
		}
	}
	if plan != nil {
		plan.placeStore(stderr, cfg)
		cfg.UseCase(plan.c) // detectors read the case's data files (actor files)
	}
	rt, err := cfg.Build(env)
	if err != nil {
		return nil, nil, err
	}
	return cfg, rt, nil
}
