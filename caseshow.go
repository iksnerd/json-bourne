package jb

import (
	"fmt"

	"github.com/iksnerd/json-bourne/internal/config"
)

// Types of [CaseShow]. They are aliases of the config package's plain data types.
type (
	// CaseShowResult is the described config of one config of a case.
	CaseShowResult = config.CaseShow
	// Description is a config as plain data: sources, detectors, store and alerts.
	// It holds the name of a credential variable, never a value.
	Description = config.Description
	// SourceDescription is one source of a [Description].
	SourceDescription = config.SourceDescription
	// DetectorDescription is one detector of a [Description].
	DetectorDescription = config.DetectorDescription
	// StoreDescription says where the evidence database is.
	StoreDescription = config.StoreDescription
	// AlertDescription is one alert sink of a [Description].
	AlertDescription = config.AlertDescription
)

// CaseShowOptions are the options of [CaseShow].
type CaseShowOptions struct {
	// Config names one of the case's configs, as in [CaseHuntOptions.Config]. Empty
	// means the case's only config; a case that lists several needs it.
	Config string `jb:"config" desc:"One of the case's configs: a name from case.yaml or a file inside the case. Default: the only config."`
}

// CaseShow describes what one config of a case would run, as `jb case show` does. It
// reads no environment variable, runs no git command, makes no connection and opens no
// store, so it is safe to call before any credential is set.
func CaseShow(caseDir string, opts CaseShowOptions) (*CaseShowResult, error) {
	r, err := config.ShowCase(caseDir, opts.Config)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return r, nil
}
