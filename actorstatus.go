package jb

import (
	"context"
	"fmt"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// ActorStatusOptions are the options of [ActorStatus].
type ActorStatusOptions struct {
	// Config names one of the case's configs, as in [CaseHuntOptions.Config]. Empty
	// means the config the case's commands list for `actor`, else its only config.
	Config string "jb:\"config\" desc:\"one of the case's configs (default: the config whose `commands:` lists this command, else the case's only config)\""
}

// ActorMatch is when one user agent of an actor last matched in the evidence store. It
// is one row of `jb actor status --output json`.
type ActorMatch struct {
	Actor     string `json:"actor"`
	Label     string `json:"label,omitempty"`
	UserAgent string `json:"user_agent"`
	// LastGenuine is nil when the user agent never matched a genuine event.
	LastGenuine *time.Time `json:"last_genuine,omitempty"`
	Examined    int        `json:"examined"`
	Noise       int        `json:"noise"`
	Ignored     int        `json:"ignored"`
	Unparsable  int        `json:"unparsable"`
	// Capped is true when the scan stopped at its cap before a genuine match, so no date
	// can be given and LastGenuine being nil does not mean "never".
	Capped bool `json:"capped,omitempty"`
}

// ActorStatusResult is the document `jb actor status --output json` prints.
type ActorStatusResult struct {
	Store  string       `json:"store"`
	Events int64        `json:"store_events"`
	From   *time.Time   `json:"store_from,omitempty"`
	To     *time.Time   `json:"store_to,omitempty"`
	Actors []ActorMatch `json:"actors"`
	// Notes are advice lines for the operator, in order. The CLI prints them to stderr.
	// They are not part of the JSON document.
	Notes []string `json:"-"`
}

// Complete is false when any row's scan was capped: that actor has no date, and a nil
// LastGenuine there must not be read as "never matched".
func (r *ActorStatusResult) Complete() bool {
	for _, a := range r.Actors {
		if a.Capped {
			return false
		}
	}
	return true
}

// ActorStatus reports, for every actor the case's fingerprint detector names, each exact
// user agent and the time of its last genuine match in the evidence store, as `jb actor
// status --case DIR` does. Scanner noise and traffic relayed by the config's ignore_ips
// are set aside by the rules a hunt applies.
//
// It reads only what earlier hunts stored: the store is opened read-only, one fixed
// parameterised query runs per user agent, and no environment variable or network is
// used. An empty store is an error, not "never matched". The result is filled in, with
// its Notes, even when the error comes after the case was planned. Check
// [ActorStatusResult.Complete] before reading a missing date as "never".
func ActorStatus(ctx context.Context, caseDir string, opts ActorStatusOptions) (*ActorStatusResult, error) {
	if caseDir == "" {
		return nil, usagef("case directory is required")
	}
	plan, err := config.PlanCase(caseDir, opts.Config, "actor", true)
	if err != nil {
		return nil, err
	}
	res := &ActorStatusResult{Actors: []ActorMatch{}, Notes: plan.Notes}
	cfg, err := config.Load(plan.ConfigPath)
	if err != nil {
		return res, err
	}
	if note := config.PlaceCaseStore(plan.Case, cfg); note != "" {
		res.Notes = append(res.Notes, note)
	}
	cfg.UseCase(plan.Case)
	dets, err := cfg.BuildDetectors()
	if err != nil {
		return res, err
	}
	st, err := duckdb.OpenContext(ctx, cfg.StorePath(), true, duckdb.OpenOptions{})
	if err != nil {
		return res, fmt.Errorf("open database read-only: %w", err)
	}
	defer st.Close()
	stats, err := st.Stats()
	if err != nil {
		return res, fmt.Errorf("read database stats: %w", err)
	}
	res.Store, res.Events, res.From, res.To = stats.Path, stats.Events, utcPtr(stats.FirstSeen), utcPtr(stats.LastSeen)
	if stats.Events == 0 {
		return res, fmt.Errorf("the evidence store %s holds no events, so \"never matched\" cannot be said; run `jb hunt --case` first", stats.Path)
	}
	hist, err := app.ActorStatus(ctx, app.ActorStatusDeps{Detectors: dets, Finder: st})
	if err != nil {
		return res, err
	}
	for _, h := range hist {
		res.Actors = append(res.Actors, actorMatch(h))
	}
	return res, nil
}

func actorMatch(h core.ActorHistory) ActorMatch {
	return ActorMatch{
		Actor: h.Actor, Label: h.Label, UserAgent: h.Indicator, LastGenuine: utcPtr(h.LastGenuine),
		Examined: h.Scanned, Noise: h.Noise, Ignored: h.Ignored, Unparsable: h.Unparsable, Capped: h.Capped,
	}
}

// utcPtr is nil for the zero time, so the JSON field is left out, else the time in UTC.
func utcPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
