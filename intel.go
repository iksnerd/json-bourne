package jb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
)

// IntelNote is carried by every [IntelResult], in every format. It is the reading rule
// for a reputation snapshot, kept next to the data so it travels with a pasted table.
const IntelNote = "A reputation snapshot is context, not attribution. It describes an address as a third-party " +
	"feed saw it; a CDN or proxy edge address says nothing about the visitor behind it. " +
	"It never changes a finding or a severity."

// IntelRow is one answer of a feed about one address, "not_found" included.
type IntelRow struct {
	Indicator string `json:"indicator"`
	Feed      string `json:"feed"`
	Verdict   string `json:"verdict"`
	Observed  string `json:"observed"` // RFC 3339
}

// IntelFailure is an address a feed could not answer. It is not an answer and nothing
// is stored for it.
type IntelFailure struct {
	Indicator string `json:"indicator"`
	Feed      string `json:"feed"`
	Error     string `json:"error"`
}

// IntelResult is the account of one [Intel] run. It is complete only when every
// address got an answer from every enabled feed: check [IntelResult.Complete].
type IntelResult struct {
	// Note is [IntelNote].
	Note string
	// Run is the stored hunt the addresses were read from, empty when the caller gave them.
	Run string
	// Skipped counts values in that run that were not IP addresses.
	Skipped int
	// Results are the answers, in the order the feeds gave them.
	Results []IntelRow
	// Failures are the lookups that got no answer, including addresses not asked
	// because the run's cap was reached.
	Failures []IntelFailure

	// Requested lists the addresses that were asked about. It is not part of the JSON.
	Requested []string
	// Notes are caveats for the person running the command, such as a feed that is
	// listed but not enabled. They are not part of the JSON.
	Notes []string
}

// Complete reports whether every requested address got an answer from every feed. An
// incomplete result is never a clean one.
func (r IntelResult) Complete() bool { return len(r.Failures) == 0 }

// MarshalJSON prints what `jb intel --output json` prints.
func (r IntelResult) MarshalJSON() ([]byte, error) {
	out := struct {
		Note     string         `json:"note"`
		Run      string         `json:"run,omitempty"`
		Complete bool           `json:"complete"`
		Skipped  int            `json:"skipped_non_ip,omitempty"`
		Results  []IntelRow     `json:"results"`
		Failures []IntelFailure `json:"failures"`
	}{r.Note, r.Run, r.Complete(), r.Skipped, r.Results, r.Failures}
	if out.Results == nil {
		out.Results = []IntelRow{}
	}
	if out.Failures == nil {
		out.Failures = []IntelFailure{}
	}
	return json.Marshal(out)
}

// IntelOptions are the options of [Intel].
type IntelOptions struct {
	// Config names the config with the `feeds:` section. With a case directory it is
	// one of the case's configs, as in [CaseHuntOptions.Config]; empty means the case's
	// only config. Without one it is the path of a config file and is required.
	Config string
	// Env resolves the variables the config names, such as a feed's API key. Nil reads
	// the process environment.
	Env Env
}

// Intel asks the reputation feeds of the config (`feeds:`, only those with `enabled:
// true` where the feed needs it) about addresses and appends each answer, with the time
// and the feed, to the evidence database's reputation table, as `jb intel` does. With no
// addresses it reads the distinct values of the config's intel.ip_fields from the
// latest stored hunt, most frequent first.
//
// Requests go to the feeds' APIs only (for a dnsbl feed, a DNS question under the
// zone), never to the address. They are capped (`max_lookups`, `intel.max_indicators`),
// spaced (`min_interval`), timed out and size-limited. A lookup that failed, timed out,
// was rate limited or was not made because a cap was reached is never an answer: it is
// listed in [IntelResult.Failures], nothing is stored for it, and [IntelResult.Complete]
// is false. "not_found" is a real answer and is stored.
//
// caseDir may be empty when opts.Config is the path of a config file. A nil error
// means the feeds were asked, not that every lookup was answered: check Complete. When
// the error is not nil the result is nil unless some addresses were already asked.
func Intel(ctx context.Context, caseDir string, indicators []string, opts IntelOptions) (*IntelResult, error) {
	if caseDir == "" && opts.Config == "" {
		return nil, usagef("a case directory or a config file is required")
	}
	for _, a := range indicators {
		if _, err := netip.ParseAddr(strings.TrimSpace(a)); err != nil {
			return nil, usagef("%q is not an IP address", a)
		}
	}
	var notes []string
	cfgPath := opts.Config
	var plan *config.CasePlan
	if caseDir != "" {
		// windowSet is true: intel has no window, so the case's default is not announced.
		var err error
		if plan, err = config.PlanCase(caseDir, opts.Config, "intel", true); err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		cfgPath = plan.ConfigPath
		notes = append(notes, plan.Notes...)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if plan != nil {
		if n := config.PlaceCaseStore(plan.Case, cfg); n != "" {
			notes = append(notes, n)
		}
	}
	if len(cfg.Feeds) == 0 {
		return nil, fmt.Errorf("%s has no feeds: add a `feeds:` entry (docs/CONFIG.md)", cfgPath)
	}
	feeds, err := cfg.BuildFeeds(opts.Env)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	for _, name := range cfg.DisabledFeeds() {
		notes = append(notes, fmt.Sprintf("note: feed %s is listed but not enabled (enabled: true), so it is not asked and nothing is sent to it", name))
	}
	if len(feeds) == 0 {
		return nil, fmt.Errorf("%s lists feeds but none is enabled: set `enabled: true` on the feed you mean to ask (docs/CONFIG.md)", cfgPath)
	}
	iopts := cfg.IntelOptions()

	st, err := duckdb.OpenContext(ctx, cfg.StorePath(), false, duckdb.OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	if _, err := st.Migrate(); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	r, ierr := app.Intel(ctx, app.IntelDeps{Feeds: feeds, Store: st, Indicators: st},
		app.IntelRequest{Indicators: indicators, Fields: iopts.IPFields, MaxIndicators: iopts.MaxIndicators})
	if ierr != nil && len(r.Requested) == 0 {
		return nil, fmt.Errorf("%w", ierr) // nothing was asked: an input problem, nothing to report
	}
	res := &IntelResult{Note: IntelNote, Run: r.Run, Skipped: r.Skipped, Requested: r.Requested, Notes: notes}
	for _, x := range r.Rows {
		res.Results = append(res.Results, IntelRow{x.Indicator, x.Source, x.Verdict, x.Observed.Format(time.RFC3339)})
	}
	for _, x := range r.Failures {
		f := IntelFailure{Indicator: x.Indicator, Feed: x.Feed}
		if x.Err != nil {
			f.Error = x.Err.Error()
		}
		res.Failures = append(res.Failures, f)
	}
	if ierr != nil {
		return res, fmt.Errorf("%w", ierr)
	}
	return res, nil
}
