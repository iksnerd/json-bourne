package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
)

// maxRunIndicators bounds how many distinct values are read back from a stored run
// before the lookup cap is applied.
const maxRunIndicators = 10000

// ReputationStore appends reputation snapshots. Rows are never updated or deleted.
type ReputationStore interface {
	AppendReputation(ctx context.Context, rs []core.Reputation) error
}

// IndicatorReader yields the indicators of the latest stored run, most frequent first.
type IndicatorReader interface {
	LatestRunIndicators(ctx context.Context, fields []string, limit int) (run string, indicators []string, err error)
}

// IntelDeps are the ports Intel works through.
type IntelDeps struct {
	Feeds      []core.Feed
	Store      ReputationStore
	Indicators IndicatorReader // used only when the request names no indicator
}

// IntelRequest says what to look up. A reputation snapshot is context about an
// address, not attribution: nothing here feeds a detector or a severity.
type IntelRequest struct {
	Indicators    []string // IP addresses; empty means "the latest stored run"
	Fields        []string // event fields to read addresses from when Indicators is empty
	MaxIndicators int      // how many distinct indicators to ask about; the rest are failures
}

// IntelFailure is an indicator a feed could not answer. It is not an answer.
type IntelFailure struct {
	Feed      string
	Indicator string
	Err       error
}

// IntelResult is the full account of one lookup run.
type IntelResult struct {
	Run       string // the stored run the indicators came from, if any
	Requested []string
	Rows      []core.Reputation // answers, including not_found
	Failures  []IntelFailure
	Skipped   int // values in the run that were not IP addresses
}

// Complete reports whether every requested indicator got an answer from every feed.
// An incomplete result must never be shown as clean.
func (r IntelResult) Complete() bool { return len(r.Failures) == 0 }

// Intel looks the indicators up in every feed and appends the answers to the store.
// Answers obtained before a failure are kept; failures are returned in the result, never
// stored. The returned error is for input and storage problems only.
func Intel(ctx context.Context, d IntelDeps, req IntelRequest) (IntelResult, error) {
	var res IntelResult
	if len(d.Feeds) == 0 {
		return res, errors.New("no feed is configured: add a feeds: entry")
	}
	if d.Store == nil {
		return res, errors.New("no store to record the snapshots in")
	}
	if req.MaxIndicators <= 0 {
		return res, errors.New("MaxIndicators must be positive")
	}
	names := map[string]bool{}
	for _, f := range d.Feeds {
		if names[f.Name()] {
			return res, fmt.Errorf("two feeds are both named %q: the stored source would not say which one answered", f.Name())
		}
		names[f.Name()] = true
	}

	var candidates []string
	if len(req.Indicators) > 0 {
		var bad []string
		for _, s := range req.Indicators {
			if _, err := netip.ParseAddr(strings.TrimSpace(s)); err != nil {
				bad = append(bad, s)
			}
		}
		if len(bad) > 0 {
			return res, fmt.Errorf("not IP addresses: %s", strings.Join(bad, ", "))
		}
		candidates = req.Indicators
	} else {
		if d.Indicators == nil {
			return res, errors.New("no indicators given and no stored run to read them from")
		}
		run, vals, err := d.Indicators.LatestRunIndicators(ctx, req.Fields, maxRunIndicators)
		if err != nil {
			return res, err
		}
		res.Run = run
		for _, v := range vals {
			if _, err := netip.ParseAddr(strings.TrimSpace(v)); err != nil {
				res.Skipped++
				continue
			}
			candidates = append(candidates, v)
		}
		if len(candidates) == 0 {
			return res, fmt.Errorf("run %s holds %d value(s) in %s and none is an IP address: nothing to look up",
				run, res.Skipped, strings.Join(req.Fields, ", "))
		}
	}

	// Canonicalise and de-duplicate, keeping order.
	seen := map[string]bool{}
	var all []string
	for _, s := range candidates {
		a, _ := netip.ParseAddr(strings.TrimSpace(s))
		c := a.String()
		if !seen[c] {
			seen[c] = true
			all = append(all, c)
		}
	}
	ask, over := all, []string(nil)
	if len(all) > req.MaxIndicators {
		ask, over = all[:req.MaxIndicators], all[req.MaxIndicators:]
	}
	res.Requested = ask

	for _, f := range d.Feeds {
		rows, err := f.Lookup(ctx, ask)
		answered := map[string]bool{}
		failed := map[string]error{}
		for _, le := range core.LookupErrors(err) {
			failed[le.Indicator] = le.Err
		}
		for _, r := range rows {
			if r.Verdict == "" || !contains(ask, r.Indicator) {
				continue // an empty verdict is not an answer; an unasked row is not ours
			}
			if r.Source != f.Name() {
				// The source column must name the feed that answered.
				failed[r.Indicator] = fmt.Errorf("%w: the feed returned a row naming source %q, not %q; not stored", core.ErrFeedFailed, r.Source, f.Name())
				continue
			}
			if answered[r.Indicator] {
				continue // one answer per indicator and feed
			}
			answered[r.Indicator] = true
			res.Rows = append(res.Rows, r)
		}
		for _, ind := range ask {
			if answered[ind] {
				continue
			}
			cause := failed[ind]
			switch {
			case cause != nil:
			case err != nil:
				cause = err
			default:
				cause = errors.New("the feed returned neither an answer nor an error")
			}
			res.Failures = append(res.Failures, IntelFailure{Feed: f.Name(), Indicator: ind, Err: cause})
		}
		for _, ind := range over {
			res.Failures = append(res.Failures, IntelFailure{Feed: f.Name(), Indicator: ind,
				Err: fmt.Errorf("%w: not asked, the cap is %d indicators per run", core.ErrBudgetExceeded, req.MaxIndicators)})
		}
	}

	if err := d.Store.AppendReputation(ctx, res.Rows); err != nil {
		return res, fmt.Errorf("store reputation snapshots: %w", err)
	}
	return res, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
