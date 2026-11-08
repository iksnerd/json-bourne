package jb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Limits of [Reputation].
const (
	// DefaultReputationRows is the row cap when [ReputationOptions.Limit] is zero.
	DefaultReputationRows = 1000
	// MaxReputationRows is the largest row cap a caller may ask for.
	MaxReputationRows = 10000
	// MaxReputationIndicators is the most addresses one call may filter by.
	MaxReputationIndicators = 100
)

// ReputationOptions are the options of [Reputation].
type ReputationOptions struct {
	// Config names the config that places the store. With a case directory it is one of
	// the case's configs (empty: the case's only config, or the one that declares
	// `commands: [intel]`, because the rows are what `jb intel` wrote). Without one it
	// is the path of a YAML config and is required.
	Config string
	// Indicators limits the rows to these IP addresses, at most [MaxReputationIndicators].
	// Any other value is a usage error. Empty means every indicator.
	Indicators []string
	// Source limits the rows to one feed name, as written in the config's `feeds:`.
	Source string
	// Since keeps rows observed at or after this time. Zero means no lower bound.
	Since time.Time
	// Until keeps rows observed before this time (exclusive). Zero means no upper
	// bound. Since must not be after Until, or the call is a usage error.
	Until time.Time
	// Limit is the row cap: zero means [DefaultReputationRows], and the most is
	// [MaxReputationRows].
	Limit int
	// Latest keeps only the newest row of each indicator from each feed.
	Latest bool
}

// ReputationRow is one stored reputation row. The table holds no run id, so these four
// fields are all there is.
type ReputationRow struct {
	Indicator string `json:"indicator"`
	Verdict   string `json:"verdict"`
	Observed  string `json:"observed"` // UTC, RFC 3339
	Source    string `json:"source"`   // the feed's name
}

// ReputationResult is what [Reputation] reads. Its JSON is the output of
// `jb db reputation --output json`.
type ReputationResult struct {
	// Path is the store the rows were read from.
	Path string
	// Note is [IntelNote]: a snapshot is context, not attribution.
	Note string
	// Rows are ordered by indicator, then observed time newest first, then source. Times
	// are UTC, RFC 3339.
	Rows []ReputationRow
	// Limit is the row cap that applied.
	Limit int
	// Truncated is true when more rows matched than Limit: Rows is a cut, not the answer.
	Truncated bool

	// Notes are advice the CLI prints to stderr. They are not part of the JSON.
	Notes []string
}

// Complete reports whether Rows holds every row that matched. It is false when the
// result was cut at the cap: narrow the filters or raise the limit.
func (r *ReputationResult) Complete() bool { return r != nil && !r.Truncated }

// MarshalJSON prints what `jb db reputation --output json` prints.
func (r ReputationResult) MarshalJSON() ([]byte, error) {
	rows := r.Rows
	if rows == nil {
		rows = []ReputationRow{}
	}
	return json.Marshal(struct {
		Path      string          `json:"path"`
		Note      string          `json:"note"`
		Complete  bool            `json:"complete"`
		Limit     int             `json:"limit"`
		Truncated bool            `json:"truncated"`
		Rows      []ReputationRow `json:"rows"`
	}{r.Path, r.Note, !r.Truncated, r.Limit, r.Truncated, rows})
}

// Reputation reads the reputation rows `jb intel` stored, as `jb db reputation` does.
// It is read-only: the store is opened as the dashboard opens it, which the engine
// enforces, a writer such as `jb watch` is not locked out, and a missing store is an
// error ("no evidence database at ...") and is never created. A store another process
// holds read-write is waited for (the lock wait of the store), then refused.
//
// caseDir may be empty, then opts.Config is the path of a config file. A nil error
// does not mean the answer is whole: check [ReputationResult.Complete].
func Reputation(ctx context.Context, caseDir string, opts ReputationOptions) (*ReputationResult, error) {
	limit := opts.Limit
	switch {
	case limit < 0 || limit > MaxReputationRows:
		return nil, usagef("limit %d is outside 1..%d (0 means %d)", limit, MaxReputationRows, DefaultReputationRows)
	case limit == 0:
		limit = DefaultReputationRows
	}
	if !opts.Since.IsZero() && !opts.Until.IsZero() && opts.Since.After(opts.Until) {
		return nil, usagef("since %s is after until %s", opts.Since.UTC().Format(time.RFC3339), opts.Until.UTC().Format(time.RFC3339))
	}
	if len(opts.Indicators) > MaxReputationIndicators {
		return nil, usagef("%d indicators: at most %d", len(opts.Indicators), MaxReputationIndicators)
	}
	var inds []string
	seen := map[string]bool{}
	for _, v := range opts.Indicators {
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil {
			return nil, usagef("%q is not an IP address", v)
		}
		if c := a.String(); !seen[c] { // the form `jb intel` stores
			seen[c] = true
			inds = append(inds, c)
		}
	}
	s, err := resolveStoreFor(caseDir, opts.Config, "intel")
	if err != nil {
		return nil, err
	}
	d, err := duckdb.OpenDashboardContext(ctx, s.path)
	switch {
	case errors.Is(err, duckdb.ErrLocked):
		return nil, fmt.Errorf("refusing: %w", err)
	case errors.Is(err, duckdb.ErrSchemaBehind):
		return nil, fmt.Errorf("open database: %w; any `jb hunt` or `jb watch` cycle migrates it, and so does `jb db prune --apply`", err)
	case err != nil:
		return nil, fmt.Errorf("open database read-only: %w", err)
	}
	defer d.Close()
	// One row more than the cap tells a cut from an exact fit.
	got, err := d.Reputation(ctx, core.ReputationFilter{Indicators: inds, Source: opts.Source, Since: opts.Since, Until: opts.Until,
		Latest: opts.Latest, Limit: limit + 1})
	if err != nil {
		return nil, fmt.Errorf("read reputation: %w", err)
	}
	res := &ReputationResult{Path: s.path, Note: IntelNote, Limit: limit, Notes: s.notes}
	if len(got) > limit {
		res.Truncated, got = true, got[:limit]
	}
	for _, x := range got {
		res.Rows = append(res.Rows, ReputationRow{Indicator: x.Indicator, Verdict: x.Verdict,
			Observed: x.Observed.UTC().Format(time.RFC3339), Source: x.Source})
	}
	return res, nil
}
