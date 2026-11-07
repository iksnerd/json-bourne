package newkey

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
)

// History limits (RFC 0014).
const (
	maxLookback          = 31 * 24 * time.Hour
	defaultMaxCandidates = 50
	maxMaxCandidates     = 100
)

// HistoryConfig replaces the preceding-window baseline with a count of every event of a
// candidate key over [window.From - Lookback, window.From), asked of the sources. A key
// with at least MinEvents events is known.
type HistoryConfig struct {
	Lookback      time.Duration `yaml:"lookback"`
	MinEvents     int           `yaml:"min_events"`
	MaxCandidates int           `yaml:"max_candidates"`
}

// validated returns a copy with the default applied, or an error. nil stays nil.
func (h *HistoryConfig) validated() (*HistoryConfig, error) {
	if h == nil {
		return nil, nil
	}
	c := *h
	switch {
	case c.Lookback <= 0:
		return nil, errors.New("newkey: history.lookback is required and must be positive (for example 168h)")
	case c.Lookback > maxLookback:
		return nil, fmt.Errorf("newkey: history.lookback %s is over the limit of %s", c.Lookback, maxLookback)
	case c.MinEvents < 1:
		return nil, errors.New("newkey: history.min_events is required and must be 1 or more")
	case c.MaxCandidates < 0 || c.MaxCandidates > maxMaxCandidates:
		return nil, fmt.Errorf("newkey: history.max_candidates %d is outside 1..%d", c.MaxCandidates, maxMaxCandidates)
	}
	if c.MaxCandidates == 0 {
		c.MaxCandidates = defaultMaxCandidates
	}
	return &c, nil
}

const maxProbeKeyBytes = 256

// safeProbeKey mirrors the character set the Kibana source accepts (letters, digits and
// . : @ _ -, 1 to 256 bytes). The source refuses the same keys as a second line; the
// detector filters first so one hostile key cannot fail the request for the rest.
func safeProbeKey(k string) bool {
	if k == "" || len(k) > maxProbeKeyBytes {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == ':', c == '@', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// modeReporter is implemented by a KeyHistory that knows how its sources match a key
// ("term" or "phrase"). The finding records it, because a phrase can over-count.
type modeReporter interface{ MatchMode() string }

// DetectWithHistory is Detect with a KeyHistory (core.HistoryDetector). Without a
// History block it is Detect and h is not used.
//
// A candidate is a key that meets MinHits on the sensitive paths and is not ignored.
// Candidates are cut at MaxCandidates by hits descending then key ascending; the rest
// are not judged. A candidate whose count over the lookback is under MinEvents is a
// finding. If the count cannot be read, or candidates were cut, the findings already
// proven are kept and the error names how many candidates were not judged.
func (d *Detector) DetectWithHistory(ctx context.Context, cur, prev core.EventReader, w core.Window, h core.KeyHistory) ([]core.Finding, error) {
	hc := d.cfg.History
	if hc == nil {
		return d.detectPreceding(ctx, cur, prev, w)
	}
	if cur == nil {
		return nil, fmt.Errorf("%s: nil event reader", d.name)
	}
	if h == nil {
		return nil, fmt.Errorf("%s: history is configured but was not provided", d.name)
	}
	if hc.Lookback <= w.Duration() {
		return nil, core.Usagef("%s: history.lookback %s must be longer than the window (%s)", d.name, hc.Lookback, w.Duration())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ct, err := d.scan(ctx, cur, w, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: current window: %w", d.name, err)
	}
	if ct.keyed == 0 && d.cfg.EmptyIsQuiet && ct.unkeyed == 0 {
		return nil, nil
	}
	if ct.keyed == 0 {
		return nil, fmt.Errorf("%s: %w: current window had %d events, %d without a usable %q, %d from ignored keys",
			d.name, core.ErrNoRecords, ct.seen, ct.unkeyed, d.cfg.KeyField, ct.ignored)
	}
	cands := make([]string, 0, len(ct.keys))
	for k, kt := range ct.keys {
		if kt.hits >= d.cfg.MinHits {
			cands = append(cands, k)
		}
	}
	if len(cands) == 0 {
		return nil, nil
	}
	sort.Slice(cands, func(i, j int) bool {
		hi, hj := ct.keys[cands[i]].hits, ct.keys[cands[j]].hits
		if hi != hj {
			return hi > hj
		}
		return cands[i] < cands[j]
	})
	// A key comes from traffic the attacker controls. An unsafe key is refused alone and
	// before the cut, so it can neither fail the request for the others nor push a real
	// candidate out of max_candidates. It is counted as not judged.
	safe := cands[:0:0]
	for _, k := range cands {
		if safeProbeKey(k) {
			safe = append(safe, k)
		}
	}
	refused := len(cands) - len(safe)
	judged := safe
	cut := 0
	if len(judged) > hc.MaxCandidates {
		cut = len(judged) - hc.MaxCandidates
		judged = judged[:hc.MaxCandidates]
	}

	base := core.Window{From: w.From.Add(-hc.Lookback), To: w.From}
	// The probe takes the plain key. Nothing below puts it in an error.
	counts, cerr := h.Counts(ctx, append([]string(nil), judged...), base)
	if cerr != nil {
		return nil, fmt.Errorf("%s: history probe failed, %d candidate(s) not judged: %w", d.name, len(cands), cerr)
	}
	mode := ""
	if mr, ok := h.(modeReporter); ok {
		mode = mr.MatchMode()
	}

	keys := make([]string, 0, len(judged))
	missing := 0
	for _, k := range judged {
		if _, ok := counts[k]; !ok {
			missing++
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []core.Finding
	for _, k := range keys {
		n := counts[k]
		if n >= int64(hc.MinEvents) {
			continue // known
		}
		kt := ct.keys[k]
		byPath := make(map[string]int, len(kt.byPath))
		for p, c := range kt.byPath {
			byPath[p] = c
		}
		shown := piiguard.Shown(k, d.cfg.HashKeys)
		detail := map[string]any{
			"key_field":              d.cfg.KeyField,
			"key":                    shown,
			"key_cur_events":         kt.events,
			"key_cur_sensitive_hits": kt.hits,
			"sensitive_paths_hit":    byPath,
			"min_hits":               d.cfg.MinHits,
			"history_lookback":       hc.Lookback.String(),
			"history_count":          n,
			"history_min_events":     hc.MinEvents,
			"history_mode":           mode,
			"pop_cur_events":         ct.keyed,
			"pop_cur_keys":           countKeys(ct),
			"unkeyed_cur":            ct.unkeyed,
			"ignored_cur":            ct.ignored,
		}
		if len(d.uaRE) > 0 {
			detail["user_agent_filter"] = true
			detail["key_cur_sensitive_any_agent"] = kt.anyUA
		}
		sev := d.floor.Apply(core.SevHigh, detail)
		out = append(out, core.Finding{
			Detector: d.name,
			Tag:      d.name + ":" + shown,
			Severity: sev,
			Window:   w,
			Baseline: base,
			Summary: fmt.Sprintf("key %q has %d events of any kind in the %s before the window (fewer than %d) and made %d requests to sensitive paths (%d events in all)",
				shown, n, hc.Lookback, hc.MinEvents, kt.hits, kt.events),
			Detail: detail,
		})
	}
	if notJudged := cut + missing + refused; notJudged > 0 {
		cause := fmt.Sprintf("only the %d highest-hit candidates are judged (history.max_candidates)", hc.MaxCandidates)
		switch {
		case refused > 0:
			cause = fmt.Sprintf("%d candidate key(s) are over %d bytes or use characters outside letters, digits and . : @ _ - and were not sent", refused, maxProbeKeyBytes)
		case missing > 0:
			cause = "the history answer lacked a count for a candidate"
		}
		return out, fmt.Errorf("%s: history incomplete, %d candidate(s) not judged: %s", d.name, notJudged, cause)
	}
	return out, nil
}
