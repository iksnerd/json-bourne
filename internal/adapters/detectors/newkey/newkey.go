// Package newkey detects a key that appears in the current window with no
// history in the preceding window and goes straight to sensitive paths. It is
// deliberately product-agnostic: the key field, the path field and the list of
// sensitive paths are configuration, not code.
//
// The key is whatever you configure, usually a client address. CHOOSE IT WITH
// CARE: a CDN or load-balancer edge address is not a client. One edge carries
// many unrelated visitors and a visitor moves between edges, so "never seen
// before" and "seen N times" about an edge say nothing about any visitor, and
// grouping by it invents both findings and alibis. Key on a field that
// identifies the client (a forwarded client address your edge sets and you
// trust, a device or session identifier), and list your own infrastructure in
// IgnoreKeys. Nothing here identifies who is behind a key.
//
// Rules, each of which came from a real false result:
//
//   - Volume alone is not a signal. A client opening an application makes dozens
//     of ordinary calls a minute. A key is raised only when it is new (no event
//     at all, on any path, in the preceding window) AND makes at least MinHits
//     requests to SensitivePaths. Ordinary-path traffic from a new key is never
//     counted toward the hits.
//   - History is read from the preceding window of the same length, nothing
//     older, and any path counts: one earlier ordinary request makes a key
//     known. A longer memory belongs in a longer window, not in this detector.
//   - A current window with no event carrying a key is core.ErrNoRecords, never
//     a clean result. A preceding window with no keyed event at all is reported
//     (Detail["baseline_empty"]) and the severity drops one step: every key is
//     then new, and that is a missing baseline, not a finding about the key.
//   - An empty key, or one listed in IgnoreKeys, is never a suspect and never
//     counts as history.
//   - Every number in a Finding was counted from the events read. Tag is the
//     detector name plus the key and nothing else, so one ongoing condition
//     dedupes across runs.
//   - A key that is personal data never appears in a Finding. A key_field named
//     username, email or user id is refused unless HashKeys is set, and then the
//     key is shown only as piiguard.Hash (stable, so dedupe holds; unsalted, so
//     not secret). IgnoreKeys still takes the plain value.
//
// Scripted clients (optional). With UserAgentField and UserAgentMatches set, a
// sensitive request counts toward MinHits only when the event's user-agent field
// matches one of the patterns: the whole value, case-insensitive, with "*" as the one
// wildcard (so "curl/*" matches "curl/8.4.0" and "mycurl/1" is not matched). A pattern
// is never a substring test, and a pattern that is only "*" is refused because it
// matches everything. A user agent is chosen by the client, so this narrows a lead to
// the clients that announce themselves as scripts; a client that does not is not
// caught by it, and the key is still judged new only by its history. Requests that hit
// a sensitive path with another agent are counted apart in Detail.
//
// Paths are matched as case-insensitive substrings of the path field. Detail
// reports which configured entries were hit and how often, not the requested
// paths themselves.
//
// The package imports the standard library and internal/core only.
package newkey

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
	"github.com/iksnerd/json-bourne/internal/severityfloor"
)

const (
	defaultName    = "newkey"
	defaultMinHits = 3
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Config selects the event fields and thresholds. Zero values take the defaults
// documented on New.
type Config struct {
	Name           string   `yaml:"name"`
	KeyField       string   `yaml:"key_field"`
	PathField      string   `yaml:"path_field"`
	SensitivePaths []string `yaml:"sensitive_paths"`
	MinHits        int      `yaml:"min_hits"`
	IgnoreKeys     []string `yaml:"ignore_keys"`
	// HashKeys shows each key in a Finding as piiguard.Hash(key). Required when
	// KeyField is a personal field (username, email, user id).
	HashKeys bool `yaml:"hash_keys"`

	// EmptyIsQuiet makes a current window with nothing to judge a quiet answer
	// (no findings) instead of core.ErrNoRecords. Events that exist but cannot be
	// read (no usable key) are still an error: that is a blind detector, not a quiet one. Set it
	// only when every source the detector reads filters on the server and proves its
	// index alive; internal/config refuses it otherwise.
	EmptyIsQuiet bool `yaml:"empty_is_quiet"`

	// UserAgentField and UserAgentMatches select scripted clients; see the package
	// comment. Both or neither.
	UserAgentField   string   `yaml:"user_agent_field"`
	UserAgentMatches []string `yaml:"user_agent_matches"`

	// MinSeverity is a floor: high or critical. See internal/severityfloor.
	MinSeverity string `yaml:"min_severity"`
	// Note is carried in Detail["note"]; required with MinSeverity critical and
	// refused without MinSeverity.
	Note string `yaml:"note"`

	// History, when set, replaces the preceding-window baseline with a count of every
	// event of the key over a longer lookback, asked of the sources (RFC 0014). The
	// detector then runs only through DetectWithHistory.
	History *HistoryConfig `yaml:"history"`
}

// Limits on user_agent_matches.
const (
	maxUAPatterns     = 32
	maxUAPatternBytes = 128
	maxUABytes        = 1024 // a longer agent is not matched, never partly matched
)

// Detector implements core.Detector.
type Detector struct {
	name      string
	cfg       Config
	sensitive []string // lower-cased, unique, in config order
	ignore    map[string]struct{}
	uaRE      []*regexp.Regexp // anchored, case-insensitive; empty = no filter
	floor     severityfloor.Floor
}

var (
	_ core.Detector        = (*Detector)(nil)
	_ core.HistoryDetector = (*Detector)(nil)
)

// New validates c and applies defaults: Name "newkey", MinHits 3. KeyField,
// PathField and at least one SensitivePaths entry are required.
func New(c Config) (*Detector, error) {
	if c.Name == "" {
		c.Name = defaultName
	}
	if !nameRE.MatchString(c.Name) {
		return nil, fmt.Errorf("newkey: name %q must match %s", c.Name, nameRE)
	}
	if strings.TrimSpace(c.KeyField) == "" {
		return nil, errors.New("newkey: key_field is required")
	}
	if !c.HashKeys && piiguard.Personal(c.KeyField) {
		return nil, fmt.Errorf("newkey: key_field %q holds personal data and would appear in findings: set hash_keys: true, or key on client_ip", c.KeyField)
	}
	if strings.TrimSpace(c.PathField) == "" {
		return nil, errors.New("newkey: path_field is required")
	}
	if len(c.SensitivePaths) == 0 {
		return nil, errors.New("newkey: sensitive_paths is required")
	}
	if c.MinHits < 0 {
		return nil, fmt.Errorf("newkey: min_hits %d is negative", c.MinHits)
	}
	if c.MinHits == 0 {
		c.MinHits = defaultMinHits
	}
	uaRE, err := compileUAPatterns(c.UserAgentField, c.UserAgentMatches)
	if err != nil {
		return nil, err
	}
	floor, err := severityfloor.Parse(c.MinSeverity, c.Note, []core.Severity{core.SevHigh, core.SevCritical}, true)
	if err != nil {
		return nil, fmt.Errorf("newkey: %w", err)
	}
	hist, err := c.History.validated()
	if err != nil {
		return nil, err
	}
	c.History = hist
	d := &Detector{name: c.Name, uaRE: uaRE, floor: floor, ignore: make(map[string]struct{}, len(c.IgnoreKeys))}
	seen := map[string]struct{}{}
	for _, p := range c.SensitivePaths {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			return nil, errors.New("newkey: blank entry in sensitive_paths")
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			d.sensitive = append(d.sensitive, p)
		}
	}
	for _, k := range c.IgnoreKeys {
		if k = strings.TrimSpace(k); k != "" {
			d.ignore[k] = struct{}{}
		}
	}
	// Own the slices: the caller may reuse theirs.
	c.SensitivePaths = append([]string(nil), c.SensitivePaths...)
	c.IgnoreKeys = append([]string(nil), c.IgnoreKeys...)
	c.UserAgentMatches = append([]string(nil), c.UserAgentMatches...)
	d.cfg = c
	return d, nil
}

// compileUAPatterns turns each pattern into an anchored RE2 expression (linear time).
// Everything but "*" is literal.
func compileUAPatterns(field string, pats []string) ([]*regexp.Regexp, error) {
	if len(pats) == 0 && strings.TrimSpace(field) == "" {
		return nil, nil
	}
	if strings.TrimSpace(field) == "" || len(pats) == 0 {
		return nil, errors.New("newkey: user_agent_field and user_agent_matches go together")
	}
	if len(pats) > maxUAPatterns {
		return nil, fmt.Errorf("newkey: user_agent_matches has %d entries, at most %d", len(pats), maxUAPatterns)
	}
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
			return nil, errors.New("newkey: blank entry in user_agent_matches")
		case len(p) > maxUAPatternBytes:
			return nil, fmt.Errorf("newkey: user_agent_matches entry is over %d bytes", maxUAPatternBytes)
		case strings.Trim(p, "*") == "":
			return nil, fmt.Errorf("newkey: user_agent_matches entry %q matches every agent; remove the filter instead", p)
		}
		parts := strings.Split(p, "*")
		for i := range parts {
			parts[i] = regexp.QuoteMeta(parts[i])
		}
		re, err := regexp.Compile("(?is)^" + strings.Join(parts, ".*") + "$")
		if err != nil {
			return nil, fmt.Errorf("newkey: user_agent_matches entry %q: %v", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// scripted reports whether ev's user agent matches a pattern. No filter: always true.
func (d *Detector) scripted(ev core.Event) bool {
	if len(d.uaRE) == 0 {
		return true
	}
	ua, _ := ev.Fields[d.cfg.UserAgentField].(string)
	if ua == "" || len(ua) > maxUABytes {
		return false
	}
	for _, re := range d.uaRE {
		if re.MatchString(ua) {
			return true
		}
	}
	return false
}

// Name returns the configured detector name.
func (d *Detector) Name() string { return d.name }

type keyTally struct {
	events int
	hits   int            // events that matched a sensitive entry (and the agent filter, if any)
	anyUA  int            // sensitive requests of any agent; differs from hits only with a filter
	byPath map[string]int // per configured entry
}

// tally is what one window's events add up to.
type tally struct {
	seen    int
	keyed   int // events with a usable key
	unkeyed int // no key, or not text
	ignored int
	keys    map[string]*keyTally // see scan
}

// scan streams r once. With only == nil it tracks every key; otherwise only the
// keys in only, which bounds memory for the baseline window. keyed counts all
// usable-key events either way.
func (d *Detector) scan(ctx context.Context, r core.EventReader, w core.Window, only map[string]struct{}) (tally, error) {
	t := tally{keys: map[string]*keyTally{}}
	for ev, err := range r.Events(ctx, w) {
		if cerr := ctx.Err(); cerr != nil {
			return t, cerr
		}
		if err != nil {
			return t, err
		}
		t.seen++
		key := keyOf(ev.Fields[d.cfg.KeyField])
		if key == "" {
			t.unkeyed++
			continue
		}
		if _, skip := d.ignore[key]; skip {
			t.ignored++
			continue
		}
		t.keyed++
		if only != nil {
			if _, want := only[key]; !want {
				continue
			}
		}
		kt := t.keys[key]
		if kt == nil {
			kt = &keyTally{}
			t.keys[key] = kt
		}
		kt.events++
		p, _ := ev.Fields[d.cfg.PathField].(string)
		if p == "" {
			continue
		}
		p = strings.ToLower(p)
		hit := false
		counted := d.scripted(ev)
		for _, s := range d.sensitive {
			if strings.Contains(p, s) {
				if counted {
					if kt.byPath == nil {
						kt.byPath = map[string]int{}
					}
					kt.byPath[s]++
				}
				hit = true
			}
		}
		if hit {
			kt.anyUA++
			if counted {
				kt.hits++
			}
		}
	}
	// A reader that stops quietly on cancellation would otherwise pass for a
	// short window.
	if err := ctx.Err(); err != nil {
		return t, err
	}
	return t, nil
}

// Detect looks in cur (window w) for keys absent from prev (w.Previous()) that
// hit sensitive paths.
//
// A detector configured with History cannot run this way: it returns an error that
// names the missing history, and never falls back to the preceding window.
func (d *Detector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	if d.cfg.History != nil {
		return nil, fmt.Errorf("%s: history is configured but was not provided: this detector must run through DetectWithHistory, and does not fall back to the preceding window", d.name)
	}
	return d.detectPreceding(ctx, cur, prev, w)
}

func (d *Detector) detectPreceding(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	if cur == nil || prev == nil {
		return nil, fmt.Errorf("%s: nil event reader", d.name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ct, err := d.scan(ctx, cur, w, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: current window: %w", d.name, err)
	}
	if ct.keyed == 0 && d.cfg.EmptyIsQuiet && ct.unkeyed == 0 {
		return nil, nil // no event, or only ignored keys; nothing unreadable
	}
	if ct.keyed == 0 {
		return nil, fmt.Errorf("%s: %w: current window had %d events, %d without a usable %q, %d from ignored keys",
			d.name, core.ErrNoRecords, ct.seen, ct.unkeyed, d.cfg.KeyField, ct.ignored)
	}
	cands := map[string]struct{}{}
	for k, kt := range ct.keys {
		if kt.hits >= d.cfg.MinHits {
			cands[k] = struct{}{}
		}
	}
	if len(cands) == 0 {
		return nil, nil
	}
	base := w.Previous()
	pt, err := d.scan(ctx, prev, base, cands)
	if err != nil {
		// A failed baseline read is not an empty baseline.
		return nil, fmt.Errorf("%s: preceding window: %w", d.name, err)
	}
	baselineEmpty := pt.keyed == 0

	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []core.Finding
	for _, k := range keys {
		kt := ct.keys[k]
		prevEvents := 0
		if kp := pt.keys[k]; kp != nil {
			prevEvents = kp.events
		}
		if prevEvents > 0 {
			continue // known: it was here before
		}
		byPath := make(map[string]int, len(kt.byPath))
		for p, n := range kt.byPath {
			byPath[p] = n
		}
		sev := core.SevHigh
		shown := piiguard.Shown(k, d.cfg.HashKeys)
		var summary string
		if baselineEmpty {
			sev-- // one step down: every key is new against an empty window
			summary = fmt.Sprintf("key %q made %d requests to sensitive paths (%d events in all); no preceding window to compare",
				shown, kt.hits, kt.events)
		} else {
			summary = fmt.Sprintf("key %q has no events in the preceding window and made %d requests to sensitive paths (%d events in all)",
				shown, kt.hits, kt.events)
		}
		detail := map[string]any{
			"key_field":              d.cfg.KeyField,
			"key":                    shown,
			"key_cur_events":         kt.events,
			"key_cur_sensitive_hits": kt.hits,
			"sensitive_paths_hit":    byPath,
			"key_prev_events":        0,
			"min_hits":               d.cfg.MinHits,
			"baseline_empty":         baselineEmpty,
			"pop_cur_events":         ct.keyed,
			"pop_cur_keys":           countKeys(ct),
			"pop_prev_events":        pt.keyed,
			"unkeyed_cur":            ct.unkeyed,
			"ignored_cur":            ct.ignored,
		}
		if len(d.uaRE) > 0 {
			detail["user_agent_filter"] = true
			detail["key_cur_sensitive_any_agent"] = kt.anyUA
		}
		sev = d.floor.Apply(sev, detail) // after the empty-baseline drop; can only raise
		out = append(out, core.Finding{
			Detector: d.name,
			Tag:      d.name + ":" + shown,
			Severity: sev,
			Window:   w,
			Baseline: base,
			Summary:  summary,
			Detail:   detail,
		})
	}
	return out, nil
}

// countKeys is the number of distinct usable keys in the current window.
func countKeys(t tally) int { return len(t.keys) }

// keyOf returns the grouping key, or "" when the field is absent or not text.
func keyOf(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case fmt.Stringer:
		return strings.TrimSpace(x.String())
	}
	return ""
}
