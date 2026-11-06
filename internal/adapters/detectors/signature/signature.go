// Package signature flags events that carry a marker no legitimate client sets: a
// header (or any other event field) a test harness adds to its own requests. It is
// product-agnostic: the field, the match and the key are configuration.
//
// WHAT A HIT MEANS. A header is text the sender chose. A hit shows that someone SENT
// the marker; it does not show who. Anyone who has seen the marker (in a report, a
// ticket, a screenshot) can send it, to frame a person or to test whether you watch
// for it. Treat a finding as "the marker was seen from these keys", a lead that needs
// other evidence before it names anyone, and never as attribution. The keys are the
// addresses the log carries, and behind a CDN or proxy an address may be an edge (see
// internal/adapters/detectors/newkey for why that is not a client).
//
// Rules, each of which answers a way this detector could mislead:
//
//   - Exactly one match mode: Present (the field exists on the event) or Equals (the
//     field is one of the listed values, compared exactly and case-sensitively).
//   - A current window with no event at all is core.ErrNoRecords, never a clean
//     result: a silent log is a blind detector, not proof nobody sent the marker.
//     Unless EmptyIsQuiet, which internal/config accepts only for a source that proves
//     its index alive. Events that exist but hold a value that is not text where the
//     field is looked up are unreadable; if every event is unreadable the answer is
//     ErrNoRecords even with EmptyIsQuiet.
//   - A window with events and no marker is a quiet answer: that is the normal state.
//   - The marker is something that should never exist, so there is no baseline: the
//     first sight is severity high. There is no comparison with the preceding window
//     and Tag is the detector name plus the marker and nothing else, so one ongoing
//     condition dedupes across runs.
//   - A finding states counts the detector made from the events read: events with the
//     marker, distinct keys, events with no usable key, distinct paths when PathField
//     is set, the first and last event time. It never prints a header value: in
//     Present mode a value appears only as piiguard.Hash (up to five), and in Equals
//     mode only the configured expected value (the one that matched), which the
//     operator wrote. A key that is personal data is refused unless HashKeys is set.
//
// The package imports the standard library and internal/core only (and piiguard).
package signature

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
)

const (
	defaultName = "signature"
	maxEquals   = 32
	maxValue    = 128
	maxKeysShow = 10
	maxHashes   = 5
)

var (
	nameRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	fieldRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.@-]{0,63}$`)
)

// Config selects the field to look at and how a marker is recognised.
type Config struct {
	Name string `yaml:"name"`
	// Field is the event field that holds the marker, for instance the field a mapper
	// fills from a request header (request_dump's header_fields).
	Field string `yaml:"field"`
	// Present: any event with the field is a hit (an empty value counts). Equals: only
	// an event whose field is exactly one of the values. Set one, not both.
	Present bool     `yaml:"present"`
	Equals  []string `yaml:"equals"`
	// KeyField says who sent the request, normally client_ip. Required.
	KeyField string `yaml:"key_field"`
	// PathField is optional; with it a finding counts the distinct paths hit.
	PathField  string   `yaml:"path_field"`
	IgnoreKeys []string `yaml:"ignore_keys"`
	HashKeys   bool     `yaml:"hash_keys"`
	// EmptyIsQuiet: see the package comment.
	EmptyIsQuiet bool `yaml:"empty_is_quiet"`
}

// Detector implements core.Detector.
type Detector struct {
	name   string
	cfg    Config
	equals map[string]struct{}
	order  []string // Equals in config order, unique
	ignore map[string]struct{}
}

var _ core.Detector = (*Detector)(nil)

// New validates c and applies the default name "signature".
func New(c Config) (*Detector, error) {
	if c.Name == "" {
		c.Name = defaultName
	}
	if !nameRE.MatchString(c.Name) {
		return nil, fmt.Errorf("signature: name %q must match %s", c.Name, nameRE)
	}
	if !fieldRE.MatchString(c.Field) {
		return nil, fmt.Errorf("signature: field %q is required and must match %s", c.Field, fieldRE)
	}
	if c.Present == (len(c.Equals) > 0) {
		return nil, errors.New("signature: set exactly one of present: true and equals: [...]")
	}
	if len(c.Equals) > maxEquals {
		return nil, fmt.Errorf("signature: equals has %d entries, at most %d", len(c.Equals), maxEquals)
	}
	if strings.TrimSpace(c.KeyField) == "" {
		return nil, errors.New("signature: key_field is required")
	}
	if !c.HashKeys && piiguard.Personal(c.KeyField) {
		return nil, fmt.Errorf("signature: key_field %q holds personal data and would appear in findings: set hash_keys: true, or key on client_ip", c.KeyField)
	}
	d := &Detector{name: c.Name, equals: map[string]struct{}{}, ignore: map[string]struct{}{}}
	for _, v := range c.Equals {
		if v == "" || len(v) > maxValue || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("signature: equals entries must be 1..%d characters on one line", maxValue)
		}
		if _, dup := d.equals[v]; !dup {
			d.equals[v] = struct{}{}
			d.order = append(d.order, v)
		}
	}
	for _, k := range c.IgnoreKeys {
		if k = strings.TrimSpace(k); k != "" {
			d.ignore[k] = struct{}{}
		}
	}
	c.Equals = append([]string(nil), c.Equals...)
	c.IgnoreKeys = append([]string(nil), c.IgnoreKeys...)
	d.cfg = c
	return d, nil
}

// Name returns the configured detector name.
func (d *Detector) Name() string { return d.name }

// Field returns the event field the detector reads.
func (d *Detector) Field() string { return d.cfg.Field }

// marker accumulates the hits of one marker (the field, or one Equals value).
type marker struct {
	events   int
	unkeyed  int
	keys     map[string]int
	paths    map[string]struct{}
	hashes   map[string]struct{}
	first    time.Time
	last     time.Time
	ignoredN int
}

// Detect reads the current window only. prev is accepted for the interface and is not
// read: a marker that should never exist needs no baseline.
func (d *Detector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	if cur == nil {
		return nil, fmt.Errorf("%s: nil event reader", d.name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seen, unreadable := 0, 0
	byMarker := map[string]*marker{}
	for ev, err := range cur.Events(ctx, w) {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		if err != nil {
			return nil, fmt.Errorf("%s: current window: %w", d.name, err)
		}
		seen++
		raw, has := ev.Fields[d.cfg.Field]
		var val string
		if has {
			s, isText := raw.(string)
			if !isText {
				unreadable++
				continue
			}
			val = s
		}
		if !has {
			continue
		}
		label := d.cfg.Field
		if !d.cfg.Present {
			if _, want := d.equals[val]; !want {
				continue
			}
			label = d.cfg.Field + "=" + val
		}
		key := ""
		if s, ok := ev.Fields[d.cfg.KeyField].(string); ok {
			key = strings.TrimSpace(s)
		}
		m := byMarker[label]
		if m == nil {
			m = &marker{keys: map[string]int{}, paths: map[string]struct{}{}, hashes: map[string]struct{}{}}
			byMarker[label] = m
		}
		if _, skip := d.ignore[key]; skip && key != "" {
			m.ignoredN++
			continue
		}
		m.events++
		if key == "" {
			m.unkeyed++
		} else {
			m.keys[key]++
		}
		if d.cfg.PathField != "" {
			if p, ok := ev.Fields[d.cfg.PathField].(string); ok && p != "" {
				if len(m.paths) < 10000 {
					m.paths[p] = struct{}{}
				}
			}
		}
		if d.cfg.Present {
			m.hashes[piiguard.Hash(val)] = struct{}{}
		}
		if !ev.Time.IsZero() {
			if m.first.IsZero() || ev.Time.Before(m.first) {
				m.first = ev.Time
			}
			if ev.Time.After(m.last) {
				m.last = ev.Time
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch {
	case seen == 0 && d.cfg.EmptyIsQuiet:
		return nil, nil
	case seen == 0:
		return nil, fmt.Errorf("%s: %w: current window had no events", d.name, core.ErrNoRecords)
	case unreadable == seen:
		return nil, fmt.Errorf("%s: %w: all %d events hold a %q that is not text", d.name, core.ErrNoRecords, seen, d.cfg.Field)
	}

	labels := make([]string, 0, len(byMarker))
	for l, m := range byMarker {
		if m.events > 0 {
			labels = append(labels, l)
		}
	}
	sort.Strings(labels)
	var out []core.Finding
	for _, l := range labels {
		m := byMarker[l]
		keys := make([]string, 0, len(m.keys))
		for k := range m.keys {
			keys = append(keys, piiguard.Shown(k, d.cfg.HashKeys))
		}
		sort.Strings(keys)
		shownKeys := keys
		if len(shownKeys) > maxKeysShow {
			shownKeys = shownKeys[:maxKeysShow]
		}
		hashes := make([]string, 0, len(m.hashes))
		for h := range m.hashes {
			hashes = append(hashes, h)
		}
		sort.Strings(hashes)
		if len(hashes) > maxHashes {
			hashes = hashes[:maxHashes]
		}
		detail := map[string]any{
			"marker_field":      d.cfg.Field,
			"mode":              map[bool]string{true: "present", false: "equals"}[d.cfg.Present],
			"events":            m.events,
			"distinct_keys":     len(m.keys),
			"keys":              shownKeys,
			"keys_truncated":    len(keys) > len(shownKeys),
			"unkeyed_events":    m.unkeyed,
			"ignored_events":    m.ignoredN,
			"events_in_window":  seen,
			"unreadable_events": unreadable,
			"first":             m.first.UTC().Format(time.RFC3339),
			"last":              m.last.UTC().Format(time.RFC3339),
			"key_field":         d.cfg.KeyField,
			"sent_not_proven":   "a hit shows the marker was sent, not who sent it",
		}
		if !d.cfg.Present {
			detail["expected_value"] = strings.TrimPrefix(l, d.cfg.Field+"=")
		} else {
			detail["distinct_values"] = len(m.hashes)
			detail["value_hashes"] = hashes
		}
		if d.cfg.PathField != "" {
			detail["distinct_paths"] = len(m.paths)
		}
		out = append(out, core.Finding{
			Detector: d.name,
			Tag:      d.name + ":" + l,
			Severity: core.SevHigh,
			Window:   w,
			Summary: fmt.Sprintf("marker %q was sent on %d requests from %d distinct keys (%d with no usable key), first %s, last %s; a header can be sent by anyone, so this shows the marker was sent, not who sent it",
				l, m.events, len(m.keys), m.unkeyed, m.first.UTC().Format(time.RFC3339), m.last.UTC().Format(time.RFC3339)),
			Detail: detail,
		})
	}
	return out, nil
}
