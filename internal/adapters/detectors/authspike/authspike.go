// Package authspike detects a credential-stuffing or password-spray style spike
// on an authentication endpoint. It is deliberately product-agnostic: the event
// fields that carry the client key, the HTTP status and the request path are
// configuration, not code.
//
// Rules, each of which came from a real false result:
//
//   - A raw count means nothing. A key is judged on its failure share
//     (failures/total) against the same-length preceding window, and against the
//     population in the current window.
//   - A volume spike with no failures is a busy platform. The failure share must
//     rise by at least MinFailureShareRise (absolute) and the key must have at
//     least MinEvents parsable events.
//   - A current window with no parsable events is core.ErrNoRecords, never an
//     empty clean result. An empty preceding window is reported
//     (Detail["baseline_empty"]) and the severity drops one step.
//   - An empty key, or one listed in IgnoreKeys, is never a suspect.
//   - A failure is a numeric HTTP status in FailStatuses or, for a log that has no
//     status (Keycloak events carry a type and an error string), a text value in
//     FailValues. Exactly one of the two is configured. In text mode a missing or
//     non-text value is unparsable, never a success.
//   - A key that is personal data (a username, an address) never appears in a
//     Finding: HashKeys replaces it with a short digest in the Tag, Summary and
//     Detail, and a key_field named username or email without HashKeys is refused.
//   - A window with failures and no success event at all (a deployment that logs
//     errors but not successes) has every share at 100%, so the comparison with the
//     population cannot tell a spray from the normal state. In text mode the finding
//     is then kept rather than dropped, Detail["success_events_cur"] is 0, the summary
//     says the share is not meaningful, and the severity is one step lower. With
//     HTTP statuses the same window is an outage and stays quiet. The count is in
//     every finding.
//   - Every number in a Finding was counted from the events read.
//   - Tag is detector name plus key and nothing else, so one ongoing condition
//     dedupes across runs.
//   - A spray that continues into the next window has a high share in the
//     baseline, so no rise: the rising rule alone goes quiet while the attack
//     goes on, and a quiet detector looks like a clean platform. A key that is
//     not raised as rising is therefore also reported as sustained (one step
//     lower severity, tag suffix ":sustained") when it fails at least
//     SustainedMinShare of the time and exceeds the whole population by at
//     least MinFailureShareRise. One key yields one finding per call; the
//     rising one wins.
//
// The package imports the standard library and internal/core only.
package authspike

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
)

const (
	defaultName          = "authspike"
	defaultMinEvents     = 20
	defaultMinRise       = 0.20
	defaultSustained     = 0.5
	minStatus, maxStatus = 100, 599

	// emptyBaselineMinShare applies only when there is no preceding data at all,
	// so no rise can be computed and none is invented: the key must then be
	// failing a majority of the time to be raised.
	emptyBaselineMinShare = 0.5

	// epsilon absorbs float rounding at the threshold (0.6-0.4 is not 0.2).
	epsilon = 1e-9
)

// noSuccessNote is appended to the summary of a finding raised in a window that holds
// failures and no success event.
const noSuccessNote = "no successful events were logged in this window; the failure share is not meaningful"

// Config selects the event fields and thresholds. Zero values take the defaults
// documented on New.
type Config struct {
	Name                string   `yaml:"name"`
	KeyField            string   `yaml:"key_field"`
	StatusField         string   `yaml:"status_field"`
	FailStatuses        []int    `yaml:"fail_statuses"`
	FailValues          []string `yaml:"fail_values"`
	HashKeys            bool     `yaml:"hash_keys"`
	PathField           string   `yaml:"path_field"`
	PathContains        string   `yaml:"path_contains"`
	MinEvents           int      `yaml:"min_events"`
	MinFailureShareRise float64  `yaml:"min_failure_share_rise"`
	IgnoreKeys          []string `yaml:"ignore_keys"`

	// SustainedMinShare is the failure share a key must hold in the current
	// window to be reported as a continuing spray. Default 0.5.
	SustainedMinShare float64 `yaml:"sustained_min_share"`
	// DisableSustained turns the continuing-spray finding off.
	DisableSustained bool `yaml:"disable_sustained"`

	// EmptyIsQuiet makes a current window with nothing to judge a quiet answer
	// (no findings) instead of core.ErrNoRecords. Events that exist but cannot be
	// read (a status that is not an HTTP status or a failure value) are still an error: that is a blind detector, not a quiet one. Set it
	// only when every source the detector reads filters on the server and proves its
	// index alive; internal/config refuses it otherwise.
	EmptyIsQuiet bool `yaml:"empty_is_quiet"`
}

// Detector implements core.Detector.
type Detector struct {
	name   string
	cfg    Config
	fail   map[int]struct{}
	failV  map[string]struct{} // text mode: non-nil when FailValues is set
	ignore map[string]struct{}
}

var _ core.Detector = (*Detector)(nil)

// New validates c and applies defaults: Name "authspike", FailStatuses 401 and
// 403, MinEvents 20, MinFailureShareRise 0.20, SustainedMinShare 0.5. KeyField and StatusField are
// required. PathContains needs PathField.
func New(c Config) (*Detector, error) {
	if strings.TrimSpace(c.KeyField) == "" {
		return nil, errors.New("authspike: key_field is required")
	}
	if strings.TrimSpace(c.StatusField) == "" {
		return nil, errors.New("authspike: status_field is required")
	}
	if c.PathContains != "" && c.PathField == "" {
		return nil, errors.New("authspike: path_contains needs path_field")
	}
	if c.MinEvents < 0 {
		return nil, fmt.Errorf("authspike: min_events %d is negative", c.MinEvents)
	}
	if c.MinEvents == 0 {
		c.MinEvents = defaultMinEvents
	}
	if math.IsNaN(c.MinFailureShareRise) || c.MinFailureShareRise < 0 || c.MinFailureShareRise > 1 {
		return nil, fmt.Errorf("authspike: min_failure_share_rise %v outside (0,1]", c.MinFailureShareRise)
	}
	if c.MinFailureShareRise == 0 {
		c.MinFailureShareRise = defaultMinRise
	}
	if math.IsNaN(c.SustainedMinShare) || c.SustainedMinShare < 0 || c.SustainedMinShare > 1 {
		return nil, fmt.Errorf("authspike: sustained_min_share %v outside (0,1]", c.SustainedMinShare)
	}
	if c.SustainedMinShare == 0 {
		c.SustainedMinShare = defaultSustained
	}
	if len(c.FailStatuses) > 0 && len(c.FailValues) > 0 {
		return nil, errors.New("authspike: set fail_statuses or fail_values, not both")
	}
	if !c.HashKeys && piiguard.Personal(c.KeyField) {
		return nil, fmt.Errorf("authspike: key_field %q holds personal data and would appear in findings: set hash_keys: true, or key on client_ip", c.KeyField)
	}
	if len(c.FailValues) == 0 && len(c.FailStatuses) == 0 {
		c.FailStatuses = []int{401, 403}
	}
	if c.Name == "" {
		c.Name = defaultName
	}
	d := &Detector{
		name:   c.Name,
		fail:   make(map[int]struct{}, len(c.FailStatuses)),
		ignore: make(map[string]struct{}, len(c.IgnoreKeys)),
	}
	for _, s := range c.FailStatuses {
		if s < minStatus || s > maxStatus {
			return nil, fmt.Errorf("authspike: fail status %d is not an HTTP status", s)
		}
		d.fail[s] = struct{}{}
	}
	if len(c.FailValues) > 0 {
		d.failV = make(map[string]struct{}, len(c.FailValues))
		for _, v := range c.FailValues {
			if strings.TrimSpace(v) == "" {
				return nil, errors.New("authspike: blank fail value")
			}
			d.failV[v] = struct{}{}
		}
	}
	for _, k := range c.IgnoreKeys {
		if k = strings.TrimSpace(k); k != "" {
			d.ignore[k] = struct{}{}
		}
	}
	// Own the slices: the caller may reuse theirs.
	c.FailStatuses = append([]int(nil), c.FailStatuses...)
	c.FailValues = append([]string(nil), c.FailValues...)
	c.IgnoreKeys = append([]string(nil), c.IgnoreKeys...)
	d.cfg = c
	return d, nil
}

// Name returns the configured detector name.
func (d *Detector) Name() string { return d.name }

type counts struct{ total, fail int }

func (c counts) share() float64 { return float64(c.fail) / float64(c.total) }

// tally is what one window's events add up to. Only counters are kept.
type tally struct {
	pop        counts            // every parsable on-path event, any key
	keys       map[string]counts // suspects only: never empty or ignored keys
	seen       int
	offPath    int
	unparsable int
}

// scan streams r once. With only == nil it tracks every eligible key; otherwise
// only the keys in only, which bounds memory for the baseline window.
func (d *Detector) scan(ctx context.Context, r core.EventReader, w core.Window, only map[string]struct{}) (tally, error) {
	t := tally{keys: map[string]counts{}}
	for ev, err := range r.Events(ctx, w) {
		if cerr := ctx.Err(); cerr != nil {
			return t, cerr
		}
		if err != nil {
			return t, err
		}
		t.seen++
		if d.cfg.PathContains != "" {
			p, _ := ev.Fields[d.cfg.PathField].(string)
			if !strings.Contains(p, d.cfg.PathContains) {
				t.offPath++
				continue
			}
		}
		failed, ok := d.judge(ev.Fields[d.cfg.StatusField])
		if !ok {
			t.unparsable++
			continue
		}
		t.pop.total++
		if failed {
			t.pop.fail++
		}
		key := keyOf(ev.Fields[d.cfg.KeyField])
		if key == "" {
			continue
		}
		if _, skip := d.ignore[key]; skip {
			continue
		}
		if only != nil {
			if _, want := only[key]; !want {
				continue
			}
		}
		c := t.keys[key]
		c.total++
		if failed {
			c.fail++
		}
		t.keys[key] = c
	}
	// A reader that stops quietly on cancellation would otherwise pass for a
	// short window.
	if err := ctx.Err(); err != nil {
		return t, err
	}
	return t, nil
}

// Detect compares the key failure shares of cur (window w) with prev (w.Previous()).
func (d *Detector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
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
	if ct.pop.total == 0 && d.cfg.EmptyIsQuiet && ct.unparsable == 0 {
		return nil, nil // no on-path event, and nothing unreadable
	}
	if ct.pop.total == 0 {
		return nil, fmt.Errorf("%s: %w: current window had %d events, %d off-path, %d with unparsable status",
			d.name, core.ErrNoRecords, ct.seen, ct.offPath, ct.unparsable)
	}
	cands := map[string]struct{}{}
	for k, c := range ct.keys {
		if c.total >= d.cfg.MinEvents {
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

	baselineEmpty := pt.pop.total == 0
	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []core.Finding
	for _, rawKey := range keys {
		k := d.shown(rawKey)
		kc, kp := ct.keys[rawKey], pt.keys[rawKey]
		// The rising finding needs the key to fail more than the population it
		// sits in; if everyone fails, the platform is down, not sprayed.
		popOK := kc.fail*ct.pop.total > ct.pop.fail*kc.total
		// A text-mode window (Keycloak) with failures and no success at all is a
		// deployment that logs errors but not successes: nothing to compare a key
		// against, every share is 100%, and the check above would drop every finding,
		// a quiet result for a platform that may be under spray. Keep the finding, say
		// so, and lower it a step. With HTTP statuses the same window is an outage (a
		// platform that answers 2xx normally is answering none), which stays quiet.
		successes := ct.pop.total - ct.pop.fail
		noSuccess := successes == 0 && ct.pop.fail > 0
		if noSuccess && d.failV != nil {
			popOK = true
		}
		detail := map[string]any{
			"key_field":              d.cfg.KeyField,
			"key":                    k,
			"key_cur_events":         kc.total,
			"key_cur_failures":       kc.fail,
			"key_cur_failure_share":  kc.share(),
			"key_prev_events":        kp.total,
			"key_prev_failures":      kp.fail,
			"pop_cur_events":         ct.pop.total,
			"pop_cur_failures":       ct.pop.fail,
			"pop_cur_failure_share":  ct.pop.share(),
			"pop_prev_events":        pt.pop.total,
			"pop_prev_failures":      pt.pop.fail,
			"min_events":             d.cfg.MinEvents,
			"min_failure_share_rise": d.cfg.MinFailureShareRise,
			"baseline_empty":         baselineEmpty,
			"key_baseline_empty":     kp.total == 0,
			"unparsable_cur":         ct.unparsable,
			"unparsable_prev":        pt.unparsable,
			"success_events_cur":     successes,
		}
		if kp.total > 0 {
			detail["key_prev_failure_share"] = kp.share()
		}
		if !baselineEmpty {
			detail["pop_prev_failure_share"] = pt.pop.share()
		}

		var raised bool
		var summary string
		switch {
		case kp.total > 0:
			rise := kc.share() - kp.share()
			detail["baseline_source"], detail["failure_share_rise"] = "key", rise
			raised = rise >= d.cfg.MinFailureShareRise-epsilon
			summary = fmt.Sprintf("failure share for %q rose from %.1f%% (%d/%d) to %.1f%% (%d/%d)",
				k, 100*kp.share(), kp.fail, kp.total, 100*kc.share(), kc.fail, kc.total)
		case !baselineEmpty:
			// New key: its own history is empty, so the population's is the
			// only honest reference. Flagged in Detail.
			rise := kc.share() - pt.pop.share()
			detail["baseline_source"], detail["failure_share_rise"] = "population", rise
			raised = rise >= d.cfg.MinFailureShareRise-epsilon
			summary = fmt.Sprintf("new key %q fails %.1f%% (%d/%d) against a %.1f%% (%d/%d) population baseline",
				k, 100*kc.share(), kc.fail, kc.total, 100*pt.pop.share(), pt.pop.fail, pt.pop.total)
		default:
			detail["baseline_source"] = "none"
			raised = kc.share() >= emptyBaselineMinShare
			summary = fmt.Sprintf("key %q fails %.1f%% (%d/%d); no preceding window to compare",
				k, 100*kc.share(), kc.fail, kc.total)
		}
		if popOK && raised {
			sev := core.SevHigh
			if baselineEmpty {
				sev-- // one step down: nothing to compare against
			}
			if noSuccess {
				sev-- // one step down: the failure share is not meaningful
				summary += "; " + noSuccessNote
			}
			out = append(out, core.Finding{
				Detector: d.name,
				Tag:      d.name + ":" + k,
				Severity: sev,
				Window:   w,
				Baseline: base,
				Summary:  summary,
				Detail:   detail,
			})
			continue // one key, one finding per call: rising wins
		}
		if d.cfg.DisableSustained || kc.share() < d.cfg.SustainedMinShare-epsilon {
			continue
		}
		over := kc.share() - ct.pop.share()
		if over < d.cfg.MinFailureShareRise-epsilon {
			continue // everyone fails: an outage, not a spray
		}
		detail["sustained"] = true
		detail["sustained_min_share"] = d.cfg.SustainedMinShare
		detail["key_over_population_share"] = over
		summary = fmt.Sprintf("key %q is still failing %.1f%% (%d/%d) against %.1f%% (%d/%d) for all keys: continuing, not new",
			k, 100*kc.share(), kc.fail, kc.total, 100*ct.pop.share(), ct.pop.fail, ct.pop.total)
		if kp.total > 0 {
			summary += fmt.Sprintf("; preceding window %.1f%% (%d/%d)", 100*kp.share(), kp.fail, kp.total)
		}
		out = append(out, core.Finding{
			Detector: d.name,
			Tag:      d.name + ":" + k + ":sustained",
			Severity: core.SevActivity,
			Window:   w,
			Baseline: base,
			Summary:  summary,
			Detail:   detail,
		})
	}
	return out, nil
}

// judge says whether the event's status field marks a failure, and false in the
// second result when the field cannot be read in the configured mode.
func (d *Detector) judge(v any) (failed, ok bool) {
	if d.failV != nil {
		s, isText := v.(string)
		if !isText || s == "" {
			return false, false
		}
		_, failed = d.failV[s]
		return failed, true
	}
	status, ok := parseStatus(v)
	if !ok {
		return false, false
	}
	_, failed = d.fail[status]
	return failed, true
}

// shown is the key as it may appear in a Finding.
func (d *Detector) shown(k string) string {
	return piiguard.Shown(k, d.cfg.HashKeys)
}

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

// parseStatus accepts int, float64 (as JSON decodes numbers) and string forms.
// Anything else, a non-integer, or a value outside 100..599 is unparsable.
func parseStatus(v any) (int, bool) {
	var n int
	switch x := v.(type) {
	case int:
		n = x
	case int32:
		n = int(x)
	case int64:
		if x < minStatus || x > maxStatus {
			return 0, false
		}
		n = int(x)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x != math.Trunc(x) || x < minStatus || x > maxStatus {
			return 0, false
		}
		n = int(x)
	case json.Number:
		return parseStatus(string(x))
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0, false
		}
		n = i
	default:
		return 0, false
	}
	if n < minStatus || n > maxStatus {
		return 0, false
	}
	return n, true
}
