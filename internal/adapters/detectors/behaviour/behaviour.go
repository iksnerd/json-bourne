// Package behaviour detects activity by WHAT is done, not by who claims to do
// it. A user-agent string is chosen by the client and rotates freely; the
// request path, method and status are what the client actually asked the
// platform to do. The detector is product-agnostic: the actions, the event
// fields and every threshold are configuration, not code.
//
// An action is a named matcher (path, optionally method, status set and field
// equalities) plus a class:
//
//   - rare: the platform's own baseline is near zero (a device-code request, an
//     account creation). Any occurrence in the current window at or above the
//     action's MinEvents is notable, whatever the baseline holds. Detail always
//     carries the preceding window's count beside the current one.
//   - common: a large legitimate baseline (a token endpoint carries service
//     traffic all day). A count means nothing here. Only the failure share
//     (failures/total) moving against the same-length preceding window is
//     raised, by the authspike rule: it must rise by at least
//     MinFailureShareRise (absolute) and the action needs MinEvents events.
//
// Rules, each of which came from a real false result:
//
//   - A matcher is exact or anchored, never an unanchored substring. A path is
//     compared whole, with the query string and one trailing slash removed;
//     "/signup" does not match "/signup/form". A pattern is wrapped in ^(?:...)$
//     before it is compiled. Field equalities and patterns are whole-value too.
//   - Infrastructure is never a suspect. Events whose key is in IgnoreKeys, or
//     whose user agent contains one of IgnoreUserAgents (case-insensitive), are
//     counted as ignored and take no part in any count. Prefer IgnoreKeys (the
//     gateway's address): a user-agent substring can be forged by a client to
//     hide, which is why it is only an accepted, reported trade-off. A gateway
//     once reported itself as activity from three requests of its own.
//   - A raw count alone is never a finding for a common action.
//   - The key is whatever KeyField names. A CDN or load-balancer edge address is
//     not a client: one edge carries many unrelated visitors. A rare-action
//     finding states how many distinct keys took part (keys_cur), so "one
//     client" and "an edge relaying many" are told apart by choosing a key field
//     that identifies the client. Nothing here identifies who is behind a key.
//   - A current window with no judged event (parsable path, not ignored) is
//     core.ErrNoRecords, never a clean result. A preceding window with no judged
//     event is reported (Detail["baseline_empty"]) and the severity drops one
//     step. A failed read of the preceding window is an error, not an empty one.
//   - Every number in a Finding was counted from the events read, in both
//     windows. Tag is the detector name plus the action name and nothing else,
//     so one ongoing condition dedupes across runs.
//   - An event is judged against every action independently: one request may
//     count toward several actions if their matchers overlap.
//
// A key that is personal data never appears in a Finding. A key_field named
// username, email or user id is refused unless HashKeys is set, and then the only
// place a key is shown (Detail["sole_key"]) carries piiguard.Hash, stable and
// unsalted. IgnoreKeys still takes the plain value.
//
// Memory is bounded: per action a handful of integer counters, plus at most
// MaxKeys distinct key strings for the current window only (the preceding
// window keeps counters and no keys). Beyond MaxKeys further new keys are not
// stored; the count is then a lower bound and Detail["keys_truncated"] is true.
// Total state is O(actions * MaxKeys), independent of the number of events.
//
// The package imports the standard library and internal/core only.
package behaviour

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/piiguard"
)

// Action classes.
const (
	ClassRare   = "rare"
	ClassCommon = "common"
)

const (
	defaultName          = "behaviour"
	defaultMinRise       = 0.20
	defaultMaxKeys       = 10000
	maxActions           = 64
	defaultRareMin       = 1
	defaultCommonMin     = 20
	minStatus, maxStatus = 100, 599

	// emptyBaselineMinShare applies when a common action has no preceding data:
	// no rise can be computed and none is invented, so the action must be failing
	// a majority of the time to be raised.
	emptyBaselineMinShare = 0.5

	// epsilon absorbs float rounding at the threshold (0.6-0.4 is not 0.2).
	epsilon = 1e-9
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Action is one named thing a client can do.
type Action struct {
	Name  string `yaml:"name"`
	Class string `yaml:"class"`

	// Exactly one of Path and PathPattern. Path is compared whole after the query
	// string and one trailing slash are removed. PathPattern is an anchored
	// regular expression (RE2) over the same normalised path.
	Path        string `yaml:"path"`
	PathPattern string `yaml:"path_pattern"`

	// Methods restricts the HTTP method (case-insensitive, whole value). Needs
	// Config.MethodField.
	Methods []string `yaml:"methods"`
	// Statuses restricts the HTTP status to this set. Needs Config.StatusField.
	Statuses []int `yaml:"statuses"`
	// Fields requires event field NAME to equal VALUE exactly (text or number
	// rendered as text). FieldPatterns requires an anchored match instead.
	Fields        map[string]string `yaml:"fields"`
	FieldPatterns map[string]string `yaml:"field_patterns"`

	// MinEvents: events needed in the current window. Default 1 for rare, 20 for
	// common.
	MinEvents int `yaml:"min_events"`
	// FailStatuses overrides Config.FailStatuses for this action (common only).
	FailStatuses []int `yaml:"fail_statuses"`
}

// Config selects the event fields, the actions and thresholds. Zero values take
// the defaults documented on New.
type Config struct {
	Name     string `yaml:"name"`
	KeyField string `yaml:"key_field"`
	// HashKeys shows a key in a Finding as piiguard.Hash(key). Required when
	// KeyField is a personal field (username, email, user id).
	HashKeys     bool   `yaml:"hash_keys"`
	PathField    string `yaml:"path_field"`
	MethodField  string `yaml:"method_field"`
	StatusField  string `yaml:"status_field"`
	FailStatuses []int  `yaml:"fail_statuses"`

	// UserAgentField is read only to apply IgnoreUserAgents. It never matches an
	// action.
	UserAgentField   string   `yaml:"user_agent_field"`
	IgnoreKeys       []string `yaml:"ignore_keys"`
	IgnoreUserAgents []string `yaml:"ignore_user_agents"`

	MinFailureShareRise float64 `yaml:"min_failure_share_rise"`
	// MaxKeys bounds distinct keys remembered per action. Default 10000.
	MaxKeys int `yaml:"max_keys"`

	Actions []Action `yaml:"actions"`

	// EmptyIsQuiet makes a current window with nothing to judge a quiet answer
	// (no findings) instead of core.ErrNoRecords. Events that exist but cannot be
	// read (no path) are still an error: that is a blind detector, not a quiet one. Set it
	// only when every source the detector reads filters on the server and proves its
	// index alive; internal/config refuses it otherwise.
	EmptyIsQuiet bool `yaml:"empty_is_quiet"`
}

type matcher struct {
	name      string
	class     string
	path      string
	pathRE    *regexp.Regexp
	methods   map[string]struct{}
	statuses  map[int]struct{}
	fields    map[string]string
	fieldREs  map[string]*regexp.Regexp
	minEvents int
	fail      map[int]struct{}
}

// Detector implements core.Detector.
type Detector struct {
	name    string
	cfg     Config
	acts    []matcher
	ignore  map[string]struct{}
	ignoreU []string // lower-cased
}

var _ core.Detector = (*Detector)(nil)

// New validates c and applies defaults: Name "behaviour", FailStatuses 401 and
// 403, MinFailureShareRise 0.20, MaxKeys 10000, per-action MinEvents 1 (rare) or
// 20 (common). PathField and at least one action are required; KeyField is
// required. MethodField is required by any action with Methods, StatusField by
// any action with Statuses and by every common action, UserAgentField by
// IgnoreUserAgents. At most 64 actions.
func New(c Config) (*Detector, error) {
	if c.Name == "" {
		c.Name = defaultName
	}
	if !nameRE.MatchString(c.Name) {
		return nil, fmt.Errorf("behaviour: name %q must match %s", c.Name, nameRE)
	}
	if strings.TrimSpace(c.KeyField) == "" {
		return nil, errors.New("behaviour: key_field is required")
	}
	if !c.HashKeys && piiguard.Personal(c.KeyField) {
		return nil, fmt.Errorf("behaviour: key_field %q holds personal data and would appear in findings: set hash_keys: true, or key on client_ip", c.KeyField)
	}
	if strings.TrimSpace(c.PathField) == "" {
		return nil, errors.New("behaviour: path_field is required")
	}
	if len(c.IgnoreUserAgents) > 0 && c.UserAgentField == "" {
		return nil, errors.New("behaviour: ignore_user_agents needs user_agent_field")
	}
	if math.IsNaN(c.MinFailureShareRise) || c.MinFailureShareRise < 0 || c.MinFailureShareRise > 1 {
		return nil, fmt.Errorf("behaviour: min_failure_share_rise %v outside (0,1]", c.MinFailureShareRise)
	}
	if c.MinFailureShareRise == 0 {
		c.MinFailureShareRise = defaultMinRise
	}
	if c.MaxKeys < 0 {
		return nil, fmt.Errorf("behaviour: max_keys %d is negative", c.MaxKeys)
	}
	if c.MaxKeys == 0 {
		c.MaxKeys = defaultMaxKeys
	}
	if len(c.FailStatuses) == 0 {
		c.FailStatuses = []int{401, 403}
	}
	defFail, err := statusSet(c.FailStatuses, "fail_statuses")
	if err != nil {
		return nil, err
	}
	if len(c.Actions) == 0 {
		return nil, errors.New("behaviour: actions is required")
	}
	if len(c.Actions) > maxActions {
		return nil, fmt.Errorf("behaviour: %d actions, at most %d", len(c.Actions), maxActions)
	}
	d := &Detector{name: c.Name, ignore: map[string]struct{}{}}
	seen := map[string]struct{}{}
	for i := range c.Actions {
		m, err := buildMatcher(c, c.Actions[i], defFail)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[m.name]; dup {
			return nil, fmt.Errorf("behaviour: duplicate action name %q", m.name)
		}
		seen[m.name] = struct{}{}
		d.acts = append(d.acts, m)
	}
	for _, k := range c.IgnoreKeys {
		if k = strings.TrimSpace(k); k != "" {
			d.ignore[k] = struct{}{}
		}
	}
	for _, u := range c.IgnoreUserAgents {
		u = strings.ToLower(strings.TrimSpace(u))
		if u == "" {
			return nil, errors.New("behaviour: blank entry in ignore_user_agents")
		}
		d.ignoreU = append(d.ignoreU, u)
	}
	// Own the slices and maps: the caller may reuse theirs.
	c.FailStatuses = append([]int(nil), c.FailStatuses...)
	c.IgnoreKeys = append([]string(nil), c.IgnoreKeys...)
	c.IgnoreUserAgents = append([]string(nil), c.IgnoreUserAgents...)
	c.Actions = append([]Action(nil), c.Actions...)
	d.cfg = c
	return d, nil
}

func statusSet(ss []int, what string) (map[int]struct{}, error) {
	m := make(map[int]struct{}, len(ss))
	for _, s := range ss {
		if s < minStatus || s > maxStatus {
			return nil, fmt.Errorf("behaviour: %s %d is not an HTTP status", what, s)
		}
		m[s] = struct{}{}
	}
	return m, nil
}

// anchored compiles pat so that it must match the whole value.
func anchored(pat string) (*regexp.Regexp, error) {
	return regexp.Compile(`^(?:` + pat + `)$`)
}

func buildMatcher(c Config, a Action, defFail map[int]struct{}) (matcher, error) {
	var m matcher
	if !nameRE.MatchString(a.Name) {
		return m, fmt.Errorf("behaviour: action name %q must match %s", a.Name, nameRE)
	}
	pre := fmt.Sprintf("behaviour: action %q: ", a.Name)
	m.name, m.class = a.Name, a.Class
	switch a.Class {
	case ClassRare, ClassCommon:
	default:
		return m, fmt.Errorf("%sclass %q must be %q or %q", pre, a.Class, ClassRare, ClassCommon)
	}
	switch {
	case a.Path != "" && a.PathPattern != "":
		return m, errors.New(pre + "give path or path_pattern, not both")
	case a.Path == "" && a.PathPattern == "":
		return m, errors.New(pre + "path or path_pattern is required")
	case a.Path != "":
		if !strings.HasPrefix(a.Path, "/") {
			return m, errors.New(pre + "path must start with /")
		}
		m.path = normPath(a.Path)
	default:
		re, err := anchored(a.PathPattern)
		if err != nil {
			return m, fmt.Errorf("%spath_pattern: %w", pre, err)
		}
		m.pathRE = re
	}
	if len(a.Methods) > 0 {
		if c.MethodField == "" {
			return m, errors.New(pre + "methods needs method_field")
		}
		m.methods = map[string]struct{}{}
		for _, x := range a.Methods {
			if x = strings.ToUpper(strings.TrimSpace(x)); x == "" {
				return m, errors.New(pre + "blank entry in methods")
			}
			m.methods[x] = struct{}{}
		}
	}
	if len(a.Statuses) > 0 {
		if c.StatusField == "" {
			return m, errors.New(pre + "statuses needs status_field")
		}
		var err error
		if m.statuses, err = statusSet(a.Statuses, "statuses"); err != nil {
			return m, fmt.Errorf("%s%w", pre, err)
		}
	}
	for f, v := range a.Fields {
		if strings.TrimSpace(f) == "" {
			return m, errors.New(pre + "blank field name in fields")
		}
		if m.fields == nil {
			m.fields = map[string]string{}
		}
		m.fields[f] = v
	}
	for f, p := range a.FieldPatterns {
		if strings.TrimSpace(f) == "" {
			return m, errors.New(pre + "blank field name in field_patterns")
		}
		if _, both := a.Fields[f]; both {
			return m, fmt.Errorf("%sfield %q is in both fields and field_patterns", pre, f)
		}
		re, err := anchored(p)
		if err != nil {
			return m, fmt.Errorf("%sfield_patterns[%s]: %w", pre, f, err)
		}
		if m.fieldREs == nil {
			m.fieldREs = map[string]*regexp.Regexp{}
		}
		m.fieldREs[f] = re
	}
	if a.MinEvents < 0 {
		return m, fmt.Errorf("%smin_events %d is negative", pre, a.MinEvents)
	}
	m.minEvents = a.MinEvents
	if m.minEvents == 0 {
		m.minEvents = defaultRareMin
		if a.Class == ClassCommon {
			m.minEvents = defaultCommonMin
		}
	}
	if a.Class == ClassCommon {
		if c.StatusField == "" {
			return m, errors.New(pre + "a common action needs status_field")
		}
		m.fail = defFail
		if len(a.FailStatuses) > 0 {
			var err error
			if m.fail, err = statusSet(a.FailStatuses, "fail_statuses"); err != nil {
				return m, fmt.Errorf("%s%w", pre, err)
			}
		}
	} else if len(a.FailStatuses) > 0 {
		return m, errors.New(pre + "fail_statuses only applies to a common action")
	}
	return m, nil
}

// Name returns the configured detector name.
func (d *Detector) Name() string { return d.name }

// actTally is one action's counters for one window.
type actTally struct {
	total, fail int
	unparsable  int // matched on path/method/fields but the status was unreadable
	keys        map[string]struct{}
	failKeys    map[string]struct{}
	truncated   bool
	unkeyed     int
	last        time.Time // latest judged event that counted for the action
}

// tally is what one window's events add up to.
type tally struct {
	seen        int
	judged      int // parsable path, not ignored
	noPath      int
	ignored     int
	ignoredByUA int
	acts        []actTally
}

// scan streams r once. withKeys keeps distinct keys (current window only).
func (d *Detector) scan(ctx context.Context, r core.EventReader, w core.Window, withKeys bool) (tally, error) {
	t := tally{acts: make([]actTally, len(d.acts))}
	for ev, err := range r.Events(ctx, w) {
		if cerr := ctx.Err(); cerr != nil {
			return t, cerr
		}
		if err != nil {
			return t, err
		}
		t.seen++
		raw, _ := ev.Fields[d.cfg.PathField].(string)
		if strings.TrimSpace(raw) == "" {
			t.noPath++
			continue
		}
		key := keyOf(ev.Fields[d.cfg.KeyField])
		if key != "" {
			if _, skip := d.ignore[key]; skip {
				t.ignored++
				continue
			}
		}
		if len(d.ignoreU) > 0 {
			ua, _ := ev.Fields[d.cfg.UserAgentField].(string)
			if ua = strings.ToLower(ua); ua != "" && containsAny(ua, d.ignoreU) {
				t.ignored++
				t.ignoredByUA++
				continue
			}
		}
		t.judged++
		path := normPath(raw)
		for i := range d.acts {
			m := &d.acts[i]
			if !m.matchesRequest(d.cfg, ev.Fields, path) {
				continue
			}
			at := &t.acts[i]
			status, sok := 0, true
			if d.cfg.StatusField != "" && (m.statuses != nil || m.class == ClassCommon) {
				status, sok = parseStatus(ev.Fields[d.cfg.StatusField])
				if !sok {
					at.unparsable++
					continue
				}
			}
			if m.statuses != nil {
				if _, ok := m.statuses[status]; !ok {
					continue
				}
			}
			at.total++
			if ev.Time.After(at.last) {
				at.last = ev.Time
			}
			_, failed := m.fail[status]
			if m.class == ClassCommon && failed {
				at.fail++
			}
			if !withKeys {
				continue
			}
			if key == "" {
				at.unkeyed++
				continue
			}
			at.addKey(&at.keys, key, d.cfg.MaxKeys)
			if m.class == ClassCommon && failed {
				at.addKey(&at.failKeys, key, d.cfg.MaxKeys)
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

func (a *actTally) addKey(set *map[string]struct{}, key string, max int) {
	if *set == nil {
		*set = map[string]struct{}{}
	}
	if _, ok := (*set)[key]; ok {
		return
	}
	if len(*set) >= max {
		a.truncated = true
		return
	}
	(*set)[key] = struct{}{}
}

// matchesRequest applies path, method and field matchers. Status is applied by
// the caller because an unreadable status is counted, not silently skipped.
func (m *matcher) matchesRequest(c Config, f map[string]any, path string) bool {
	if m.pathRE != nil {
		if !m.pathRE.MatchString(path) {
			return false
		}
	} else if path != m.path {
		return false
	}
	if m.methods != nil {
		s, _ := f[c.MethodField].(string)
		if _, ok := m.methods[strings.ToUpper(strings.TrimSpace(s))]; !ok {
			return false
		}
	}
	for name, want := range m.fields {
		got, ok := text(f[name])
		if !ok || got != want {
			return false
		}
	}
	for name, re := range m.fieldREs {
		got, ok := text(f[name])
		if !ok || !re.MatchString(got) {
			return false
		}
	}
	return true
}

// outcome is what one action came to in the two windows.
type outcome struct {
	m       *matcher
	c, p    actTally
	finding *core.Finding // nil when the action is not raised
}

// analysis is the shared result of reading both windows.
type analysis struct {
	ct, pt        tally
	base          core.Window
	baselineEmpty bool
	acts          []outcome
}

// analyse reads both windows once and decides, per action, whether it is raised. Detect
// turns the outcomes into findings and Activity into a report, so the matchers, the
// ignore rules and the thresholds exist once.
func (d *Detector) analyse(ctx context.Context, cur, prev core.EventReader, w core.Window) (analysis, error) {
	if cur == nil || prev == nil {
		return analysis{}, fmt.Errorf("%s: nil event reader", d.name)
	}
	if err := ctx.Err(); err != nil {
		return analysis{}, err
	}
	ct, err := d.scan(ctx, cur, w, true)
	if err != nil {
		return analysis{}, fmt.Errorf("%s: current window: %w", d.name, err)
	}
	// With EmptyIsQuiet an empty window falls through: every action is below its
	// minimum, the preceding window is still read, and nothing is raised.
	quiet := d.cfg.EmptyIsQuiet && ct.noPath == 0
	if ct.judged == 0 && !quiet {
		return analysis{}, fmt.Errorf("%s: %w: current window had %d events, %d without a path, %d ignored",
			d.name, core.ErrNoRecords, ct.seen, ct.noPath, ct.ignored)
	}
	base := w.Previous()
	pt, err := d.scan(ctx, prev, base, false)
	if err != nil {
		// A failed baseline read is not an empty baseline.
		return analysis{}, fmt.Errorf("%s: preceding window: %w", d.name, err)
	}
	baselineEmpty := pt.judged == 0

	a := analysis{ct: ct, pt: pt, base: base, baselineEmpty: baselineEmpty}
	for i := range d.acts {
		m := &d.acts[i]
		c, p := ct.acts[i], pt.acts[i]
		o := outcome{m: m, c: c, p: p}
		if c.total < m.minEvents {
			a.acts = append(a.acts, o)
			continue
		}
		detail := map[string]any{
			"action":          m.name,
			"class":           m.class,
			"min_events":      m.minEvents,
			"key_field":       d.cfg.KeyField,
			"cur_events":      c.total,
			"prev_events":     p.total,
			"keys_cur":        len(c.keys),
			"keys_truncated":  c.truncated,
			"unkeyed_cur":     c.unkeyed,
			"baseline_empty":  baselineEmpty,
			"judged_cur":      ct.judged,
			"judged_prev":     pt.judged,
			"ignored_cur":     ct.ignored,
			"ignored_prev":    pt.ignored,
			"ignored_ua_cur":  ct.ignoredByUA,
			"ignored_ua_prev": pt.ignoredByUA,
			"unparsable_cur":  c.unparsable,
			"unparsable_prev": p.unparsable,
		}
		if len(c.keys) == 1 && !c.truncated {
			for k := range c.keys {
				detail["sole_key"] = piiguard.Shown(k, d.cfg.HashKeys)
			}
		}
		var f *core.Finding
		if m.class == ClassRare {
			f = d.rare(m, c, p, baselineEmpty, detail)
		} else {
			f = d.common(m, c, p, baselineEmpty, detail)
		}
		if f != nil {
			f.Detector, f.Tag, f.Window, f.Baseline = d.name, d.name+":"+m.name, w, base
		}
		o.finding = f
		a.acts = append(a.acts, o)
	}
	return a, nil
}

// Detect compares each action in cur (window w) with prev (w.Previous()).
func (d *Detector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	a, err := d.analyse(ctx, cur, prev, w)
	if err != nil {
		return nil, err
	}
	var out []core.Finding
	for _, o := range a.acts {
		if o.finding != nil {
			out = append(out, *o.finding)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out, nil
}

var _ core.ActivityReporter = (*Detector)(nil)

// Activity answers "was any action active in w" from the same analysis as Detect. An
// action is active when Detect would raise it: a rare action at or above its
// MinEvents, or a common action whose failure share rose. A common action with only
// ordinary traffic is not active, whatever its count. Events from ignored keys and user
// agents are in no count. The report carries counts and times, never a key.
func (d *Detector) Activity(ctx context.Context, cur, prev core.EventReader, w core.Window) (core.ActivityReport, error) {
	a, err := d.analyse(ctx, cur, prev, w)
	if err != nil {
		return core.ActivityReport{}, err
	}
	rep := core.ActivityReport{Seen: a.ct.seen, Unparsable: a.ct.noPath}
	for _, o := range a.acts {
		sub := core.ActivitySubject{
			Subject: o.m.name, Kind: o.m.class,
			Current: o.c.total, Previous: o.p.total, Active: o.finding != nil,
		}
		if sub.Active {
			sub.Last = o.c.last
		}
		if o.c.unparsable > 0 {
			rep.Unparsable += o.c.unparsable
			sub.Note = fmt.Sprintf("%d matching event(s) with an unreadable status are in no count", o.c.unparsable)
		}
		if o.c.truncated {
			rep.Notes = append(rep.Notes, fmt.Sprintf("action %q: distinct-key tracking stopped at %d; its key count is a lower bound, its event counts are not affected", o.m.name, d.cfg.MaxKeys))
		}
		rep.Subjects = append(rep.Subjects, sub)
	}
	rep.Unparsable = min(rep.Unparsable, rep.Seen)
	if a.ct.ignored > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d event(s) set aside as ignored infrastructure", a.ct.ignored))
	}
	return rep, nil
}

func keysPhrase(c actTally) string {
	n := fmt.Sprint(len(c.keys))
	if c.truncated {
		n = "at least " + n
	}
	if c.unkeyed > 0 {
		return fmt.Sprintf("%s distinct key(s), %d event(s) with no key", n, c.unkeyed)
	}
	return n + " distinct key(s)"
}

func (d *Detector) rare(m *matcher, c, p actTally, baselineEmpty bool, detail map[string]any) *core.Finding {
	sev := core.SevActivity
	if baselineEmpty {
		sev = core.SevCheck
	}
	detail["new"] = p.total == 0
	how := "new, none in the preceding window"
	if p.total > 0 {
		how = fmt.Sprintf("preceding window %d", p.total)
	}
	return &core.Finding{
		Severity: sev,
		Summary: fmt.Sprintf("rare action %q occurred %d time(s) (%s) from %s",
			m.name, c.total, how, keysPhrase(c)),
		Detail: detail,
	}
}

func (d *Detector) common(m *matcher, c, p actTally, baselineEmpty bool, detail map[string]any) *core.Finding {
	share := float64(c.fail) / float64(c.total)
	detail["cur_failures"] = c.fail
	detail["cur_failure_share"] = share
	detail["prev_failures"] = p.fail
	detail["failing_keys_cur"] = len(c.failKeys)
	detail["min_failure_share_rise"] = d.cfg.MinFailureShareRise
	var raised bool
	var summary string
	switch {
	case p.total > 0:
		pshare := float64(p.fail) / float64(p.total)
		rise := share - pshare
		detail["prev_failure_share"], detail["failure_share_rise"] = pshare, rise
		detail["baseline_source"] = "action"
		raised = rise >= d.cfg.MinFailureShareRise-epsilon
		summary = fmt.Sprintf("failure share of common action %q rose from %.1f%% (%d/%d) to %.1f%% (%d/%d); failures from %d distinct key(s)",
			m.name, 100*pshare, p.fail, p.total, 100*share, c.fail, c.total, len(c.failKeys))
	default:
		detail["baseline_source"] = "none"
		raised = share >= emptyBaselineMinShare
		summary = fmt.Sprintf("common action %q fails %.1f%% (%d/%d); no events of it in the preceding window to compare; failures from %d distinct key(s)",
			m.name, 100*share, c.fail, c.total, len(c.failKeys))
	}
	if !raised {
		return nil
	}
	sev := core.SevHigh
	if baselineEmpty || p.total == 0 {
		sev-- // one step down: nothing to compare against
	}
	return &core.Finding{Severity: sev, Summary: summary, Detail: detail}
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// normPath drops a query string or fragment and one trailing slash (not the root).
func normPath(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
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

// text renders a field for an equality match: text as is, numbers and booleans
// in their plain form. Anything else (absent, object, list) does not match.
func text(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return "", false
		}
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case json.Number:
		return x.String(), true
	}
	return "", false
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
