// Package signup detects an account-creation burst. It is deliberately
// product-agnostic: the paths, the fields and the statuses that mean "an account
// was created" are configuration, not code.
//
// Rules, each of which came from a real false result:
//
//   - Count the request that CREATES the account, never the form that precedes
//     it. An identity provider renders its signup form with a GET that every
//     curious client makes and creates the user with a POST to another endpoint:
//     one week measured 1,071 form renders against 87 accounts, and a detector
//     watching the form counted the wrong one. CreatePaths names the creating
//     endpoint, matched against the whole path (query string and one trailing
//     slash ignored), never as a substring, so "/signup" does not also match
//     "/signup/form". MethodField and Methods exclude the GET that renders the
//     form when it shares the creating path. Without MethodField that GET cannot
//     be told apart and counts; say so in the config, do not hope.
//   - Only a configured success status counts as a creation (default 2xx
//     success and the redirects that follow a created account: 200, 201, 202,
//     204, 302, 303). Other responses on the creating path are attempts and are
//     reported as such. If a failed attempt also answers with one of the success
//     statuses on your system (a form re-rendered with an error is often a 200),
//     narrow SuccessStatuses to the one that only success returns.
//   - A raw count means nothing. A window is flagged only when its creations
//     reach MinCreations and are at least Factor times those of the same-length
//     preceding window. A steadily busy signup is not a burst.
//   - A current window with no parsable event on the creating path is
//     core.ErrNoRecords, never a clean result. A preceding window with no
//     parsable event on that path is reported (Detail["baseline_empty"]) and the
//     severity drops one step; no multiple is invented against it.
//   - Disposable-looking addresses are surfaced only against a domain list the
//     config supplies; there is no built-in list. A domain matches when the
//     address domain equals a listed one or is a subdomain of it, never as a
//     substring ("mail.example" does not match "notmail.example"). Findings and
//     Detail carry the listed domain and counts, never an address.
//   - Every number in a Finding was counted from the events read. Tags are the
//     detector name (the burst) or the name plus "disposable" plus the listed
//     domain, and nothing else, so one ongoing condition dedupes across runs.
//
// A log with no path and no HTTP status (Keycloak events) names the creating
// event instead: EventField holds the event type, CreateValues lists the value
// that means an account was created (REGISTER) and AttemptValues the failed
// attempt (REGISTER_ERROR). This is the event-type mode. It replaces the path,
// status and method settings, which are then refused rather than ignored, and it
// keeps the rule above: the event that creates the account is counted, a failed
// attempt is only an attempt.
//
// Failed-attempt rule (off unless MinAttempts is set): a spray of failed signups
// is many attempts and few creations, which the creation rule above cannot see.
// A window is raised, tagged name+":attempts", when its failed attempts (parsable
// events on the creating path that did not create an account) reach MinAttempts
// AND are at least AttemptFactor times those of the preceding window. Both are
// required; a raw count alone is never a finding. The finding states failed
// attempts, creations and the failure share failed/(failed+creations), all
// counted from the events read, and takes the same baseline_empty severity step
// as the creation rule. attempts_cur in Detail stays the total of both outcomes.
//
// Not a rate limiter and not attribution: it says an unusual number of accounts
// were created in your logs, not who made them.
//
// The package imports the standard library and internal/core only.
package signup

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/httpstatus"
)

const (
	defaultName          = "signup"
	defaultMinCreations  = 5
	defaultFactor        = 3.0
	defaultAttemptFactor = 3.0

	// epsilon absorbs float rounding at the threshold.
	epsilon = 1e-9
)

var (
	nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

	defaultSuccess = []int{200, 201, 202, 204, 302, 303}
)

// Config selects the event fields and thresholds. Zero values take the defaults
// documented on New.
type Config struct {
	Name string `yaml:"name"`

	// CreatePaths are the paths of the endpoint that creates the account.
	CreatePaths []string `yaml:"create_paths"`
	PathField   string   `yaml:"path_field"`
	StatusField string   `yaml:"status_field"`
	// SuccessStatuses are the statuses that mean the account was created.
	SuccessStatuses []int `yaml:"success_statuses"`

	// MethodField and Methods restrict creations to these HTTP methods
	// (compared case-insensitively). Methods needs MethodField.
	MethodField string   `yaml:"method_field"`
	Methods     []string `yaml:"methods"`

	// Event-type mode, instead of CreatePaths/PathField/StatusField/
	// SuccessStatuses/MethodField/Methods: EventField is the field holding the
	// event type, CreateValues the values that mean an account was created and
	// AttemptValues the values that are attempts that did not create one.
	EventField    string   `yaml:"event_field"`
	CreateValues  []string `yaml:"create_values"`
	AttemptValues []string `yaml:"attempt_values"`

	// MinCreations is the least number of creations that can be a burst.
	MinCreations int `yaml:"min_creations"`
	// Factor is the multiple of the preceding window's creations a burst must reach.
	Factor float64 `yaml:"factor"`

	// MinAttempts turns on the failed-attempt rule: 0 (the default) leaves it
	// off. A failed attempt is a parsable event on the creating path that did not
	// create an account (REGISTER_ERROR in event-type mode, a non-success status
	// in path mode). The rule raises when the window's failed attempts reach
	// MinAttempts AND are at least AttemptFactor times those of the preceding
	// window.
	MinAttempts int `yaml:"min_attempts"`
	// AttemptFactor is the multiple of the preceding window's failed attempts
	// the rule needs. Default 3; refused without MinAttempts.
	AttemptFactor float64 `yaml:"attempt_factor"`

	// AddressField and DisposableDomains go together: the field that holds the
	// new account's address and the domains to flag.
	AddressField      string   `yaml:"address_field"`
	DisposableDomains []string `yaml:"disposable_domains"`

	// EmptyIsQuiet makes a current window with nothing to judge a quiet answer
	// (no findings) instead of core.ErrNoRecords. Events that exist but cannot be
	// read (no readable status or method, or no event type) are still an error: that is a blind detector, not a quiet one. Set it
	// only when every source the detector reads filters on the server and proves its
	// index alive; internal/config refuses it otherwise.
	EmptyIsQuiet bool `yaml:"empty_is_quiet"`
}

// Detector implements core.Detector.
type Detector struct {
	name    string
	cfg     Config
	paths   map[string]struct{}
	success map[int]struct{}
	methods map[string]struct{}
	create  map[string]struct{} // event-type mode when non-nil
	attempt map[string]struct{}
	domains []string // normalised, sorted, unique
}

var _ core.Detector = (*Detector)(nil)

// New validates c and applies defaults: Name "signup", SuccessStatuses 200, 201,
// 202, 204, 302 and 303, MinCreations 5, Factor 3, Methods (when MethodField is
// set) POST. CreatePaths, PathField and StatusField are required; every path
// starts with "/".
func New(c Config) (*Detector, error) {
	if c.Name == "" {
		c.Name = defaultName
	}
	if !nameRE.MatchString(c.Name) {
		return nil, fmt.Errorf("signup: name %q must match %s", c.Name, nameRE)
	}
	eventMode := c.EventField != "" || len(c.CreateValues) > 0 || len(c.AttemptValues) > 0
	if eventMode {
		if strings.TrimSpace(c.EventField) == "" || len(c.CreateValues) == 0 {
			return nil, errors.New("signup: event_field and create_values go together; name the event that creates the account")
		}
		if len(c.CreatePaths) > 0 || c.PathField != "" || c.StatusField != "" || len(c.SuccessStatuses) > 0 || c.MethodField != "" || len(c.Methods) > 0 {
			return nil, errors.New("signup: event_field mode replaces create_paths, path_field, status_field, success_statuses, method_field and methods; set one mode")
		}
	} else {
		if strings.TrimSpace(c.PathField) == "" {
			return nil, errors.New("signup: path_field is required")
		}
		if strings.TrimSpace(c.StatusField) == "" {
			return nil, errors.New("signup: status_field is required")
		}
		if len(c.CreatePaths) == 0 {
			return nil, errors.New("signup: create_paths is required: name the endpoint that creates the account, not the form")
		}
		if len(c.Methods) > 0 && strings.TrimSpace(c.MethodField) == "" {
			return nil, errors.New("signup: methods needs method_field")
		}
	}
	if c.MinCreations < 0 {
		return nil, fmt.Errorf("signup: min_creations %d is negative", c.MinCreations)
	}
	if c.MinCreations == 0 {
		c.MinCreations = defaultMinCreations
	}
	if math.IsNaN(c.Factor) || math.IsInf(c.Factor, 0) || c.Factor < 0 || (c.Factor != 0 && c.Factor <= 1) {
		return nil, fmt.Errorf("signup: factor %v must be greater than 1 (0 takes the default)", c.Factor)
	}
	if c.Factor == 0 {
		c.Factor = defaultFactor
	}
	if c.MinAttempts < 0 {
		return nil, fmt.Errorf("signup: min_attempts %d is negative", c.MinAttempts)
	}
	if math.IsNaN(c.AttemptFactor) || math.IsInf(c.AttemptFactor, 0) || c.AttemptFactor < 0 || (c.AttemptFactor != 0 && c.AttemptFactor <= 1) {
		return nil, fmt.Errorf("signup: attempt_factor %v must be greater than 1 (0 takes the default)", c.AttemptFactor)
	}
	if c.MinAttempts == 0 && c.AttemptFactor != 0 {
		return nil, errors.New("signup: attempt_factor needs min_attempts; the failed-attempt rule is off while min_attempts is 0")
	}
	if c.MinAttempts > 0 && c.AttemptFactor == 0 {
		c.AttemptFactor = defaultAttemptFactor
	}
	if (c.AddressField != "") != (len(c.DisposableDomains) > 0) {
		return nil, errors.New("signup: address_field and disposable_domains go together")
	}
	if len(c.SuccessStatuses) == 0 && !eventMode {
		c.SuccessStatuses = defaultSuccess
	}
	if c.MethodField != "" && len(c.Methods) == 0 {
		c.Methods = []string{"POST"}
	}

	d := &Detector{
		name:    c.Name,
		paths:   map[string]struct{}{},
		success: map[int]struct{}{},
		methods: map[string]struct{}{},
	}
	if eventMode {
		d.create, d.attempt = map[string]struct{}{}, map[string]struct{}{}
		for _, v := range c.CreateValues {
			if strings.TrimSpace(v) == "" {
				return nil, errors.New("signup: blank create value")
			}
			d.create[v] = struct{}{}
		}
		for _, v := range c.AttemptValues {
			if strings.TrimSpace(v) == "" {
				return nil, errors.New("signup: blank attempt value")
			}
			if _, both := d.create[v]; both {
				return nil, fmt.Errorf("signup: %q is both a create value and an attempt value", v)
			}
			d.attempt[v] = struct{}{}
		}
	}
	for _, p := range c.CreatePaths {
		p = normPath(p)
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("signup: create path %q must start with /", p)
		}
		d.paths[p] = struct{}{}
	}
	for _, s := range c.SuccessStatuses {
		if s < httpstatus.Min || s > httpstatus.Max {
			return nil, fmt.Errorf("signup: success status %d is not an HTTP status", s)
		}
		d.success[s] = struct{}{}
	}
	for _, m := range c.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			return nil, errors.New("signup: blank method")
		}
		d.methods[m] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, dom := range c.DisposableDomains {
		dom = strings.ToLower(strings.Trim(strings.TrimSpace(dom), "@."))
		if dom == "" || strings.ContainsAny(dom, "@ \t/") {
			return nil, fmt.Errorf("signup: disposable domain %q is not a domain", dom)
		}
		if _, dup := seen[dom]; !dup {
			seen[dom] = struct{}{}
			d.domains = append(d.domains, dom)
		}
	}
	sort.Strings(d.domains)
	// Own the slices: the caller may reuse theirs.
	c.CreateValues = append([]string(nil), c.CreateValues...)
	c.AttemptValues = append([]string(nil), c.AttemptValues...)
	c.CreatePaths = append([]string(nil), c.CreatePaths...)
	c.SuccessStatuses = append([]int(nil), c.SuccessStatuses...)
	c.Methods = append([]string(nil), c.Methods...)
	c.DisposableDomains = append([]string(nil), c.DisposableDomains...)
	d.cfg = c
	return d, nil
}

// Name returns the configured detector name.
func (d *Detector) Name() string { return d.name }

// tally is what one window's events add up to. Only counters are kept.
type tally struct {
	seen        int
	offPath     int
	unparsable  int
	attempts    int // parsable events on a creating path, any outcome
	creations   int
	disposable  map[string]int // creations per listed domain
	noAddress   int            // creations whose address could not be read
	otherMethod int            // on-path events excluded by method
}

func (d *Detector) scan(ctx context.Context, r core.EventReader, w core.Window) (tally, error) {
	t := tally{disposable: map[string]int{}}
	for ev, err := range r.Events(ctx, w) {
		if cerr := ctx.Err(); cerr != nil {
			return t, cerr
		}
		if err != nil {
			return t, err
		}
		t.seen++
		if d.create != nil {
			if !d.scanEvent(&t, ev) {
				continue
			}
			t.creations++
			d.noteAddress(&t, ev)
			continue
		}
		p, _ := ev.Fields[d.cfg.PathField].(string)
		if _, on := d.paths[normPath(p)]; !on {
			t.offPath++
			continue
		}
		status, ok := httpstatus.Parse(ev.Fields[d.cfg.StatusField])
		if !ok {
			t.unparsable++
			continue
		}
		if d.cfg.MethodField != "" {
			m, ok := ev.Fields[d.cfg.MethodField].(string)
			if !ok || strings.TrimSpace(m) == "" {
				t.unparsable++
				continue
			}
			if _, want := d.methods[strings.ToUpper(strings.TrimSpace(m))]; !want {
				// A form render. It is on the path, but it is not an attempt
				// to create anything.
				t.otherMethod++
				continue
			}
		}
		t.attempts++
		if _, created := d.success[status]; !created {
			continue
		}
		t.creations++
		d.noteAddress(&t, ev)
	}
	// A reader that stops quietly on cancellation would otherwise pass for a
	// short window.
	if err := ctx.Err(); err != nil {
		return t, err
	}
	return t, nil
}

// scanEvent classifies one event in event-type mode. It returns true when the
// event is a creation; attempts and unparsable events are counted in t.
func (d *Detector) scanEvent(t *tally, ev core.Event) bool {
	v, ok := ev.Fields[d.cfg.EventField].(string)
	if !ok || v == "" {
		t.unparsable++
		return false
	}
	if _, ok := d.create[v]; ok {
		t.attempts++
		return true
	}
	if _, ok := d.attempt[v]; ok {
		t.attempts++
		return false
	}
	t.offPath++
	return false
}

// noteAddress counts a creation against the listed domains. Only the domain is
// kept; the address is dropped here.
func (d *Detector) noteAddress(t *tally, ev core.Event) {
	if len(d.domains) == 0 {
		return
	}
	dom := domainOf(ev.Fields[d.cfg.AddressField])
	if dom == "" {
		t.noAddress++
		return
	}
	for _, listed := range d.domains {
		if dom == listed || strings.HasSuffix(dom, "."+listed) {
			t.disposable[listed]++
			return
		}
	}
}

// Detect compares the account creations of cur (window w) with prev (w.Previous()).
func (d *Detector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	if cur == nil || prev == nil {
		return nil, fmt.Errorf("%s: nil event reader", d.name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ct, err := d.scan(ctx, cur, w)
	if err != nil {
		return nil, fmt.Errorf("%s: current window: %w", d.name, err)
	}
	if ct.attempts == 0 && d.cfg.EmptyIsQuiet && ct.unparsable == 0 {
		return nil, nil // nothing attempted to create an account, and nothing unreadable
	}
	if ct.attempts == 0 {
		return nil, fmt.Errorf("%s: %w: current window had %d events, %d off the creating path, %d excluded by method, %d with an unparsable status or method",
			d.name, core.ErrNoRecords, ct.seen, ct.offPath, ct.otherMethod, ct.unparsable)
	}
	anyDisposable := len(ct.disposable) > 0
	failedCur := ct.attempts - ct.creations
	attemptCand := d.cfg.MinAttempts > 0 && failedCur >= d.cfg.MinAttempts
	if ct.creations < d.cfg.MinCreations && !anyDisposable && !attemptCand {
		return nil, nil
	}
	base := w.Previous()
	pt, err := d.scan(ctx, prev, base)
	if err != nil {
		// A failed baseline read is not an empty baseline.
		return nil, fmt.Errorf("%s: preceding window: %w", d.name, err)
	}
	baselineEmpty := pt.attempts == 0

	detail := func() map[string]any {
		return map[string]any{
			"creations_cur":        ct.creations,
			"attempts_cur":         ct.attempts,
			"creations_prev":       pt.creations,
			"attempts_prev":        pt.attempts,
			"min_creations":        d.cfg.MinCreations,
			"factor":               d.cfg.Factor,
			"baseline_empty":       baselineEmpty,
			"unparsable_cur":       ct.unparsable,
			"unparsable_prev":      pt.unparsable,
			"excluded_method_cur":  ct.otherMethod,
			"excluded_method_prev": pt.otherMethod,
		}
	}

	var out []core.Finding
	if ct.creations >= d.cfg.MinCreations && float64(ct.creations) >= d.cfg.Factor*float64(pt.creations)-epsilon {
		dt := detail()
		sev := core.SevActivity
		var summary string
		if baselineEmpty {
			sev-- // one step down: nothing to compare against
			summary = fmt.Sprintf("%d accounts created (%d attempts); no preceding window to compare", ct.creations, ct.attempts)
		} else {
			summary = fmt.Sprintf("%d accounts created (%d attempts) against %d (%d attempts) in the preceding window",
				ct.creations, ct.attempts, pt.creations, pt.attempts)
			if pt.creations > 0 {
				dt["creations_multiple"] = float64(ct.creations) / float64(pt.creations)
			}
		}
		if len(d.domains) > 0 {
			dt["disposable_cur"] = sum(ct.disposable)
			dt["address_unreadable_cur"] = ct.noAddress
		}
		out = append(out, core.Finding{
			Detector: d.name, Tag: d.name, Severity: sev,
			Window: w, Baseline: base, Summary: summary, Detail: dt,
		})
	}
	failedPrev := pt.attempts - pt.creations
	if attemptCand && float64(failedCur) >= d.cfg.AttemptFactor*float64(failedPrev)-epsilon {
		dt := detail()
		dt["min_attempts"] = d.cfg.MinAttempts
		dt["attempt_factor"] = d.cfg.AttemptFactor
		dt["failed_attempts_cur"] = failedCur
		dt["failed_attempts_prev"] = failedPrev
		share := float64(failedCur) / float64(failedCur+ct.creations)
		dt["failure_share_cur"] = share
		sev := core.SevActivity
		var summary string
		if baselineEmpty {
			sev--
			summary = fmt.Sprintf("%d failed signup attempts and %d accounts created (failure share %.1f%%); no preceding window to compare",
				failedCur, ct.creations, 100*share)
		} else {
			if pt.attempts > 0 {
				dt["failure_share_prev"] = float64(failedPrev) / float64(pt.attempts)
			}
			if failedPrev > 0 {
				dt["failed_attempts_multiple"] = float64(failedCur) / float64(failedPrev)
			}
			summary = fmt.Sprintf("%d failed signup attempts and %d accounts created (failure share %.1f%%) against %d failed attempts and %d created in the preceding window",
				failedCur, ct.creations, 100*share, failedPrev, pt.creations)
		}
		out = append(out, core.Finding{
			Detector: d.name, Tag: d.name + ":attempts", Severity: sev,
			Window: w, Baseline: base, Summary: summary, Detail: dt,
		})
	}
	for _, dom := range d.domains {
		n := ct.disposable[dom]
		if n == 0 {
			continue
		}
		dt := detail()
		dt["domain"] = dom
		dt["domain_cur"] = n
		dt["domain_prev"] = pt.disposable[dom]
		dt["address_unreadable_cur"] = ct.noAddress
		sev := core.SevCheck
		if baselineEmpty {
			sev--
		}
		out = append(out, core.Finding{
			Detector: d.name, Tag: d.name + ":disposable:" + dom, Severity: sev,
			Window: w, Baseline: base,
			Summary: fmt.Sprintf("%d of %d accounts created with an address on the listed domain %q (%d in the preceding window)",
				n, ct.creations, dom, pt.disposable[dom]),
			Detail: dt,
		})
	}
	return out, nil
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
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

// domainOf returns the lower-case domain of an address, or "" when v is not text
// holding exactly the shape local@domain.
func domainOf(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, "@")
	if i <= 0 || i == len(s)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimRight(s[i+1:], ". >"))
}
