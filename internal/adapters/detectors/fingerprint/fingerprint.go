// Package fingerprint flags events that match a known actor, where the actor is
// data (a jb.actor/v1 file in the case) and not code.
//
// Rules, each of which came from a real false result in the sister tool:
//
//   - A user agent is matched by full-string equality, never by prefix or
//     substring. A substring match on a stale browser build flagged real customers
//     and invented successful grants.
//   - A user agent alone is not a fingerprint. Commodity scanners reuse it on junk
//     paths. An event is noise, counted as filtered and never as a hit, when its
//     path contains a noise marker (case-insensitive) or, with BareRoot4xxNoise,
//     when the path is "/" and the status is 4xx. The path is judged without its
//     query string: "/?junk" is still "/". A path judged with its query once put
//     the actor "last seen" a day late.
//   - An address is an observation, not an identity. A CDN edge address is not a
//     client, so no address is ever used to match and none appears in a Finding.
//     IgnoreIPs names our own infrastructure: a matching event relayed by it is
//     counted as ignored and is never a suspect.
//   - The tripwire: a 2xx on a grant path for a genuine event of the actor is a
//     critical finding on its own (tag name:actor:grant). It means the actor holds
//     a credential. Everything else is activity level.
//   - Compare with the same-length preceding window. The last genuine activity is
//     reported even when the current window has none: it falls back to the
//     preceding window, and the finding says "no genuine activity in window".
//   - A current window with no parsable event is core.ErrNoRecords. An event
//     missing user_agent, path, status or a time is unparsable. client_ip and
//     method are read when present and never required.
//
// The package imports the standard library and internal/core only.
package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Canonical event field names. A mapper must emit exactly these.
const (
	FieldUserAgent = "user_agent"
	FieldPath      = "path"
	FieldStatus    = "status"
	FieldClientIP  = "client_ip" // optional: only used to skip our own infrastructure
	FieldMethod    = "method"    // optional: not read by this detector

	DefaultName = "fingerprint"

	minStatus, maxStatus = 100, 599
	maxList              = 1000
	maxString            = 1024
)

var (
	nameRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	actorRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// Actor is one actor reduced to what matching needs.
type Actor struct {
	ID    string
	Label string
	// UserAgents are matched by full-string equality.
	UserAgents []string
	// NoisePaths are case-insensitive substring markers of scanner traffic.
	NoisePaths []string
	// BareRoot4xxNoise treats "/" answered with a 4xx as noise.
	BareRoot4xxNoise bool
	// GrantPaths are case-insensitive substrings of a token endpoint's path.
	GrantPaths []string
}

// Config is the detector's configuration.
type Config struct {
	Name   string // default "fingerprint"; part of every tag
	Actors []Actor
	// IgnoreIPs are single addresses or CIDRs of our own infrastructure.
	IgnoreIPs []string
	// EmptyIsQuiet treats a current window with no parsable event as "the actor was not
	// seen" and not as core.ErrNoRecords. Set it only when the source filters on the
	// server and has shown its index alive, so a dead source cannot read as a quiet one.
	EmptyIsQuiet bool
}

type actorSpec struct {
	Actor
	uas    map[string]struct{}
	noise  []string // lower-case
	grants []string // lower-case
}

// Detector implements core.Detector.
type Detector struct {
	name   string
	actors []actorSpec
	ignore []netip.Prefix
	quiet  bool // Config.EmptyIsQuiet
}

var _ core.Detector = (*Detector)(nil)

// New validates c. Every problem is reported at once.
func New(c Config) (*Detector, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("fingerprint: "+format, a...)) }

	name := c.Name
	if name == "" {
		name = DefaultName
	}
	if err := ValidateName(name); err != nil {
		errs = append(errs, err)
	}
	if len(c.Actors) == 0 {
		bad("at least one actor is required")
	}
	d := &Detector{name: name, quiet: c.EmptyIsQuiet}
	ignore, err := ParseIgnoreIPs(c.IgnoreIPs)
	if err != nil {
		errs = append(errs, err)
	}
	d.ignore = ignore
	seen := map[string]bool{}
	for i, a := range c.Actors {
		if !actorRE.MatchString(a.ID) {
			bad("actors[%d]: id %q must match %s", i, a.ID, actorRE)
			continue
		}
		if seen[a.ID] {
			bad("actor %q appears twice", a.ID)
			continue
		}
		seen[a.ID] = true
		s, es := newActor(a)
		for _, e := range es {
			bad("actor %q: %v", a.ID, e)
		}
		d.actors = append(d.actors, s)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return d, nil
}

func newActor(a Actor) (actorSpec, []error) {
	var errs []error
	s := actorSpec{Actor: a, uas: map[string]struct{}{}}
	if len(a.UserAgents) == 0 {
		errs = append(errs, errors.New("at least one user agent is required: no other indicator is matched"))
	}
	if len(a.UserAgents) > maxList || len(a.NoisePaths) > maxList || len(a.GrantPaths) > maxList {
		errs = append(errs, fmt.Errorf("a list holds more than %d entries", maxList))
		return s, errs
	}
	for _, ua := range a.UserAgents {
		switch {
		case ua == "" || len(ua) > maxString:
			errs = append(errs, fmt.Errorf("user agent must be 1 to %d bytes", maxString))
		case strings.ContainsFunc(ua, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			errs = append(errs, errors.New("user agent contains a control character"))
		default:
			s.uas[ua] = struct{}{}
		}
	}
	for _, m := range a.NoisePaths {
		switch {
		case strings.TrimSpace(m) != m || len(m) < 2 || len(m) > 256:
			// A one-character marker such as "/" would call every path noise.
			errs = append(errs, fmt.Errorf("noise path %q must be 2 to 256 bytes with no surrounding space", m))
		default:
			s.noise = append(s.noise, strings.ToLower(m))
		}
	}
	for _, g := range a.GrantPaths {
		lg := strings.ToLower(g)
		switch {
		case !strings.HasPrefix(g, "/") || len(g) > 256 || strings.ContainsAny(g, "? \t"):
			errs = append(errs, fmt.Errorf("grant path %q must start with / and carry no query string", g))
			continue
		}
		for _, m := range s.noise {
			if strings.Contains(lg, m) {
				// Noise is judged first, so a grant path holding a marker could never fire.
				errs = append(errs, fmt.Errorf("grant path %q contains the noise marker %q, so it could never raise the tripwire", g, m))
			}
		}
		s.grants = append(s.grants, lg)
	}
	return s, errs
}

// ValidateName checks a detector name. An empty name is valid and means DefaultName.
func ValidateName(name string) error {
	if name != "" && !nameRE.MatchString(name) {
		return fmt.Errorf("fingerprint: name %q must match %s", name, nameRE)
	}
	return nil
}

// ParseIgnoreIPs parses single addresses and CIDRs. Every bad entry is reported.
func ParseIgnoreIPs(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	var errs []error
	for _, p := range in {
		pf, err := parseIgnore(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("fingerprint: ignore_ips: %w", err))
			continue
		}
		out = append(out, pf)
	}
	return out, errors.Join(errs...)
}

func parseIgnore(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Name returns the detector name.
func (d *Detector) Name() string { return d.name }

// tally is what one window's events add up to for one actor.
type tally struct {
	genuine, filtered, ignored int
	last                       time.Time // latest genuine event; zero when none
	grants                     int
	firstGrant, lastGrant      time.Time
}

type scan struct {
	parsable, unparsable int
	per                  []tally // parallel to Detector.actors
}

// IsNoise reports whether a path and status are scanner traffic that merely shares
// the actor's user agent. The path is judged without its query string.
func isNoise(path string, status int, markers []string, bareRoot4xx bool) bool {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	lp := strings.ToLower(path)
	for _, m := range markers {
		if strings.Contains(lp, m) {
			return true
		}
	}
	return bareRoot4xx && path == "/" && status >= 400 && status <= 499
}

func (d *Detector) isIgnored(ip string) bool {
	if ip == "" || len(d.ignore) == 0 {
		return false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range d.ignore {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (d *Detector) scan(ctx context.Context, r core.EventReader, w core.Window) (scan, error) {
	s := scan{per: make([]tally, len(d.actors))}
	for ev, err := range r.Events(ctx, w) {
		if cerr := ctx.Err(); cerr != nil {
			return s, cerr
		}
		if err != nil {
			return s, err
		}
		ua, _ := ev.Fields[FieldUserAgent].(string)
		path, _ := ev.Fields[FieldPath].(string)
		status, ok := parseStatus(ev.Fields[FieldStatus])
		if ua == "" || path == "" || !ok || ev.Time.IsZero() {
			s.unparsable++
			continue
		}
		s.parsable++
		ip, _ := ev.Fields[FieldClientIP].(string)
		for i := range d.actors {
			a := &d.actors[i]
			if _, hit := a.uas[ua]; !hit { // equality, never a prefix or substring
				continue
			}
			t := &s.per[i]
			switch {
			case d.isIgnored(ip):
				t.ignored++
			case isNoise(path, status, a.noise, a.BareRoot4xxNoise):
				t.filtered++
			default:
				t.genuine++
				if ev.Time.After(t.last) {
					t.last = ev.Time
				}
				if status >= 200 && status <= 299 && a.isGrant(path) {
					t.grants++
					if t.firstGrant.IsZero() || ev.Time.Before(t.firstGrant) {
						t.firstGrant = ev.Time
					}
					if ev.Time.After(t.lastGrant) {
						t.lastGrant = ev.Time
					}
				}
			}
		}
	}
	// A reader that stops quietly on cancellation would otherwise pass for a short window.
	if err := ctx.Err(); err != nil {
		return s, err
	}
	return s, nil
}

func (a *actorSpec) isGrant(path string) bool {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	lp := strings.ToLower(path)
	for _, g := range a.grants {
		if strings.Contains(lp, g) {
			return true
		}
	}
	return false
}

// scanBoth scans the window and the one before it. A failed read of either is an
// error, and an empty current window is core.ErrNoRecords unless the detector was
// configured to read it as quiet. Detect and Activity share it so they cannot disagree
// about what was read.
func (d *Detector) scanBoth(ctx context.Context, cur, prev core.EventReader, w core.Window) (cs, ps scan, err error) {
	if cur == nil || prev == nil {
		return cs, ps, fmt.Errorf("%s: nil event reader", d.name)
	}
	if err := ctx.Err(); err != nil {
		return cs, ps, err
	}
	cs, err = d.scan(ctx, cur, w)
	if err != nil {
		return cs, ps, fmt.Errorf("%s: current window: %w", d.name, err)
	}
	if cs.parsable == 0 && !d.quiet {
		return cs, ps, fmt.Errorf("%s: %w: current window had no event with user_agent, path, status and a time (%d unparsable)",
			d.name, core.ErrNoRecords, cs.unparsable)
	}
	ps, err = d.scan(ctx, prev, w.Previous())
	if err != nil {
		// A failed baseline read is not an empty baseline.
		return cs, ps, fmt.Errorf("%s: preceding window: %w", d.name, err)
	}
	return cs, ps, nil
}

// Detect compares each actor's genuine activity in cur (window w) with prev (w.Previous()).
func (d *Detector) Detect(ctx context.Context, cur, prev core.EventReader, w core.Window) ([]core.Finding, error) {
	cs, ps, err := d.scanBoth(ctx, cur, prev, w)
	if err != nil {
		return nil, err
	}
	base := w.Previous()
	baselineEmpty := ps.parsable == 0

	var out []core.Finding
	for i := range d.actors {
		a, c, p := &d.actors[i], cs.per[i], ps.per[i]
		detail := map[string]any{
			"actor":           a.ID,
			"cur_genuine":     c.genuine,
			"cur_filtered":    c.filtered,
			"cur_ignored":     c.ignored,
			"prev_genuine":    p.genuine,
			"prev_filtered":   p.filtered,
			"prev_ignored":    p.ignored,
			"cur_parsable":    cs.parsable,
			"prev_parsable":   ps.parsable,
			"unparsable_cur":  cs.unparsable,
			"unparsable_prev": ps.unparsable,
			"baseline_empty":  baselineEmpty,
		}
		if a.Label != "" {
			detail["actor_label"] = a.Label
		}
		last, lastIn := c.last, "window"
		if last.IsZero() {
			last, lastIn = p.last, "preceding window"
		}
		if last.IsZero() {
			lastIn = "neither window"
		} else {
			detail["last_genuine"] = last.UTC()
		}
		detail["last_genuine_in"] = lastIn

		var lastText string
		if last.IsZero() {
			lastText = "no genuine activity in the preceding window either"
		} else {
			lastText = fmt.Sprintf("last genuine activity %s (%s)", last.UTC().Format(time.RFC3339), lastIn)
		}
		filtered := ""
		if c.filtered > 0 || c.ignored > 0 {
			filtered = fmt.Sprintf("; %d matching events filtered as noise, %d relayed by ignored infrastructure", c.filtered, c.ignored)
		}

		switch {
		case c.genuine > 0:
			sev := core.SevActivity
			if baselineEmpty {
				sev = core.SevCheck // nothing to compare against
			}
			out = append(out, core.Finding{
				Detector: d.name, Tag: d.name + ":" + a.ID, Severity: sev, Window: w, Baseline: base, Detail: detail,
				Summary: fmt.Sprintf("actor %q: %d genuine events against %d in the preceding window; %s%s",
					a.ID, c.genuine, p.genuine, lastText, filtered),
			})
		case p.genuine > 0 || c.filtered > 0 || c.ignored > 0:
			out = append(out, core.Finding{
				Detector: d.name, Tag: d.name + ":" + a.ID, Severity: core.SevInfo, Window: w, Baseline: base, Detail: detail,
				Summary: fmt.Sprintf("actor %q: no genuine activity in window (%d in the preceding window); %s%s",
					a.ID, p.genuine, lastText, filtered),
			})
		}
		if c.grants > 0 {
			gd := map[string]any{
				"actor":       a.ID,
				"grants":      c.grants,
				"first_grant": c.firstGrant.UTC(),
				"last_grant":  c.lastGrant.UTC(),
				"grant_paths": append([]string(nil), a.GrantPaths...),
			}
			out = append(out, core.Finding{
				Detector: d.name, Tag: d.name + ":" + a.ID + ":grant", Severity: core.SevCritical, Window: w, Baseline: base, Detail: gd,
				Summary: fmt.Sprintf("actor %q: %d successful (2xx) grant requests between %s and %s: the actor may hold a valid credential",
					a.ID, c.grants, c.firstGrant.UTC().Format(time.RFC3339), c.lastGrant.UTC().Format(time.RFC3339)),
			})
		}
	}
	return out, nil
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

var _ core.ActivityReporter = (*Detector)(nil)

// Activity answers "was any actor active in w". An actor is active when it has at least
// one genuine event in the window: not scanner noise on a shared user agent, and not
// relayed by our own infrastructure. It reads through scanBoth and the same scan as
// Detect, so the noise rules exist once. No address appears in the report.
func (d *Detector) Activity(ctx context.Context, cur, prev core.EventReader, w core.Window) (core.ActivityReport, error) {
	cs, ps, err := d.scanBoth(ctx, cur, prev, w)
	if err != nil {
		return core.ActivityReport{}, err
	}
	rep := core.ActivityReport{Seen: cs.parsable + cs.unparsable, Unparsable: cs.unparsable}
	for i := range d.actors {
		a, c, p := &d.actors[i], cs.per[i], ps.per[i]
		sub := core.ActivitySubject{
			Subject: a.ID, Kind: "actor",
			Current: c.genuine, Previous: p.genuine, Last: c.last, LastEarlier: p.last,
			Active: c.genuine > 0, Noise: c.filtered, Ignored: c.ignored,
		}
		if c.grants > 0 {
			sub.Note = fmt.Sprintf("%d successful (2xx) grant request(s): the actor may hold a valid credential", c.grants)
		}
		rep.Subjects = append(rep.Subjects, sub)
	}
	return rep, nil
}

// maxHistoryScan bounds how many stored events History examines per user agent.
const maxHistoryScan = 100000

var _ core.ActorHistorian = (*Detector)(nil)

// History reports, per actor and user agent, when the stored evidence last matched it.
// Events are read newest first through f and judged by the same rules as scan
// (full-string user agent, noise, our own infrastructure), stopping at the first
// genuine one. A stored event that cannot be judged is counted, never skipped silently.
func (d *Detector) History(ctx context.Context, f core.FieldEventFinder) ([]core.ActorHistory, error) {
	if f == nil {
		return nil, fmt.Errorf("%s: nil event finder", d.name)
	}
	var out []core.ActorHistory
	for i := range d.actors {
		a := &d.actors[i]
		uas := make([]string, 0, len(a.uas))
		for ua := range a.uas {
			uas = append(uas, ua)
		}
		sort.Strings(uas)
		for _, ua := range uas {
			h := core.ActorHistory{Actor: a.ID, Label: a.Label, Indicator: ua}
			for ev, err := range f.EventsByField(ctx, FieldUserAgent, ua) {
				if err != nil {
					return nil, fmt.Errorf("%s: actor %q: %w", d.name, a.ID, err)
				}
				if cerr := ctx.Err(); cerr != nil {
					return nil, cerr
				}
				if h.Scanned >= maxHistoryScan {
					h.Capped = true
					break
				}
				h.Scanned++
				path, _ := ev.Fields[FieldPath].(string)
				status, ok := parseStatus(ev.Fields[FieldStatus])
				if path == "" || !ok || ev.Time.IsZero() {
					h.Unparsable++
					continue
				}
				ip, _ := ev.Fields[FieldClientIP].(string)
				switch {
				case d.isIgnored(ip):
					h.Ignored++
				case isNoise(path, status, a.noise, a.BareRoot4xxNoise):
					h.Noise++
				default:
					h.LastGenuine = ev.Time.UTC()
				}
				if !h.LastGenuine.IsZero() {
					break
				}
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			out = append(out, h)
		}
	}
	return out, nil
}
