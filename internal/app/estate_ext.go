package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// ErrTooManyTargets means the request named more targets than the run allows. The run is
// refused whole: truncating would answer for fewer targets than were asked about.
var ErrTooManyTargets = errors.New("too many targets for one run")

// ExternalDeps are the ports the extra collectors ask. None ever contacts a target.
type ExternalDeps struct {
	BGP core.BGPSource
	CT  core.CTSource
	DNS core.DNSForward
	Now func() time.Time
	// Sleep waits between requests; nil sleeps for real. It returns early with the
	// context's error.
	Sleep func(ctx context.Context, d time.Duration) error
}

// ExternalRequest is one collection run of asn, dns or ct.
type ExternalRequest struct {
	Targets    []string
	MaxTargets int
	// Interval is the least time between two requests to the service in one run.
	Interval time.Duration
}

// ExternalFailure is a question that got no answer. It is reported, never stored, with
// one exception: a Truncated failure keeps what was read (see ErrTruncated).
type ExternalFailure struct {
	Target string
	Lookup string // "bgp", "crt.sh" or "dns/<type>"
	Err    error
}

// ExternalResult is what a run observed. Estate holds claims only; the caller merges it
// into an estate file. Notes are reading caveats that belong next to the data.
type ExternalResult struct {
	Targets  []string
	Estate   *casefile.Estate
	Failures []ExternalFailure
	Notes    []string
}

// Complete is true when every question got an answer in full. A real "not found" is an
// answer; a truncated one is not.
func (r ExternalResult) Complete() bool { return len(r.Failures) == 0 }

var (
	domainLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	asnRE         = regexp.MustCompile(`^(?:as)?([0-9]{1,10})$`)
)

// NormaliseDomain lower-cases s, drops one trailing dot and checks it is a DNS name with
// at least two labels whose last label starts with a letter (so an address cannot pass
// for one). It is the only place a domain given on the command line is accepted.
func NormaliseDomain(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	labels := strings.Split(d, ".")
	if len(d) == 0 || len(d) > 253 || len(labels) < 2 {
		return "", fmt.Errorf("%q is not a domain name (need at least two labels)", s)
	}
	for _, l := range labels {
		if !domainLabelRE.MatchString(l) {
			return "", fmt.Errorf("%q is not a domain name", s)
		}
	}
	if last := labels[len(labels)-1]; last[0] < 'a' || last[0] > 'z' {
		return "", fmt.Errorf("%q is not a domain name (the last label must start with a letter)", s)
	}
	return d, nil
}

func canonTargets(targets []string, canon func(string) (string, error), max int) ([]string, error) {
	if len(targets) == 0 {
		return nil, errors.New("no targets given")
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range targets {
		k, err := canon(s)
		if err != nil {
			return nil, err
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	if max <= 0 || len(out) > max {
		return nil, fmt.Errorf("%w: %d given, the cap is %d", ErrTooManyTargets, len(out), max)
	}
	return out, nil
}

type extRun struct {
	*estateCollector
	res      *ExternalResult
	interval time.Duration
	sleep    func(context.Context, time.Duration) error
	asked    int
}

func newExtRun(d ExternalDeps, req ExternalRequest, targets []string) *extRun {
	res := &ExternalResult{Estate: &casefile.Estate{}, Targets: targets}
	sleep := d.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, dur time.Duration) error {
			t := time.NewTimer(dur)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &extRun{
		estateCollector: &estateCollector{d: EstateDeps{Now: d.Now}, out: res.Estate, nodes: map[string]bool{}, edges: map[string]bool{}},
		res:             res, interval: req.Interval, sleep: sleep,
	}
}

// pace waits the rate-limit interval before every request after the first, and reports
// a cancelled context as an error: a question not asked is a failure, not a no.
func (r *extRun) pace(ctx context.Context) error {
	if r.asked > 0 && r.interval > 0 {
		if err := r.sleep(ctx, r.interval); err != nil {
			return fmt.Errorf("%w: not asked: %v", core.ErrLookupFailed, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: not asked: %v", core.ErrLookupFailed, err)
	}
	r.asked++
	return nil
}

func (r *extRun) fail(target, lookup string, err error) {
	r.res.Failures = append(r.res.Failures, ExternalFailure{target, lookup, err})
}

func (r *extRun) note(format string, a ...any) {
	r.res.Notes = append(r.res.Notes, fmt.Sprintf(format, a...))
}

func truncated(what string, kept int) error {
	return fmt.Errorf("%w: %s; kept the first %d, the rest are unknown", core.ErrTruncated, what, kept)
}

// ---- asn ----

// CollectASN asks the BGP data service about each AS number or address and records the
// announced prefixes, origin ASes and holders (source "bgp"). It reads and writes no file.
func CollectASN(ctx context.Context, d ExternalDeps, req ExternalRequest) (ExternalResult, error) {
	targets, err := canonTargets(req.Targets, func(s string) (string, error) {
		s = strings.ToLower(strings.TrimSpace(s))
		if m := asnRE.FindStringSubmatch(s); m != nil {
			n, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil || n == 0 {
				return "", fmt.Errorf("%q is not an AS number (1 to 4294967295)", s)
			}
			return "as" + strconv.FormatUint(n, 10), nil
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf("%q is neither an AS number (AS64500) nor an IP address", s)
		}
		return a.Unmap().String(), nil
	}, req.MaxTargets)
	if err != nil {
		return ExternalResult{Estate: &casefile.Estate{}}, err
	}
	r := newExtRun(d, req, targets)
	var stopped error
	for _, t := range targets {
		if stopped != nil {
			r.fail(t, "bgp", fmt.Errorf("%w: not asked after the service refused a request", stopped))
			continue
		}
		if err := r.pace(ctx); err != nil {
			r.fail(t, "bgp", err)
			continue
		}
		var lerr error
		if m := asnRE.FindStringSubmatch(t); m != nil {
			n, _ := strconv.ParseUint(m[1], 10, 32)
			lerr = r.asn(ctx, t, uint32(n), d.BGP)
		} else {
			lerr = r.ipOrigin(ctx, t, netip.MustParseAddr(t), d.BGP)
		}
		if errors.Is(lerr, core.ErrRateLimited) {
			stopped = core.ErrRateLimited
		}
	}
	r.note("A BGP origin says who announces a range, not who runs the site: for a CDN, transit or hosting address it is the provider, and it says nothing about the visitor behind it.")
	r.note("The AS numbers or addresses asked about were sent to the BGP data service; no address was contacted.")
	return *r.res, nil
}

func asnID(n uint32) string { return "asn:as" + strconv.FormatUint(uint64(n), 10) }

func (r *extRun) holder(h core.BGPHolder, source, method, at string) {
	r.node(asnID(h.ASN), "asn", "AS"+strconv.FormatUint(uint64(h.ASN), 10), source, method, at)
	name := cleanText(h.Holder, 255)
	if part := idPart(name); part != "" {
		r.node("org:"+part, "org", name, source, method, at)
		r.edge(asnID(h.ASN), "org:"+part, "held_by", source, method, at)
	}
}

func (r *extRun) asn(ctx context.Context, target string, n uint32, src core.BGPSource) error {
	ans, err := src.LookupASN(ctx, n)
	at := r.now()
	switch {
	case errors.Is(err, core.ErrNotFound):
		r.node(asnID(n), "asn", "AS"+strconv.FormatUint(uint64(n), 10), "bgp", ans.Query, at)
		r.absence(asnID(n), "bgp", ans.Query, at)
		return nil
	case err != nil:
		r.fail(target, "bgp", err)
		return err
	case len(ans.Prefixes) == 0:
		err := fmt.Errorf("%w: the service answered with no prefix and no not-found", core.ErrLookupFailed)
		r.fail(target, "bgp", err)
		return err
	}
	h := ans.Holder
	h.ASN = n
	r.holder(h, "bgp", ans.Query, at)
	for _, p := range ans.Prefixes {
		id := "network:" + p.String()
		r.node(id, "network", p.String(), "bgp", ans.Query, at)
		r.edge(id, asnID(n), "originated_by", "bgp", ans.Query, at)
	}
	if ans.Truncated {
		r.fail(target, "bgp", truncated("the AS announces more prefixes than the cap", len(ans.Prefixes)))
	}
	return nil
}

func (r *extRun) ipOrigin(ctx context.Context, target string, ip netip.Addr, src core.BGPSource) error {
	ans, err := src.LookupIP(ctx, ip)
	at := r.now()
	ipID := "ip:" + ip.String()
	switch {
	case errors.Is(err, core.ErrNotFound):
		r.node(ipID, "ip", ip.String(), "bgp", ans.Query, at)
		r.absence(ipID, "bgp", ans.Query, at)
		return nil
	case err != nil:
		r.fail(target, "bgp", err)
		return err
	case !ans.Prefix.IsValid() || !ans.Prefix.Contains(ip) || len(ans.Origin) == 0:
		err := fmt.Errorf("%w: the answer has no usable prefix or origin", core.ErrLookupFailed)
		r.fail(target, "bgp", err)
		return err
	}
	netID := "network:" + ans.Prefix.String()
	r.node(ipID, "ip", ip.String(), "bgp", ans.Query, at)
	r.node(netID, "network", ans.Prefix.String(), "bgp", ans.Query, at)
	r.edge(ipID, netID, "announced_in", "bgp", ans.Query, at)
	for _, o := range ans.Origin {
		r.holder(o, "bgp", ans.Query, at)
		r.edge(netID, asnID(o.ASN), "originated_by", "bgp", ans.Query, at)
	}
	return nil
}

// ---- ct ----

const ctInferredFrom = "name on a publicly logged certificate (crt.sh); a certificate name is a candidate, not proof the host exists or is live"

// CollectCT asks the certificate transparency search for each domain and records the
// names on its certificates as candidate hosts (source "crt.sh").
func CollectCT(ctx context.Context, d ExternalDeps, req ExternalRequest) (ExternalResult, error) {
	targets, err := canonTargets(req.Targets, NormaliseDomain, req.MaxTargets)
	if err != nil {
		return ExternalResult{Estate: &casefile.Estate{}}, err
	}
	r := newExtRun(d, req, targets)
	var stopped error
	for _, dom := range targets {
		if stopped != nil {
			r.fail(dom, "crt.sh", fmt.Errorf("%w: not asked after the service refused a request", stopped))
			continue
		}
		if err := r.pace(ctx); err != nil {
			r.fail(dom, "crt.sh", err)
			continue
		}
		ans, err := d.CT.LookupSubdomains(ctx, dom)
		at := r.now()
		domID := "domain:" + dom
		switch {
		case errors.Is(err, core.ErrNotFound):
			r.node(domID, "domain", dom, "crt.sh", ans.Query, at)
			r.absence(domID, "crt.sh", ans.Query, at)
			continue
		case err != nil:
			r.fail(dom, "crt.sh", err)
			if errors.Is(err, core.ErrRateLimited) {
				stopped = core.ErrRateLimited
			}
			continue
		}
		r.node(domID, "domain", dom, "crt.sh", ans.Query, at)
		kept := 0
		for _, raw := range ans.Names {
			name := strings.ToLower(strings.TrimSuffix(raw, "."))
			if !hostRE.MatchString(name) || !(strings.HasSuffix(name, "."+dom)) {
				continue
			}
			r.node("host:"+name, "host", name, "crt.sh", ans.Query, at)
			r.edgeC(domID, "host:"+name, "ct_candidate", "crt.sh", ans.Query, at, "inferred", ctInferredFrom)
			kept++
		}
		r.note("%s: %d candidate host name(s) from certificates; %d wildcard name(s) and %d name(s) outside the domain were seen and not recorded.", dom, kept, ans.Wildcards, ans.OutOfScope)
		if ans.Truncated {
			r.fail(dom, "crt.sh", truncated("the search returned more distinct names than the cap", kept))
		}
	}
	r.note("Names from certificate transparency are candidates, not confirmed live hosts: they may be expired, internal, never served or shared with a CDN, and a wildcard certificate names no host at all.")
	r.note("The domain names asked about were sent to the certificate transparency search service; no host was contacted.")
	return *r.res, nil
}

// ---- dns ----

const spfNote = "SPF names senders the domain owner authorises; it says nothing about where the site is hosted"

// CollectDNS asks a resolver for the A, AAAA, CNAME, MX, NS and SPF records of each
// domain (source "dns").
func CollectDNS(ctx context.Context, d ExternalDeps, req ExternalRequest) (ExternalResult, error) {
	targets, err := canonTargets(req.Targets, NormaliseDomain, req.MaxTargets)
	if err != nil {
		return ExternalResult{Estate: &casefile.Estate{}}, err
	}
	r := newExtRun(d, req, targets)
	for _, dom := range targets {
		for _, t := range core.DNSTypes {
			lookup := "dns/" + string(t)
			if err := r.pace(ctx); err != nil {
				r.fail(dom, lookup, err)
				continue
			}
			ans, err := d.DNS.Lookup(ctx, dom, t)
			at := r.now()
			domID := "domain:" + dom
			switch {
			case errors.Is(err, core.ErrNotFound):
				r.node(domID, "domain", dom, "dns", ans.Query, at)
				r.absence(domID, "dns", ans.Query, at)
				continue
			case err != nil:
				r.fail(dom, lookup, err)
				continue
			case len(ans.Values) == 0:
				r.fail(dom, lookup, fmt.Errorf("%w: the resolver answered with no value and no not-found", core.ErrLookupFailed))
				continue
			}
			r.node(domID, "domain", dom, "dns", ans.Query, at)
			bad := 0
			for _, v := range ans.Values {
				if !r.dnsValue(domID, t, v, ans.Query, at) {
					bad++
				}
			}
			if bad > 0 {
				r.fail(dom, lookup, fmt.Errorf("%w: %d value(s) were not valid for %s and were not recorded", core.ErrLookupFailed, bad, t))
			}
			if ans.Truncated {
				r.fail(dom, lookup, truncated("the resolver returned more values than the cap", len(ans.Values)))
			}
		}
	}
	r.note("An address a name resolves to is where it is served from today: for a CDN, proxy or shared hosting it is the provider's edge, and it says nothing about who runs the site or the visitor behind it.")
	r.note("Records are what one resolver returned at one time; a different resolver or vantage point can return different answers.")
	r.note("The names asked about were sent to the resolver, which asks the domain's name servers on your behalf; no host was contacted by jb.")
	return *r.res, nil
}

// dnsValue records one value and reports whether it was usable.
func (r *extRun) dnsValue(domID string, t core.DNSType, v, method, at string) bool {
	switch t {
	case core.DNSA, core.DNSAAAA:
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" || (t == core.DNSA && !a.Is4()) || (t == core.DNSAAAA && !a.Is6()) {
			return false
		}
		r.node("ip:"+a.String(), "ip", a.String(), "dns", method, at)
		r.edge(domID, "ip:"+a.String(), "resolves_to", "dns", method, at)
	case core.DNSCNAME, core.DNSMX, core.DNSNS:
		name := strings.ToLower(strings.TrimSuffix(v, "."))
		if !hostRE.MatchString(name) {
			return false
		}
		rel := map[core.DNSType]string{core.DNSCNAME: "cname", core.DNSMX: "mx", core.DNSNS: "ns"}[t]
		r.node("host:"+name, "host", name, "dns", method, at)
		r.edge(domID, "host:"+name, rel, "dns", method, at)
	case core.DNSSPF:
		return r.spf(domID, v, method, at)
	default:
		return false
	}
	return true
}

const maxSPFItems = 50

// spf records include, redirect, ip4 and ip6 terms. The a, mx, ptr and exists
// mechanisms name no fixed thing and are not followed (no further lookup is made).
func (r *extRun) spf(domID, record, method, at string) bool {
	ok := true
	n := 0
	for _, tok := range strings.Fields(strings.ToLower(record))[1:] {
		tok = strings.TrimLeft(tok, "+-~?")
		var key, val string
		if k, v, found := strings.Cut(tok, ":"); found {
			key, val = k, v
		} else if k, v, found := strings.Cut(tok, "="); found {
			key, val = k, v
		} else {
			continue
		}
		switch key {
		case "include", "redirect":
			val = strings.TrimSuffix(val, ".")
			if strings.Contains(val, "%") { // an SPF macro is a pattern, not a name
				continue
			}
			if !hostRE.MatchString(val) {
				ok = false
				continue
			}
			if n++; n > maxSPFItems {
				return false
			}
			r.node("domain:"+val, "domain", val, "dns", method, at)
			r.edge(domID, "domain:"+val, "spf_"+key, "dns", method, at)
		case "ip4", "ip6":
			if n++; n > maxSPFItems {
				return false
			}
			if p, err := netip.ParsePrefix(val); err == nil {
				p = p.Masked()
				if (key == "ip4") != p.Addr().Is4() {
					ok = false
					continue
				}
				if p.IsSingleIP() {
					r.node("ip:"+p.Addr().String(), "ip", p.Addr().String(), "dns", method, at)
					r.edge(domID, "ip:"+p.Addr().String(), "spf_authorises", "dns", method, at)
				} else {
					r.node("network:"+p.String(), "network", p.String(), "dns", method, at)
					r.edge(domID, "network:"+p.String(), "spf_authorises", "dns", method, at)
				}
			} else if a, err := netip.ParseAddr(val); err == nil && (key == "ip4") == a.Is4() {
				r.node("ip:"+a.String(), "ip", a.String(), "dns", method, at)
				r.edge(domID, "ip:"+a.String(), "spf_authorises", "dns", method, at)
			} else {
				ok = false
			}
		}
	}
	if ok {
		r.noteOnce(spfNote)
	}
	return ok
}

func (r *extRun) noteOnce(s string) {
	for _, n := range r.res.Notes {
		if n == s {
			return
		}
	}
	r.res.Notes = append(r.res.Notes, s)
}
