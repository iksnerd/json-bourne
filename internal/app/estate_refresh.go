package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

// RefreshTargets are the questions an estate file already records having asked, read
// back out of its claims. Nothing here is guessed from outside the file: a refresh asks
// again what the file shows was asked, with the same kind of question, and never widens
// the set (a name that only appeared as an answer, such as an SPF include or a PTR
// target, was not asked about and is not a target).
type RefreshTargets struct {
	DNS       []string // domains whose forward records were asked of a resolver
	CT        []string // domains searched in certificate transparency
	Addresses []string // addresses asked for reverse DNS and RDAP
	BGPIPs    []string // addresses asked for their BGP origin
	BGPASNs   []string // AS numbers asked for their announced prefixes, as AS64500
}

// Total is the number of distinct targets across all services.
func (t RefreshTargets) Total() int {
	seen := map[string]bool{}
	for _, l := range [][]string{t.DNS, t.CT, t.Addresses, t.BGPIPs, t.BGPASNs} {
		for _, s := range l {
			seen[s] = true
		}
	}
	return len(seen)
}

// EstateTargets reads the recorded questions out of e. The rules are structural, on the
// shape of the claims the collectors write, not on the text of a method:
//
//   - dns: a domain with an edge or an absence from source dns, or a domain node from dns
//     that no spf_include or spf_redirect edge points at.
//   - ct: a domain with a ct_candidate edge, an absence, or a node from crt.sh.
//   - rdns and rdap: an address with an edge, an absence or a node from either source.
//   - bgp for an address: an address with an announced_in edge or an absence from bgp.
//   - bgp for an AS: an AS with an absence from bgp, or an originated_by edge from bgp
//     that no announced_in edge shares a method with (an address question writes both).
func EstateTargets(e *casefile.Estate) RefreshTargets {
	dns, ct, addr, bgpIP, bgpAS := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	pointedAt := map[string]bool{} // domains that are the object of an SPF include or redirect
	announcedMethods := map[string]bool{}
	for _, ed := range e.Edges {
		if ed.Source == "dns" && (ed.Relation == "spf_include" || ed.Relation == "spf_redirect") {
			pointedAt[ed.To] = true
		}
		if ed.Source == "bgp" && ed.Relation == "announced_in" {
			announcedMethods[ed.Method] = true
		}
	}
	domain := func(id string) (string, bool) { return strings.CutPrefix(id, "domain:") }
	ip := func(id string) (string, bool) {
		s, ok := strings.CutPrefix(id, "ip:")
		if !ok {
			return "", false
		}
		a, err := netip.ParseAddr(s)
		return a.String(), err == nil
	}
	asn := func(id string) (string, bool) {
		s, ok := strings.CutPrefix(id, "asn:as")
		if !ok {
			return "", false
		}
		if _, err := strconv.ParseUint(s, 10, 32); err != nil {
			return "", false
		}
		return "AS" + s, true
	}
	touch := func(id, source string, viaNode bool) {
		switch source {
		case "dns":
			if d, ok := domain(id); ok && (!viaNode || !pointedAt[id]) {
				dns[d] = true
			}
		case "crt.sh":
			if d, ok := domain(id); ok {
				ct[d] = true
			}
		case "rdns", "rdap":
			if a, ok := ip(id); ok {
				addr[a] = true
			}
		}
	}
	for _, n := range e.Nodes {
		touch(n.ID, n.Source, true)
	}
	for _, ed := range e.Edges {
		touch(ed.From, ed.Source, false)
		if ed.Source == "bgp" {
			switch ed.Relation {
			case "announced_in":
				if a, ok := ip(ed.From); ok {
					bgpIP[a] = true
				}
			case "originated_by":
				if !announcedMethods[ed.Method] {
					if a, ok := asn(ed.To); ok {
						bgpAS[a] = true
					}
				}
			}
		}
	}
	for _, a := range e.Absences {
		touch(a.Subject, a.Source, false)
		if a.Source == "bgp" {
			if x, ok := ip(a.Subject); ok {
				bgpIP[x] = true
			}
			if x, ok := asn(a.Subject); ok {
				bgpAS[x] = true
			}
		}
	}
	list := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return RefreshTargets{DNS: list(dns), CT: list(ct), Addresses: list(addr), BGPIPs: list(bgpIP), BGPASNs: list(bgpAS)}
}

// RefreshDeps are the ports a refresh asks. Enabled says whether the operator switched
// an external service on (estate.external); a service that is off is skipped and listed,
// and its question is not sent.
type RefreshDeps struct {
	Estate  EstateDeps
	Ext     ExternalDeps
	Enabled func(service string) bool
	Now     func() time.Time
}

// RefreshRequest is one refresh run.
type RefreshRequest struct {
	Base       *casefile.Estate
	BasedOn    string
	MaxTargets int
	// Intervals are the least times between two requests to each external service.
	BGPInterval, CTInterval, DNSInterval time.Duration
}

// ErrNoTargets means the estate file names nothing to ask again.
var ErrNoTargets = errors.New("the estate file records no target to refresh")

const maxFailureText = 300

func failText(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > maxFailureText {
		s = strings.ToValidUTF8(s[:maxFailureText], "") + "..."
	}
	return s
}

// RefreshEstate re-runs the passive collectors for the targets already recorded in
// req.Base and returns the result as a snapshot. It reads and writes no file. A target
// list longer than req.MaxTargets is refused whole. A service that is not enabled is
// skipped and listed; a lookup that failed, was cut at a cap or was not asked makes the
// snapshot incomplete, and so does a claim that conflicts with another in the same run.
func RefreshEstate(ctx context.Context, d RefreshDeps, req RefreshRequest) (*casefile.EstateSnapshot, error) {
	t := EstateTargets(req.Base)
	if t.Total() == 0 {
		return nil, ErrNoTargets
	}
	if req.MaxTargets <= 0 || t.Total() > req.MaxTargets {
		return nil, fmt.Errorf("%w: %d given, the cap is %d", ErrTooManyTargets, t.Total(), req.MaxTargets)
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	taken := now().UTC().Truncate(time.Second)
	snap := &casefile.EstateSnapshot{
		APIVersion: casefile.EstateSnapshotAPIVersion, ID: casefile.SnapshotID(taken), Taken: taken.Format(time.RFC3339),
		BasedOn:  req.BasedOn,
		Targets:  casefile.SnapshotTargets{Domains: union(t.DNS, t.CT), Addresses: union(t.Addresses, t.BGPIPs), ASNs: t.BGPASNs},
		Estate:   casefile.Estate{APIVersion: casefile.EstateAPIVersion, ID: "estate", Caveat: casefile.DefaultEstateCaveat, Subject: req.Base.Subject},
		Services: []casefile.SnapshotService{},
	}
	fail := func(target, lookup string, err error) {
		snap.Failures = append(snap.Failures, casefile.SnapshotFailure{Target: target, Lookup: lookup, Reason: failText(err)})
	}
	merge := func(frag *casefile.Estate) {
		merged, mr := casefile.MergeEstate(&snap.Estate, frag)
		snap.Estate = *merged
		for _, c := range mr.Conflicts {
			fail("-", "merge", errors.New(c))
		}
	}
	svc := func(name string, targets int, run func() error) {
		s := casefile.SnapshotService{Name: name, Targets: targets}
		switch {
		case targets == 0:
			s.State, s.Reason = casefile.ServiceNone, "the estate file records no target for this service"
		case name != "rdap" && (d.Enabled == nil || !d.Enabled(name)):
			s.State, s.Reason = casefile.ServiceSkipped, "not enabled in estate.external, so nothing was sent for its "+strconv.Itoa(targets)+" target(s)"
		default:
			s.State = casefile.ServiceRan
			if err := run(); err != nil {
				fail("-", name, err)
			}
		}
		snap.Services = append(snap.Services, s)
	}

	// Reverse DNS and RDAP are the older address lookups and are not behind the switch.
	svc("rdap", len(t.Addresses), func() error {
		res, err := CollectEstate(ctx, d.Estate, EstateRequest{IPs: t.Addresses, MaxIPs: len(t.Addresses)})
		if err != nil {
			return err
		}
		for _, f := range res.Failures {
			fail(f.IP, f.Lookup, f.Err)
		}
		merge(res.Estate)
		return nil
	})
	ext := func(name string, targets []string, interval time.Duration, collect extCollectFn) {
		svc(name, len(targets), func() error {
			res, err := collect(ctx, d.Ext, ExternalRequest{Targets: targets, MaxTargets: len(targets), Interval: interval})
			if err != nil {
				return err
			}
			for _, f := range res.Failures {
				fail(f.Target, f.Lookup, f.Err)
			}
			merge(res.Estate)
			return nil
		})
	}
	ext("bgp", union(t.BGPIPs, t.BGPASNs), req.BGPInterval, CollectASN)
	ext("dns", t.DNS, req.DNSInterval, CollectDNS)
	ext("crt.sh", t.CT, req.CTInterval, CollectCT)

	carryBaseline(&snap.Estate, req.Base)
	snap.Complete = len(snap.Failures) == 0
	return snap, nil
}

// carryBaseline copies what the collectors never write from the baseline into the new
// body, so that promoting a snapshot does not erase it. The facts of a node go onto the
// same node of the snapshot unchanged (value, source, method and time); they are not
// asked again. A node the snapshot does not name takes its facts with it: the diff lists
// that group as not comparable, and the archive made by promotion keeps the old file.
// An assessment is carried when its subject and every basis reference still resolve.
func carryBaseline(body, base *casefile.Estate) {
	facts := map[string][]casefile.Fact{}
	for _, n := range base.Nodes {
		if len(n.Facts) > 0 {
			facts[n.ID] = n.Facts
		}
	}
	keys := map[string]map[string]bool{}
	for i := range body.Nodes {
		n := &body.Nodes[i]
		n.Facts = append([]casefile.Fact(nil), facts[n.ID]...)
		keys[n.ID] = map[string]bool{}
		for _, f := range n.Facts {
			keys[n.ID][f.Key] = true
		}
	}
	resolves := func(ref string) bool {
		node, key, hasKey := strings.Cut(ref, "#")
		k, ok := keys[node]
		return ok && (!hasKey || k[key])
	}
	for _, a := range base.Assessments {
		ok := resolves(a.Subject)
		for _, ref := range a.Basis {
			ok = ok && resolves(ref)
		}
		if ok {
			body.Assessments = append(body.Assessments, a)
		}
	}
}

type extCollectFn func(context.Context, ExternalDeps, ExternalRequest) (ExternalResult, error)

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ErrNotPromotable means a snapshot may not become the baseline.
var ErrNotPromotable = errors.New("snapshot cannot become the baseline")

// PromoteSnapshot makes a snapshot the baseline: it archives the current estate file
// (case-relative path returned), then replaces it with the snapshot's body. An incomplete
// snapshot is refused, and so is one with a skipped service, because the replaced file
// would silently lose that service's claims. Promotion is the only way a snapshot
// becomes the baseline.
func PromoteSnapshot(c *casefile.Case, id, file string, now time.Time) (archived string, err error) {
	s, err := casefile.LoadEstateSnapshot(c, id)
	if err != nil {
		return "", err
	}
	if !s.Complete {
		return "", fmt.Errorf("%w: %s is incomplete (%d lookup(s) got no full answer)", ErrNotPromotable, id, len(s.Failures))
	}
	var skipped []string
	for _, sv := range s.Services {
		if sv.State == casefile.ServiceSkipped {
			skipped = append(skipped, sv.Name)
		}
	}
	if len(skipped) > 0 {
		return "", fmt.Errorf("%w: %s skipped %s, so promoting it would drop that service's claims from the baseline; enable the service and refresh again", ErrNotPromotable, id, strings.Join(skipped, ", "))
	}
	archived, err = casefile.ArchiveEstateFile(c, file, casefile.SnapshotID(now))
	if err != nil {
		return "", fmt.Errorf("could not archive the current baseline, so it was not replaced: %w", err)
	}
	body := s.Estate
	if err := casefile.SaveEstateFile(c, file, &body); err != nil {
		return archived, err
	}
	return archived, nil
}
