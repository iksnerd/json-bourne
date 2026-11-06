package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/core"
)

// ErrTooManyIPs means the request named more addresses than the run allows. The run is
// refused whole: truncating would answer for fewer addresses than were asked about.
var ErrTooManyIPs = errors.New("too many addresses for one run")

// EstateDeps are the ports the collector asks. Neither ever contacts an address.
type EstateDeps struct {
	PTR  core.PTRResolver
	RDAP core.RDAPRegistry
	Now  func() time.Time
}

// EstateRequest is one collection run.
type EstateRequest struct {
	IPs    []string
	MaxIPs int
}

// EstateFailure is a question that got no answer. It is reported, never stored.
type EstateFailure struct {
	IP     string
	Lookup string // "rdns" or "rdap"
	Err    error
}

// EstateResult is what a run observed. Estate holds claims only (no apiVersion, id or
// caveat); the caller merges it into an estate file.
type EstateResult struct {
	IPs      []netip.Addr
	Estate   *casefile.Estate
	Failures []EstateFailure
}

// Complete is true when every question got an answer. A real "not found" is an answer.
func (r EstateResult) Complete() bool { return len(r.Failures) == 0 }

var hostRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$`)

// CollectEstate asks, for each address, the PTR record and the RDAP registration, and
// turns the answers into estate claims stamped with source, method and time. It does
// not read or write files.
//
// A lookup that failed is a failure for that address and leaves no node. A real
// not-found becomes an absence. After the registry rate limits, it is not asked again
// in this run, and each address it was not asked about is listed as a failure.
func CollectEstate(ctx context.Context, d EstateDeps, req EstateRequest) (EstateResult, error) {
	res := EstateResult{Estate: &casefile.Estate{}}
	if len(req.IPs) == 0 {
		return res, errors.New("no addresses given")
	}
	seen := map[netip.Addr]bool{}
	for _, s := range req.IPs {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.Zone() != "" {
			return res, fmt.Errorf("%q is not an IP address", s)
		}
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			res.IPs = append(res.IPs, a)
		}
	}
	if req.MaxIPs <= 0 || len(res.IPs) > req.MaxIPs {
		return EstateResult{Estate: res.Estate}, fmt.Errorf("%w: %d given, the cap is %d", ErrTooManyIPs, len(res.IPs), req.MaxIPs)
	}

	c := &estateCollector{d: d, out: res.Estate, nodes: map[string]bool{}, edges: map[string]bool{}}
	var rdapStopped error
	for _, ip := range res.IPs {
		c.ptr(ctx, ip, &res)
		if rdapStopped != nil {
			res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdap", fmt.Errorf("%w: not asked after the registry refused a request", rdapStopped)})
			continue
		}
		if err := c.rdap(ctx, ip, &res); errors.Is(err, core.ErrRateLimited) {
			rdapStopped = core.ErrRateLimited
		}
	}
	return res, nil
}

type estateCollector struct {
	d     EstateDeps
	out   *casefile.Estate
	nodes map[string]bool
	edges map[string]bool
}

func (c *estateCollector) now() string {
	n := time.Now
	if c.d.Now != nil {
		n = c.d.Now
	}
	return n().UTC().Truncate(time.Second).Format(time.RFC3339)
}

func (c *estateCollector) node(id, kind, label, source, method, observed string) {
	if c.nodes[id] {
		return
	}
	c.nodes[id] = true
	c.out.Nodes = append(c.out.Nodes, casefile.Node{ID: id, Kind: kind, Label: label, Source: source, Method: method, Observed: observed})
}

func (c *estateCollector) edge(from, to, relation, source, method, observed string) {
	c.edgeC(from, to, relation, source, method, observed, "stated", "")
}

func (c *estateCollector) edgeC(from, to, relation, source, method, observed, confidence, inferredFrom string) {
	k := from + "\x00" + to + "\x00" + relation + "\x00" + source
	if c.edges[k] {
		return
	}
	c.edges[k] = true
	c.out.Edges = append(c.out.Edges, casefile.Edge{From: from, To: to, Relation: relation, Source: source, Method: method, Observed: observed, Confidence: confidence, InferredFrom: inferredFrom})
}

func (c *estateCollector) absence(subject, source, method, observed string) {
	c.out.Absences = append(c.out.Absences, casefile.Absence{Subject: subject, Source: source, Method: method, Observed: observed, Answer: casefile.AbsenceAnswer})
}

func (c *estateCollector) ptr(ctx context.Context, ip netip.Addr, res *EstateResult) {
	if err := ctx.Err(); err != nil {
		res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdns", fmt.Errorf("%w: not asked: %v", core.ErrLookupFailed, err)})
		return
	}
	ipID := "ip:" + ip.String()
	ans, err := c.d.PTR.LookupPTR(ctx, ip)
	at := c.now()
	switch {
	case errors.Is(err, core.ErrNotFound):
		c.node(ipID, "ip", ip.String(), "rdns", ans.Query, at)
		c.absence(ipID, "rdns", ans.Query, at)
		return
	case err != nil:
		res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdns", err})
		return
	}
	c.node(ipID, "ip", ip.String(), "rdns", ans.Query, at)
	bad := 0
	for _, raw := range ans.Names {
		name := strings.ToLower(strings.TrimSuffix(raw, "."))
		if !hostRE.MatchString(name) {
			bad++
			continue
		}
		c.node("host:"+name, "host", name, "rdns", ans.Query, at)
		c.edge(ipID, "host:"+name, "ptr", "rdns", ans.Query, at)
	}
	if bad > 0 {
		res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdns", fmt.Errorf("%w: %d PTR value(s) are not DNS names and were not recorded", core.ErrLookupFailed, bad)})
	} else if len(ans.Names) == 0 {
		// A success with no names is not a not-found answer and not data.
		res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdns", fmt.Errorf("%w: the resolver answered with no PTR value", core.ErrLookupFailed)})
	}
}

func (c *estateCollector) rdap(ctx context.Context, ip netip.Addr, res *EstateResult) error {
	if err := ctx.Err(); err != nil {
		err = fmt.Errorf("%w: not asked: %v", core.ErrLookupFailed, err)
		res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdap", err})
		return err
	}
	ipID := "ip:" + ip.String()
	n, err := c.d.RDAP.LookupIP(ctx, ip)
	at := c.now()
	switch {
	case errors.Is(err, core.ErrNotFound):
		c.node(ipID, "ip", ip.String(), "rdap", n.Query, at)
		c.absence(ipID, "rdap", n.Query, at)
		return nil
	case err != nil:
		res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdap", err})
		return err
	}
	netPart := idPart(n.Handle)
	if netPart == "" {
		netPart = idPart(n.Start + "-" + n.End)
	}
	if netPart == "" {
		err := fmt.Errorf("%w: the registry record has no handle or range", core.ErrLookupFailed)
		res.Failures = append(res.Failures, EstateFailure{ip.String(), "rdap", err})
		return err
	}
	c.node(ipID, "ip", ip.String(), "rdap", n.Query, at)
	netID := "network:" + netPart
	label := cleanText(strings.TrimSpace(n.Name+" "+n.Start+" - "+n.End), 255)
	c.node(netID, "network", label, "rdap", n.Query, at)
	c.edge(ipID, netID, "within", "rdap", n.Query, at)
	for _, e := range n.Entities {
		if !hasRole(e.Roles, "registrant") {
			continue
		}
		part := idPart(e.Handle)
		if part == "" {
			continue
		}
		name := cleanText(e.Name, 255)
		if name == "" {
			name = part
		}
		c.node("org:"+part, "org", name, "rdap", n.Query, at)
		c.edge(netID, "org:"+part, "registered_to", "rdap", n.Query, at)
	}
	return nil
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// cleanText makes text from a remote registry safe for a one-line label: control
// characters become spaces, runs of space collapse, and the length is capped on a rune
// boundary.
func cleanText(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			r = ' '
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// idPart turns registry text into the part of a node id after "kind:".
func idPart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 200 {
			break
		}
	}
	return strings.Trim(b.String(), "-.")
}
