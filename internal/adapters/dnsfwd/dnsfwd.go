// Package dnsfwd is a core.DNSForward over a net.Resolver: A, AAAA, CNAME, MX, NS and
// the SPF policy among the TXT records.
//
// What it will and will not do:
//
//   - Passive. It asks a DNS resolver. It never dials the name it is asked about or any
//     address that name resolves to.
//   - Failure is not silence. NXDOMAIN and "no such record" are core.ErrNotFound. A
//     timeout, SERVFAIL, an unreachable resolver or a cancelled context are
//     core.ErrLookupFailed, never an answer.
//   - Bounded. One timeout per lookup, at most MaxValues values kept; more is reported
//     through Truncated, never dropped silently.
//   - TXT is read for SPF only. Other TXT values are not returned: they can hold
//     verification tokens and are not infrastructure relationships.
//   - Values are text chosen by whoever controls the zone. Names that are not plausible
//     DNS names are dropped and counted as a failure, not recorded.
//
// The *net.Resolver is injected, so tests use one whose Dial reaches a fake server.
package dnsfwd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	// DefaultTimeout bounds one lookup.
	DefaultTimeout = 5 * time.Second
	// DefaultMaxValues bounds the values kept for one name and type.
	DefaultMaxValues = 20

	maxSPF = 1024
)

var nameRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$`)

var _ core.DNSForward = (*Resolver)(nil)

// Resolver asks the injected net.Resolver.
type Resolver struct {
	R         *net.Resolver // nil means net.DefaultResolver
	Label     string        // names the resolver in the recorded method
	Timeout   time.Duration // per lookup; <= 0 means DefaultTimeout
	MaxValues int           // <= 0 means DefaultMaxValues
}

// New returns a Resolver with the default bounds.
func New(r *net.Resolver, label string) *Resolver {
	return &Resolver{R: r, Label: label, Timeout: DefaultTimeout, MaxValues: DefaultMaxValues}
}

// Lookup implements core.DNSForward.
func (r *Resolver) Lookup(ctx context.Context, name string, t core.DNSType) (core.DNSAnswer, error) {
	label := string(t)
	if t == core.DNSSPF {
		label = "TXT (SPF only)"
	}
	ans := core.DNSAnswer{Query: fmt.Sprintf("%s %s via %s", label, name, r.Label)}
	res := r.R
	if res == nil {
		res = net.DefaultResolver
	}
	timeout, max := r.Timeout, r.MaxValues
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if max <= 0 {
		max = DefaultMaxValues
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var vals []string
	var err error
	switch t {
	case core.DNSA, core.DNSAAAA:
		network := "ip4"
		if t == core.DNSAAAA {
			network = "ip6"
		}
		var addrs []string
		ips, e := res.LookupNetIP(ctx, network, name)
		err = e
		for _, a := range ips {
			addrs = append(addrs, a.Unmap().String())
		}
		vals = addrs
	case core.DNSCNAME:
		var c string
		c, err = res.LookupCNAME(ctx, name)
		c = strings.ToLower(strings.TrimSuffix(c, "."))
		// Go returns the name itself when it has no CNAME.
		if err == nil && (c == "" || c == strings.ToLower(strings.TrimSuffix(name, "."))) {
			return ans, fmt.Errorf("%w: no CNAME record", core.ErrNotFound)
		}
		vals = []string{c}
	case core.DNSMX:
		var mx []*net.MX
		mx, err = res.LookupMX(ctx, name)
		nullMX := false
		for _, m := range mx {
			if m.Host == "." {
				nullMX = true
				continue
			}
			vals = append(vals, m.Host)
		}
		if err == nil && len(vals) == 0 && nullMX {
			return ans, fmt.Errorf("%w: null MX (the domain says it accepts no mail)", core.ErrNotFound)
		}
	case core.DNSNS:
		var ns []*net.NS
		ns, err = res.LookupNS(ctx, name)
		for _, n := range ns {
			vals = append(vals, n.Host)
		}
	case core.DNSSPF:
		var txt []string
		txt, err = res.LookupTXT(ctx, name)
		for _, v := range txt {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=spf1") {
				v = strings.TrimSpace(v)
				if len(v) > maxSPF {
					return ans, fmt.Errorf("%w: SPF record larger than %d bytes", core.ErrLookupFailed, maxSPF)
				}
				vals = append(vals, v)
			}
		}
		if err == nil && len(vals) == 0 {
			return ans, fmt.Errorf("%w: no SPF record among %d TXT record(s)", core.ErrNotFound, len(txt))
		}
	default:
		return ans, fmt.Errorf("%w: unsupported record type %q", core.ErrLookupFailed, t)
	}
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return ans, fmt.Errorf("%w: no %s record", core.ErrNotFound, label)
		}
		return ans, fmt.Errorf("%w: %v", core.ErrLookupFailed, err)
	}
	seen := map[string]bool{}
	bad := 0
	for _, v := range vals {
		if t != core.DNSSPF && t != core.DNSA && t != core.DNSAAAA {
			v = strings.ToLower(strings.TrimSuffix(v, "."))
			if !nameRE.MatchString(v) {
				bad++
				continue
			}
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		if len(ans.Values) == max {
			ans.Truncated = true
			break
		}
		ans.Values = append(ans.Values, v)
	}
	if bad > 0 {
		return ans, fmt.Errorf("%w: %d value(s) are not DNS names; the answer is not recorded", core.ErrLookupFailed, bad)
	}
	if len(ans.Values) == 0 {
		return ans, fmt.Errorf("%w: the resolver answered with no usable %s value", core.ErrLookupFailed, label)
	}
	return ans, nil
}
