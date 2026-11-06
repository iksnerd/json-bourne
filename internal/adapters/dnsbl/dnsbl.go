// Package dnsbl is a core.Feed for DNS blocklists (DNSBL): an IP address is looked up
// as a name under the list's zone, 4.3.2.1.<zone> for 1.2.3.4, and the answer is read
// from the A record.
//
// What it will and will not do:
//
//   - The indicator is sent to a DNS resolver and, through it, to the operator of the
//     zone. That is what a DNSBL lookup is, and why the config layer keeps this feed off
//     until the operator enables it. The address itself is never dialled: the
//     question is a name, asked of an injected Resolver.
//   - NXDOMAIN (or no A record) is a real answer: not listed, recorded as
//     core.VerdictNotFound. Everything else that is not a usable listing is a
//     core.LookupError for that indicator: a timeout, SERVFAIL, REFUSED, an unreachable
//     resolver, a cancelled context and an exhausted lookup budget.
//   - A DNSBL operator answers a resolver it will not serve (a public or open resolver,
//     a query volume over its limit) with a code in 127.255.255.0/24, or a hijacking
//     resolver answers with an address outside 127.0.0.0/8. Neither says anything about
//     the indicator, so both are lookup errors, never "not listed" and never "listed".
//     After a refusal nothing more is sent to the zone in that run.
//   - Bounded: at most MaxLookups questions per Lookup call, MinInterval between them,
//     Timeout per question, at most maxCodes return codes kept.
//   - IPv4 is the default. An IPv6 address is asked as 32 reversed nibbles when IPv6 is
//     enabled and is a lookup error otherwise: a zone that does not publish IPv6 data
//     answers NXDOMAIN for every address, which would read as "not listed".
//
// The resolver must tell NXDOMAIN from other failures. net.Resolver does that with the
// pure Go resolver (PreferGo); the config layer builds it that way.
//
// A listing is context about an address. It is not attribution: a CDN or proxy edge
// address says nothing about the visitor behind it.
package dnsbl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// maxCodes bounds how many return codes are copied into one verdict.
const maxCodes = 8

// Resolver is the port the feed asks. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var (
	_ core.Feed = (*Feed)(nil)
	_ Resolver  = (*net.Resolver)(nil)
)

var (
	refusalNet  = netip.MustParsePrefix("127.255.255.0/24")
	loopbackNet = netip.MustParsePrefix("127.0.0.0/8")
)

// Feed looks addresses up under one DNSBL zone.
type Feed struct {
	Zone        string                // e.g. "zen.example.org"; see ValidZone
	Resolver    Resolver              // nil means net.DefaultResolver
	Codes       map[netip.Addr]string // 127.x.y.z -> label; a listed code not here is "unmapped"
	ErrorCodes  []netip.Addr          // 127.x addresses this zone uses to refuse service, besides 127.255.255.0/24
	IPv6        bool                  // the zone publishes IPv6 data
	MaxLookups  int                   // questions per Lookup call; <= 0 allows none
	MinInterval time.Duration         // pause between two questions
	Timeout     time.Duration         // per question; <= 0 means 5s

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

func (f *Feed) Name() string { return "dnsbl:" + f.Zone }

func (f *Feed) now() time.Time {
	if f.Now != nil {
		return f.Now().UTC()
	}
	return time.Now().UTC()
}

func (f *Feed) sleep(ctx context.Context, d time.Duration) error {
	if f.Sleep != nil {
		return f.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ValidZone reports whether z is a plain DNS zone name: lower-case labels of letters,
// digits and hyphen, at least two labels, no trailing dot, not an IP address.
func ValidZone(z string) error {
	if len(z) == 0 || len(z) > 200 {
		return errors.New("zone must be 1 to 200 characters")
	}
	if z != strings.ToLower(z) {
		return errors.New("zone must be lower case")
	}
	if _, err := netip.ParseAddr(z); err == nil {
		return errors.New("zone must be a DNS name, not an IP address")
	}
	labels := strings.Split(z, ".")
	if len(labels) < 2 {
		return errors.New("zone must have at least two labels, for example bl.example.org")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("zone has an empty, over-long or hyphen-edged label (no leading or trailing dot)")
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("zone labels may hold only letters, digits and hyphen")
			}
		}
	}
	return nil
}

// QueryName is the fully qualified name (trailing dot) asked for addr under zone:
// reversed octets for IPv4, reversed nibbles for IPv6. An IPv4-mapped IPv6 address is
// asked as its IPv4 address. The trailing dot matters: without it the system resolver's
// search list can append local domains and send a second, unintended question.
func QueryName(addr netip.Addr, zone string) string {
	addr = addr.Unmap()
	var sb strings.Builder
	if addr.Is4() {
		b := addr.As4()
		fmt.Fprintf(&sb, "%d.%d.%d.%d.", b[3], b[2], b[1], b[0])
	} else {
		b := addr.As16()
		for i := 15; i >= 0; i-- {
			fmt.Fprintf(&sb, "%x.%x.", b[i]&0x0f, b[i]>>4)
		}
	}
	return sb.String() + zone + "."
}

// Lookup asks the zone about each indicator, in order. Answers are in the slice,
// failures are joined *core.LookupError.
func (f *Feed) Lookup(ctx context.Context, indicators []string) ([]core.Reputation, error) {
	var (
		out     []core.Reputation
		errs    []error
		asked   int
		stopped error // set after a refusal: nothing more is sent
	)
	fail := func(ind string, cause error, detail string) {
		errs = append(errs, &core.LookupError{Indicator: ind, Err: fmt.Errorf("%w: %s", cause, detail)})
	}
	zoneErr := ValidZone(f.Zone)
	for _, ind := range indicators {
		addr, perr := netip.ParseAddr(ind)
		if perr != nil || addr.Zone() != "" {
			fail(ind, core.ErrFeedFailed, "not an IP address, not sent")
			continue
		}
		if zoneErr != nil {
			fail(ind, core.ErrFeedFailed, "invalid zone, not sent: "+zoneErr.Error())
			continue
		}
		if !f.IPv6 && !addr.Unmap().Is4() {
			fail(ind, core.ErrFeedFailed, "IPv6 is not enabled for this zone (ipv6: true), not sent; a zone without IPv6 data answers NXDOMAIN for everything, which would read as not listed")
			continue
		}
		if stopped != nil {
			fail(ind, core.ErrFeedFailed, "not asked after the zone refused service")
			continue
		}
		if asked >= f.MaxLookups {
			fail(ind, core.ErrBudgetExceeded, fmt.Sprintf("not asked: the per-run cap is %d lookups", f.MaxLookups))
			continue
		}
		if err := ctx.Err(); err != nil {
			fail(ind, core.ErrFeedFailed, "not asked: "+err.Error())
			continue
		}
		if asked > 0 && f.MinInterval > 0 {
			if err := f.sleep(ctx, f.MinInterval); err != nil {
				fail(ind, core.ErrFeedFailed, "not asked: "+err.Error())
				continue
			}
		}
		asked++
		rep, refused, err := f.one(ctx, ind, addr)
		if err != nil {
			if refused {
				stopped = err
			}
			errs = append(errs, &core.LookupError{Indicator: ind, Err: err})
			continue
		}
		out = append(out, rep)
	}
	return out, errors.Join(errs...)
}

func (f *Feed) one(ctx context.Context, ind string, addr netip.Addr) (rep core.Reputation, refused bool, err error) {
	res := f.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ans, lerr := res.LookupNetIP(ctx, "ip4", QueryName(addr, f.Zone))
	if lerr != nil {
		var de *net.DNSError
		if errors.As(lerr, &de) && de.IsNotFound {
			return f.rep(ind, core.VerdictNotFound), false, nil
		}
		return rep, false, fmt.Errorf("%w: %v", core.ErrFeedFailed, lerr)
	}
	if len(ans) == 0 {
		return rep, false, fmt.Errorf("%w: the resolver returned neither an answer nor an error", core.ErrFeedFailed)
	}
	codes := map[netip.Addr]bool{}
	for _, a := range ans {
		a = a.Unmap()
		if !a.Is4() || !loopbackNet.Contains(a) {
			return rep, false, fmt.Errorf("%w: answer outside 127.0.0.0/8 (a resolver rewriting names?); not a listing and not a not-listed", core.ErrFeedFailed)
		}
		if refusalNet.Contains(a) || f.isErrorCode(a) {
			return rep, true, fmt.Errorf("%w: the zone refused service (answered %s: the resolver or the query volume is not accepted); not a listing and not a not-listed", core.ErrFeedFailed, a)
		}
		codes[a] = true
	}
	sorted := make([]netip.Addr, 0, len(codes))
	for a := range codes {
		sorted = append(sorted, a)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Less(sorted[j]) })
	if len(sorted) > maxCodes {
		sorted = sorted[:maxCodes]
	}
	parts := make([]string, len(sorted))
	for i, a := range sorted {
		label := "unmapped"
		if l := clean(f.Codes[a], 40); l != "" {
			label = l
		}
		parts[i] = a.String() + ":" + label
	}
	return f.rep(ind, fmt.Sprintf("listed=true;zone=%s;codes=%s", f.Zone, strings.Join(parts, ","))), false, nil
}

func (f *Feed) isErrorCode(a netip.Addr) bool {
	for _, e := range f.ErrorCodes {
		if e == a {
			return true
		}
	}
	return false
}

func (f *Feed) rep(ind, verdict string) core.Reputation {
	return core.Reputation{Indicator: ind, Verdict: verdict, Observed: f.now(), Source: f.Name()}
}

// clean keeps letters, digits and . _ - of a configured label, so it cannot break the
// key=value verdict, and caps its length.
func clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}
