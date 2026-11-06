// Package dnsptr is a core.PTRResolver over a net.Resolver.
//
// What it will and will not do:
//
//   - Passive. It asks a DNS resolver for the PTR record of an address. The address
//     itself is never dialled: a PTR question goes to the resolver as a name under
//     in-addr.arpa or ip6.arpa.
//   - Failure is not silence. NXDOMAIN and "no such record" are core.ErrNotFound, a real
//     answer. A timeout, SERVFAIL, an unreachable resolver or a cancelled context are
//     core.ErrLookupFailed, never an answer.
//   - Bounded. One timeout per lookup, at most MaxNames values kept.
//   - A PTR value is text chosen by whoever controls the reverse zone. Only values that
//     are plausible DNS names are returned.
//
// The *net.Resolver is injected, so tests use one whose Dial reaches a fake server.
package dnsptr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

const (
	// DefaultTimeout bounds one lookup.
	DefaultTimeout = 5 * time.Second
	// DefaultMaxNames bounds the PTR values kept for one address.
	DefaultMaxNames = 5
)

var nameRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$`)

var _ core.PTRResolver = (*Resolver)(nil)

// Resolver asks the injected net.Resolver.
type Resolver struct {
	R        *net.Resolver // nil means net.DefaultResolver
	Label    string        // names the resolver in the recorded method, e.g. "system resolver"
	Timeout  time.Duration // per lookup; <= 0 means DefaultTimeout
	MaxNames int           // <= 0 means DefaultMaxNames
}

// New returns a Resolver with the default bounds.
func New(r *net.Resolver, label string) *Resolver {
	return &Resolver{R: r, Label: label, Timeout: DefaultTimeout, MaxNames: DefaultMaxNames}
}

// LookupPTR implements core.PTRResolver.
func (r *Resolver) LookupPTR(ctx context.Context, ip netip.Addr) (core.PTRAnswer, error) {
	ans := core.PTRAnswer{Query: fmt.Sprintf("PTR %s via %s", reverseName(ip), r.Label)}
	res := r.R
	if res == nil {
		res = net.DefaultResolver
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	max := r.MaxNames
	if max <= 0 {
		max = DefaultMaxNames
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	names, err := res.LookupAddr(ctx, ip.String())
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return ans, fmt.Errorf("%w: no PTR record", core.ErrNotFound)
		}
		return ans, fmt.Errorf("%w: %v", core.ErrLookupFailed, err)
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !nameRE.MatchString(n) {
			continue
		}
		if len(ans.Names) == max {
			break
		}
		ans.Names = append(ans.Names, n)
	}
	if len(ans.Names) == 0 {
		return ans, fmt.Errorf("%w: the resolver returned no usable PTR value", core.ErrLookupFailed)
	}
	return ans, nil
}

// reverseName is the name a PTR question asks for.
func reverseName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0x0f, b[i]>>4)
	}
	return sb.String() + "ip6.arpa"
}
