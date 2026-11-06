package core

import (
	"context"
	"errors"
	"net/netip"
)

// Passive estate collectors beyond the address lookups: BGP origin data, forward DNS
// and certificate transparency. Each port asks a public service or a resolver. None may
// contact the thing it is asked about.

// ErrTruncated means an answer was cut at a cap. What was kept is real; what was not
// kept is unknown, so the run that saw it is incomplete. It is never a clean result.
var ErrTruncated = errors.New("result truncated at the cap")

// BGPHolder is an autonomous system and the name its registry gives it.
type BGPHolder struct {
	ASN    uint32
	Holder string
}

// BGPAnnouncement is what a route collector says an AS announces.
type BGPAnnouncement struct {
	Query     string // every request made, for the method field; set on ErrNotFound too
	Holder    BGPHolder
	Prefixes  []netip.Prefix
	Truncated bool // more prefixes were announced than the cap kept
}

// BGPOrigin is what a route collector says about the route covering an address.
type BGPOrigin struct {
	Query  string
	Prefix netip.Prefix
	Origin []BGPHolder
}

// BGPSource asks a public BGP data service. It is a third-party service: the question
// (an AS number or an address) leaves the machine to it.
type BGPSource interface {
	// LookupASN returns ErrNotFound (wrapped) when the service says the AS announces
	// nothing, ErrRateLimited for a 429 and ErrLookupFailed for anything else that is
	// not an answer.
	LookupASN(ctx context.Context, asn uint32) (BGPAnnouncement, error)
	// LookupIP returns ErrNotFound (wrapped) when no route covers the address. The
	// adapter never connects to the address.
	LookupIP(ctx context.Context, ip netip.Addr) (BGPOrigin, error)
}

// CTAnswer is what a certificate transparency search returned for a domain.
type CTAnswer struct {
	Query      string
	Names      []string // distinct, lower case, inside the domain, capped, wildcards removed
	Wildcards  int      // distinct wildcard names seen (*.example.com); not hosts, not recorded
	OutOfScope int      // distinct names on the same certificates outside the domain, or not DNS names
	Truncated  bool     // more distinct names than the cap
}

// CTSource searches certificate transparency logs through a public search service. It
// is a third-party service: the domain name leaves the machine to it.
type CTSource interface {
	// LookupSubdomains returns ErrNotFound (wrapped) when the service has no
	// certificate for the domain, ErrRateLimited for a 429 and ErrLookupFailed for
	// anything else that is not an answer. A name on a certificate is a candidate
	// host, not a confirmed one. The adapter never connects to the domain.
	LookupSubdomains(ctx context.Context, domain string) (CTAnswer, error)
}

// DNSType is a forward record type. DNSSPF is TXT filtered to SPF policies: other TXT
// values (verification tokens and the like) are never returned.
type DNSType string

const (
	DNSA     DNSType = "A"
	DNSAAAA  DNSType = "AAAA"
	DNSCNAME DNSType = "CNAME"
	DNSMX    DNSType = "MX"
	DNSNS    DNSType = "NS"
	DNSSPF   DNSType = "SPF"
)

// DNSTypes is the fixed order a profile asks in.
var DNSTypes = []DNSType{DNSA, DNSAAAA, DNSCNAME, DNSMX, DNSNS, DNSSPF}

// DNSAnswer is the values of one record type for one name.
type DNSAnswer struct {
	Query     string
	Values    []string // addresses, lower-case names without the trailing dot, or SPF text
	Truncated bool
}

// DNSForward asks a DNS resolver for forward records of a name.
type DNSForward interface {
	// Lookup returns ErrNotFound (wrapped) for NXDOMAIN or no record of that type, and
	// ErrLookupFailed (wrapped) for a timeout, SERVFAIL or anything else that is not an
	// answer.
	Lookup(ctx context.Context, name string, t DNSType) (DNSAnswer, error)
}
