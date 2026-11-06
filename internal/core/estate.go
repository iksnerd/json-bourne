package core

import (
	"context"
	"errors"
	"net/netip"
)

// Passive estate lookups. Both ports answer a question about an address by asking a
// resolver or a registry. Neither is ever allowed to contact the address itself.

var (
	// ErrNotFound is a real answer: the resolver or registry said there is no record
	// (NXDOMAIN, HTTP 404). It is recorded as an absence. It is not a failure.
	ErrNotFound = errors.New("not found")
	// ErrLookupFailed means the question was not answered: a timeout, a network error,
	// a non-success status, an unreadable or oversized response. It is never recorded
	// as data, and the run that saw it is incomplete.
	ErrLookupFailed = errors.New("lookup failed")
)

// PTRAnswer is what a reverse lookup returned. Query names the exact question and the
// resolver, for the method field of the estate file; it is set even when the answer is
// ErrNotFound.
type PTRAnswer struct {
	Query string
	Names []string // lower case, no trailing dot, validated as DNS names
}

// PTRResolver asks a DNS resolver for the PTR record of an address.
type PTRResolver interface {
	// LookupPTR returns ErrNotFound (wrapped) for NXDOMAIN or no PTR record, and
	// ErrLookupFailed (wrapped) for anything that is not an answer.
	LookupPTR(ctx context.Context, ip netip.Addr) (PTRAnswer, error)
}

// RDAPEntity is a contact or organisation attached to a registered network.
type RDAPEntity struct {
	Handle string
	Name   string
	Roles  []string
}

// RDAPNetwork is the registry's record of the range that covers an address.
type RDAPNetwork struct {
	Query        string // the exact URL asked, for the method field
	Handle       string
	Name         string
	Country      string
	Start, End   string
	ParentHandle string
	Entities     []RDAPEntity
}

// RDAPRegistry asks an RDAP service (the rdap.org-style bootstrap or a registry) who
// holds an address.
type RDAPRegistry interface {
	// LookupIP returns ErrNotFound (wrapped) for a real 404, ErrRateLimited (wrapped)
	// for a 429 and ErrLookupFailed (wrapped) for anything else that is not an answer.
	// Query is set even when the answer is ErrNotFound.
	LookupIP(ctx context.Context, ip netip.Addr) (RDAPNetwork, error)
}
