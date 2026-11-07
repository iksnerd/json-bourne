// Package estateseam carries test doubles for the network adapters of the estate
// functions of package jb, on the context of the call.
//
// It is not public API. Package jb used to export the doubles as EstatePorts (RFC 0017,
// step 6); the module's own tests and cmd/jb still need to replace the adapters, and
// they reach package jb through this internal package instead. The enable switch of
// `estate.external` is checked by package jb whether or not a port is set.
package estateseam

import (
	"context"
	"time"

	"github.com/iksnerd/json-bourne/internal/core"
)

// Ports replace the network adapters. A nil field keeps the real adapter.
type Ports struct {
	PTR  core.PTRResolver
	RDAP core.RDAPRegistry
	BGP  core.BGPSource
	CT   core.CTSource
	DNS  core.DNSForward
	// Sleep replaces the wait between two requests to a service.
	Sleep func(ctx context.Context, d time.Duration) error
}

type key struct{}

// With returns a context whose estate calls use p.
func With(ctx context.Context, p Ports) context.Context { return context.WithValue(ctx, key{}, p) }

// From returns the ports set by [With], or the zero value.
func From(ctx context.Context) Ports {
	p, _ := ctx.Value(key{}).(Ports)
	return p
}
