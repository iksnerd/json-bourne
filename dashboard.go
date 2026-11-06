package jb

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/adapters/web"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
	"github.com/iksnerd/json-bourne/internal/watchrun"
)

// DefaultServeAddr is the address `jb serve` listens on when none is given.
const DefaultServeAddr = "127.0.0.1:8090"

// DashboardOptions select the evidence the dashboard shows. Set Case, or Config alone.
type DashboardOptions struct {
	// Case is a case directory (jb.case/v1). The dashboard then shows the case's
	// evidence store, watch log and state, and estate map.
	Case string
	// Config names one of the case's configs, as in [CaseHuntOptions.Config], when Case
	// is set (empty means the case's only config, or the one that declares "serve").
	// Without Case it is the path of a YAML config: only its store path is read, the
	// watch files are looked for beside the store and there is no estate map.
	Config string
	// PathField, StatusField and KeyField name the event fields the run page reads.
	// Empty means "path", "status" and "client_ip".
	PathField, StatusField, KeyField string
	// AllowRemote switches off the Host header check. Leave it false unless the
	// handler is bound to, or reached through, a non-loopback name.
	AllowRemote bool
	// AllowedHosts, when set, replaces the loopback-only Host rule with an exact list
	// of Host header values (host or host:port, at most 16, no wildcards). Use it when
	// the handler sits behind a reverse proxy that rewrites Host, so the check stays
	// on. An invalid list is a usage error. Empty keeps the loopback rule.
	AllowedHosts []string
	// Now is the clock. Nil means time.Now. The dashboard reads no environment
	// variable and no credential, so there is no Env option.
	Now func() time.Time
}

// DashboardInfo says what a handler reads.
type DashboardInfo struct {
	// Store is the evidence database. It is opened read-only for each request and
	// closed when the request ends, so a writer (`jb watch`) is never locked out
	// between requests. The handler therefore holds no handle and needs no Close.
	Store string
	// Evidence is the directory of the watch log and state.
	Evidence string
	// Notes are things the caller may want to show (a case outside git, a store placed
	// in the case). The function does not print them.
	Notes []string
}

// DashboardHandler returns the `jb serve` dashboard as an http.Handler over a
// read-only evidence store, with the rules of RFC 0003: GET and HEAD only, no
// mutation endpoint, no SQL, a strict Content-Security-Policy and the other security
// headers on every response, and (unless AllowRemote) a 421 for a Host that is not a
// loopback name. The store is opened with access_mode=READ_ONLY, enforced by the
// storage engine.
//
// A caller that mounts the handler MUST:
//   - serve it on a loopback address only, or put authentication in front of it. The
//     dashboard has none and shows evidence. [Serve] does this for you.
//   - keep the Host check (leave AllowRemote false) unless it sits behind its own.
//   - not add a route that writes next to it on the same origin, and not strip or
//     replace its headers.
//   - mount it at the root of its own origin. Its pages link to root paths such as
//     /run and /static/, so under a prefix (http.StripPrefix) the security rules still
//     hold but the pages' links lead outside the prefix.
//
// A usage error (see [IsUsage]) is returned when neither Case nor Config is set.
func DashboardHandler(opts DashboardOptions) (http.Handler, *DashboardInfo, error) {
	if opts.Case == "" && opts.Config == "" {
		return nil, nil, usagef("one of Case or Config is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	fields := core.DashboardFields{Path: "path", Status: "status", Key: "client_ip"}
	if opts.PathField != "" {
		fields.Path = opts.PathField
	}
	if opts.StatusField != "" {
		fields.Status = opts.StatusField
	}
	if opts.KeyField != "" {
		fields.Key = opts.KeyField
	}
	info := &DashboardInfo{}
	var estate core.EstateReader
	if opts.Case == "" {
		cfg, err := config.Load(opts.Config)
		if err != nil {
			return nil, nil, err
		}
		info.Store = cfg.StorePath()
		info.Evidence = filepath.Dir(info.Store)
	} else {
		plan, err := config.PlanCase(opts.Case, opts.Config, "serve", true)
		if err != nil {
			return nil, nil, fmt.Errorf("%w", err)
		}
		cfg, err := config.Load(plan.ConfigPath)
		if err != nil {
			return nil, nil, err
		}
		info.Notes = append(info.Notes, plan.Notes...)
		if n := config.PlaceCaseStore(plan.Case, cfg); n != "" {
			info.Notes = append(info.Notes, n)
		}
		info.Store, info.Evidence = cfg.StorePath(), plan.Case.EvidenceDir()
		estate = dashEstate{c: plan.Case}
	}
	store := info.Store
	wopts := web.Options{Loopback: !opts.AllowRemote, AllowedHosts: opts.AllowedHosts}
	if err := wopts.Validate(); err != nil {
		return nil, nil, core.UsageWrap(err)
	}
	h := web.New(web.Deps{
		Open: func(ctx context.Context) (core.DashboardStore, error) {
			st, err := duckdb.OpenDashboardContext(ctx, store)
			if err != nil {
				return nil, err // not a typed nil: the caller tests the interface
			}
			return st, nil
		},
		Estate: estate,
		Log:    alertlog.Tailer{Path: filepath.Join(info.Evidence, watchrun.LogFile)},
		State:  watchstate.Store{Path: filepath.Join(info.Evidence, watchrun.StateFile)},
		Fields: fields,
		Now:    opts.Now,
	}, wopts)
	return h, info, nil
}

// ServeOptions are the options of [Serve].
type ServeOptions struct {
	Dashboard DashboardOptions
	// Addr is HOST:PORT; empty means [DefaultServeAddr]. Port 0 picks a free port,
	// reported to Ready. "localhost" binds 127.0.0.1.
	Addr string
	// AllowRemote accepts a non-loopback Addr. There is no authentication, so anyone
	// who can reach the port can read the evidence. It also switches off the Host check.
	AllowRemote bool
	// Ready, if set, is called once after the listener is bound and before requests
	// are served.
	Ready func(ServeInfo)
}

// ServeInfo is what [ServeOptions.Ready] receives.
type ServeInfo struct {
	// Addr is the bound address, with the real port.
	Addr string
	// Remote is true when Addr is not loopback; the caller should warn.
	Remote bool
	DashboardInfo
}

// Serve runs the dashboard until ctx ends, then shuts down gracefully and returns
// nil. A non-loopback Addr is a usage error unless AllowRemote is set. Serve prints
// nothing and reads no credential or environment variable.
func Serve(ctx context.Context, opts ServeOptions) error {
	addr := opts.Addr
	if addr == "" {
		addr = DefaultServeAddr
	}
	if opts.Dashboard.Case == "" && opts.Dashboard.Config == "" {
		return usagef("one of Dashboard.Case or Dashboard.Config is required")
	}
	listen, remote, err := web.CheckAddr(addr, opts.AllowRemote)
	if err != nil {
		return core.UsageWrap(err)
	}
	dopts := opts.Dashboard
	dopts.AllowRemote = remote
	h, info, err := DashboardHandler(dopts)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	if opts.Ready != nil {
		opts.Ready(ServeInfo{Addr: ln.Addr().String(), Remote: remote, DashboardInfo: *info})
	}
	if err := web.Serve(ctx, web.NewServer(h), ln); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// dashEstate adapts the case's estate files to core.EstateReader. It is the only
// place the case format meets the dashboard's view types, so the web adapter never
// imports casefile.
type dashEstate struct{ c *casefile.Case }

func (e dashEstate) Estates(ctx context.Context) ([]core.EstateGraph, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	es, err := casefile.LoadEstates(e.c)
	if err != nil {
		return nil, err
	}
	if len(es) == 0 {
		return nil, fmt.Errorf("%w: estate dir absent or holds no estate file (%s)", core.ErrAbsent, e.c.Paths.Estate)
	}
	out := make([]core.EstateGraph, 0, len(es))
	for _, x := range es {
		g := core.EstateGraph{ID: x.ID, Subject: x.Subject, Caveat: x.Caveat}
		for _, n := range x.Nodes {
			en := core.EstateNode{ID: n.ID, Kind: n.Kind, Label: n.Label, Source: n.Source, Method: n.Method, Observed: n.Observed}
			for _, f := range n.Facts {
				en.Facts = append(en.Facts, core.EstateFact{Key: f.Key, Value: f.Value, Source: f.Source, Method: f.Method, Observed: f.Observed})
			}
			g.Nodes = append(g.Nodes, en)
		}
		for _, ed := range x.Edges {
			g.Edges = append(g.Edges, core.EstateEdge{From: ed.From, To: ed.To, Relation: ed.Relation, Source: ed.Source, Method: ed.Method,
				Observed: ed.Observed, Confidence: ed.Confidence, InferredFrom: ed.InferredFrom})
		}
		for _, a := range x.Absences {
			g.Absences = append(g.Absences, core.EstateAbsence{Subject: a.Subject, Source: a.Source, Method: a.Method, Observed: a.Observed, Answer: a.Answer})
		}
		for _, a := range x.Assessments {
			g.Assessments = append(g.Assessments, core.EstateAssessment{ID: a.ID, Subject: a.Subject, Label: a.Label, By: a.By, Decided: a.Decided,
				Basis: append([]string(nil), a.Basis...), Note: a.Note})
		}
		out = append(out, g)
	}
	return out, nil
}
