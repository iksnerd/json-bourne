package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/adapters/web"
	"github.com/iksnerd/json-bourne/internal/casefile"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

const defaultServeAddr = "127.0.0.1:8090"

func newServeCmdWith(d deps) *cobra.Command {
	var (
		cfgPath     string
		caseDir     string
		addr        = defaultServeAddr
		allowRemote bool
		fields      = core.DashboardFields{Path: "path", Status: "status", Key: "client_ip"}
	)
	cmd := &cobra.Command{
		Use:   "serve (--case DIR | --config FILE)",
		Short: "Serve a read-only HTML dashboard over the evidence store",
		Long: "serve shows the runs, findings, reputation snapshots, watch log and estate map of one case in a browser.\n" +
			"It is read-only: the database is opened with access_mode=READ_ONLY for each request and closed again\n" +
			"(so `jb watch` can write between requests), and no request can carry SQL. It reads no credential and\n" +
			"makes no network call; the page loads nothing from another origin and works offline.\n\n" +
			"It binds 127.0.0.1 and answers only loopback Host names. There is NO authentication: a non-loopback\n" +
			"--addr is refused unless --allow-remote is also given, and then anyone who can reach the port can read\n" +
			"the evidence. With --case the watch files and the estate directory of the case are shown too; with\n" +
			"--config alone the watch files are looked for beside the store and there is no estate.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" && cfgPath == "" {
				return usageErrorf("one of --case DIR or --config FILE is required")
			}
			listen, remote, err := web.CheckAddr(addr, allowRemote)
			if err != nil {
				return usageErrorf("%v", err)
			}
			src, err := openServeSource(cmd, caseDir, cfgPath)
			if err != nil {
				return err
			}
			h := web.New(web.Deps{
				Open: func(ctx context.Context) (core.DashboardStore, error) {
					st, err := duckdb.OpenDashboardContext(ctx, src.store)
					if err != nil {
						return nil, err // not a typed nil: the caller tests the interface
					}
					return st, nil
				},
				Estate: src.estate,
				Log:    alertlog.Tailer{Path: filepath.Join(src.evidence, watchLogFile)},
				State:  watchstate.Store{Path: filepath.Join(src.evidence, watchStateFile)},
				Fields: fields,
				Now:    d.now,
			}, web.Options{Loopback: !remote})

			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", listen, err)
			}
			if remote {
				fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: serving evidence on %s, which is not loopback, with NO authentication. Anyone who can reach this port can read the evidence store. Stop with Ctrl-C.\n", ln.Addr())
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "store %s (opened read-only per request); evidence dir %s\n", src.store, src.evidence)
			fmt.Fprintf(cmd.OutOrStdout(), "listening on http://%s/ (read-only, no authentication)\n", ln.Addr())
			if err := web.Serve(cmd.Context(), web.NewServer(h), ln); err != nil {
				return fmt.Errorf("serve: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&caseDir, "case", "", "case directory (jb.case/v1): its config, evidence directory and estate directory")
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to the YAML config; with --case, one of the case's configs")
	cmd.Flags().StringVar(&addr, "addr", addr, "listen address; must be loopback unless --allow-remote")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "accept a non-loopback --addr (there is no authentication; a loud warning is printed)")
	cmd.Flags().StringVar(&fields.Path, "path-field", fields.Path, "event field holding the request path")
	cmd.Flags().StringVar(&fields.Status, "status-field", fields.Status, "event field holding the status")
	cmd.Flags().StringVar(&fields.Key, "key-field", fields.Key, "event field holding the key (usually the client address)")
	return cmd
}

// serveSource is where the dashboard's inputs live. Only the config's store path is
// read from the config: serve never builds a source, so it never reads a credential
// or the environment.
type serveSource struct {
	store    string
	evidence string
	estate   core.EstateReader // nil without a case
}

func openServeSource(cmd *cobra.Command, caseDir, cfgPath string) (*serveSource, error) {
	if caseDir == "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return nil, err
		}
		sp := cfg.StorePath()
		return &serveSource{store: sp, evidence: filepath.Dir(sp)}, nil
	}
	plan, err := planCase(cmd.ErrOrStderr(), caseDir, cfgPath, true)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(plan.configPath)
	if err != nil {
		return nil, err
	}
	plan.placeStore(cmd.ErrOrStderr(), cfg)
	return &serveSource{store: cfg.StorePath(), evidence: plan.c.EvidenceDir(), estate: serveEstate{c: plan.c}}, nil
}

// serveEstate adapts the case's estate files to core.EstateReader. It is the only
// place the case format meets the dashboard's view types, so the web adapter never
// imports casefile.
type serveEstate struct{ c *casefile.Case }

func (e serveEstate) Estates(ctx context.Context) ([]core.EstateGraph, error) {
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
		g := core.EstateGraph{ID: x.ID, Caveat: x.Caveat}
		for _, n := range x.Nodes {
			g.Nodes = append(g.Nodes, core.EstateNode{ID: n.ID, Kind: n.Kind, Label: n.Label, Source: n.Source, Method: n.Method, Observed: n.Observed})
		}
		for _, ed := range x.Edges {
			g.Edges = append(g.Edges, core.EstateEdge{From: ed.From, To: ed.To, Relation: ed.Relation, Source: ed.Source, Method: ed.Method,
				Observed: ed.Observed, Confidence: ed.Confidence, InferredFrom: ed.InferredFrom})
		}
		for _, a := range x.Absences {
			g.Absences = append(g.Absences, core.EstateAbsence{Subject: a.Subject, Source: a.Source, Method: a.Method, Observed: a.Observed, Answer: a.Answer})
		}
		out = append(out, g)
	}
	return out, nil
}
