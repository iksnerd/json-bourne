package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"
	"github.com/iksnerd/json-bourne/internal/adapters/web"
	"github.com/iksnerd/json-bourne/internal/core"
)

const defaultServeAddr = jb.DefaultServeAddr

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
			errw, outw := cmd.ErrOrStderr(), cmd.OutOrStdout()
			err := jb.Serve(cmd.Context(), jb.ServeOptions{
				Dashboard: jb.DashboardOptions{Case: caseDir, Config: cfgPath,
					PathField: fields.Path, StatusField: fields.Status, KeyField: fields.Key, Now: d.now},
				Addr:        addr,
				AllowRemote: allowRemote,
				Ready: func(i jb.ServeInfo) {
					for _, n := range i.Notes {
						fmt.Fprintln(errw, n)
					}
					if i.Remote {
						fmt.Fprintf(errw, "WARNING: serving evidence on %s, which is not loopback, with NO authentication. Anyone who can reach this port can read the evidence store. Stop with Ctrl-C.\n", i.Addr)
					}
					fmt.Fprintf(errw, "store %s (opened read-only per request); evidence dir %s\n", i.Store, i.Evidence)
					fmt.Fprintf(outw, "listening on http://%s/ (read-only, no authentication)\n", i.Addr)
				},
			})
			switch {
			case errors.Is(err, web.ErrNotLoopback):
				return usageErrorf("%v; use 127.0.0.1, or pass --allow-remote to accept that risk", err)
			case errors.Is(err, web.ErrBadAddr):
				return usageErrorf("--addr: %v", err)
			}
			return err
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
