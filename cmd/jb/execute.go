package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Exit codes: 0 success, 1 runtime failure, 2 usage error.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// usageErrorf marks an error caused by how jb was invoked rather than by what it found.
// The type is core.UsageError, shared with the Go package (jb.IsUsage).
func usageErrorf(format string, a ...any) error { return core.Usagef(format, a...) }

// deps are the process-level inputs a command reads. Tests replace them.
type deps struct {
	env config.Env
	now func() time.Time
	// ptr and rdap replace the passive estate lookups. Nil means build the real
	// adapters from the command's flags; tests set them.
	ptr  core.PTRResolver
	rdap core.RDAPRegistry
	// bgp, ct and fwd replace the adapters of `estate asn|ct|dns`; sleep replaces the
	// wait between requests. The enable switch in the config is checked regardless.
	bgp   core.BGPSource
	ct    core.CTSource
	fwd   core.DNSForward
	sleep func(context.Context, time.Duration) error
}

func defaultDeps() deps { return deps{env: config.OSEnv, now: time.Now} }

// Execute runs jb and returns its exit code. It is the only place an error is
// printed, so every failure appears exactly once, on stderr.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return executeWith(ctx, defaultDeps(), args, stdout, stderr)
}

func executeWith(ctx context.Context, d deps, args []string, stdout, stderr io.Writer) int {
	root := newRootCmdWith(d)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	if core.IsUsage(err) {
		fmt.Fprintf(stderr, "jb: %v\nRun 'jb --help' for usage.\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "jb: %v\n", err)
	return exitFailure
}
