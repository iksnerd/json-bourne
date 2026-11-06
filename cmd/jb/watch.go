package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/alertlog"
	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/adapters/runlock"
	"github.com/iksnerd/json-bourne/internal/adapters/watchstate"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
)

// The unnamed watcher's files, as they have always been. A named watcher inserts its
// name before the extension (watchFile).
const (
	watchStateFile = "watch-state.json"
	watchLogFile   = "watch.log"
	watchLockFile  = "watch.lock"
)

// watchFile is the evidence-directory file of one kind for the watcher called name:
// "watch-state.json" unnamed, "watch-state.a.json" for --name a, and likewise for
// "watch.log" and "watch.lock". The unnamed names are unchanged.
func watchFile(unnamed, name string) string {
	if name == "" {
		return unnamed
	}
	ext := filepath.Ext(unnamed)
	return strings.TrimSuffix(unnamed, ext) + "." + name + ext
}

func newWatchCmdWith(d deps) *cobra.Command {
	var (
		cfgPath string
		caseDir string
		every   = 5 * time.Minute
		window  = 60 * time.Minute
		ttl     = app.DefaultWatchTTL
		keep    = app.DefaultWatchKeep
		repeat  = app.DefaultHealthRepeat
		once    bool
		name    string
	)
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Run a case's hunt on a repeating interval and alert on what is new",
		Long: "watch runs the case's hunt (as `jb hunt --case` does, same checks and same config choice)\n" +
			"every --every, and surfaces findings that are new: a tag that was alerted within --ttl is\n" +
			"held back unless its severity rose. The dedupe memory is <case>/<evidence>/watch-state.json;\n" +
			"alerts go to stdout and are appended to <case>/<evidence>/watch.log, which stays the source of\n" +
			"truth. Config `alerts:` adds a webhook (docs/CONFIG.md): it gets findings and outages of at least\n" +
			"min_severity, capped per cycle. A webhook failure fails the cycle but never loses the alert, which\n" +
			"is already in the log.\n\n" +
			"A cycle in which a source or detector did not finish raises an alert of its own and ends\n" +
			"with CYCLE INCOMPLETE; it is never reported as quiet. A cycle that errors does not stop the\n" +
			"loop. --window must be at least --every, or events between cycles would never be examined.\n\n" +
			"Every cycle stores its window and the baseline before it under a new run id, so the store would\n" +
			"grow without limit. After each cycle, watch deletes the events and findings of watch runs older\n" +
			"than --keep (default 48h) from the store, in one transaction, and says how many it removed on\n" +
			"the cycle line. It never touches a run that does not start with \"watch-\", and never the newest\n" +
			"watch run. A failed prune raises an alert and fails the cycle. --keep must be at least twice --window.\n\n" +
			"A source that stays down raises its alert at once and then, while the failure text is unchanged, at\n" +
			"most every --repeat (default 30m); in between, each cycle line still says CYCLE INCOMPLETE and\n" +
			"that the outage is still down. A different failure text, or a recovery, alerts immediately.\n" +
			"Findings are never held back by --repeat. Set --repeat at or below --every to alert every cycle.\n\n" +
			"--name NAME (^[a-z][a-z0-9_-]{0,31}$) makes this one of several watchers on one case, each with its\n" +
			"own --config: its state is watch-state.NAME.json, its log watch.NAME.log, its lock watch.NAME.lock\n" +
			"and its runs watch-NAME-<time>, and retention prunes only runs of that name. The name is on the\n" +
			"banner, on every alert and on every CYCLE line. Dedupe is per watcher, so a finding two watchers\n" +
			"both see alerts once in each. Watchers share only the DuckDB file, which each opens for one hunt at\n" +
			"a time. Without --name nothing changes. Two processes with the same name (or two unnamed) on one\n" +
			"case are refused, naming the PID that holds the lock; the lock dies with its process.\n\n" +
			"A source or detector with `enabled: false` in the config is neither read nor run and is listed as\n" +
			"DISABLED on the banner and on every cycle line; a quiet cycle then means the enabled ones.\n\n" +
			"watch has no --until: a watch cycle always ends now, so that what it alerts on is what is\n" +
			"happening. To examine a past window use `jb hunt --until` or `jb activity --until`.\n\n" +
			"--once runs one cycle and exits 0 when it was complete (quiet or with findings) and 1 when it\n" +
			"was incomplete or failed. Without --once, watch runs until interrupted.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caseDir == "" {
				return usageErrorf("--case is required")
			}
			if err := app.ValidWatchName(name); err != nil {
				return usageErrorf("--name: %v", err)
			}
			if every <= 0 {
				return usageErrorf("--every must be positive, got %s", every)
			}
			if window <= 0 {
				return usageErrorf("--window must be positive, got %s", window)
			}
			if ttl <= 0 {
				return usageErrorf("--ttl must be positive, got %s", ttl)
			}
			if keep <= 0 {
				return usageErrorf("--keep must be positive, got %s", keep)
			}
			if repeat <= 0 {
				return usageErrorf("--repeat must be positive, got %s", repeat)
			}
			stderr := cmd.ErrOrStderr()
			plan, err := planCase(stderr, caseDir, cfgPath, cmd.Flags().Changed("window"))
			if err != nil {
				return err
			}
			if plan.window > 0 {
				window = plan.window
			}
			if !cmd.Flags().Changed("keep") {
				keep = max(keep, 2*window) // the default must never be shorter than what a cycle stores
			}
			opts := app.WatchOptions{Every: every, Window: window, TTL: ttl, Keep: keep, Repeat: repeat, Once: once}
			if err := opts.Validate(); err != nil {
				return usageErrorf("%v", err)
			}

			evidence := plan.c.EvidenceDir()
			if err := os.MkdirAll(evidence, 0o700); err != nil {
				return fmt.Errorf("evidence directory: %w", err)
			}
			// One watcher per name and case, taken before anything is built or read: a second
			// process with the same name would share this one's state file and alert twice.
			lock, err := runlock.Acquire(filepath.Join(evidence, watchFile(watchLockFile, name)))
			if err != nil {
				var held *runlock.HeldError
				if errors.As(err, &held) {
					return fmt.Errorf("another watcher%s is already running on this case (%w); stop it, or give this one a different --name", nameClause(name), err)
				}
				return fmt.Errorf("watch lock: %w", err)
			}
			defer lock.Release()

			cfg, rt, err := openCase(stderr, d.env, plan.configPath, plan)
			if err != nil {
				return err
			}
			defer rt.Close() // ends any plugin child process, on success, failure and interrupt alike

			ctx := cmd.Context()
			if !once {
				var stop context.CancelFunc
				ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
				defer stop()
			}

			// The local log is the required sink and is written first; a webhook is extra.
			logSink := &alertlog.Sink{Out: cmd.OutOrStdout(), Path: filepath.Join(evidence, watchFile(watchLogFile, name))}
			var alerts core.AlertSink = logSink
			extra, aerr := cfg.BuildAlerts(d.env)
			if aerr != nil {
				return aerr
			}
			if len(extra) > 0 {
				alerts = core.FanOut{Required: logSink, Optional: extra}
			}

			deps := app.WatchDeps{
				Name:     name,
				Disabled: disabledOf(rt),
				Hunt: func(ctx context.Context, run string, w core.Window) (app.Result, error) {
					// The store is opened for one hunt and closed again: DuckDB admits one
					// process at a time, and `jb db` must still work between cycles.
					st, err := duckdb.OpenContext(ctx, cfg.StorePath(), false, duckdb.OpenOptions{})
					if err != nil {
						return app.Result{Run: run, Window: w, Baseline: w.Previous()}, fmt.Errorf("open database: %w", err)
					}
					defer st.Close()
					if _, err := st.Migrate(); err != nil {
						return app.Result{Run: run, Window: w, Baseline: w.Previous()}, fmt.Errorf("migrate database: %w", err)
					}
					res, herr := app.Hunt(ctx, runDeps(rt, rt.Detectors, st), run, w)
					// Advice in the cycle's own output; the cycle's status does not depend on it.
					warnSourceOverlap(ctx, stderr, st, core.Window{From: w.Previous().From, To: w.To}, renameScope(caseDir, cfgPath))
					return res, herr
				},
				Prune: func(ctx context.Context, before time.Time) (core.PruneResult, error) {
					st, err := duckdb.OpenContext(ctx, cfg.StorePath(), false, duckdb.OpenOptions{})
					if err != nil {
						return core.PruneResult{}, fmt.Errorf("open database: %w", err)
					}
					defer st.Close()
					if _, err := st.Migrate(); err != nil {
						return core.PruneResult{}, fmt.Errorf("migrate database: %w", err)
					}
					// Only this watcher's runs: prefix + a stamp, so "watch-a-" never reaches
					// "watch-ab-" and the unnamed "watch-" never reaches a named watcher's.
					return st.PruneRuns(ctx, app.WatchRunPrefixFor(name)+"-", before)
				},
				State:  watchstate.Store{Path: filepath.Join(evidence, watchFile(watchStateFile, name))},
				Alerts: alerts,
				Now:    d.now,
			}
			fmt.Fprintf(stderr, "watching case %s%s every %s over a %s window, ttl %s, keep %s, repeat %s, %d source(s), %d detector(s), %d webhook(s)\n",
				plan.c.ID, nameClause(name), every, window, ttl, keep, repeat, len(rt.Sources), len(rt.Detectors), len(extra))
			if note := app.DisabledNote(deps.Disabled); note != "" {
				fmt.Fprintln(stderr, note)
			}

			rep, err := app.Watch(ctx, deps, opts, app.WatchRunPrefixFor(name))
			if err != nil {
				return err
			}
			if once && !rep.Status.Healthy() {
				return fmt.Errorf("watch cycle %s, no clean result: %v %v", rep.Status, rep.Failed, rep.Err)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfgPath, "config", "", "one of the case's configs (default: the case's only config)")
	f.StringVar(&caseDir, "case", "", "case directory to watch (docs/CASE-SPEC.md; required)")
	f.Var((*windowValue)(&every), "every", "time between cycles: 90s, 5m or 1h")
	f.Var((*windowValue)(&window), "window", "length of each cycle's hunt window, at least --every (defaults to the case's windows.default, else 60m)")
	f.Var((*windowValue)(&ttl), "ttl", "how long an alerted tag stays quiet unless its severity rises")
	f.Var((*windowValue)(&keep), "keep", "how long the events and findings of past watch runs stay in the store (at least twice --window; default 48h, or twice --window when longer)")
	f.Var((*windowValue)(&repeat), "repeat", "least time between alerts for the same unchanged outage; a changed failure or a recovery alerts at once")
	f.StringVar(&name, "name", "", "name this watcher (^[a-z][a-z0-9_-]{0,31}$): own state, log, lock and run ids, so several can watch one case; default: the unnamed watcher")
	f.BoolVar(&once, "once", false, "run one cycle and exit; 0 when complete, 1 when incomplete or failed")
	return cmd
}

// nameClause is " (watcher NAME)" for a named watcher and nothing for the unnamed one, so
// the unnamed watcher's banner and messages are exactly what they were.
func nameClause(name string) string {
	if name == "" {
		return ""
	}
	return " (watcher " + name + ")"
}
