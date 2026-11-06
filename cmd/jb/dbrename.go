package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

func newDBRenameSourceCmd() *cobra.Command {
	var (
		cfgPath, caseDir string
		apply, merge     bool
	)
	cmd := &cobra.Command{
		Use:   "rename-source (--config FILE | --case DIR) OLD NEW [--apply] [--merge]",
		Short: "Relabel the events stored under source label OLD as NEW (dry run unless --apply)",
		Long: "The store keys an event by its source label, so the same documents saved once under a source's\n" +
			"default label (kibana:<index>) and again under an explicit `name:` are read as two sets, and a\n" +
			"detector that reads both counts every document twice. This renames the label of every stored\n" +
			"event, in one transaction, without touching run ids, findings or the identity rule.\n\n" +
			"It is a DRY RUN by default: it opens the store read-only (the engine refuses a write), prints the\n" +
			"counts and changes nothing. --apply opens it read-write and does the rename.\n\n" +
			"If NEW already holds documents OLD also holds (same time, kind and content digest) the rename is\n" +
			"REFUSED, dry run or not, unless --merge: then the rows of OLD that NEW already covers are dropped\n" +
			"(counted and printed) in the same transaction and the rest are relabelled. Identical lines inside\n" +
			"one run are real events and survive up to the count NEW holds.\n\n" +
			"NEW must be a valid source name (the rule for `name:` in a config). OLD is a stored label: a valid\n" +
			"name, or a default kibana:<index> label. An event saved with no raw document digests its label into\n" +
			"doc_sha256, which stays as stored; the count of such rows is printed.\n\n" +
			"Another process holding the database file is waited for (" + duckdb.EnvLockWait + ", default " + duckdb.DefaultLockWait.String() + "), then reported.\n" +
			"A running `jb watch` need not be stopped: it holds the file only for the write phase of a cycle.",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(2)(cmd, args); err != nil {
				return usageErrorf("%v (OLD and NEW)", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			oldL, newL := args[0], args[1]
			if caseDir == "" && cfgPath == "" {
				return usageErrorf("one of --case DIR or --config FILE is required (it names the store)")
			}
			if !config.ValidStoredLabel(oldL) {
				return usageErrorf("OLD %q is not a stored source label: expected a source name (lower case letter first, then a-z 0-9 _ . : -, at most 64) or a default kibana:<index> label", oldL)
			}
			if !config.ValidSourceName(newL) {
				return usageErrorf("NEW %q is not a valid source name: a lower case letter, then a-z 0-9 _ . : -, at most 64 characters", newL)
			}
			if oldL == newL {
				return usageErrorf("OLD and NEW are the same label")
			}
			store, err := storePathFor(cmd.ErrOrStderr(), caseDir, cfgPath)
			if err != nil {
				return err
			}
			if _, err := os.Stat(store); err != nil {
				return fmt.Errorf("no evidence database at %s: %w", store, err)
			}
			// A dry run opens read-only, so the engine itself guarantees it changes nothing.
			st, err := duckdb.OpenContext(cmd.Context(), store, !apply, duckdb.OpenOptions{})
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()
			res, rerr := st.RenameSource(cmd.Context(), core.RenameSourceRequest{Old: oldL, New: newL, Merge: merge, DryRun: !apply})
			if res.Events > 0 || res.NewEvents > 0 {
				if err := writeRename(cmd.OutOrStdout(), store, res, apply, merge); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
			}
			switch {
			case errors.Is(rerr, core.ErrSourceOverlap):
				return fmt.Errorf("refused: %q already holds %d of the documents under %q; nothing was changed. If they are the same documents, re-run with --merge to drop OLD's copies and relabel the rest", newL, res.Overlap, oldL)
			case errors.Is(rerr, core.ErrNoSuchSource):
				return fmt.Errorf("no event in %s carries the source label %q; nothing to do", store, oldL)
			case rerr != nil:
				return fmt.Errorf("rename source: %w", rerr)
			}
			if !apply {
				fmt.Fprintf(cmd.OutOrStdout(), "dry run: nothing was changed. Add --apply to do it.\n")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfgPath, "config", "", "YAML config naming the store (with --case: one of the case's configs)")
	f.StringVar(&caseDir, "case", "", "case directory (docs/CASE-SPEC.md); the store is placed as `jb hunt --case` places it")
	f.BoolVar(&apply, "apply", false, "do the rename (default: dry run)")
	f.BoolVar(&merge, "merge", false, "when NEW already holds some of OLD's documents, drop OLD's copies and relabel the rest")
	return cmd
}

// storePathFor resolves the store path the way the commands that read it do, loading
// the config only: it reads no credential.
func storePathFor(stderr io.Writer, caseDir, cfgPath string) (string, error) {
	if caseDir == "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return "", err
		}
		return cfg.StorePath(), nil
	}
	plan, err := planCase(stderr, caseDir, cfgPath, "rename-source", true)
	if err != nil {
		return "", err
	}
	cfg, err := loadCaseConfig(stderr, plan)
	if err != nil {
		return "", err
	}
	return cfg.StorePath(), nil
}

func writeRename(w io.Writer, store string, r core.RenameSourceResult, apply, merge bool) error {
	mode := "dry run"
	if apply {
		mode = "apply"
		if !r.Applied {
			mode = "apply, NOT applied"
		}
	}
	fmt.Fprintf(w, "rename source %q -> %q in %s (%s)\n", r.Old, r.New, store, mode)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "events under %s\t%d in %d run(s)\n", r.Old, r.Events, r.Runs)
	fmt.Fprintf(tw, "events already under %s\t%d\n", r.New, r.NewEvents)
	fmt.Fprintf(tw, "documents under both\t%d\n", r.Overlap)
	if merge || r.Dropped > 0 {
		fmt.Fprintf(tw, "dropped from %s (already under %s)\t%d\n", r.Old, r.New, r.Dropped)
	}
	verb := "would be relabelled"
	if r.Applied {
		verb = "relabelled"
	}
	fmt.Fprintf(tw, "%s\t%d\n", verb, r.Relabelled)
	if err := tw.Flush(); err != nil {
		return err
	}
	if r.NoRaw > 0 {
		fmt.Fprintf(w, "note: %d event(s) under %s have no raw document; their digest covers the old label and is left as stored, so a later fetch of the same document under %s is read as a separate event\n", r.NoRaw, r.Old, r.New)
	}
	fmt.Fprintf(w, "run ids and findings are unchanged\n")
	return nil
}

// renameScope is the part of a `jb db rename-source` command line that names the
// config, as the caller was given it, quoted for a shell.
func renameScope(caseDir, cfgPath string) string {
	var parts []string
	if caseDir != "" {
		parts = append(parts, "--case "+app.ShellQuote(caseDir))
	}
	if cfgPath != "" {
		parts = append(parts, "--config "+app.ShellQuote(cfgPath))
	}
	return strings.Join(parts, " ")
}

// warnSourceOverlap prints, to w, a WARNING when the store holds the same documents
// under two source labels inside win. It is advice: it never returns an error and the
// caller's verdict and exit code do not depend on it. A failed check is noted, not hidden.
func warnSourceOverlap(ctx context.Context, w io.Writer, r core.SourceOverlapReader, win core.Window, scope string) {
	ov, err := app.SourceOverlaps(ctx, r, win)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(w, "note: the check for one set of documents stored under two source labels did not run: %v\n", err)
		}
		return
	}
	if msg := app.SourceOverlapWarning(ov, scope); msg != "" {
		fmt.Fprint(w, msg)
	}
}
