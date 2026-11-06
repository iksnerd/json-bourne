package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	jb "github.com/iksnerd/json-bourne"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/core"
)

func newDBRenameSourceCmd() *cobra.Command {
	var output string
	var fl *opFlags
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
			caseDir, cfgPath, apply, merge := fl.String("case"), fl.String("config"), fl.Bool("apply"), fl.Bool("merge")
			if err := checkOutput(output); err != nil {
				return err
			}
			res, err := jb.DBRenameSource(cmd.Context(), caseDir, jb.DBRenameSourceOptions{
				Config: cfgPath, Old: args[0], New: args[1], Merge: merge, Apply: apply,
			})
			if res == nil { // a refusal before the store was opened
				return err
			}
			printNotes(cmd.ErrOrStderr(), res.Notes)
			// A refusal that found something (an overlap) still prints what it found.
			if res.Events > 0 || res.NewEvents > 0 {
				var werr error
				if output == "json" {
					werr = writeIndentedJSON(cmd.OutOrStdout(), res)
				} else {
					werr = writeRename(cmd.OutOrStdout(), res.Store, *res, apply, merge)
				}
				if werr != nil {
					return fmt.Errorf("write output: %w", werr)
				}
			}
			if err != nil {
				return err
			}
			if !apply && output != "json" {
				fmt.Fprintf(cmd.OutOrStdout(), "dry run: nothing was changed. Add --apply to do it.\n")
			}
			return nil
		},
	}
	fl = addOperationFlags(cmd, "db_rename_source")
	f := cmd.Flags()
	f.StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func writeRename(w io.Writer, store string, r jb.DBRenameSourceResult, apply, merge bool) error {
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
