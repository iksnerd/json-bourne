package main

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/iksnerd/json-bourne/jb"

	"github.com/iksnerd/json-bourne/internal/adapters/duckdb"
	"github.com/iksnerd/json-bourne/internal/app"
	"github.com/iksnerd/json-bourne/internal/config"
	"github.com/iksnerd/json-bourne/internal/core"
)

// Store maintenance: `jb db usage`, `jb db prune`, `jb db compact`. They print counts,
// sizes and run ids, never a stored document or an address from one.

func humanBytes(n int64) string {
	const k = 1024.0
	f := float64(n)
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case f < k*k:
		return fmt.Sprintf("%.1f KiB", f/k)
	case f < k*k*k:
		return fmt.Sprintf("%.1f MiB", f/(k*k))
	}
	return fmt.Sprintf("%.2f GiB", f/(k*k*k))
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func checkOutput(o string) error {
	if o != "table" && o != "json" {
		return usageErrorf("--output %q: expected table or json", o)
	}
	return nil
}

func writeIndentedJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// parseAge reads a duration like 36h, 90m or 14d (days and weeks are accepted here
// only; time.ParseDuration has no unit above the hour).
func parseAge(s string) (time.Duration, error) { return config.ParseAge(s) }

// ---- usage ----

func newDBUsageCmd() *cobra.Command {
	var output string
	var fl *opFlags
	cmd := &cobra.Command{
		Use:   "usage (--config FILE | --case DIR) [--output table|json]",
		Short: "Show what the evidence database holds, by run kind and by source label (read-only)",
		Long: "usage measures the store with fixed queries and opens it read-only (the engine refuses a write).\n" +
			"It reports, for each run kind (watch per watcher, hunt, hunt-until, activity, activity-until,\n" +
			"search, search-until, other) and for each source label: runs, events, raw bytes, fields bytes and\n" +
			"the oldest and newest run time, then the database file size on disk.\n\n" +
			"Raw and fields bytes are the UNCOMPRESSED size of the stored documents. DuckDB compresses on disk,\n" +
			"so they show proportions between kinds and labels, not the file size. Runs are hunts (a hunt's\n" +
			"findings run and its per-source event runs count once); a run whose events were pruned\n" +
			"(`jb db prune`) is counted in 'events pruned'.\n\n" +
			"A store another process holds read-write is waited for (" + duckdb.EnvLockWait + ", default " + duckdb.DefaultLockWait.String() + "), then reported.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caseDir, cfgPath := fl.String("case"), fl.String("config")
			if err := checkOutput(output); err != nil {
				return err
			}
			rep, err := jb.DBUsage(cmd.Context(), caseDir, jb.DBOptions{Config: cfgPath})
			if err != nil {
				return err
			}
			printNotes(cmd.ErrOrStderr(), rep.Notes)
			if output == "json" {
				return writeIndentedJSON(cmd.OutOrStdout(), rep)
			}
			return writeUsage(cmd.OutOrStdout(), rep)
		},
	}
	fl = addOperationFlags(cmd, "db_usage")
	f := cmd.Flags()
	f.StringVar(&output, "output", "table", "table or json")
	return cmd
}

func writeUsage(w io.Writer, r *jb.DBUsageResult) error {
	fmt.Fprintf(w, "evidence database %s (schema %d)\n", r.Path, r.SchemaVersion)
	fmt.Fprintf(w, "file on disk: %s", humanBytes(r.FileBytes))
	if r.UsedBytes > 0 || r.FreeBytes > 0 {
		fmt.Fprintf(w, " (blocks in use %s, free inside the file %s: a deleted row does not shrink it, `jb db compact` writes a smaller copy)", humanBytes(r.UsedBytes), humanBytes(r.FreeBytes))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "run records %d, events %d, findings %d, reputation rows %d\n\n", r.Runs, r.Events, r.Findings, r.Reputation)
	fmt.Fprintf(w, "events without a document identity %d (rows written before schema 4; the reader tells them apart by source label)\n", r.LegacyEvents)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN KIND\tRUNS\tEVENTS PRUNED\tEVENTS\tRAW\tFIELDS\tOLDEST\tNEWEST")
	for _, k := range r.Kinds {
		name := string(k.Kind)
		if k.Kind == core.KindWatch {
			if k.Watcher == "" {
				name += " (unnamed)"
			} else {
				name += " " + k.Watcher
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n", name, k.Runs, k.PrunedRuns, k.Events, humanBytes(k.RawBytes), humanBytes(k.FieldsBytes), fmtTime(k.Oldest), fmtTime(k.Newest))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE LABEL\tRUNS\tEVENTS\tRAW\tFIELDS\tOLDEST\tNEWEST")
	for _, l := range r.Labels {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\n", l.Label, l.Runs, l.Events, humanBytes(l.RawBytes), humanBytes(l.FieldsBytes), fmtTime(l.Oldest), fmtTime(l.Newest))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	switch {
	case r.Overlap.Error != "":
		fmt.Fprintf(w, "documents stored under two source labels: not checked (%s)\n", r.Overlap.Error)
	case r.Overlap.Pairs == 0:
		fmt.Fprintln(w, "documents stored under two source labels: none")
	default:
		more := ""
		if r.Overlap.AtLeast {
			more = "at least "
		}
		fmt.Fprintf(w, "documents stored under two source labels: %s%d across %d label pair(s); `jb db rename-source` fixes it\n", more, r.Overlap.Documents, r.Overlap.Pairs)
	}
	fmt.Fprintln(w, "note: RAW and FIELDS are the uncompressed size of the stored text. DuckDB compresses it on disk, so they show proportions between rows of this table, not the file size.")
	fmt.Fprintln(w, "note: the same document fetched by overlapping runs is stored once per run; the identity rule collapses it when the store is READ, not when it is written, so these counts are higher than the distinct documents.")
	return nil
}

// ---- prune ----

func newDBPruneCmd(d deps) *cobra.Command {
	var output string
	var fl *opFlags
	cmd := &cobra.Command{
		Use:   "prune (--config FILE | --case DIR) (--kind K[,K...] --older-than DURATION [--keep-latest N] | --run ID [--run ID ...]) [--drop-findings] [--apply]",
		Short: "Delete the stored events of old hunt/activity/search runs (dry run unless --apply)",
		Long: "prune removes the bulk of the evidence store that nothing else prunes: the events (and so the raw\n" +
			"documents) of one-off runs. It is a DRY RUN by default: it opens the store read-only, prints what\n" +
			"would go (hunts, events, raw bytes per kind) and what is kept and why, and changes nothing.\n" +
			"--apply opens it read-write and does it in ONE transaction.\n\n" +
			"--kind is required: one or more of hunt, hunt-until, activity, activity-until, search, search-until.\n" +
			"Watch runs are refused: `jb watch --keep` owns their retention, per watcher. There is no wildcard.\n" +
			"A run is matched by the whole shape of its id, so hunt does not reach hunt-until; its age is its\n" +
			"stored created_at (a hunt's newest record), compared with now minus --older-than.\n\n" +
			"--keep-latest N (default 1) keeps the N newest hunts of EACH selected kind whatever their age, so the\n" +
			"latest hunt that `jb intel` reads and the latest activity check are never pruned by accident. 0 is\n" +
			"accepted only when you pass --keep-latest 0.\n\n" +
			"--run ID (repeatable, at most 20) is the other way to choose: it removes exactly the runs you name,\n" +
			"whatever their age, and cannot be combined with --kind, --older-than or --keep-latest. The id is\n" +
			"compared whole (never a prefix or pattern) and is the hunt id as the dry run prints it. Watch ids are\n" +
			"refused. An id that is not in the store is an error that names it, and then nothing is deleted. A\n" +
			"repeated id counts once. Everything below applies to it too.\n\n" +
			"By default FINDINGS and RUN RECORDS stay: only events are deleted, and the run record is marked\n" +
			"pruned_at so `jb db usage` can say the events are gone. --drop-findings also deletes those hunts'\n" +
			"findings and run records. Reputation rows are never touched.\n\n" +
			"The counts printed after --apply are the engine's own row counts, checked equal to the plan inside the\n" +
			"transaction; a difference rolls everything back. The file does not shrink: see `jb db compact`.\n" +
			"A store held by another process is waited for (" + duckdb.EnvLockWait + "), then refused, naming the holder.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caseDir, cfgPath, runIDs, kinds, olderThan, keepLatest, dropFindings, apply := fl.String("case"), fl.String("config"), fl.Strings("run"), fl.String("kind"), fl.String("older_than"), fl.Int("keep_latest"), fl.Bool("drop_findings"), fl.Bool("apply")
			if err := checkOutput(output); err != nil {
				return err
			}
			opts := jb.DBPruneOptions{Config: cfgPath, DropFindings: dropFindings, Apply: apply, Now: d.now}
			var ks []core.RunKind
			if fl.Changed("run") {
				opts.RunIDs = runIDs
				if len(opts.RunIDs) == 0 {
					opts.RunIDs = []string{""} // an empty --run is refused by name, not read as "no --run"
				}
			}
			// Flags are text; the library takes typed values and validates them.
			if fl.Changed("kind") {
				var err error
				if ks, err = core.ParsePrunableKinds(kinds); err != nil {
					return usageErrorf("%v", err)
				}
				opts.Kinds = ks
			}
			if fl.Changed("older_than") {
				age, err := parseAge(olderThan)
				if err != nil {
					return usageErrorf("--older-than: %v", err)
				}
				if age <= 0 {
					return usageErrorf("--older-than must be positive")
				}
				opts.OlderThan = age
			}
			if fl.Changed("keep_latest") {
				opts.KeepLatest = &keepLatest
			}
			res, err := jb.DBPrune(cmd.Context(), caseDir, opts)
			if err != nil {
				return err
			}
			printNotes(cmd.ErrOrStderr(), res.Notes)
			if output == "json" {
				return writeIndentedJSON(cmd.OutOrStdout(), res)
			}
			return writePrune(cmd.OutOrStdout(), res.Store, olderThan, ks, res.EventPruneResult, apply)
		},
	}
	fl = addOperationFlags(cmd, "db_prune")
	f := cmd.Flags()
	f.StringVar(&output, "output", "table", "table or json")
	return cmd
}

const pruneListCap = 60

func writePrune(w io.Writer, store, olderThan string, ks []core.RunKind, r core.EventPruneResult, applied bool) error {
	mode := "dry run"
	if applied {
		mode = "apply"
	}
	fmt.Fprintf(w, "prune events in %s (%s)\n", store, mode)
	keep := "findings and run records are kept (run records are marked pruned)"
	if r.DropFindings {
		keep = "findings and run records of the pruned hunts are deleted too"
	}
	if r.ByRunID {
		fmt.Fprintf(w, "the %d hunt(s) named with --run, matched by exact id (no age or keep-latest rule applies); %s\n\n", len(r.Runs), keep)
	} else {
		fmt.Fprintf(w, "hunts whose newest record is older than %s (created before %s), keeping the %d newest of each kind; %s\n\n", olderThan, r.Before.Format(time.RFC3339), r.KeepLatest, keep)
		writePruneKindTable(w, ks, r)
	}
	return writePruneBody(w, r, applied)
}

func writePruneKindTable(w io.Writer, ks []core.RunKind, r core.EventPruneResult) {
	type row struct{ matched, prune, latest, recent, done int }
	rows := map[core.RunKind]*row{}
	for _, k := range ks {
		rows[k] = &row{}
	}
	for _, pr := range r.Runs {
		x := rows[pr.Kind]
		x.matched++
		switch pr.Action {
		case core.ActionPrune:
			x.prune++
		case core.ActionKeepLatest:
			x.latest++
		case core.ActionKeepRecent:
			x.recent++
		case core.ActionAlreadyDone:
			x.done++
		}
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tHUNTS\tPRUNE\tKEPT: LATEST\tKEPT: NEWER\tEVENTS ALREADY PRUNED\tEVENTS\tRAW (uncompressed)")
	for _, k := range ks {
		var ev, raw int64
		for _, pr := range r.Runs {
			if pr.Kind == k && pr.Action == core.ActionPrune {
				ev += pr.Events
				raw += pr.RawBytes
			}
		}
		x := rows[k]
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", k, x.matched, x.prune, x.latest, x.recent, x.done, ev, humanBytes(raw))
	}
	tw.Flush()
	fmt.Fprintln(w)
}

func writePruneBody(w io.Writer, r core.EventPruneResult, applied bool) error {
	var listed int
	for _, pr := range r.Runs {
		if pr.Action == core.ActionAlreadyDone && r.ByRunID {
			fmt.Fprintf(w, "skip (events already pruned)  %s  %s  created %s\n", pr.ID, pr.Kind, fmtTime(pr.Created))
		}
		if pr.Action == core.ActionKeepLatest {
			fmt.Fprintf(w, "keep (latest of its kind)  %s  created %s  %d events\n", pr.ID, fmtTime(pr.Created), pr.Events)
		}
	}
	for _, pr := range r.Runs {
		if pr.Action != core.ActionPrune {
			continue
		}
		if listed == pruneListCap {
			fmt.Fprintf(w, "... and %d more (--output json lists every hunt)\n", int(r.Plan.Runs)-listed)
			break
		}
		listed++
		kind := ""
		if r.ByRunID {
			kind = " (" + string(pr.Kind) + ")"
		}
		fmt.Fprintf(w, "prune  %s%s  created %s  %d events  %s raw  %d findings\n", pr.ID, kind, fmtTime(pr.Created), pr.Events, humanBytes(pr.RawBytes), pr.Findings)
	}
	if listed > 0 || r.Plan.Runs > 0 {
		fmt.Fprintln(w)
	}
	p := r.Plan
	verb := "would delete"
	if applied {
		verb = "planned"
	}
	fmt.Fprintf(w, "%s: %d hunt(s), %d run record(s), %d events (%s raw, %s fields, uncompressed)", verb, p.Runs, p.RunRecords, p.Events, humanBytes(p.RawBytes), humanBytes(p.FieldsBytes))
	if r.DropFindings {
		fmt.Fprintf(w, ", %d findings", p.Findings)
	}
	fmt.Fprintln(w)
	if !applied {
		fmt.Fprintln(w, "dry run: nothing was changed. Add --apply to do it.")
		return nil
	}
	d := r.Deleted
	fmt.Fprintf(w, "deleted: %d events", d.Events)
	if r.DropFindings {
		fmt.Fprintf(w, ", %d findings, %d run records", d.Findings, d.RunRecords)
	} else {
		fmt.Fprintf(w, "; %d run record(s) marked pruned; findings kept", r.Marked)
	}
	fmt.Fprintln(w, " (equal to the plan, checked inside the transaction before it committed)")
	fmt.Fprintln(w, "reminder: the file does not shrink when rows are deleted. Run `jb db compact --to FILE` to write a smaller copy, then swap it in by hand (docs/config/store.md, Store maintenance).")
	return nil
}

// ---- compact ----

func newDBCompactCmd() *cobra.Command {
	var output string
	var fl *opFlags
	cmd := &cobra.Command{
		Use:   "compact (--config FILE | --case DIR) --to FILE [--apply] [--allow-outside-evidence]",
		Short: "Write a compacted copy of the evidence database to a new file (dry run unless --apply)",
		Long: "DuckDB does not give the space of deleted rows back to the file system, so after `jb db prune` the\n" +
			"file is as large as before. compact writes a COMPACTED COPY: a new database file with this build's\n" +
			"schema (schema_migrations carries over) and every table copied into it. It NEVER replaces the original;\n" +
			"swapping the files is yours, and the steps are printed.\n\n" +
			"--to must not exist (it is never overwritten), must be inside the case's evidence directory (git-ignored;\n" +
			"with --config alone, the store's own directory) unless --allow-outside-evidence, and its directory must\n" +
			"pass the same git-ignore guard as evidence. The copy is created mode 0600.\n\n" +
			"Dry run (default) opens the store read-only and prints the source size, an estimate and the target.\n" +
			"--apply opens it READ-WRITE, which no other process can share, so it is refused while anything holds the\n" +
			"store (a running `jb watch`, `jb serve`, another jb command): the holder is named. Stop watchers first.\n" +
			"After copying, it verifies the copy (rows per table equal, raw bytes equal, schema version, a read-only\n" +
			"open) and only then puts it at --to; a copy that fails is deleted.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caseDir, cfgPath, to, apply, outside := fl.String("case"), fl.String("config"), fl.String("to"), fl.Bool("apply"), fl.Bool("allow_outside_evidence")
			if err := checkOutput(output); err != nil {
				return err
			}
			res, err := jb.DBCompact(cmd.Context(), caseDir, jb.DBCompactOptions{
				Config: cfgPath, To: to, AllowOutsideEvidence: outside, Apply: apply,
			})
			if err != nil {
				return err
			}
			printNotes(cmd.ErrOrStderr(), res.Notes)
			if output == "json" {
				return writeIndentedJSON(cmd.OutOrStdout(), res)
			}
			return writeCompact(cmd.OutOrStdout(), res.Store, caseDir, cfgPath, res.CompactResult)
		},
	}
	fl = addOperationFlags(cmd, "db_compact")
	f := cmd.Flags()
	f.StringVar(&output, "output", "table", "output format: table or json (the result, without the swap steps)")
	return cmd
}

func writeCompact(w io.Writer, store, caseDir, cfgPath string, r core.CompactResult) error {
	mode := "dry run"
	if r.Applied {
		mode = "apply"
	}
	fmt.Fprintf(w, "compact %s (%s)\n", store, mode)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "source file\t%s\n", humanBytes(r.SourceBytes))
	fmt.Fprintf(tw, "blocks in use / free inside it\t%s / %s\n", humanBytes(r.UsedBytes), humanBytes(r.FreeBytes))
	fmt.Fprintf(tw, "schema version\t%d\n", r.SchemaVersion)
	fmt.Fprintf(tw, "target\t%s\n", r.Target)
	if r.Applied {
		fmt.Fprintf(tw, "copy file\t%s (source was %s)\n", humanBytes(r.TargetBytes), humanBytes(r.SourceBytes))
	} else {
		fmt.Fprintf(tw, "estimated copy\tabout %s or less (the blocks in use; the copy is rewritten and recompressed)\n", humanBytes(r.EstimateBytes))
	}
	for i, t := range r.Source {
		if r.Applied && i < len(r.Copy) {
			fmt.Fprintf(tw, "rows: %s\t%d in source, %d in copy\n", t.Table, t.Rows, r.Copy[i].Rows)
		} else {
			fmt.Fprintf(tw, "rows: %s\t%d\n", t.Table, t.Rows)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if !r.Applied {
		fmt.Fprintln(w, "dry run: nothing was written. Add --apply to write the copy (it is refused while any process holds the store: stop `jb watch` first).")
		return nil
	}
	fmt.Fprintln(w, "verified: rows per table and raw bytes equal, schema version equal, the copy opens read-only; mode 0600. The original was not changed.")
	scope := renameScope(caseDir, cfgPath)
	q := app.ShellQuote
	fmt.Fprintf(w, "\nswapping the copy in is yours to do. STOP EVERY `jb watch` AND `jb serve` on this store first, then:\n")
	fmt.Fprintf(w, "  mv %s %s.before-compact\n", q(store), q(store))
	fmt.Fprintf(w, "  mv %s %s\n", q(r.Target), q(store))
	fmt.Fprintf(w, "  jb db usage %s    # schema version and the counts of run records, events and findings must match the table above\n", scope)
	fmt.Fprintf(w, "then restart the watchers. Delete %s only when you are satisfied; until then it is your way back.\n", q(store+".before-compact"))
	return nil
}
