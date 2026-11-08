# Store

This page covers the database path, locking, source labels and the store maintenance commands.

## Database path

Resolved in this order:

1. `store.path` in the config. A leading `~/` is expanded to your home directory.
2. The `JB_DB` environment variable.
3. `~/.jb/jb.duckdb`.

In `jb hunt --case DIR` the order is different: an empty `store.path` means `<case>/<paths.evidence>/jb.duckdb` (`JB_DB` is ignored), a relative `store.path` is relative to the case directory, and an absolute or `~/` path is used as written. Without `--case`, a relative `store.path` is relative to the working directory.

`hunt` creates the file and applies schema migrations. `db status` opens it read-only and fails if it does not exist.

### Locking: one writer or many readers

DuckDB lets one process open the file read-write **or** any number open it read-only, never both. A running `jb watch` opens the store once per cycle and holds it for the write phase (measured at about 2 percent of the time, a few seconds per 5 minute cycle), so a `jb serve` request, `jb doctor`, `jb actor status`, `jb db status` or a manual `jb hunt` that lands in that moment would fail with DuckDB's `Could not set lock on file ... Conflicting lock is held in ... (PID n)`.

Every open therefore **waits for that one error, and only that one**, with a bounded jittered backoff: 100 ms, doubling to a 1 s cap, each step cut to between half and all of itself, and never more than the budget in total. The default budget is **15 s**. Set it with the environment variable `JB_DB_LOCK_WAIT`:

| Value | Meaning |
|---|---|
| unset | 15s |
| `30s`, `1m`, ... | that total wait, at most `2m` (a larger value is refused with an error, not clamped) |
| `0` | no retry: fail at the first lock error |
| anything else | refused with an error naming the variable |

A corrupt file, a schema ahead of the build, a permission error or a DuckDB storage-version mismatch is **not** retried and fails at once, unchanged. An interrupt (Ctrl-C, SIGTERM) ends the wait immediately. When the budget runs out the error names the file, says another process holds it, gives the holder's executable name and PID when DuckDB names one (nothing else of DuckDB's message is repeated), and says what to do: wait for it or stop that process.

`jb doctor` keeps reporting a held lock as a **FAIL**, but only after a fixed 3 s budget (not `JB_DB_LOCK_WAIT`), so a watch cycle that happens to be writing at that instant does not make the report flap, and the failing line says who holds it.

### Source labels and double counting

An event is stored with its source **label**: the source's `name:`, or `kibana:<index>` when it has none. Every event written since schema 4 also carries a document identity (the store refuses one without), so it is read once whichever label stores it. The label still decides which source a `sources:` scope reads. Name your sources before you backfill (docs/BACKFILL.md), and if you add or change a `name:` later, relabel what is already stored:

```sh
jb db rename-source --case DIR 'kibana:logs-ingress-*' ingress            # dry run: counts, changes nothing
jb db rename-source --case DIR 'kibana:logs-ingress-*' ingress --apply    # do it
jb db rename-source --case DIR 'kibana:logs-ingress-*' ingress --apply --merge
```

(`--config FILE` instead of `--case DIR` names the store from a config.) `OLD` is a stored label: a valid source name, or a default `kibana:<index>` label (quote it, the index may hold `*`). `NEW` must be a valid source name, the same rule as `name:` (a lower case letter, then `a-z 0-9 _ . : -`, at most 64 characters).

- **Dry run is the default.** Without `--apply` the store is opened read-only, so the engine refuses any write, and the counts are printed: events and runs under `OLD`, events already under `NEW`, documents under both, rows that would be dropped, rows that would be relabelled.
- **One transaction.** The `source` and `returners` columns of `events` are the only columns that store an event's source label (`returners` lists every source that returned a shared document; a rename rewrites both together, keeps the list a sorted set that includes the owner, and renames a label that appears only as a returner) (`runs` and `findings` are keyed by run id; `reputation.source` names a feed, a different thing). A failure half way leaves nothing changed.
- **Run ids are never touched**, so a stored run id such as `hunt-20261101T120000Z/kibana:logs-ingress-*` keeps its old text; only the events' label changes.
- **Overlap is refused.** If `NEW` already holds a document `OLD` also holds (same `ts`, `kind` and `doc_sha256`), the command refuses, dry run or not, and says how many. `--merge` allows it: in the same transaction the rows of `OLD` that `NEW` already covers are deleted (counted and printed) and the rest are relabelled. A run that holds more identical copies of a document than `NEW` does is kept whole, so real repeated lines survive.
- **Locks.** If another process holds the file the command waits as above, then reports the holder.
- **No raw document.** An event stored without a raw payload digests its label into `doc_sha256`. That digest is left as stored (the identity rule leaves stored digests alone), so such a row cannot match across labels and a later fetch of the same document under `NEW` is read as a separate event. The count of such rows is printed.

`jb hunt`, `jb activity`, `jb watch` (in each cycle) and `jb doctor` print a **WARNING** when the same documents (same `ts`, `kind` and `doc_sha256`) are stored under two labels inside the window being read (for `doctor`, the last 24 hours). It names both labels, the number of documents and the exact `jb db rename-source ... --merge` command, as a dry run. Documents that carry a stored document identity (schema 4 and later, from a source with a document scope) are read once and are not reported. It is advice only: it never changes a verdict or an exit code, and in `doctor` it is a `warn`, not a failure. Two labels holding different documents are two sources and are not reported.

## Store maintenance

The evidence store only grows. Nothing prunes it except `jb watch --keep`, which removes its own `watch-` runs, per watcher. Everything else stays: `hunt-*`, `hunt-until-*`, `activity-*`, `activity-until-*`, `search-*`, `search-until-*`. Found live, a case store reached 1.7 GB, mostly one-off runs of those kinds. Two things made it worse:

- **Duplicates are stored per run.** The identity rule collapses the same document fetched by overlapping runs when the store is *read* (docs/ARCHITECTURE.md, "Evidence store"), not when it is written. Repeated or overlapping backfills, retried days and replays store the documents again under each run id, so the file is several times the distinct document count. A backfill loop should be followed by a prune ([docs/BACKFILL.md](../BACKFILL.md#prune-after-a-backfill)).
- **DuckDB does not shrink the file after a delete.** The freed blocks are reused by later writes, but the file keeps its size. Only a copy into a new file gives the space back.

Three commands, all strict. The runbook is: **usage, prune dry run, prune `--apply`, compact `--to`, swap.**

```sh
jb db usage   --case DIR                                                              # 1. what is big (read-only)
jb db prune   --case DIR --kind hunt,activity,hunt-until --older-than 14d             # 2. dry run: what would go, what is kept and why
jb db prune   --case DIR --kind hunt,activity,hunt-until --older-than 14d --apply     # 3. do it, one transaction
jb db compact --case DIR --to DIR/evidence/jb.compacted.duckdb                        # 4. dry run: sizes and the target
jb db compact --case DIR --to DIR/evidence/jb.compacted.duckdb --apply                # 5. write and verify the copy
# 6. swap by hand (the command prints these steps with your paths): stop every `jb watch` and `jb serve`, then
#    mv jb.duckdb jb.duckdb.before-compact; mv jb.compacted.duckdb jb.duckdb; jb db usage --case DIR
#    restart the watchers; delete the old file later
```

(`--config FILE` instead of `--case DIR` names the store from a config; with `--case`, `--config` picks one of the case's configs.)

### `jb db usage`

Read-only: the store is opened with `access_mode=READ_ONLY`, so the engine refuses a write, and another process holding it read-write is waited for as in [Locking](#locking-one-writer-or-many-readers). The queries are fixed text; there is no user SQL. For each **run kind** and each **source label** it prints runs, events, raw bytes, fields bytes and the oldest and newest run time, then the file size on disk, how much of it DuckDB counts as free, and how many documents are stored under two labels (the same check as the warnings in [Source labels and double counting](#source-labels-and-double-counting), reused, capped at five label pairs). `--output json` gives the same numbers.

- **Run kind** is read from the whole shape of the run id: `watch` (one row per watcher, the unnamed one included), `hunt`, `hunt-until`, `activity`, `activity-until`, `search`, `search-until`, and `other` for anything that is not exactly one of those shapes. `hunt-` therefore never counts `hunt-until-...`, and `watch-a-` never counts `watch-ab-...`.
- **Runs** are hunts: a hunt's findings run and its `id/source` event runs count once. `EVENTS PRUNED` counts the hunts whose events `jb db prune` removed.
- **Raw and fields bytes are the uncompressed size** of the stored text (`octet_length` of the raw column, the length of the fields JSON). DuckDB compresses on disk, so these show proportions between kinds and labels, not the file size. The file size is printed separately.

### `jb db prune`

```
jb db prune (--config FILE | --case DIR) --kind K[,K...] --older-than DURATION [--keep-latest N] [--drop-findings] [--apply]
jb db prune (--config FILE | --case DIR) --run ID [--run ID ...] [--drop-findings] [--apply]
```

It deletes the stored **events**, and with them the raw documents, of old runs. Rules:

- **Dry run by default.** Without `--apply` the store is opened read-only (the engine refuses a write) and the command prints what would go (hunts, run records, events and raw bytes per kind) and what is kept and why. `--apply` opens the store read-write and does everything in one transaction.
- **`--kind` is required**, one or more of `hunt`, `hunt-until`, `activity`, `activity-until`, `search`, `search-until`. There is no `all` and no wildcard. `watch`, a `watch-...` id and a named watcher are refused with a pointer to `jb watch --keep`, which owns watch retention and keeps each watcher's newest run; this command does not duplicate it. A run whose id is not exactly one of those shapes (`other`) is never matched.
- **Matching is by the whole run-id shape**, so `--kind hunt` does not reach `hunt-until-...`, and `hunt-20261106T040000Z/ingress` (the events of one source of a hunt) belongs to the hunt `hunt-20261106T040000Z`. The prune works on hunts: the findings run and all event runs of one hunt go or stay together.
- **Age is the stored `created_at`.** A hunt is old when its newest record was created before now minus `--older-than` (`14d`, `72h`, `2w`). Saving a run again keeps its creation time. The age of the data inside is irrelevant.
- **`--keep-latest N`** (default 1) keeps the N newest hunts of **each selected kind**, whatever their age, so the latest hunt that `jb intel` reads and the latest activity check are not removed by accident. `0` is accepted only when you write `--keep-latest 0`; leaving the flag out means 1.
- **Findings and run records stay by default.** Only events are deleted. The run record is stamped `runs.pruned_at` (schema v2, docs/CASE-SPEC.md) so `jb db usage` can say the events are gone. `--drop-findings` also deletes the findings and run records of the pruned hunts. A hunt whose events are already gone is reported as such and left alone. `reputation` is never touched.
- **`--run ID` removes exactly the runs you name.** It is the other way to choose, for a one-off run that `--keep-latest` would keep (the newest runs are the ones you want gone). Repeat it, at most 20 times. It cannot be combined with `--kind`, `--older-than` or `--keep-latest` (exit 2): the age and keep-latest rules do not apply to a run you named. The id is the hunt id as the dry run prints it, compared whole, never as a prefix or a pattern; `hunt-20261106T040000Z/ingress` (one source of a hunt), a wildcard and an id of no prunable kind are refused. Watch ids are refused as `--kind watch` is. An id that is not in the store is an error that names it, and then nothing is deleted. An id given twice counts once. Everything else on this list (dry run by default, one transaction, checked counts, findings kept unless `--drop-findings`, no shrink, no reputation) holds for `--run` too, and the plan and `--output json` list each named run with its kind, events and bytes (`"by_run_id": true`).
- **Counts are checked.** The plan is counted inside the transaction, the deletes' row counts are compared with it, and any difference rolls everything back. What it prints after `--apply` is the engine's count.
- **Locking.** `--apply` needs the store to itself. It waits `JB_DB_LOCK_WAIT`, then refuses and names the holder (a running `jb watch` holds the file only for the write phase of each cycle). A missing store is never created.
- The output has counts and run ids, which can hold index patterns. It never prints a stored document or an address from one.

Example: remove two comparison runs and nothing else.

```
jb db prune --case DIR --run hunt-20261106T040000Z --run hunt-20261106T041500Z           # dry run
jb db prune --case DIR --run hunt-20261106T040000Z --run hunt-20261106T041500Z --apply   # do it
```

The file does **not** shrink. The command says so after `--apply`; go on to `compact`.

### `jb db compact`

```
jb db compact (--config FILE | --case DIR) --to FILE [--apply] [--allow-outside-evidence]
```

DuckDB keeps the space of deleted rows inside the file. `compact` writes a **new file**: it creates the schema in it from this build's migrations (so `schema_migrations` and the `runs.pruned_at` column carry over exactly) and copies the five tables with `INSERT ... SELECT`, inside a private directory next to the target. It then verifies the copy and only then puts it at `--to`.

- **Dry run by default.** Read-only open; prints the source size, the blocks DuckDB counts as in use and as free, an estimate for the copy (the blocks in use; the copy is recompressed, so it can differ) and the target.
- **`--apply` needs the store to itself.** It opens it read-write, which no other process can share, so it is refused while *anything* holds it (`jb watch`, `jb serve`, another `jb` command) and names the holder. Stop watchers first. It writes nothing to the original.
- **`--to` must not exist** (never overwritten), its directory must exist (it is not created), and it must be inside the case's evidence directory, which git ignores (with `--config` alone: the store's own directory), or `--allow-outside-evidence` must be given. Its directory must also pass the same git-ignore guard as evidence (`jb case check`), with or without that flag. Mode `0600`.
- **Verified before it appears.** Rows per table equal to the source, a content digest of every copied column equal (a sum of per-row hashes, so the order does not matter; it covers `returners` and `doc_ident` too), the schema version, and a fresh read-only open of the file as written. A test fails when a migration adds a column to a copied table that `compact` does not copy. A copy that fails is deleted and never appears at `--to`.
- **It never replaces the original.** Swapping is the operator's step, printed with your paths. Stop every watcher and `jb serve` first (a watcher that opens the store between the two `mv` commands would create an empty database), keep the old file until the new one has served a cycle, and check with `jb db usage`.
- **Disk.** The copy needs room for the compacted size beside the original. The command does not check free space. Only the five tables of this schema are copied; a table someone added to the file by hand is not.

A store older than this build's schema (`jb db usage` and a prune dry run refuse it read-only) is migrated by the next `jb hunt`, `jb watch` cycle or `jb db prune --apply`.

[Back to the configuration index](../CONFIG.md)
