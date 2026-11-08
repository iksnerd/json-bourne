# Watch

This page covers what `jb watch` prints and how several watchers share a case.

What `jb watch` prints and how several watchers share a case.

`--every` (`WatchOptions.Every`) must be at least `5s`; a smaller value is a usage error naming the flag and the minimum. A run id carries the cycle's start to the second, so two cycles inside one second would share a run id: they would replace each other's stored run and share the webhook cap.

## Watch output

`jb watch --once --output json` prints the cycle report as one JSON document on stdout. The alert lines go to stderr instead, so stdout stays parseable; the log file and any webhook get them as always. `--output json` without `--once` is a usage error (exit 2), because a loop has no single result. A cycle that is not healthy still prints its report, then exits 1. The same fields are in the Go package as `jb.CycleReport`.

| Field | Type | Meaning |
|---|---|---|
| `run` | string | Run id of the cycle (`watch-<time>`, `watch-NAME-<time>` for a named watcher). |
| `watcher` | string | The `--name`; absent for the unnamed watcher. |
| `window` | [from, to] | RFC 3339 times; the hunt window, `[from, to)`. |
| `status` | string | `quiet`, `findings`, `incomplete` or `failed`. |
| `healthy` | bool | True only for `quiet` and `findings`. |
| `failed` | list of string | Sources and detectors that did not finish. Empty, never null. |
| `new` | int | Finding alerts delivered. |
| `suppressed` | int | Findings held back by `--ttl`. |
| `repeated` | int | Outage alerts held back by `--repeat`. |
| `recovered` | int | Recovery alerts delivered. |
| `optional_failed` | int | Alerts the log took and a webhook did not. |
| `gap` | string | Present on a cycle that completed when its window starts after the end of the last window that completed: the text gives the length and bounds of the span no completed cycle covered. Never set on an incomplete cycle (the outage alert covers that), so it appears once, on the cycle that recovers. The cycle that carries it is `incomplete`. Kept in memory: a restart forgets it. |
| `error` | string | Present when something broke the cycle itself. |
| `alerts` | list of alert | Everything delivered this cycle, health alerts first. Each has `kind`, `tag`, `severity`, `text`, `at`, and `detector`, `run`, `watcher` when set. |
| `pruned` | object or null | `runs`, `events`, `findings` removed by retention; null when it did not run or failed. |

`jb hunt --no-store` and `jb activity --no-store` do not use this path at all. They run the same code over a private temporary store (a `jb-nostore-*` directory, mode 0700, in `TMPDIR`) that is deleted when the command returns. The evidence database is not opened, created or changed, and a `TMPDIR` inside the case is refused. The output says `not stored: this run left no evidence` (`"stored": false` in JSON; `true` for a stored run). Detectors then see only the events this run fetched, not those saved by earlier runs, so a result can differ from a stored run. Not offered on `watch`, `db`, `actor`, `estate`, `intel` or `serve`. See [RFC 0009](../rfcs/0009-no-store.md).

## Several watchers on one case

`jb watch --name NAME` (`^[a-z][a-z0-9_-]{0,31}$`) lets one case hold several watch profiles, each with its own `--config`. Without `--name` nothing changes. With it, everything the watcher owns is named after it:

| | unnamed | `--name a` |
|---|---|---|
| dedupe memory | `evidence/watch-state.json` | `evidence/watch-state.a.json` |
| log | `evidence/watch.log` | `evidence/watch.a.log` |
| single-instance lock | `evidence/watch.lock` | `evidence/watch.a.lock` |
| run id | `watch-<UTC time>` | `watch-a-<UTC time>` |

The name is on the `watching case ...` banner, on every alert (`[w:a]` after the tag) and on every `CYCLE` line (`[w:a]` after the run id), so merged logs stay attributable.

- **Dedupe is per watcher.** The state files are separate, so a finding two watchers both see alerts once in each of them. That is deliberate: two profiles are two readers of the alerts. Give them different detectors, or send them to different channels, if that is not wanted.
- **Retention is per watcher.** After a cycle, `--keep` prunes only runs shaped exactly `watch-a-<20060102T150405Z>` (and their `/source` runs), never another watcher's and never the unnamed watcher's; the unnamed watcher prunes only `watch-<stamp>`. The test is on the whole shape, not a prefix, so `watch-a-` does not reach `watch-ab-...` or `watch-a-b-...`, and `watch-` does not reach `watch-a-...`. Each watcher also keeps its own newest run, whatever its age.
- **One process per name and case.** A watcher takes an exclusive lock on its lock file before it builds anything; a second `jb watch` with the same name (or a second unnamed one) on the same case is refused at once and the message names the holder's PID. The lock is `flock(2)` on Unix, so it is released by the kernel when the holder exits however it dies; a lock file left behind by a killed process is not a held lock, and the next watcher takes it over. The file is never deleted.
- **The `jb serve` Watch page shows the unnamed watcher's log and state only** (it reads `watch.log` and `watch-state.json`); the [Timeline](serve.md#timeline) page shows the cycles of every watcher, named or not.
- **They share only the DuckDB file.** Each opens it for one hunt at a time, and the one that arrives while the other is writing waits for it ([Locking](store.md#locking-one-writer-or-many-readers); with `JB_DB_LOCK_WAIT=0` they would collide and a cycle would fail, which is why the default wait matters here). Keep the same `store.path` (or none) in the configs of one case, so that they share one store.

[Back to the configuration index](../CONFIG.md)
