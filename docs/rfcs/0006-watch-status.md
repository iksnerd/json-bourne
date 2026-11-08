# RFC 0006: Watcher status record and `jb watch status`
Status: implemented
Scope: a machine-readable health record written by `jb watch`, and a command and Go function that report whether each watcher of a case is alive.
Accepted: 2026-11-06 by the maintainer
Update: 2026-11-08. Package `jb` now lives in `jb/` (import path `github.com/iksnerd/json-bourne/jb`). Where this RFC says "the root package" or names a root file (`jb.go`, `activity.go`, a `*_test.go` at the root), it means that package and its files, which were at the module root when this was written. The text below is otherwise unchanged.

## Summary

`jb watch` writes a small JSON file, `watch-status.json` (`watch-status.NAME.json` for a named watcher), at start and at the end of every cycle. It names the watcher, its process, its options, its last cycle and when the next is due. A new command, `jb watch status`, and a new Go function, `jb.WatchStatus`, read that record and probe the watcher's lock without taking it. They report each watcher as `running`, `stale`, `stopped` or `unknown`. A program no longer parses `watch.log`, reads the PID in `watch.lock` or runs `ps`.

## Motivation

A downstream program runs several named watchers on one case with `jb watch --case DIR --name NAME`. It needs to know if each one is alive and what it runs. Today it finds the last `CYCLE` line in `watch.NAME.log`, reads the bare PID in `watch.NAME.lock` and runs `ps` to learn the options.

All three couple it to details that `jb` does not promise. The log line is human text. The PID in the lock file is not proof of a live holder, because a killed watcher leaves it behind. The options exist only on a command line. The cause is that the watcher writes no health record. Parsing it better in the caller treats a symptom.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

The watcher writes the record; a reader does not infer it. The watcher alone knows its options, its cycle verdict and its next start. Writing it at the end of each cycle makes the record a heartbeat as well as a description.

Liveness comes from the lock, not from the record. A record outlives its process, so a record alone cannot say "alive". The kernel drops the `flock(2)` lock when the holder dies in any way, so a held lock is the one reliable sign of a live process. The record adds the second half: a live process that has stopped cycling is `stale`.

The probe asks for a shared lock without waiting and drops it at once. That never takes the exclusive lock from a real holder. It can refuse a watcher that starts in the same instant, so `Acquire` asks again a few times before it reports the lock as held. The alternative, signalling the PID in the file, was rejected because PIDs are reused.

The record is a new file, not new keys in `watch-state.json`. The state file is dedupe memory that a damaged copy may lose; this file is a contract for other programs and has its own `apiVersion`.

The heartbeat limit is three intervals. One missed cycle, such as a slow hunt, is not an outage. Three is a stated constant, not a flag, because no caller has asked to change it.

## The design

Implemented, all of it.

**The record.** `<evidence>/watch-status.json`, or `watch-status.NAME.json`, named by the same rule as the other watch files. The format, with every key, is in docs/CASE-SPEC.md section 3.1 under `watch-status.json`. In short: `apiVersion` (`jb.watch-status/v1`), `name`, `pid`, `started`, `updated`, `config` (relative to the case), `everySeconds`, `windowSeconds`, `ttlSeconds`, `keepSeconds`, `repeatSeconds`, `lastCycle` (`run`, `verdict`, `ended`, `windowFrom`, `windowTo`, `new`, `suppressed`, `repeated`, `recovered`, `failed`) and `nextDue`. `verdict` is `QUIET`, `FINDINGS`, `INCOMPLETE` or `FAILED`. The record holds names, counts and times. It holds no error text, so it cannot carry a credential.

**When it is written.** Once before the first cycle, and once after each cycle, by the watch loop. Writes replace the file atomically: temp file in the same directory, sync, rename. A failed write raises a `watch-status-save` alert and does not stop the watcher or change the cycle's verdict.

**The reader.** A reader accepts only `jb.watch-status/v1`. An older or newer version, an unknown field, trailing data, no `pid`, no `started` or a non-positive `everySeconds` is an error. The error for another version says the watcher rewrites the file at its next cycle.

**The states.** For each watcher found:

| State | Lock | Record | Last cycle |
|---|---|---|---|
| `running` | held | readable | ended within 3 x `everySeconds` of now |
| `stale` | held | readable | older than that (before the first cycle: counted from `started`) |
| `stopped` | free | readable | any |
| `unknown` | any | missing, unreadable, or for another name | any |

**The command.** `jb watch status --case DIR [--config FILE] [--name NAME] [--output table|json]`. It finds watchers from the `watch*.lock` and `watch-status*.json` files in the evidence directory. It writes nothing and never holds the lock. Without `--name` it reports every watcher found. `--name ""` selects the unnamed watcher. `--config` keeps the watchers whose record names that config. Exit status is 0 whatever the states.

**The Go function.** `jb.WatchStatus(caseDir string, opts WatchStatusOptions) ([]WatcherStatus, error)`, in `watchstatus.go` at the repository root, with the same selection options and the same result as the command.

**The lock probe.** `runlock.Probe(path) (Holder, error)`. A missing file is free. A file that cannot be opened is an error, never "free". Where `flock` is not available, an existing lock file counts as held, as `Acquire` already treats it.

Examples in docs/CASE-SPEC.md are not run, except by the tests named under Conformance.

## Non-goals

- It does not start, stop or restart a watcher.
- It does not change how `watch.log`, `watch-state.json` or `watch.lock` are written or read.
- It does not add a flag for the heartbeat limit.
- It does not report the health of the evidence store or of a source; the last cycle's `failed` list carries that.
- It does not watch a watcher on another machine. The lock and the record are local files.

## Drawbacks

- A fourth file per watcher in `evidence/`, written at every cycle: one small synced write.
- A status probe holds a shared lock for an instant. A watcher that starts in that instant waits up to 40 ms before `Acquire` reports it as held.
- A cycle that runs longer than three intervals makes a healthy watcher read `stale` until it ends. The reason names the age, so the reader can see why.
- The record is only as fresh as the last cycle. A watcher that dies between cycles reads `stopped` immediately, but one that hangs inside a cycle reads `running` for up to three intervals.
- A watcher from an older build has no record. It reads `unknown` until it is restarted.

## Alternatives and prior art

Parsing `watch.log` or `ps` in the caller, as today. Rejected: it ties the caller to human text and a command line.

A PID check in the record (`kill(pid, 0)`). Rejected: PIDs are reused, and the lock already answers the question exactly.

Putting the fields into `watch-state.json`. Rejected: that file is memory the watcher may drop when damaged, and it has no `apiVersion`.

A local socket the watcher serves. Rejected: it adds a listener and a protocol for a question a file answers.

Many supervisors report liveness from a lock or a pid file plus a heartbeat timestamp. This design follows the same split: the lock proves the process, the timestamp proves progress.

## Compatibility

Nothing is kept for old forms. A watcher from an older build writes no record, so `jb watch status` reports it `unknown` with that reason until it is restarted on the new build. `watch-state.json`, `watch.log` and `watch.lock` do not change.

The two users must do two things. A program that parses the log, the lock file or `ps` for health should call `jb watch status --output json` or `jb.WatchStatus` instead. Any test or script that lists the files in `evidence/` after a watch must expect `watch-status[.NAME].json`.

A reader of `jb.watch-status/v1` that meets another `apiVersion` gets a clear error that says to rewrite the file; the watcher does so at its next cycle. There is no loader for two versions.

## Security considerations

The record names the PID, start time, config path, options and the names of components that failed. It holds no error text and no value read from the environment, so a credential has no path into it. The `watchstatus` adapter is limited by `internal/archtest` to `core` and the standard library, with no network and no process.

The file is written with mode 0600 inside `evidence/`, which the case guard already requires to be ignored by git. `jb watch status` reads two files per watcher and takes no exclusive lock, so it cannot stop a watcher or make one start late for more than the retry. A hostile file in `evidence/` can make a watcher read `unknown` or, with a forged recent time, `stopped`; it cannot make a dead watcher read `running`, because that needs the lock.

## Conformance

- `internal/adapters/watchstatus/watchstatus_test.go`: round trip, key names, strict reading, the rewrite message, atomic replace.
- `internal/adapters/runlock/probe_test.go`: held, free, missing, killed holder, unreadable file, and an `Acquire` racing probes.
- `internal/app/watch_status_test.go`: the record is published at start and after each cycle, verdict and failed names, a failed save raises an alert, no sink still runs.
- `internal/watchrun/status_test.go`: each state, the exact heartbeat boundary, a lock held by the test process, discovery and ordering, name mismatch, the config filter, and that status never disturbs a lock.
- `cmd/jb/watchstatus_test.go`: a real `jb watch --once` against the fake Kibana writes the record and `status` reads it; running, stale and unknown together; usage errors.
- `watchstatus_test.go` at the root: `jb.WatchStatus`.
- `internal/archtest`: the dependency rule for `internal/adapters/watchstatus`.

## Reference implementations

Shipped: yes. The list below is where it lives.

Implemented in:

- `internal/core/watchstatus.go`: the record's domain types and the `WatchStatusSink` port.
- `internal/adapters/watchstatus/watchstatus.go`: writer and strict reader.
- `internal/adapters/runlock/runlock.go`, `runlock_unix.go`, `runlock_other.go`: `Probe`.
- `internal/app/watch.go`: `WatchDeps.Status`, published by the loop.
- `internal/watchrun/status.go`: discovery and the state rule.
- `cmd/jb/watchstatus.go`: the command.
- `watchstatus.go` (root): `jb.WatchStatus`.

## Open questions

- Should the heartbeat factor be configurable? The maintainer decides, when a caller needs a value other than 3.
- Should `status` exit non-zero when a watcher is not `running`? Exit 0 today so that a caller reads the states; the downstream program's owner decides.
- Should a watcher write one last record on a clean stop, saying it stopped on purpose? The maintainer decides; today `stopped` covers a clean stop and a kill alike.
- 2026-11-06: accepted by the maintainer. The code is merged; the status becomes `implemented` when the Reference implementations section is moved from proposed to shipped.
