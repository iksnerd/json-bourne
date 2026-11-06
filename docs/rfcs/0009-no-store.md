# RFC 0009: Ask a question without leaving evidence
Status: draft
Scope: a `--no-store` flag on `jb hunt` and `jb activity`, and the matching Go options, that run the same code over a private temporary store.

## Summary

`jb hunt` and `jb activity` always write their run to the evidence database. This RFC adds `--no-store`. With it, the command creates a private temporary store, runs the unchanged hunt or activity code over it, and deletes it when the command returns. The evidence database is not opened, created or changed. The output says the run was not stored: the table prints `not stored: this run left no evidence`, and the JSON carries `"stored": false` (`true` otherwise).

## Motivation

A downstream program wants to ask "is this actor active?" and must not leave a run, events or findings in the case's evidence. Today no flag allows this. The program can point `store.path` at a scratch file, but then it owns the cleanup and the placement rules, and a mistake writes into the evidence directory.

The writes are by design. Detectors judge stored evidence, so every finding traces to rows in the store (the comment on `Deps.Reader` in `internal/app/hunt.go`, and "What a hunt does" in `docs/ARCHITECTURE.md`). A second code path that feeds detectors from memory would break that rule. The cause is that the store is welded to the evidence location, not that the detectors need a durable store. This RFC separates the two.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

Same code, different store. Detectors, sources and the use case (`app.Hunt`, `app.Activity`) are untouched. The only thing that changes is which DuckDB file `Sink` and `Reader` point at. This keeps the invariant that a finding traces to stored rows; the rows live in a store that is deleted afterwards.

One typed step. Today `cmd/jb/hunt.go`, `cmd/jb/activity.go`, `jb.go` and `activity.go` each open `cfg.StorePath()` and migrate it. The RFC replaces those four copies with `config.OpenRunStore(ctx, cfg, noStore, keepOut...)`, so the choice is one boolean in one function. `duckdb.OpenTemp` makes the directory, and `Store.Close` removes it, so every existing `defer st.Close()` is the cleanup path.

The result learns it from the store. `watchrun.RunDeps` sets `app.Deps.Scratch` from `Store.TempDir() != ""`, and `app.Hunt` and `app.Activity` copy it into `Stored`. A caller cannot forget to say so, and the zero value of `Deps` means stored.

Considered and rejected: an in-memory DuckDB (`:memory:`). It would skip the file, but `OpenContext` and the lock code assume a path, and a file in a 0700 directory keeps the one open path.

## The design

Proposed. Nothing below exists yet.

Flag. `jb hunt` and `jb activity` take `--no-store` (bool, default false). It combines with `--case`, `--config`, `--window`, `--until`, `--search`, `--search-field` and `--output`.

Store. With the flag, `config.OpenRunStore` calls `duckdb.OpenTemp`, which uses `os.MkdirTemp("", "jb-nostore-")` (mode 0700) and opens `jb.duckdb` inside it. The store is migrated like any other. The configured path (`store.path`, `JB_DB`, the case's evidence directory) is never passed to the open call.

Placement. When the run is in a case, `OpenRunStore` receives the case directory and its evidence directory. If the temporary directory is inside either, which happens only when `TMPDIR` points there, the command MUST refuse with an error that names `--no-store` and `TMPDIR`, and the directory it made MUST be removed.

Cleanup. `Store.Close` closes the database and then removes the temporary directory. Every command already defers `Close`. Success, failure and interrupt all return through the deferred call, because `main` cancels the context on SIGINT and SIGTERM. A process killed by SIGKILL leaves its `jb-nostore-*` directory in the temporary directory; this is stated as a limit.

Output. `app.Result.Stored` and `app.ActivityResult.Stored` are true unless the run was not stored. Table output of both commands prints `not stored: this run left no evidence` on the line after `run`. JSON of both carries `"stored"` as a boolean. `jb.HuntOptions.NoStore` and `jb.ActivityOptions.NoStore` (and so `jb.CaseHuntOptions`, which embeds `HuntOptions`) give the same behaviour to Go callers, and the returned result has `Stored` set.

The run id keeps its form (`hunt-...`, `activity-...`). The `stored` field and the line, not the id, say that the run is not stored, because an id is a stable identifier and a reader that parses it should not meet a new shape.

Semantic cost. Detectors compare a window with the one before it, and they read the events saved by earlier runs as well as this run's. With `--no-store` the temporary store holds only the events this run fetched. A result can therefore differ from a stored run when earlier runs hold events the source no longer returns (for example after an index was rolled over or a retention limit passed). Both windows are still fetched by the same run, so the comparison is sound; it is narrower. The output of `--no-store` does not claim equivalence.

Commands this does not apply to:

- `jb watch`. Its state, the alert log and the stored runs are the point of the command. A watcher with nothing stored has nothing to compare cycles against.
- `jb db` and `jb actor status`. They inspect the evidence database read-only. A temporary store would be empty.
- `jb estate`, `jb intel` and `jb serve`. They read or present stored evidence or the estate files, and `--no-store` would make them read nothing.

The flag is refused on those commands as an unknown flag.

## Non-goals

- A second, non-stored code path for detectors.
- Making `watch` read-only.
- A way to keep the temporary store for debugging. The caller who wants it should run without the flag.
- Protection from SIGKILL or a power loss.
- Hiding that a request was made. The sources still receive the same queries.

## Drawbacks

The result can differ from a stored run, as described above. A caller who compares a `--no-store` answer with a stored one must know this. The cost is also a full fetch of both windows each time, because nothing earlier is reused.

A killed process leaves a directory in `TMPDIR`. It holds fetched events, so it is as sensitive as the evidence. It is mode 0700 and under the user's temporary directory, but it is not encrypted.

The temporary store is on whatever disk `TMPDIR` names. A large window needs the space the stored run would need.

## Alternatives and prior art

Point `store.path` at a scratch file, as the downstream program can do today. This pushes the placement and cleanup rules to every caller and has no check against writing inside the evidence directory.

Run detectors over events held in memory. It would be faster, but it would be a second path with its own bugs, and findings would no longer trace to rows. Rejected.

A read-only mode that fetches and prints without detectors. It answers a different question. The caller wants findings and a verdict.

No prior art was read for this RFC.

## Compatibility

Nothing breaks. `--no-store` is a new flag, and `Stored`, `NoStore` and the `"stored"` JSON key are new. Existing JSON consumers see one extra key, `stored`, which is `true`. The table output of a stored run is unchanged. The Go result types gain a field.

The two users do not need to change anything. The downstream program SHOULD pass `--no-store` (or `NoStore: true`) for a question that must leave no evidence.

## Security considerations

The flag lowers what the command writes. It does not change what the command reads or sends: credentials still come from the environment, and the sources get the same requests.

The temporary directory holds fetched events while the command runs. It is mode 0700 and made by `os.MkdirTemp`, so another local user cannot list or read it. Placing it inside the case or evidence directory is refused, so a git ignore rule for the evidence directory is not the only barrier.

An error message names the temporary path and the case path. It contains no secret and no event data.

## Conformance

Each rule has a test.

- `internal/adapters/duckdb/temp_test.go`: `TestOpenTempIsPrivateMigratableAndRemovedOnClose` (mode 0700, migrate, removal on `Close`) and `TestStoreTempDirIsEmptyForAFileStore`.
- `internal/config/runstore_test.go`: the configured path is never created, a stored run uses the configured path, and a temporary directory inside a protected directory is refused and removed.
- `cmd/jb/nostore_test.go`: the case directory is byte-for-byte unchanged after `hunt --no-store` and `activity --no-store` (a hash of every path, so a new run row in a real store would show); no store file appears; the table line and the JSON key; `--search` with `--until`; removal when the source is down; refusal when `TMPDIR` is inside the case; a config without a case never opens its configured store.
- `nostore_test.go` in the root package: `NoStore` and `Stored` through `HuntCase` and `Activity`.

A SIGKILL leaving a directory has no test. A test cannot kill its own process and then clean up.

## Reference implementations

Shipped: none.

Proposed:

- `duckdb.OpenTemp`, `Store.TempDir`, and removal in `Store.Close` (`internal/adapters/duckdb/duckdb.go`).
- `config.OpenRunStore` (`internal/config/runstore.go`).
- `app.Deps.Scratch`, `app.Result.Stored`, `app.ActivityResult.Stored` (`internal/app`).
- `--no-store` on `hunt` and `activity` (`cmd/jb/hunt.go`, `cmd/jb/activity.go`), and `NoStore` in `jb.go` and `activity.go`.

## Open questions

Should the run id carry a marker such as a `-nostore` suffix? The author proposes not, for the reason given under the design. The maintainer decides.

Should a killed run's directory be swept by the next `jb` start? The author proposes not, because a sweep deletes files in `TMPDIR` by name pattern. The maintainer decides.
