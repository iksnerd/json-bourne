# RFC 0013: Library surface
Status: accepted
Scope: expose every operation of the `jb` command line as a Go function in the root package `jb`, with result types the library owns, so that a Go program can use `jb` as a package and the CLI is a thin printer over the same functions.
Accepted: 2026-11-06 by the maintainer

## Summary

The root package exports `Hunt`, `HuntCase`, `Activity`, `Watch`, `WatchStatus` and `CaseShow`. That covers 5 of the roughly 23 runnable commands. The rest can be done only by running the binary and parsing its output, and the JSON shapes that `--output json` prints are defined in `cmd/jb`, which is `package main`, so no Go program can import them.

This RFC adds a function for each remaining operation, in four groups, and moves each JSON result type into the library. The CLI then calls the function and prints the library's value. There is one code path per operation and one definition of its result.

RFC 0010 (operations and `jb mcp`) stays a draft. It builds on this surface later and does not block it.

## Motivation

The owner wants to use `jb` as a package. A caller that needs `jb db status` today shells out and parses JSON that has no importable type. Twelve separate JSON encoders in `cmd/jb` also mean the CLI and the library can drift, which RFC 0005 and RFC 0007 each fixed one symptom of.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Operation" means one command that returns one result. "Result type" means the Go value that `--output json` prints.

## How this design was made

1. **The workflow first.** A Go program calls `jb.DBStatus(ctx, caseDir, opts)` and receives a typed value. It does not run a process or parse text.
2. **One path.** The command calls the library function and prints its result. A second implementation inside `cmd/jb` is not allowed, because it is the drift this RFC removes.
3. **The library owns the result type.** The type that `--output json` prints is the type the function returns. A test per operation pins the JSON against the shape the CLI printed before this change, so no existing key changes.
4. **Read-only first, mutating behind `Apply`.** A function that changes anything takes `Apply bool`, whose zero value is a dry run, as the CLI works today.
5. **No Go extension points.** Detectors, sources and sinks stay internal. Extension goes through the plugin protocol and `sdk`.

## The design

Everything in this section is a proposal. The shipped functions are listed under Reference implementations.

### Conventions for every function

- The first argument is `context.Context` when the operation does I/O, then the case directory or config, then an options struct.
- Options structs follow the existing ones (`HuntOptions`, `ActivityOptions`): plain fields, zero values mean the documented default, an `Env` field replaces the process environment, a `Now` field replaces the clock.
- A mistake the caller made returns a `*jb.UsageError` (RFC 0005). A failure to do the work returns an ordinary error. An operation that finished but could not answer completely returns a result whose completeness method says so, never a clean-looking value.
- A result type has JSON tags and marshals to what `--output json` printed.
- No function prints, reads `os.Args` or exits.

### The four groups

| Group | Functions | Notes |
|---|---|---|
| 1. Read-only inspection | `CaseCheck`, `Doctor`, `ActorStatus`, `DBStatus`, `DBUsage`, `Intel` | `Intel` sends addresses to a reputation feed and keeps the existing switch. |
| 2. Estate | `EstateIP`, `EstateASN`, `EstateDNS`, `EstateCT`, `EstateDiff`, `EstateRefresh` | Collectors keep their bounds and the passive-only policy. |
| 3. Mutating | `DBPrune`, `DBCompact`, `DBRenameSource`, `EstatePromote` | `Apply bool`; the zero value is a dry run. |
| 4. Dashboard | `DashboardHandler`, `Serve` | `DashboardHandler` returns an `http.Handler` over a read-only store, so a program can embed the dashboard. `Serve` runs it on a loopback address until the context ends. |
| 5. Result types | the JSON types of every command | Moved into the library and used by the CLI, which prints them. |

Group 5 is not a separate step in the code: each function in groups 1 to 3 moves its own result type as it is added.

### Not in this RFC

- A reader for stored runs and findings needs its own design.
- Loaders and types for the case, actor and estate file formats stay internal. The JSON schemas in `schemas/` serve outside readers.

## Non-goals

- It does not change what any command computes, or any flag, default or exit code.
- It does not add the registry, `jb operations` or `jb mcp` of RFC 0010.
- It does not make any `internal/` package public.
- It does not weaken the dashboard security model of RFC 0003: read-only store, no mutation endpoint, strict CSP.

## Drawbacks

- The public surface grows from 8 to about 25 exported functions, each a promise to keep working. Before 1.0 nothing is promised, but a caller will depend on them.
- Moving result types out of `cmd/jb` touches every command and its tests.
- A library function that is also the CLI's only path makes a bug in it a bug in both.

## Alternatives and prior art

- **Shell out and parse JSON.** What a caller must do today. It has no types and no completeness contract.
- **Expose the internal `app` and `config` packages.** It would expose every internal type and freeze the architecture. Declined.
- **Wait for RFC 0010 and generate the surface.** The registry would give a uniform call, but it blocks the owner's need on a larger design. Declined for now; this RFC's functions become the handlers of that registry.
- **Prior art.** The existing functions `Hunt` and `Activity` are the pattern. The author read no other Go library's API for this draft.

## Compatibility

There is no compatibility path, because `jb` and one other program are the only users and nothing is public. The CLI's flags, defaults, exit codes and JSON keys do not change, and a test per operation holds the JSON. Internal packages that cmd/jb used directly may be reorganised.

## Security considerations

- A library function is a new way to reach the same capabilities. It reads credentials only through the `Env` option or the process environment, never from an argument.
- A mutating function does nothing without `Apply`, and `Apply` defaults to false.
- `Intel` and the estate collectors send addresses and names to third-party services. They keep their existing switches and the passive-only policy in docs/POLICY.md. A library caller gets no way around either.
- A path argument is checked as the command checks it: a case path stays inside the case, a config inside the case, an output file outside the evidence directory unless asked.

## Conformance

Proposed.

- **One test per function** on synthetic data: the result, and the completeness contract where the operation can be incomplete.
- **JSON parity.** For each command, a test compares the CLI's `--output json` with the marshalled library value and with a recorded shape, so no key is renamed or dropped.
- **Dry run.** For each mutating function, a test shows that a call without `Apply` changes nothing.
- **One path.** A test fails if `cmd/jb` contains a second implementation, by checking that each command's `RunE` calls the library function (a table of command to function).
- **Usage errors.** Each function's caller mistakes return `jb.IsUsage`.

## Reference implementations

Shipped before this RFC: `Hunt`, `HuntCase`, `Activity`, `Watch`, `WatchStatus`, `CaseShow`, `LoadConfig`, `IsUsage`.

Proposed, in groups that can be built apart:

0. Group 4: `DashboardHandler` and `Serve`. The owner named `serve` a must-have on 2026-11-06.
1. Group 1 part A: `CaseCheck`, `Doctor`, `ActorStatus`.
2. Group 1 part B and group 3 for the database: `DBStatus`, `DBUsage`, `DBPrune`, `DBCompact`, `DBRenameSource`.
3. `Intel` and group 2 with `EstatePromote`: the estate functions.

## Open questions

1. **Naming.** `DBPrune` or `PruneDB`; `EstateIP` or `Estate`. Decides: the author, then the maintainer when reviewing.
2. **Sharing result types between functions.** Several estate functions return the same graph. Decides: the author.
3. **Dashboard security.** `DashboardHandler` keeps the loopback-only and read-only rules of RFC 0003 and refuses a non-loopback address in `Serve`. Does the handler alone need a documented warning for a caller who mounts it elsewhere? Decides: the author.
4. **A reader for stored evidence.** Needs its own RFC. Decides: the maintainer.

## Changes

- 2026-11-06: first draft, accepted by the maintainer the same day ("first lets just add them - we want to use JB as a package").
