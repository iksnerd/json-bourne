# RFC 0017: Public API owns its types
Status: accepted
Scope: decide which types of package `jb` are public contract, make package `jb` define them instead of aliasing internal types, and add a test that fails when the exported surface changes by accident.

Accepted: 2026-11-07 by the maintainer

## Summary

Package `jb` exports 42 type aliases of internal types (counted below). A change inside `internal/` therefore changes the public Go API with no edit to `jb` and no review of that edge. This RFC proposes that every public type is defined in package `jb` with explicit fields, that the root package converts at the boundary, and that a golden of the exported surface fails the build when the surface changes without a deliberate edit.

`--output json` stays byte for byte the same. The change adds no command, port, file format or config key. Several Go-API changes are breaking and are allowed before 1.0 ([CONTRIBUTING.md](../../CONTRIBUTING.md), "Compatibility before 1.0").

## Scope of acceptance

The maintainer accepted two parts on 2026-11-07, after a review against the Hashimoto bar. The rest is parked, not refused.

- **Accepted, build now:** step 1 (the surface golden of `jb` and `sdk`, which follows aliases and lists every field, tag and method, so a change in an internal type shows in a golden diff that must be explained) and step 6 (make `Config` opaque, remove `EstatePorts`). Step 6 waits for the answer of the one other user (open question 3).
- **Parked:** steps 2 to 5 and 7, the conversion of the 38 result types into copies defined in `jb`. They add a second definition and a conversion function per type to maintain for good, to prevent a risk the golden already makes visible. The golden's "no `/internal/` path" rule is therefore a known-leaks list that records the aliases and only shrinks. Reopen the parked steps when a concrete change needs an internal type to differ from the public one; that is a new decision.
- **Inside the freeze:** yes. The golden is a test and step 6 removes accidental surface (hardening). The conversion steps would have been a refactor and are not part of this acceptance.

## Motivation

An independent review said: "Several public types in jb.go alias internal types, so internal changes can change the public API accidentally. Use explicit public request/result types where independence matters, keep adapter interfaces internal. Before promising stability, define the supported jb/sdk surface and require deliberate review for breaking changes."

The measured state (commands run on 2026-11-07 in the working tree; `go doc -all .` in the root package):

- 42 type aliases, in 10 root files (`jb.go`, `activity.go`, `caseshow.go`, `db.go`, `doctor.go`, `errors.go`, `estate.go`, `operations.go`, `watch.go`, `watchstatus.go`). Their targets sit in `core` (13), `app` (15), `config` (8), `watchrun` (3), `casefile` (2) and `ops` (1).
- 54 other exported types are defined in package `jb` already. These are the option and result structs written for RFC 0013.
- 87 lines with a `jb:"..."` tag in non-test files, all on option structs defined in package `jb`.
- The `go doc -all` output has 52 lines that start with `func` (functions and methods together; I did not split them).

Two concrete leaks:

- `jb.Config` is `config.File`. Its method set includes `Build`, `BuildAlerts`, `BuildFeeds` and `BuildDetectors`, which return the runtime, alert sinks, feeds and detectors, all internal port types. A Go program can call them but cannot name what they return.
- `jb.EstatePorts` has fields of type `core.PTRResolver`, `core.RDAPRegistry`, `core.BGPSource`, `core.CTSource` and `core.DNSForward`. Its own doc comment says a program outside the module cannot implement them.

A third effect is hidden: a type reachable from an alias is public too, with no name in `jb`. By reading fields I found 7 such types: `app.Disabled`, `app.ActivityDetector`, `app.Failure`, `app.DriftSide`, `core.Alert`, `core.PruneResult` and `core.WatchCycleSummary`. I did not walk the whole graph; the test below does.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Public type" means a type a user of package `jb` can name or reach from an exported identifier. "Boundary" means the functions in the root package that call `app`, `config` and the other internal packages. "Surface" means the exported identifiers of package `jb` with their types, fields, tags and method sets.

## How this design was made

1. **The workflow first.** A Go program calls `jb.Hunt` and reads `Result.Findings`. It never needs `config.File.Build` or an adapter port. Anything the workflow does not need is not contract.
2. **Hashimoto's bar, as RFC 0010 and RFC 0001 apply it.** Those RFCs record that the design was grilled against his tests. The two points used here: the public interface is narrow, and the core uses its own interface. Today the core's types are the public interface, so the second point fails: `core` cannot change a field without changing `jb`. I did not find the bar written as a rule in `CLAUDE.md`, `CONTRIBUTING.md` or `docs/ARCHITECTURE.md`; it comes from the two RFCs only.
3. **Prior art in this repo.** `sdk` already follows the rule: it is a separate public package, standard library only, and `internal/archtest` scans it as if it were a plugin so it cannot import `internal/`. RFC 0013 chose the same direction for results: "The library owns the result type." Aliases were the shortcut that kept that sentence only in spirit. I read no other project's API for this draft.
4. **Define in `jb`, convert at the boundary.** See the options below.

## The design

### 1. What is contract and what is a leak

The 42 aliases fall into four groups. This is my reading of the field lists; the maintainer decides.

| Group | Count | Aliases | Verdict |
|---|---|---|---|
| Result documents that users read | 38 | `Result`, `SourceResult`, `DetectorResult`, `Finding`, `Window`, `Severity`, `Status`, `ActivityResult`, `Verdict`, `CycleReport`, `CycleStatus`, `DoctorCheck`, `DoctorService`, `CheckStatus`, `CaseShowResult`, `Description`, `SourceDescription`, `DetectorDescription`, `StoreDescription`, `AlertDescription`, `EstateComparison`, `EstateChange`, `EstateNotComparable`, `EstateAlertDelivery`, `EstateService`, `EstateSnapshotFailure`, `StoreUsage`, `KindUsage`, `LabelUsage`, `RunKind`, `EventPruneResult`, `PruneRun`, `PruneTotals`, `CompactResult`, `TableCount`, `WatchStatusResult`, `WatcherStatus`, `WatcherState` | Public contract. Define in `jb`. |
| Accidental leak | 1 | `Config` | Not contract as a type. Make it opaque (below). |
| Vocabulary of the API | 3 | `Env`, `UsageError`, `Operation` | Contract. Define in `jb`. |

Plus one non-alias leak: `EstatePorts` (not an alias). It is internal test seam text in a public struct.

Notes on the groups:

- **Results.** Four of these have their own `MarshalJSON` in `internal/`: `Result`, `ActivityResult`, `WatchStatusResult` and `WatcherStatus`. The others marshal by the plain tags of the internal struct, for example `app.Check` and `core.StoreUsage`. Root result types such as `DoctorResult` and `IntelResult` already have their own encoders.
- **`Result` and `CycleReport`** have unexported fields and methods that return internal types (`Failures() []Failure`, `Surfaced []core.Alert`, `Pruned *core.PruneResult`). Their public definitions need those types named in `jb` or dropped from the API.
- **`Finding`** has `Detail map[string]any`. The detail keys are per detector and are not a typed contract. The public type keeps the map and the doc says the keys are not covered by the type.
- **`Config`.** The only callers I found of `cfg.Build` are inside the root package and `cmd/jb`, and `cmd/jb` uses `config.File` directly (`cmd/jb/opencase.go`), not `jb.Config`. Whether a program outside the module reads `Config` fields is unverified; the one other program of CONTRIBUTING.md is not in this repo.
- **`Operation`** is the schema document of RFC 0010. Its JSON shape is already pinned by `docs/operations.json`. Its Go type is `ops.Operation`.
- **`UsageError`.** `errors.As` and `jb.IsUsage` need one identity. See the conversion section.

### 2. The ownership rule

A public type is defined in package `jb`, with explicit exported fields. It has its own `MarshalJSON` only where the CLI JSON cannot be written with tags (for example a pair of times encoded as `[2]time.Time`, which `Result` needs today).

A public type MUST NOT be an alias of a type in `internal/`. A public type MUST NOT have a field, method parameter or method result whose type is declared under `internal/`, directly or through another type.

Option rejected: a small public leaf package that holds the result types, with `jb` aliasing them (for example `.../result`). Reasons:

- It adds a second package to the supported surface and a second golden to keep.
- The internal packages would import it to return those types, so the core would again depend on the public contract. That is today's coupling moved one directory.
- A leaf package must stay standard-library-only to stay small, and the result types reference `time` only, so this would work technically. The cost is the two points above, not feasibility.

Option rejected: keep aliases and rely on review. That is the state that produced the review finding. A rule that only people check failed once already.

### 3. Conversion at the boundary

Each root function that calls `app` or `config` returns a public value built by a plain function in the root package, for example `func newResult(r app.Result) Result`. The root package is the only place that imports both sides of a type.

- **Cost.** One copy of each list per call: sources, detectors and findings of a hunt. These are tens to low thousands of elements (unverified; I did not measure a large hunt). The copy of `Finding.Detail` is a shallow copy of the map reference. The public doc says the map is read-only. A deep copy is an open question.
- **Enums.** `Status`, `Verdict`, `CheckStatus`, `CycleStatus`, `RunKind`, `WatcherState` are string types and `Severity` is an `int`. The public type is a new defined type and the conversion is a cast. A test compares every constant's value to the internal one so a renumbering fails.
- **JSON, byte for byte.** The encoders of `Result` (`internal/app/resultjson.go`), `ActivityResult` and the two in `internal/watchrun/statusjson.go` move into package `jb` with their types. I found no other caller of those encoders in non-test code outside `cmd/jb` and `internal/mcp`, which marshal what `jb` returns (unverified for the adapters; I did not read `internal/adapters/web`). The existing tests are the gate and stay unchanged: `cmd/jb/jsonparity_test.go`, `jsonkeys_test.go`, `libparity_test.go` and the golden in `cmd/jb/testdata/golden/hunt-activity`.
- **Errors.** `core.UsageError` stays in `core` for the internal code. The boundary wraps it: when an internal call returns a `*core.UsageError`, the root returns a `*jb.UsageError` whose `Unwrap` returns the cause. `jb.IsUsage` tests for the public type. The CLI exit code 2 (RFC 0005) does not change; a test keeps it.
- **`Config`.** `type Config struct{ f *config.File }`, with no exported fields or methods beyond what a user needs. `LoadConfig` and `Hunt` keep their signatures. A user who needs to read fields gets a method on request, not by default.
- **`EstatePorts`.** Remove it from the public API. The module's own tests set ports through an unexported option field in the root package. The enable switch of `estate.external` stays checked (RFC 0013 text, Security).
- **`Env`.** `type Env func(name string) (string, bool)`, a defined type in `jb`. A function literal still assigns to it.

### 4. The surface golden

A test in the root package (`api_surface_test.go`, proposed) walks the exported API with `go/types` and compares it with a committed file (`testdata/api/jb.txt`, proposed). The walk:

1. Loads the package from source. `go.mod` says Go 1.25.0, so aliases are tracked by default and `types.Unalias` is available.
2. For every exported identifier writes one line: kind, name and `types.TypeString` of its type with the full package path. For a struct it writes every field in order with its tag. For a named type it writes the exported method set.
3. Follows every named type it meets, from any exported signature, field or method, one step at a time.
4. Fails if any line or any followed type has a package path containing `/internal/`. This is the rule of section 2, checked by machine.

The file is sorted and reviewed when it changes. `go doc -all` was considered and rejected as the source: it includes comment text, so a doc edit changes the file and the diff stops being a signal for a type change.

The same test, aimed at package `sdk`, gives the `sdk` golden RFC 0018 needs. The golden is read-write only through `-update-api`, as `cmd/jb` does for flag sets (`TestFlagSetsAreUnchanged`, `-update-flagsets`).

### 5. Options structs and the `jb` tags (RFC 0010)

The option structs are already defined in package `jb` and carry the tags. The reflector (`internal/ops/reflect.go`) reads the tags and refuses an exported field with no tag. `Env` and similar fields are skipped with `jb:"-"`, so retyping `Env` does not touch the reflector. Nothing in this RFC changes a tag, so `docs/operations.json` MUST NOT change; `cmd/jb/operations_test.go` already fails if it does.

Two checks are new. The surface golden records every tag, so a tag change is visible in the diff. The registry's call path decodes into the option struct, so a field whose type is moved to a new `jb` type is covered by the existing operation tests (unverified for each; I did not read all of them).

### 6. Order of work and the freeze

This is a refactor with no behaviour change. It adds no command, port, format or config key. CONTRIBUTING.md lists what the freeze lets in: "bug fixes, hardening, tests and docs". A refactor that makes accidental API change impossible is closest to hardening, but the text does not name refactors, so the maintainer decides (Open questions).

Order, each step one commit that passes the gate:

1. Add the surface walk and its golden of the current state. The "no `/internal/` path" rule starts with a known-leaks list of the 42 aliases and `EstatePorts`. The list only shrinks.
2. Move the enums and small values: `Window`, `Severity`, `Status`, `Verdict` and the other string types. Casts only.
3. Move the flat results with plain tags: `DoctorCheck`, `DoctorService`, `StoreUsage`, `KindUsage`, `LabelUsage`, `PruneRun`, `PruneTotals`, `EventPruneResult`, `CompactResult`, `TableCount`, the estate change types, and the description types.
4. Move `Finding`, `SourceResult`, `DetectorResult`, `Result` and `ActivityResult` with their encoders. Then `CycleReport`, `WatcherStatus`, `WatchStatusResult`.
5. `UsageError`, `Operation`, `Env`.
6. Make `Config` opaque and remove `EstatePorts`.
7. Empty the known-leaks list.

Breaking Go-API changes, all allowed before 1.0: step 6 (`Config` loses its fields and methods; `EstatePorts` and the option field that holds it go away); `Result.Failures()` and similar methods whose result types change; any exported field of a public type that moves from an internal type to a new `jb` type of the same shape is source compatible for field reads but not for a program that assigned the old internal type (only the module itself could). Each goes in the changelog under "Breaking" with the migration, as CONTRIBUTING.md requires, and the other user is told before it merges.

## Non-goals

- It does not change any command, flag, exit code, config key, file format or plugin message.
- It does not freeze the API. RFC 0018 defines the policy.
- It does not make an `internal/` package public.
- It does not retype `Finding.Detail` or define detector keys as contract.
- It does not touch `sdk`, which already owns its types.

## Drawbacks

- About 40 types are written twice, once internal and once public, with copy functions. A new field needs two edits and the surface golden changes.
- The copy costs time and memory on each call. I did not measure it.
- Step 4 moves four encoders. A mistake there changes JSON; the parity tests are the only guard.
- `Config` becomes opaque, so a Go program that edited fields in place loses that.
- The module's own tests that set `EstatePorts` need another seam.

## Alternatives and prior art

- **Keep the aliases and add the golden only.** It detects accidental change and does not remove it. Leaks such as `Config.Build` stay. Declined as the end state; step 1 is this option and is a safe stopping point.
- **A public leaf package for results.** Rejected above.
- **Make `core` the public package.** `core` holds the ports. Its doc says it is standard library only, but it is the architecture, not the contract (`CLAUDE.md`: everything else "stays under `internal/` so it can change freely").
- **Code generation of the public types.** Adds a tool; 40 types do not justify it. Revisit if the count grows.
- **Prior art.** `sdk` in this repo (above) and the RFC 0013 text. I read no external project for this draft.

## Compatibility

Before 1.0 there is no compatibility promise, so the breaking Go-API changes in the design are allowed. The CLI, the JSON documents, the file formats and `docs/operations.json` do not change.

## Security considerations

Nothing changes in what `jb` reads, sends or stores. I checked that `Config.Build` takes `Env` and resolves credentials, so making `Config` opaque narrows what a library caller can reach. `EstatePorts` removal also removes a way for a library caller to replace the network adapters; the passive-only policy (docs/POLICY.md) is enforced in the adapters, not in the port types. The `Err error` fields stay as they are and keep the rule that errors hold no credential. One risk: the conversion functions are new code that copy error text. A test per result type with an error field checks the text is unchanged (proposed).

## Conformance

Shipped, and the gate for this RFC:

- `cmd/jb/jsonparity_test.go`, `cmd/jb/jsonkeys_test.go`, `cmd/jb/libparity_test.go`: JSON keys and library parity for `hunt`, `activity`, `watch status`, `case check`, `doctor` and `actor status`.
- `cmd/jb/testdata/golden/hunt-activity`: a recorded JSON output.
- `cmd/jb/flagsets_test.go` with `cmd/jb/testdata/flagsets.golden`: the flag set of every command.
- `cmd/jb/operations_test.go`: `docs/operations.json` equals `jb operations`.

Proposed:

- **Surface golden** (`api_surface_test.go`, `testdata/api/jb.txt`): the section 4 walk, with the `/internal/` rule.
- **Byte golden per result type** that the parity tests do not already cover (estate, db, intel, reputation, caseshow): one synthetic value per type, marshalled, compared byte for byte with a file recorded before the move. Recorded first, then the type moves.
- **Enum values test**: each public constant equals its internal constant.
- **Usage error test**: a usage failure from every group is `jb.IsUsage` and exits 2.
- **Known-leaks list** in the surface test; step 7 removes it.

## Reference implementations

Shipped: step 1, the surface golden (`api_surface_test.go`, `testdata/api/jb.txt`, `testdata/api/sdk.txt`, `testdata/api/known-leaks.txt`, `-update-api`). The walk follows only types of this module; standard-library and third-party types appear by name, so the golden does not depend on the Go version.

Shipped: step 6. `Config` is `struct{ f *config.File }` with no exported field or method (`TestConfigIsOpaque`, and the surface golden). `EstatePorts` and `EstateOptions.Ports` are removed; the module's own tests and `cmd/jb` set the doubles on the call's context through `internal/estateseam`, which is not public API. The golden shrank from 1093 to 918 lines and `known-leaks.txt` from 92 to 55 types.

Proposed: steps 2 to 5 and 7 in section 6 (parked).

## Open questions

Decided on 2026-11-07 by the maintainer, in a grilling session:

1. **Is this inside the freeze?** Yes, for steps 1 and 6.
2. **Shallow or deep copy of `Finding.Detail`?** Moot while the result types stay aliases.
3. **Does any program outside this repo read `jb.Config` fields or set `EstatePorts`?** No. The other user confirmed on 2026-11-07 (hub #01a1b57a) that it reads no `Config` field and never sets `EstatePorts`, so step 6 added no method to `Config`.
4. **Does `Operation` belong in `jb`?** Parked with steps 2 to 5.
5. **Stop after step 1?** Yes: steps 2 to 5 and 7 are parked until a concrete need reopens them.

## Changes

- 2026-11-07: first draft.
- 2026-11-07: accepted for steps 1 and 6; steps 2 to 5 and 7 parked.
- 2026-11-07: step 1 shipped.
- 2026-11-07: step 6 shipped; open question 3 answered.
