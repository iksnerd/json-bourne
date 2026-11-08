# RFC 0018: Stability policy for 1.0
Status: accepted
Scope: define the surfaces `jb` would support from 1.0, what counts as a breaking change on each, how one is made, and which tests enforce it.

Accepted: 2026-11-07 by the maintainer

## Summary

This is the policy to adopt at 1.0. It lists the supported surface by name, says what is breaking on each part, requires an RFC, a deliberate review and a changelog "Breaking" entry for a breaking change, and ties the rules to tests that fail, not to a promise.

Nothing in this RFC is a promise before the maintainer accepts it. Going public is a separate decision that this RFC does not make. Until 1.0 the rule in [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) ("Compatibility before 1.0") stands: no backward compatibility.

## Motivation

Two programs use `jb`: a wrapper that calls the Go functions and a pipeline that reads `--output json`. Both pin an exact version. At 1.0 the maintainer wants to say which parts a new version keeps. Today that is written nowhere, and an independent review said: "Before promising stability, define the supported jb/sdk surface and require deliberate review for breaking changes." [RFC 0017](0017-public-api-owns-its-types.md) makes the Go surface definable; this RFC defines it.

Why [RFC 0004](0004-stability-policy.md) was withdrawn, from its text and from [README.md](README.md): the owner decided on 2026-11-06 that `jb` has no backward compatibility before a public release. Nothing was public and there were two users, so tiers and notice periods cost more than they bought. I add three reasons from reading it:

- It promised more than the tests could hold. Its Conformance section lists six proposed tests and none existed. A rule without a test depends on whoever cuts the release.
- It covered detector output as a stable surface ("a changed answer is a change"). That makes tuning a detector a breaking change. Its own Drawbacks call the line hard to draw.
- It put the Go API at "stable within a minor line" while the API was aliases of internal types, so the promise could break without a `jb` edit (RFC 0017).

What is different now: the surface is smaller and named, the Go surface owns its types (RFC 0017), most of the enforcement tests already exist, and the decision to go public is separate.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Supported surface" is what this RFC lists. "Breaking" is defined per surface. "The maintainer" decides every question marked so.

## How this design was made

1. **Name the surface, then test it.** A surface that no test pins is not listed as supported.
2. **Small.** Only what a program reads or calls. Human output, error wording and the dashboard pages are not listed.
3. **Detector results are outside the contract.** The finding types and the JSON shape are supported. Which findings a detector reports for given events is not, because detectors are still tuned. The changelog lists such a change under "Changed". (RFC 0004 chose the opposite; see Open questions.)
4. **No deprecation period before 1.0, a short one after.** One user pins an exact version and can read the changelog.

## The design

Counts below were taken from the repository on 2026-11-07 with a command.

### The supported surface

| Surface | What is in it | Pinned today by |
|---|---|---|
| Go package `jb` | The exported identifiers listed in the surface golden of RFC 0017: functions, option and result types, constants, errors | `TestAPISurface` and `testdata/api/jb.txt` (RFC 0017 surface golden) |
| Go package `sdk` | `ProtocolVersion`, `MaxRequestLine`, `ErrUnparsable`, `Event`, `Mapper`, `Plugin`, `Serve`, `ReadLine`, `DecodeStrict`, `Lookup`, `Coerce`, `ParseTime`, `FieldSpec`, `TimeSpec`, `Common` and the limit constants of `sdk/mapping.go` | `TestAPISurface` and `testdata/api/sdk.txt`; `sdk/sdk_test.go` and `TestPluginsAreStdlibOnlyAndInert` in `internal/archtest` for the import rule |
| CLI | The command tree (32 command entries in `cmd/jb/testdata/flagsets.golden`), each flag with its type, default and shorthand, and the exit codes 0 success, 1 runtime failure or incomplete result, 2 usage error | `TestFlagSetsAreUnchanged` for flags; `TestExitCodeValuesAreFixed`, `TestEveryCommandExitsTwoOnAnUnknownFlag` and `TestExitCodesPerOutcome` for exit codes |
| JSON of `--output json` | The key paths of `hunt`, `activity`, `watch status`, `case check`, `doctor`, `actor status`, and the other result documents | `jsonparity_test.go`, `jsonkeys_test.go`, `libparity_test.go` and `testdata/golden/hunt-activity` in `cmd/jb`; the db commands by `TestDBCommandsPrintTheLibraryValue`; the other documents by `TestCLIDocumentsHaveTheLibraryKeyPaths` and `TestWatchOnceJSONKeyPaths` |
| File formats | `jb.case/v1`, `jb.actor/v1`, `jb.estate/v2`, `jb.estate-snapshot/v2`, `jb.estate-facts/v1`, `jb.watch-status/v1`. The proposed `jb.assets/v1` is not supported until a loader exists | `TestEachLoaderReadsOnlyItsOwnAPIVersion` (case, actor, estate, snapshot, estate-facts) and `TestReadAcceptsOnlyWatchStatusV1`; schemas for case, actor and estate in `docs/schemas/`, kept equal to the loaders by `internal/casefile/schema_test.go` |
| Plugin wire protocol | Version `v: 1` of [PLUGINS.md](../PLUGINS.md) | `internal/conformance` and the host tests; `TestPluginWireProtocolV1HostSideIsUnchanged` (`internal/adapters/plugin/testdata/wire-v1.golden`) and `TestPluginWireProtocolV1PluginSideIsUnchanged` (`sdk/testdata/wire-v1.golden`) |
| Config keys | Every key and `type` value in [CONFIG.md](../CONFIG.md), and its default | The strict loader rejects unknown keys; `TestConfigKeySetIsUnchanged` (`internal/config/testdata/config-keys.golden`) and `TestEveryConfigKeyIsDocumented` |
| Operations and MCP tools | The 22 operations in `docs/operations.json`, their names, input schemas and `readOnly` flags; `jb mcp` lists the read-only operations by default and the mutating ones named by `--allow`, and a tool name is the operation name | `cmd/jb/operations_test.go`; `internal/mcp` tests; `TestMCPToolListIsUnchanged` (`cmd/jb/testdata/mcp-tools.golden`) and `TestMCPToolListAgreesWithOperationsJSON` |
| Evidence store | The DuckDB schema version and forward-only migrations | `TestEvidenceSchemaIsUnchanged` (`internal/adapters/duckdb/testdata/schema.golden`): version, migration hashes, tables and columns |

Not supported: the wording of messages and tables, stderr progress lines, the pages and scripts of `jb serve` and `/estate/graph.json`, everything under `internal/`, the keys inside `Finding.Detail`, which findings a detector reports, and the release archive layout.

### What is breaking, per surface

- **Go `jb` and `sdk`.** Removing or renaming an exported identifier; changing a signature, a field type, a field tag or a constant's value; removing a method. Adding an identifier or a field is not breaking.
- **CLI.** Removing or renaming a command or flag; changing a default, a type or the meaning of a value; changing an exit code. Adding a command or a flag is not breaking.
- **JSON.** Removing or renaming a key, changing a key's type or the meaning of its value. Adding a key is not breaking, and a reader MUST ignore keys it does not know.
- **File formats.** Any change an old loader would read differently or refuse. A breaking change makes a new `apiVersion` and the loader reads only the current one (CONTRIBUTING.md). Adding an optional key is breaking for an older `jb`, because loaders reject unknown keys; it is not breaking for old files.
- **Plugin protocol.** Any change to a message that an existing plugin would misread. A new `v`.
- **Config keys.** Removing, renaming or re-typing a key; changing a default; making a rule stricter so an accepted config is refused.
- **Operations and MCP.** Removing or renaming an operation or property; changing a type, a default or `readOnly`. Adding an operation or an optional property is not breaking.
- **Store.** A migration is not breaking. It is forward only, so the changelog says to back up first.

### How a breaking change is made

1. An RFC, accepted by the maintainer, unless the change fixes a defect against a written spec.
2. A deliberate edit of the golden that pins the surface, in the same commit, so the diff shows it to the reviewer. A reviewer MUST NOT approve a change to a golden that the commit message does not explain.
3. A changelog entry under "Breaking" with the migration. CONTRIBUTING.md requires this today.
4. A version bump: before 1.0 a minor release; from 1.0 a major release.

A security fix MAY break a surface in a minor or patch release. The changelog says so under "Security".

### Deprecation

There is none before 1.0. From 1.0: a surface to be removed is listed under "Deprecated" in a minor release and removed no earlier than the next major release. A Go identifier gets a `// Deprecated:` comment. A flag prints one stderr line when used. The proposed minimum is one minor release; the maintainer sets the real length (Open questions).

### Enforcement

The policy is held by tests that fail, in this order of strength:

1. Goldens already in the repo: flag sets, `docs/operations.json`, hunt and activity JSON.
2. The RFC 0017 API surface golden for `jb` and `sdk`.
3. Schema files for case, actor and estate, kept equal to the loaders by tests (RFC 0004 names these).
4. The consumer contract module (`contract/`), being added by another agent. This RFC does not depend on it. If it lands, it pins JSON shapes from a consumer's side and is listed here.
5. Goldens added on 2026-11-07: config key set, plugin messages, MCP tool list, evidence schema; and the exit-code, file-format and remaining-JSON tests listed in the table.

A part of the surface with no test is listed as "proposed" above and MUST get one before 1.0, or be removed from the supported list.

### What 1.0 means

1.0 is reached by criteria, not a date. All three hold:

1. Every surface in the table above is pinned by a test that fails on a breaking change. A surface with no such test is removed from the list first.
2. The surface golden of RFC 0017 exists for `jb` and `sdk`.
3. The maintainer decides to cut it.

Going public is a separate decision. It may come before or after 1.0.

### Who decides

The maintainer. Only the maintainer accepts this RFC, lifts the freeze, sets 1.0 and decides to go public.

## Non-goals

- It does not go public or promise anything before acceptance.
- It does not promise detector output, human-readable text or the dashboard.
- It does not define a release process, a support window for old versions or a security advisory process.
- It does not add a feature, so it is outside the freeze.

## Drawbacks

- Goldens add friction. Every deliberate surface change edits a file and needs an explanation.
- Five of the ten surfaces have no full test today. The policy is only as strong as the tests that exist.
- Leaving detector output out means a consumer that records answers can see them change in a minor release. The changelog is the only warning.
- A one-person maintainer is also the only reviewer, so "deliberate review" is the maintainer reviewing their own change. The golden diff makes that visible; it does not make it independent.

## Alternatives and prior art

- **RFC 0004's three tiers with a notice period.** Withdrawn; reasons above. This RFC keeps its useful parts: a named surface, "adding is not breaking", and the changelog sections.
- **No policy.** Honest, and fine while there are two users. It does not meet the review's request.
- **Prior art.** I read RFC 0004, CONTRIBUTING.md and the existing goldens in this repo. I read no external compatibility policy for this draft.

## Compatibility

Before 1.0 nothing here binds: `jb` keeps "no backward compatibility", and the policy takes effect only when the maintainer accepts it and tags 1.0.

## Security considerations

The policy changes no behaviour. I checked that the supported list contains no credential handling beyond what the specs already state, and that a security fix is allowed to break a surface without notice. The risk is the reverse: a promise to keep a flawed default. The Security exemption above removes it. The surface golden would also make a widened Go API visible in review, which helps with the confinement rules in `internal/archtest`.

## Conformance

Shipped:

- `cmd/jb/flagsets_test.go` (`TestFlagSetsAreUnchanged`), `cmd/jb/operations_test.go`, `cmd/jb/jsonparity_test.go`, `jsonkeys_test.go`, `libparity_test.go`.
- The loaders' `apiVersion` refusal tests in `internal/casefile`.
- The surface golden of RFC 0017 for `jb` and `sdk` (`TestAPISurface`).
- Goldens and tests added on 2026-11-07, named in the table: exit codes, config keys, plugin wire protocol, MCP tool list, remaining JSON documents, evidence schema, `apiVersion` strings.
- `internal/archtest` (`TestRFCsAreWellFormed` for this file's shape; `TestPluginsAreStdlibOnlyAndInert` for `sdk` imports).

Proposed:

- A check that a changed golden file comes with a changelog "Breaking" line (a rule for review at first; a script later).

## Reference implementations

Shipped: the tests listed above under Shipped, and the CHANGELOG "Breaking" sections.

Proposed: every item under Proposed.

## Open questions

Decided on 2026-11-07 by the maintainer, in a grilling session:

1. **Detector output outside the contract.** Yes, until the detectors stop being tuned. A tuning change is listed under "Changed" in the changelog.
2. **Deprecation after 1.0.** One minor release, and removal only in a major release. None before 1.0.
3. **What must be tested before 1.0.** Every surface in the table has a test, or it comes off the list (see "What 1.0 means").
4. **Does `contract/` join the enforcement list.** Yes. It landed on 2026-11-07 and is a consumer-side check.
5. **When does 1.0 happen and when does `jb` go public.** 1.0 by the criteria above; going public is a separate decision for the maintainer and not made here.

## Changes

- 2026-11-07: first draft.
- 2026-11-07: accepted. MCP tools folded into Operations; "What 1.0 means" added.
- 2026-11-07: surface tests added for exit codes, config keys, plugin wire protocol, MCP tool list, remaining JSON documents, evidence store and file-format versions; the table names them.
