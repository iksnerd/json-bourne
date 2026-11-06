# RFC 0004: Stability policy
Status: withdrawn
Scope: what `jb` promises not to break before 1.0, how a change is announced, and what must be true before a 1.0 release.

## Summary

Withdrawn on 2026-11-06. The owner decided that `jb` has no backward compatibility before a public release: `jb` and one other program are the only users and nothing is public, so a policy of tiers and notice periods costs more than it buys. The pre-1.0 rule is in [CONTRIBUTING.md](../../CONTRIBUTING.md). The text below is kept as written, so the reasons stay readable.

Programs and people build on `jb`: a wrapper that calls the Go functions, a pipeline that parses the JSON output, a case repository that holds configs and actor files. Each needs to know which parts of `jb` stay put when it upgrades. Today the answer is scattered. One page says the Go API "may change between minor versions". The case format is frozen by its spec. Nothing says what a patch release may contain, how a flag is retired, or what 1.0 means.

This RFC sorts every surface of `jb` into one of three tiers.

- **Frozen.** A change needs a new version of the contract. This covers the file formats at v1, the mapper protocol at `v: 1`, and the exit codes.
- **Stable within a minor line.** A breaking change may ship only in a minor release, and only after one minor release of notice. This covers CLI flags and defaults, config keys, the JSON output fields, the exported Go API, and the evidence store schema.
- **No contract.** The dashboard pages, the human-readable tables, the wording of messages, and everything under `internal/`.

A patch release contains fixes only. The RFC also lists what must be true before a 1.0 release.

## Motivation

A project that pins an exact `jb` version and re-runs a recorded window of events after each upgrade will see any change in the answer. It still needs a written rule to decide whether a failing test is a bug in `jb` or an announced change.

Two facts in this repository show the gap:

- `v0.3.1` is a patch release by its number. It added `jb db prune --run`, which is a new feature. Under the rules below it would have been `0.4.0`. Nothing written told us that when the tag was cut.
- The case spec freezes the key set of `jb.case/v1` (CASE-SPEC section 7). The config file has no such rule, although the loader rejects unknown keys. A config written for a newer `jb` can therefore fail on an older one, and nobody has said that this is expected.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

A "breaking change" is defined in the design section. A "release" is a tag of the form `vMAJOR.MINOR.PATCH`. "Before 1.0" means every release whose major number is 0.

## How this design was made

1. **Tiers by cost of change, not by area.** A file format read by other tools costs the most to change, so it is frozen. A flag or a config key costs one edit in each caller, so it gets a notice period. A web page is read by a person, so it gets none.
2. **SemVer with the 0.x rule made explicit.** Semantic Versioning leaves everything open before 1.0. This RFC keeps the minor number as the place where breaking changes go, so a caller that pins `0.N` and takes every patch is safe.
3. **Notice by one minor release.** A project that pins an exact version asked for one minor release of notice. One is enough to see a warning in a normal upgrade and short enough that the old behaviour does not stay for long.
4. **A changed answer is a change.** For a detection tool the output is the product. A change that makes a detector report something different for the same input can break a consumer as much as a removed flag does, so the RFC treats it as one.

## The design

Everything in this section is a proposal unless it says "today". "Today" statements were checked against the repository on 2026-11-06.

### Tier 1: frozen

A change to a frozen contract needs a new version of that contract. The old version keeps loading.

| Contract | What is frozen | Where it is written | Today |
|---|---|---|---|
| `jb.case/v1` | the key set, the enum values, the rules | [CASE-SPEC.md](../CASE-SPEC.md) section 7 | Frozen by that section. |
| `jb.actor/v1`, `jb.estate/v1`, `jb.estate-snapshot/v1` | the key set and the rules | [CASE-SPEC.md](../CASE-SPEC.md) sections 4.4 and 4.5 | Each loader refuses another `apiVersion` and rejects an unknown key. CASE-SPEC section 7 states the freeze for `jb.case/v1` only. |
| The mapper plugin protocol, `v: 1` | the handshake, the request and response shapes, the slot rule | [PLUGINS.md](../PLUGINS.md), [RFC 0002](0002-mapper-plugin-protocol-v1.md) | Frozen by ADR 0001. |
| Exit codes | 0 success, 1 runtime failure or an incomplete result, 2 usage error | [README.md](../../README.md) | Documented. |

This RFC proposes to extend the freeze statement of CASE-SPEC section 7 to the actor, estate and snapshot formats, by one added sentence in each section. A loader MUST keep refusing a file of another `apiVersion`.

### Tier 2: stable within a minor line

A breaking change to a Tier 2 surface MAY ship only in a minor release (`0.N.0`), never in a patch. The change MUST have been announced as deprecated in the previous minor release, unless the surface is a defect (see Fixes below).

The surfaces:

- **CLI.** Command names, flag names, flag defaults, and the meaning of each flag. `jb version` output is excluded.
- **Config keys.** Every key and `type` value of the config file ([CONFIG.md](../CONFIG.md)), and its default.
- **JSON output.** The field names and types of `--output json`.
- **Go API.** The exported identifiers of the packages `jb` and `sdk`, and their documented behaviour, including the exported default constants.
- **Evidence store.** The schema version of the DuckDB file, and what each migration does.
- **Detector results.** For the same input events and the same config, the findings a detector reports: their tags, their severity, and whether a finding exists.

A breaking change is any of these:

1. Removing or renaming a command, a flag, a config key, a JSON field or an exported identifier.
2. Changing a default value, or the type or the meaning of a value.
3. Making a rule stricter so that an input that worked is refused.
4. Changing a detector so that the same input and config give different findings.
5. Adding a store migration. A migration moves the file forward and cannot be undone (see Store below).

These are not breaking changes:

- Adding a command, a flag, a config key, a JSON field, an exported identifier or a detector type. A caller MUST ignore a JSON field it does not know.
- Making a rule looser.
- Fixing a defect (see below).

Adding a config key is not breaking for an old config, but a config that uses a new key can fail on an older `jb`, because the loader rejects unknown keys (CONFIG.md, "The loader is strict"). A key SHOULD therefore state the release that added it.

#### Store

The evidence store is forward only. Today a build that finds a file with a newer schema refuses it with `ErrSchemaAhead` and the text "upgrade jb", and a read-only open of an older file is refused with `ErrSchemaBehind` (`internal/adapters/duckdb/duckdb.go`). Migrations run on a write open, each in its own transaction.

This RFC proposes three rules on top:

- A patch release MUST NOT add a migration.
- A release that adds a migration MUST say so in the changelog under the heading "Store" with the new schema number, and MUST tell the reader to back up the file first.
- No release downgrades a file.

#### Fixes

A release MAY change any Tier 2 surface without notice when the old behaviour is a defect: a crash, a wrong answer, a security flaw, or a violation of a rule in a spec. The changelog MUST list it under "Fixed" or "Security" and say what changed. A fix that changes what a detector reports is also listed under "Changed", with the detector name, so that a consumer's recorded answer can be explained.

### Tier 3: no contract

These have no stability promise. They change in any release.

- The pages, styles and scripts of `jb serve`, and the JSON document of `/estate/graph.json`. [RFC 0003](0003-dashboard-security-model.md) governs its security rules, not its appearance.
- The human-readable table output and the progress lines on stderr.
- The wording of every message, including error messages. Code and scripts MUST NOT parse them. The exit code is the contract.
- Everything under `internal/`, and the build tools.
- The release archives' internal layout. The binary is `jb`, and a checksum file accompanies each archive.

### Releases

- **Patch** (`0.N.P`): fixes only. A patch MUST NOT add a feature, a flag, a config key or a migration.
- **Minor** (`0.N.0`): new features, deprecations, and the removal of surfaces that a previous minor release deprecated.
- A release tag is annotated and its commit has a changelog entry with that version. The changelog sections are Added, Changed, Deprecated, Removed, Fixed, Security and, for a migration, Store.
- Only the latest minor line receives fixes.
- `go.mod` states the lowest Go version the packages build with. The release binaries are built with the current Go patch release, so that they carry its security fixes.

### Deprecation

To retire a Tier 2 surface:

1. In a minor release, list it in the changelog under "Deprecated" with the release that will remove it, which MUST be the next minor release or later.
2. In the same release, make the surface print one line on stderr when it is used: `jb: deprecated: <what>; removed in <version>; use <instead>`. A Go identifier gets a `// Deprecated:` comment in the form that Go tooling recognises.
3. Remove it in the stated release, with a "Removed" entry.

A surface MUST NOT be removed in the same release that deprecates it.

### Before 1.0

The maintainer decides when to release 1.0. This RFC proposes that all of these are true first:

- No breaking change to a Tier 2 surface for the last two minor releases.
- Every Tier 1 format has a JSON Schema or a corpus of files, checked by tests, and a statement of its freeze in its spec.
- The tests listed under Conformance exist and run in the release gate.
- At least one program outside this repository has run a contract test against `jb` through two upgrades.
- The open questions below are answered.

After 1.0, a breaking change to a Tier 2 surface needs a new major release.

### What a consumer should do

This is guidance, not a rule. Pin an exact version. Read the changelog for the versions in between before moving the pin. Record the answer of a fixed window of events and re-run it after each upgrade. A failing run is either a defect to report or a change that the changelog announced.

## Non-goals

- This RFC does not freeze the Go API for good. It makes breaking changes visible and slow, and 1.0 is the point where the API freezes.
- It does not promise support for old releases.
- It does not define a release process. The tag and the release workflow stay as they are.
- It does not cover the specifications of other projects.
- It does not make `jb serve` a stable web interface.

## Drawbacks

- Notice by one minor release slows removal. A flag that should go stays for a release.
- "A changed detector answer is a change" is hard to apply. Any improvement to a detector can change findings, and the line between a fix and a change is a judgement. The rule that both are listed makes the judgement visible and does not remove it.
- A patch release that may only fix defects makes small features wait for a minor release. The project has been shipping features in patches, so this slows it.
- The tiers add rules to check on every release. Without tests the checks depend on the person cutting the release. The Conformance section proposes tests, and none of them exists yet.
- The actor and estate formats have JSON Schemas that tests keep equal to the loaders. The snapshot format has none, so its freeze is held by its loader alone (see the spec index).

## Alternatives and prior art

- **No policy: "v0 may change".** This is today's state. It is honest and gives a consumer nothing to rely on.
- **Freeze everything now.** It gives the strongest promise and stops the design changes that RFC 0001 and others need before 1.0.
- **Calendar versions with a long-term support line.** It suits a larger team. For one maintainer it adds branches to keep.
- **Prior art.** This RFC does not compare itself with the compatibility policies of other projects, because the author read none for this draft. A reviewer is asked to name one worth reading. See Open questions.

## Compatibility

- This RFC changes no code. It adds rules for future releases.
- It does not apply to releases already made. `v0.1.0` to `v0.3.1` stay as they are, including that `v0.3.1` added a feature.
- If the RFC is accepted, the README sentence "The API is v0 and may change between minor versions" is replaced by a link to the policy, and the case spec gets the added freeze sentences.

## Security considerations

- The policy does not weaken any control. A security fix is allowed in any release without notice.
- Slow removal means an insecure option can stay for one more minor release. A security fix is exempt from the notice period for that reason.
- A consumer that pins an exact version needs a way to learn about a security fix. The changelog "Security" section is that way. This RFC does not add a security advisory process.
- The `internal/` rule keeps code that handles hostile input free to change.

## Conformance

Shipped, and relevant:

- The case, actor and estate loaders refuse another `apiVersion` (`internal/casefile`), and the schema tests keep the case, actor and estate v1 schemas equal to the loaders.
- `TestLibraryDefaultsAreTheCLIDefaults` in `cmd/jb/defaults_test.go` keeps the Go defaults equal to the CLI defaults.
- The store tests `TestMigrateIsIdempotent`, `TestMigrationsAreNumberedWithoutGaps` and the schema-ahead test in `internal/adapters/duckdb/duckdb_test.go`.

Proposed. None of these exists yet:

- **Go API snapshot.** A test compares the exported identifiers of `jb` and `sdk` with a committed list. A removed or changed identifier fails the test, and an added one needs the list updated in the same commit.
- **CLI snapshot.** A test compares every command, flag and default with a committed list.
- **JSON snapshot.** A test compares the field names and types of `hunt` and `activity` JSON output on a synthetic run with a committed file.
- **Changelog check.** A test fails when the tag's version has no changelog entry, and when a patch entry has an "Added" section.
- **Store check.** A test fails when a migration is added and the changelog has no "Store" entry.
- **Deprecation check.** A test that a deprecated flag prints the stderr line.

## Reference implementations

Shipped:

- The changelog in [CHANGELOG.md](../../CHANGELOG.md), kept in the Keep a Changelog form with Semantic Versioning stated at its top.
- The freeze of `jb.case/v1`: CASE-SPEC section 7.
- The mapper protocol freeze: [ADR 0001](../adr/0001-relationship-to-other-plugin-specifications.md).
- Store versioning: `internal/adapters/duckdb/duckdb.go`.

Proposed:

- Every item under Conformance.
- The deprecation line and its helper.
- The added freeze sentences in the case spec, and the README link.

## Open questions

1. **How long is the notice?** The RFC says one minor release. Is that enough for a consumer that upgrades once a quarter? Decides: the maintainer, with the consumers.
2. **Detector results as Tier 2.** Is holding detector output stable too strict for a tool whose detectors are still being tuned? The alternative is Tier 3 for detector results in 0.x, with the changelog entry as the only promise. Decides: the maintainer.
3. **What 1.0 needs.** Are the five conditions the right ones, and is "two minor releases without a breaking change" the right length? Decides: the maintainer.
4. **JSON output schemas.** Should `--output json` get a JSON Schema, kept equal to the code by a test, as the file formats have? Decides: a later RFC.
5. **Support window.** Is "only the latest minor line" acceptable to the consumers? Decides: the maintainer, with the consumers.
6. **A published policy to compare with.** Which one should the next draft read? Decides: the reviewer.
7. **A security advisory process.** Does a private repository need one before it goes public? Decides: the maintainer.

## Changes

- 2026-11-06: first draft.
- 2026-11-06: withdrawn (see the Summary).
