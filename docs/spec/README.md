# Specs

[Back to the README](../../README.md)

For a reader who needs the rules of one `jb` format or protocol. After reading, you know which file states the rule, which code loads it and which test keeps the two equal.

A spec is the normative text of a contract as it is now. The reasons for a change live in the [RFCs](../rfcs/README.md). The decisions that are not contracts live in the [ADRs](../adr/).

The specs stay in the files where they already are. This page is the index.

| Spec | Text | Loaded or run by | Schema | Tests that hold it |
|---|---|---|---|---|
| Case (`jb.case/v1`) | [CASE-SPEC.md](../CASE-SPEC.md) sections 3 to 9 | `internal/casefile` | `schemas/case.schema.json` | `TestSchemaMatchesStruct`, `TestSchemaMatchesLoaderRules` in `internal/casefile` |
| Actor file (`jb.actor/v1`) | [CASE-SPEC.md](../CASE-SPEC.md) section 4.4 | `internal/casefile` | `schemas/actor.schema.json` | `TestActorSchemaMatchesStruct`, `TestActorSchemaMatchesLoaderRules` |
| Estate file (`jb.estate/v1`) | [CASE-SPEC.md](../CASE-SPEC.md) section 4.5 | `internal/casefile/estate.go` | `schemas/estate.schema.json` | `TestEstateSchemaMatchesStruct`, `TestEstateSchemaMatchesLoaderRules`, `TestEstateAllowlistMatchesPolicyDoc` |
| Estate snapshot (`jb.estate-snapshot/v1`) | [CASE-SPEC.md](../CASE-SPEC.md) section 4.5.1 | `internal/casefile/estate_snapshot.go` | none (the loader is the spec) | the snapshot tests in `internal/casefile` |
| Mapper plugin protocol (`v` 1) | [PLUGINS.md](../PLUGINS.md) | `internal/adapters/plugin`, `sdk` | none | `internal/conformance` |
| Config file | [CONFIG.md](../CONFIG.md) | `internal/config` | none (the loader is the spec) | the tests in `internal/config` |
| Passive-only policy | [POLICY.md](../POLICY.md) | the estate and source allowlists | none | `TestEstateAllowlistIsPassiveOnly`, `TestEstateAllowlistMatchesPolicyDoc` |
| Dashboard security model | [ARCHITECTURE.md](../ARCHITECTURE.md), "The dashboard" | `internal/adapters/web` | none | the tests in `internal/adapters/web`, `TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch` |
| Dependency rules | [ARCHITECTURE.md](../ARCHITECTURE.md) | `internal/archtest` | none | `internal/archtest` |

Where the schema column says "none", the code is the only machine-checked form of the rules. An RFC that adds a schema moves the row.
