# ADR 0001: jb's relationship to other plugin specifications

Status: accepted, 2026-11-06.

## Context

`jb` has a mapper plugin protocol of its own (docs/PLUGINS.md) and a built-in dashboard. The maintainer also keeps a draft family of specifications for programs that run plugins: a core call protocol, long-lived plugins, a host checklist and profile, a "page" role for plugin-supplied pages, declared data kinds, a single definition for an operation served as both a CLI command and a tool, and, for plugins that act, plans, approvals, credential grants, an audit record and a telemetry profile. Only the long-lived plugin part is approved; the rest are drafts, and the maintainer's own reference code is the only code that implements them.

`jb`'s protocol has the shape of the long-lived one but is not it. Two public packages, `jb` and `sdk`, now exist, so the question of what `jb` claims about that family needs one written answer.

## Decision

1. **`jb` is independent of that specification.** It is not one of its hosts and does not claim to be. Becoming one would mean passing the specification's conformance corpora and publishing a profile; that is a project of its own, not a rename.
2. **Public text says "informed by", never "conformant".** No file in this repository describes `jb` as following a draft specification, and none cites a draft's section number as a requirement.
3. **`jb`'s mapper protocol is frozen at `v: 1` as `jb`'s own.** docs/PLUGINS.md says it is not another project's protocol. The cost of changing a wire format rises when the repository is public and other people write plugins, which is why the choice is made now: keep it as it is, and if `jb` ever needs to be a host of that family, migrate before going public, not after.
4. **The `sdk` package keeps its name and stays v0.** Its documentation says it implements this protocol only. Renaming it would buy little; the migration in point 3 is where its name would change.
5. **The dashboard is built in.** Pages that plugins could add are out of scope, and `jb` does not let plugins add pages. The estate graph is served as a neutral document (`/estate/graph.json`: nodes and edges with kind, label and provenance) so that it could become a host-drawn construct later without a rewrite. The Content-Security-Policy and the vendored scripts are `jb`'s own decision (docs/ARCHITECTURE.md, docs/THIRD-PARTY.md).
6. **`jb` has no action role.** It is passive (docs/POLICY.md). So it has no plans, approvals or credential grants, and a feature that acts needs its own design for those first.
7. **No data is offered to plugins as declared kinds.** Plugins receive raw log documents and nothing else, never findings, runs or estate data. Offering evidence to plugins would widen what a reviewer has to trust, and nothing needs it.
8. **One operation, two surfaces: kept in step by a test, not a mechanism.** `Hunt`, `Watch` and `Activity` exist as CLI commands and as Go functions. A test fails when the library's defaults differ from the CLI's. `jb` does not adopt a scheme that derives both from one definition: it has no tool server, and that scheme is itself a draft. Options the CLI has and the library lacks (for example `--search`) are listed in the changelog and added when a caller needs them.
9. **No OpenTelemetry.** `jb` needs no spans. Whether the evidence store should be tamper-evident is a separate decision, recorded as an open task (a per-run hash manifest is the candidate), and is not part of this one.

## Consequences

- A reader can trust that nothing here claims more than it does, and a plugin author knows which protocol they are writing for.
- Someone who wants one plugin to run under both `jb` and a host of that family has to write two thin adapters. That is accepted.
- The decisions to revisit are: becoming a host (point 1, with point 3), letting plugins add pages (point 5), and any feature that acts (point 6). Each starts from the specification as it stands then, not as it stood on 2026-11-06.
