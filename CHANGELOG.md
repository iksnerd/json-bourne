# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/). Before 1.0, the Go API (packages `jb` and `sdk`) and the CLI flags may change between minor versions.

## [Unreleased]

### Breaking
- Errors returned by the Go package no longer start with `jb: `; the command line adds its own. A caller that matched that prefix matches the message instead, or uses `jb.IsUsage` (RFC 0013).
- The address errors of the dashboard no longer name `--addr` or `--allow-remote`. Match `web.ErrNotLoopback` and `web.ErrBadAddr`; `jb serve` still prints the flag hints.
- `jb db usage` reports a failed overlap check instead of "no overlap", and `jb db status` on a missing store says so before opening it (same exit code, nothing created).

### Added
- Go API, one function per command (RFC 0013): `CaseCheck`, `Doctor`, `ActorStatus`, `DBStatus`, `DBUsage`, `DBPrune`, `DBCompact`, `DBRenameSource`, `Intel`, `EstateIP`, `EstateASN`, `EstateDNS`, `EstateCT`, `EstateRefresh`, `EstateDiff`, `EstatePromote`, `DashboardHandler` and `Serve`. The JSON result types of those commands now belong to the package, and the commands print them. The mutating `DB*` functions are a dry run unless `Apply` is set. See the README table.
- `HuntOptions.Search` and `SearchField` (the `jb hunt --search` options); refusals are `jb.UsageError` and send nothing. `Result.SearchAbsent()` says a term is absent from a live index; `Result.Complete()` is unchanged.
- `DashboardOptions.AllowedHosts`: an exact list of Host values for a handler behind a reverse proxy, so the Host check stays on (RFC 0003).
- `jb case check` notes a command that two configs of the case declare, since `jb COMMAND --case` will then ask for `--config`.
- `jb activity` prints the age of the last genuine event beside the verdict, for example `last activity 2026-11-05T11:09:00Z (51m ago)`; JSON is unchanged.

## [0.4.0] - 2026-11-06

### Breaking
- `jb hunt` can list findings while a detector's status is not `ok`; read `complete` first. `jb activity` can read ACTIVE with `complete` false, and then exits 1; before, ACTIVE with an incomplete source exited 0. `jb watch` alerts an incomplete detector's findings (RFC 0012).
- `jb case check DIR` is now `jb case check --case DIR`; the positional directory is removed (RFC 0007).
- A config file may declare `commands:`; a case with several configs picks the one that declares the command, and the error otherwise lists every config with its commands. A config with `commands:` is refused by an older `jb` as an unknown key (RFC 0008). `examples/case` now lists two configs.
- `config.UsageError` is removed (internal); use `core.IsUsage`. The unset-credential error now continues after "is not set" with a hint (RFC 0005).
- `jb watch --output json` without `--once` is a usage error. `evidence/` gains a `watch-status[.NAME].json` file per watcher, and `runlock.Acquire` retries a refusal for up to 40 ms (RFC 0006).
- The mapper protocol and the file formats carry no compatibility promise before a public release (CONTRIBUTING.md); RFC 0004 is withdrawn.

### Added
- hunt, activity, watch: findings a detector returns beside an error are now kept and reported, and the run stays incomplete; `activity` reads ACTIVE and incomplete (RFC 0012).
- behaviour: rare actions take `min_severity` (a floor; `critical` needs a `note`), `note` and `min_events_per_key`; keys dropped at `max_keys` with no key at the threshold make the run incomplete, not quiet (RFC 0011).
- `jb.UsageError` and `jb.IsUsage` tell a Go caller a caller mistake from a failure; the CLI's exit 2 uses the same type. `--output table|json` on `watch --once` (cycle report), `db status`, `db rename-source`, `db compact` and `estate promote`. `jb activity --help` explains its fixed 24h window (RFC 0005).
- `jb watch` writes a machine-readable status record (`watch-status[.NAME].json`, `jb.watch-status/v1`); `jb watch status` and `jb.WatchStatus` report each watcher as running, stale, stopped or unknown (RFC 0006).
- `jb case show --case DIR` and `jb.CaseShow` print what one config of a case would run, without reading the environment (RFC 0007).
- `jb hunt` and `jb activity` gain `--no-store` (Go: `NoStore`): the same run over a private temporary store that is deleted on return; the output says `not stored`, and hunt and activity JSON gain a `stored` field (RFC 0009).
- docs/rfcs/0005 to 0009 (drafts) and 0010 (operations, draft).
- docs/rfcs/README.md, docs/spec/README.md and docs/rfcs/0000-template.md: the RFC process, the index of specs and the RFC template. A test in `internal/archtest` checks the form of every RFC.
- docs/rfcs/0001-estate-v2.md: a draft RFC for `jb.estate/v2` (per-host facts, separate assessments, a `service` node kind, live overlays in the dashboard). Not accepted; nothing in it is implemented.
- docs/rfcs/0002-mapper-plugin-protocol-v1.md: back-fill RFC for the mapper plugin protocol at `v: 1` (scope, reasons, limits, trust model, drawbacks, conformance). The normative text stays in docs/PLUGINS.md.
- docs/rfcs/0003-dashboard-security-model.md: back-fill RFC for the security model of `jb serve` (read-only, loopback and Host check, the Content-Security-Policy, vendored pinned scripts, escaping rules), with each rule's test and the rules that have none.

## [0.3.1] - 2026-11-06

### Fixed
- `--config` with `--case` (and `Config` in `jb.HuntCase`, `jb.Watch`, `jb.Activity`) now accepts a relative path to a file inside the case, such as `config/drafts/x.yaml`: it is tried against the case directory, then the working directory, and must still resolve inside the case. Before, only an absolute path or a listed config worked.

### Added
- `jb db prune --run ID` (repeatable, at most 20) removes the events of exactly the named hunt, activity or search runs, whatever their age, for a one-off run that `--keep-latest` would keep. The id is matched whole, watch ids and unknown ids are refused (an unknown id deletes nothing), and it cannot be combined with `--kind`, `--older-than` or `--keep-latest`. Same dry run, one transaction and checked counts as the existing prune.

## [0.3.0] - 2026-11-06

### Changed
- **The dashboard (`jb serve`) is rebuilt** with templ components, htmx partial updates and Tailwind, from design tokens (shadcn/ui names, a neo-industrial dark theme with sharp edges). The Estate page draws an interactive d3 graph with a label on every connection; selecting a node or a connection opens its record and its connections in a sheet. Findings can be filtered by text and severity; the Watch panel refreshes itself. New Go packages: `internal/estategraph` (built on `dominikbraun/graph`) and the dashboard's primitives (card, alert, badge, sheet).
- **The Content-Security-Policy changes** from `default-src 'none'` (no script at all) to `script-src 'self'; connect-src 'self'; form-action 'self'`. Scripts are the vendored, hash-pinned htmx and d3 and two small files of this project; there is still no inline script, no eval and no other origin, and the dashboard stays GET-only and read-only. See docs/ARCHITECTURE.md and docs/THIRD-PARTY.md.
- New dependencies: `github.com/a-h/templ` and `github.com/dominikbraun/graph`. The `jb` and `sdk` packages do not import them.

### Added
- `GET /favicon.ico` answers 204 with the security headers, so a browser's first visit no longer logs a 404.
- `jb.DefaultWindow`, `jb.DefaultActivityWindow` and `jb.DefaultWatchEvery`: the defaults of the Go functions, now constants. A test fails if they differ from the defaults of the CLI commands of the same name.
- docs/adr/0001-relationship-to-other-plugin-specifications.md: `jb` is independent of the maintainer's draft plugin specifications, its mapper protocol is frozen at `v: 1` as its own, it has no action role, and what it would take to change that.

### Known gaps
- The Go functions lack some CLI options. `Hunt` and `HuntCase` have no equivalent of `--search` and `--search-field`, and no JSON or table output (a caller has the `Result` value). They are added when a caller needs them.

## [0.2.1] - 2026-11-06

### Security
- Release binaries are built with the current Go 1.26 patch release. Built with the latest Go 1.25 patch release, v0.1.0 and v0.2.0 carry 12 standard-library vulnerabilities that `govulncheck` reports (one path is the HTTP client of the certificate-transparency lookup). `go.mod` still allows Go 1.25 for library users; build from source with a current Go.

## [0.2.0] - 2026-11-06

### Added
- `jb.HuntCase(ctx, caseDir, opts)`: hunt inside a case with the rules of `jb hunt --case` (case checks, evidence-directory git guard, actor files for the fingerprint detector, store under the case's evidence directory, the case's default window).

- `jb.Watch(ctx, caseDir, opts)`: the named watcher loop of `jb watch` (own state, log and lock per name, TTL dedupe, retention only of its own runs, one watcher per name). A cycle that did not finish is `CycleIncomplete`, never quiet.
- `jb.Activity(ctx, caseDir, opts)`: `jb activity --case`: ACTIVE, QUIET or INCOMPLETE over a window (default 24h); INCOMPLETE is never QUIET.

### Fixed
- Release workflow uploaded `jb_test.go` as a release asset; it now uploads only the archives and checksums.

## [0.1.0] - 2026-11-06

First tagged release.

### Added
- `jb` CLI: `hunt`, `activity`, `actor status`, `watch`, `intel`, `estate`, `case check`, `doctor`, `db` and `serve`.
- Go package `github.com/iksnerd/json-bourne` (`jb`): `LoadConfig` and `Hunt`.
- Go package `github.com/iksnerd/json-bourne/sdk`: the plugin side for writing mapper plugins, standard library only.
- Example mapper plugins under `plugins/`: `jsondoc`, `kvlines`, `regexlines`.
