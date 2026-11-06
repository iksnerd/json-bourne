# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/). Before 1.0, the Go API (packages `jb` and `sdk`) and the CLI flags may change between minor versions.

## [Unreleased]

### Changed
- **The dashboard (`jb serve`) is rebuilt** with templ components, htmx partial updates and Tailwind, from design tokens (shadcn/ui names, a neo-industrial dark theme with sharp edges). The Estate page draws an interactive d3 graph with a label on every connection; selecting a node or a connection opens its record and its connections in a sheet. Findings can be filtered by text and severity; the Watch panel refreshes itself. New Go packages: `internal/estategraph` (built on `dominikbraun/graph`) and the dashboard's primitives (card, alert, badge, sheet).
- **The Content-Security-Policy changes** from `default-src 'none'` (no script at all) to `script-src 'self'; connect-src 'self'; form-action 'self'`. Scripts are the vendored, hash-pinned htmx and d3 and two small files of this project; there is still no inline script, no eval and no other origin, and the dashboard stays GET-only and read-only. See docs/ARCHITECTURE.md and docs/THIRD-PARTY.md.
- New dependencies: `github.com/a-h/templ` and `github.com/dominikbraun/graph`. The `jb` and `sdk` packages do not import them.

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
