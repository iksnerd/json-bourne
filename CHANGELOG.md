# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/). Before 1.0, the Go API (packages `jb` and `sdk`) and the CLI flags may change between minor versions.

## [Unreleased]

### Fixed
- A YAML file with one mapping of many keys stalled the loader (yaml.v3 decodes a mapping in time quadratic in its key count: about 45 s for 100,000 keys, a 1 MiB file). Case, actor, estate, snapshot and config files with a mapping of more than 1000 keys are now refused at load, before the decode.

### Added
- `jb serve`, render-only (no new route, store query or data source): a node's record shows the assessments (opinion) that cite each fact group next to it, and every basis entry `node#key` as an in-page or cross-node link, or as "unresolved" when it names nothing in the map; which estate files (by estate `id`) and which layer hold the node, so a node id in two files shows both; the node's edges grouped by relation with direction, other node, source, method, confidence and time; a fixed order for facts (key, time, value), assessments (decided time, id), edges and absences, so two loads of unchanged data are byte-identical; and a "copy this record as plain text" button, built in the browser from what the page shows by one new script file (`sheet-copy.js`) served from the binary. Not covered by tests: the copy, the anchor scroll and the button reveal in a real browser. An edge's index in its `/estate/edge` link still follows file order.

## [0.7.1] - 2026-11-07

### Added
- `jb serve`, render-only (no new route, store query or data source): a node's record groups its facts by key, each value with its source, method and time; it lists the assessments that cite the node in their basis, under the same opinion notice; the estate graph shows an edge-kind legend with a count per relation and an edge-confidence filter (`?confidence=stated|inferred`, repeatable) that works with the node-kind filter; a search box finds nodes by id or label (`/`, Escape, arrow keys); and two buttons save the drawn graph as SVG or JSON, built in the browser. Two new script files are served from the binary; there is still no inline script. Not covered by tests: the behaviour of the search keys and the export in a real browser.

### Fixed
- The `newkey` history probe grouped sources by their literal index expression, so two sources on one cluster with overlapping patterns (`logs-*`, `logs-web-*`) counted the same documents twice and a new key could read as known. It now probes each cluster once over the union of its sources' index expressions and sums across clusters.
- A detector scoped to one source (`sources:`) could read none of the documents an overlapping source on the same cluster had returned first, and the hunt still reported complete. A shared document is still stored once, and every detector whose scope includes any source that returned it now reads it, once.
- A Kibana search reply with `timed_out: true` or a failed shard (`_shards.failed` > 0) was read as complete, so low counts could hide activity. Fetch pages, the liveness probe, `CountKeys` and `CountAll` now fail with a partial-response error that marks the run incomplete and echoes no body.
- An estate, snapshot, case or actor file with a self-referencing alias crashed `jb` with an unrecoverable stack overflow, and an alias expansion bomb hung it, in the credential scan before strict validation. The scan now refuses a cyclic alias, nesting deeper than 64 levels and more than 100000 expanded nodes with a load error.

## [0.7.0] - 2026-11-07

### Added
- `newkey` takes an optional `history: {lookback, min_events, max_candidates}`: for the keys that meet `min_hits`, jb asks each distinct index one unfiltered count of every candidate over `[window.From - lookback, window.From)`, and a key under `min_events` is a finding (the history replaces the preceding-window baseline). A failed probe, a candidate beyond `max_candidates` or an index with no events in the lookback makes the run incomplete, never quiet. A kibana source takes `key_match: {field, mode: term|phrase}` (no default mode) and implements the new optional port `core.KeyCounter`; `core.KeyHistory` and `core.HistoryDetector` are the other new ports. Config accepts `history` only when every source the detector reads is a kibana source with `key_match` (RFC 0014).
- `newkey` takes `min_severity` (`high` or `critical`) and `note`: a floor applied after the empty-baseline drop that can only raise a finding, with the parse and apply logic shared with `behaviour` in `internal/severityfloor` (RFC 0011 amendment).
- An estate file takes an optional top-level `subject`, `operated` or `adversary` (absent is unclassified). Snapshots copy it and `promote` keeps it, `jb estate diff` refuses two files of different subjects with a usage error, and the Estate page groups maps under "Operated", "Adversary and third-party" and "Unclassified" without merging nodes, edges or corroboration across files (RFC 0015).
- `jb estate facts import` reads standard input when the file is `-`, and accepts JSON lines (a header object, then one entry object per line) as well as the single document, so a tool's output can be piped in. The library takes `EstateFactsImportOptions.Input`. The 1 MiB and 5000 fact caps apply to the stream, and an entry error names the entry by number.

### Fixed
- `jb watch` reported `gap=false` through an outage. An incomplete cycle advanced the edge of what counted as examined, so a source down for longer than the window left the span between the last completed window and the first completed window after the outage unexamined, with no gap reported. The edge now moves only on a cycle where nothing failed. A gap is raised once, on the first cycle that completes after the outage, and says how much time was never examined and between which times. An outage shorter than the window still gives no gap. The gap state is in memory, so a restart during an outage forgets it.

### Changed
- Behaviour change: the recovery cycle after an outage longer than the window can now be `INCOMPLETE` with a `gap` and a `watch-gap` alert. An incomplete cycle never carries a gap. The gap text no longer reports time since the last cycle.
- The `last activity` time of a `jb activity` ACTIVE line now names the subject that holds it, for example `(pago-actor, 18h0m ago)` or `(password-reset, rare action, 2h0m ago)`. The time is still the newest of any active subject, so a rare action's time (another party's password reset) read as "the actor was last seen then"; the table shows each subject's own time. `ActivityResult.Last` and the JSON are unchanged.

## [0.6.0] - 2026-11-06

### Added
- The Estate page filters nodes by kind (an htmx fragment with a repeatable `kind` parameter) and draws edge weight from the number of distinct corroborating sources (line width) and the age of the newest claim (dashed after 90 days), computed at load with nothing stored in the file. The record of an `ip` node loads, on demand, its latest reputation per source and the last time the address appeared in stored events (30 days, 3 second limit, four distinct states, no verdict colour); loading the map never queries the store (RFC 0001). `core.DashboardStore` gains `LastSeen`; `estategraph.Build` takes an `Options` struct.
- A config whose `commands:` is exactly `[intel]` may omit `sources` and `detectors` and hold only `feeds:`, `intel:` and optionally `store:`, since `jb intel` reads no source. It needs at least one feed, and `jb case check` accepts it. Every other config, including `commands: [intel, hunt]` and one without `commands:`, still fails with `sources: at least one source is required`. `jb hunt`, `jb watch`, `jb activity` and `jb actor status` refuse such a config with a usage error that names the config and the command.

### Changed
- `jb hunt` and `jb activity` now run through `jb.Hunt`, `jb.HuntCase` and `jb.Activity`, so the command line and the Go package share one implementation. The results carry the operator advice as `Notes`, and `HuntOptions.Notice` and `ActivityOptions.Notice` stream it while the call runs. CLI flags, output and exit codes are unchanged, with one ordering exception: `jb hunt --case ... --until T` with `--window` over 31d now reports that usage error before any case note or case error (RFC 0013).

## [0.5.0] - 2026-11-06

### Breaking
- `jb.estate/v1` and `jb.estate-snapshot/v1` files are refused with a message that names both versions. To migrate, change `apiVersion` to `jb.estate/v2` in each estate file (nothing else changes). Rewrite snapshot files the same way (`jb.estate-snapshot/v2`, and `jb.estate/v2` in the body), or regenerate them with `jb estate refresh`. `diff --output json` gains keys (`facts`, `value`, `subject`); none is removed (RFC 0001).
- `jb.WatchStatus` returns a `*WatchStatusResult` (`Checked` and `Watchers`) in place of a slice of `WatcherStatus`. `jb watch status --output json` is unchanged.
- `jb db status` accepts `--case DIR`, and `--config` is no longer required with it. Its `--config` help text changed.
- Errors returned by the Go package no longer start with `jb: `; the command line adds its own. A caller that matched that prefix matches the message instead, or uses `jb.IsUsage` (RFC 0013).
- The address errors of the dashboard no longer name `--addr` or `--allow-remote`. Match `web.ErrNotLoopback` and `web.ErrBadAddr`; `jb serve` still prints the flag hints.
- `jb db usage` reports a failed overlap check instead of "no overlap", and `jb db status` on a missing store says so before opening it (same exit code, nothing created).

### Added
- `jb operations [--tool]`, `jb.Operations()`, `jb.Call()` and `jb.CallTool()`: every operation is defined once from its option struct (`jb:` tags), one check validates the arguments for every surface, and the committed `docs/operations.json` lists all 22 (RFC 0010). 13 commands register their flags from their operation; a test pins every command's flags.
- `jb mcp [--allow NAME ...]`: an MCP server (revision 2025-11-25) on standard input and output. It lists only read-only operations; a mutating one needs `--allow NAME` and `apply=true`. `hunt` and `activity` run with the store off. Strings from evidence are cut at 256 characters and stripped of control characters (RFC 0010).
- Estate v2 (RFC 0001): `service` nodes, `facts` and `assessments`; drift compares facts; `jb estate facts import [--apply] FILE` reads one neutral JSON file under the source role `scan-cache` and never the network; the dashboard shows facts, and assessments marked as opinion.
- The results of `hunt`, `activity` and `watch_status` marshal to the same document `--output json` prints, so they carry the CLI keys over `jb.Call` and `jb mcp`.
- Go API, one function per command (RFC 0013): `CaseCheck`, `Doctor`, `ActorStatus`, `DBStatus`, `DBUsage`, `DBPrune`, `DBCompact`, `DBRenameSource`, `Intel`, `EstateIP`, `EstateASN`, `EstateDNS`, `EstateCT`, `EstateRefresh`, `EstateDiff`, `EstatePromote`, `DashboardHandler` and `Serve`. The JSON result types of those commands now belong to the package, and the commands print them. The mutating `DB*` functions are a dry run unless `Apply` is set. See the README table.
- `jb.Reputation` and `jb db reputation (--config FILE | --case DIR) [--indicator IP ...] [--source NAME] [--since TIME] [--until TIME] [--limit N] [--latest] [--output table|json]`: a read-only reader for the stored reputation rows (indicator, verdict, observed, source), capped at 10000 rows; a result cut at the cap is marked `truncated` and exits 1. `--latest` keeps the newest row per indicator and source.
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
