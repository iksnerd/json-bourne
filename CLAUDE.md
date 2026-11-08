# json-bourne (`jb`)

Evidence-first incident response for when you are being attacked. Go, DuckDB, cobra.

## Build and test

    export GOFLAGS=-mod=mod GOPROXY=off   # only if offline; duckdb-go uses cgo
    go build -o bin/jb ./cmd/jb
    go vet ./... && go test -race -count=1 ./...

## Layout

- `jb.go` (package `jb`, repo root): the one public Go API, a facade over `app` and `config`. The `.go` files at the repo root are that one public package `jb` (its import path is the module path), so they cannot move into a subdirectory. Everything else stays under `internal/` so it can change freely.
- `internal/core`: domain types and ports. Standard library only.
- `internal/app`: use cases. Depends on `core` only.
- `internal/adapters/*`: Elasticsearch, nginx, DuckDB, feeds. Implement `core` ports.
- `cmd/jb` + `internal/config`: the only place that knows every adapter.
- `internal/adapters/plugin`: the host for out-of-process mapper plugins. The only package besides the case git guard that may import `os/exec`. Protocol, limits and trust model: `docs/PLUGINS.md`.
- `internal/estategraph`: the estate graph model (degree, components, layered layout) over `core` and `dominikbraun/graph`; no I/O.
- `internal/adapters/web`: the dashboard. templ components (`*.templ`; generated `*_templ.go` and `static/tailwind.css` are committed, rebuild with `make ui`), htmx fragments, vendored d3/htmx. Strict CSP (`script-src 'self'` only); `TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch` bans `templ.Raw` and friends. See .github/CONTRIBUTING.md.
- `sdk/` (package `sdk`): the plugin side, public. Standard library only; it must never import `internal/` (the archtest scans it like a plugin).
- `examples/plugins/`: example mapper plugins (separate programs, standard library only; nothing in `jb` imports them). `internal/conformance` runs one corpus through them and the built-in mapper.
- `internal/ops`: an operation defined once from the option struct's `jb:` tags (RFC 0010): schema, argument check, MCP tool projection. Standard library only. `docs/operations.json` is its committed output.
- `internal/mcp`: the MCP server (JSON-RPC over stdio). Imports no `jb` package except the types in `internal/ops`.
- `internal/watchrun`: builds the ports of `app.Watch`/`app.Hunt` from a case config; shared by `cmd/jb` and `jb`. Also reads the watcher history that the Timeline page shows.
- `internal/severityfloor`: the one parse-and-apply of a detector's `min_severity` and `note` (`behaviour`, `newkey`).
- `internal/estateseam`: test doubles for the estate network adapters, on the call's context. Not public API (`jb.EstatePorts` is gone).
- `contract/`: a separate Go module of consumer tests that import only `jb` and `sdk`. It parses the README command-to-function table, so keep that table's format. `go test` at the root does not run it; CI runs it on tags (`cd contract && go test -race -count=1 ./...`).
- `docs/schemas/`: JSON Schemas for the case, actor and estate files, kept equal to the loaders by tests in `internal/casefile`.
- `testdata/api/`: the API surface golden for `jb` and `sdk` (`TestAPISurface`; update with `-update-api` and read the diff). Other goldens pin flags, exit codes, config keys, the plugin wire, the MCP tool list and the store schema.
- `internal/archtest` enforces these rules. A rule is not done until you have seen it fail.

## What you would get wrong

- A detector compares the current window with the same-length preceding one
  (`Window.Previous`). A raw count means nothing.
- A source or detector that parses zero records returns `core.ErrNoRecords`. Never
  print a clean-looking negative.
- Read-only is enforced by the storage engine, not a string check.
- Recon against third-party hosts is passive only. See `docs/POLICY.md`.
- Credentials come from the environment. YAML holds the variable name, never the value.
- No real logs, hostnames, IPs or personal data in fixtures, docs or commits. Fixtures are synthetic.
- Count with a command before writing a number in docs.
- `internal/archtest` shells out to `go list`, which Go's test cache cannot see. Always run it
  with `-count=1`, or a broken dependency rule reports `(cached)` and passes.
- A timing assertion is a backstop, not a tight bound. CI runs the tests on a slow, loaded macOS
  runner, and release builds run them there, so a tight bound fails a release.
- A test never uses a fixed date against a store that reads the real clock (retention, `--keep`,
  prune); derive times from `time.Now()`.
- A new column or stored marker must be checked in every path that copies or rewrites that table
  (compaction, source rename, prune, import), not only where it is written. v0.10.3 added
  `events.returners` and missed rename and compaction; the compaction guard test
  (`TestCompactCopiesEveryColumn`) now fails when a column is not copied. A schema golden or a row
  count does not prove a copy kept the content.
- Ownership (which source stores a row), identity (which document it is) and membership (who returned
  it) are three different facts. Do not let a stored label serve as the identity key.
- A fix whose test you never saw fail is unconfirmed. Write the test first, or say so in the report.
- Never move a published tag. A bad release gets a new patch tag.
- Feature freeze: no new command, port, file format or config key before 1.0 (`jb serve` excepted).
  See .github/CONTRIBUTING.md.
