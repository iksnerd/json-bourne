# json-bourne (`jb`)

Evidence-first incident response for when you are being attacked. Go, DuckDB, cobra.

## Build and test

    export GOFLAGS=-mod=mod GOPROXY=off   # only if offline; duckdb-go uses cgo
    go build -o bin/jb ./cmd/jb
    go vet ./... && go test -race -count=1 ./...

## Layout

- `jb.go` (package `jb`, repo root): the one public Go API, a facade over `app` and `config`. Everything else stays under `internal/` so it can change freely.
- `internal/core`: domain types and ports. Standard library only.
- `internal/app`: use cases. Depends on `core` only.
- `internal/adapters/*`: Elasticsearch, nginx, DuckDB, feeds. Implement `core` ports.
- `cmd/jb` + `internal/config`: the only place that knows every adapter.
- `internal/adapters/plugin`: the host for out-of-process mapper plugins. The only package besides the case git guard that may import `os/exec`. Protocol, limits and trust model: `docs/PLUGINS.md`.
- `internal/estategraph`: the estate graph model (degree, components, layered layout) over `core` and `dominikbraun/graph`; no I/O.
- `internal/adapters/web`: the dashboard. templ components (`*.templ`; generated `*_templ.go` and `static/tailwind.css` are committed, rebuild with `make ui`), htmx fragments, vendored d3/htmx. Strict CSP (`script-src 'self'` only); `TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch` bans `templ.Raw` and friends. See CONTRIBUTING.md.
- `sdk/` (package `sdk`): the plugin side, public. Standard library only; it must never import `internal/` (the archtest scans it like a plugin).
- `plugins/`: example mapper plugins (separate programs, standard library only; nothing in `jb` imports them). `internal/conformance` runs one corpus through them and the built-in mapper.
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
