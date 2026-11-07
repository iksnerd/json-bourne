# Contributing

Thanks for looking. `jb` is small on purpose, and the rules below exist because each one prevented a wrong answer during an incident.

## Build and test

```sh
export GOFLAGS=-mod=mod GOPROXY=off   # only if you build offline; duckdb-go uses cgo
go build -o bin/jb ./cmd/jb
test -z "$(gofmt -l .)"
go vet ./...
go test -race -count=1 ./...
```

CI and release run only when a version tag (`v1.2.3`) is pushed: the workflow tests on Linux and macOS, builds `jb` for `linux-amd64` and `darwin-arm64`, and publishes a GitHub release (`.github/workflows/ci.yml`). Nothing runs on branch pushes or pull requests, so run the three commands above before you tag.

### Changing the dashboard

The dashboard (`internal/adapters/web`) is templ components, htmx, d3 and Tailwind. The generated `*_templ.go` files and the built `static/tailwind.css` are committed, so none of the tools below are needed to build or test `jb`. They are needed when you change a `.templ` file, a class name or `assets/input.css`:

```sh
make ui         # installs the pinned templ CLI and Tailwind standalone CLI (checksum-verified), then regenerates
make ui-check   # fails if the committed generated files are stale
```

Rules that tests enforce: no script except the vendored files, no inline script or style, no `templ.Raw` or other raw-HTML escape hatch, GET only. Vendored libraries are the exact files published to npm, pinned by hash in `internal/adapters/web/web_ui_test.go`; to update one, verify the npm tarball's integrity, replace the file and its licence, and change the pin in the same commit. See [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md).

### The archtest trap

`internal/archtest` enforces the dependency rules by running `go list`. Go's test cache cannot see what that subprocess reads, so a cached run passes after you break a rule. Always use `-count=1`:

```sh
go test -count=1 ./internal/archtest
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Feature freeze (the stable core)

Decided 2026-11-06. The accepted RFCs that are not built yet are the last feature work before 1.0: the `newkey` severity floor (RFC 0011 amendment), the `newkey` history probe (RFC 0014, after its cost measurement), the estate `subject` key (RFC 0015), and the watch-gap fix. After they are built and released, `jb` takes no new command, port, file format or config key before 1.0. What goes in: bug fixes, hardening, tests and docs. A request for anything else goes on a later list and needs the maintainer to lift the freeze. RFC 0016 (own-cloud inventory) is parked behind it.

Exception, decided 2026-11-07: the freeze is lifted for `jb serve` (the dashboard) only, so it can be the one interface to a case. The dashboard rules stay: GET only, strict CSP, no `templ.Raw`, read-only store, no verdict colour, no case-specific code. A change that adds a route, a store query or a data source needs an RFC; a change that only renders data the page already has does not. Detectors, config keys, formats and every other command stay frozen.

## Compatibility before 1.0

`jb` has two users, both ours, and nothing is public. There is no backward compatibility. Change or remove a flag, a config key, a file format, an exported identifier or the plugin protocol when the design needs it. Write no shim, no alias and no dual loader.

Three things keep this safe:

- A file format keeps its `apiVersion`. The number increments when the format changes incompatibly. A loader reads only the current version and tells the writer of an old file to rewrite it.
- The evidence store keeps forward-only migrations in transactions, because evidence cannot be collected again. A build refuses a newer file. A release that adds a migration says so in the changelog and tells you to back up first.
- Every breaking change goes in the changelog under "Breaking", with how to migrate. Tell the other user before it merges. That program pins an exact version, so it moves when it chooses.

## Rules for a change

- **Red first.** Write the test, run it, and see it fail for the reason you expect before you write the fix. A test you never saw fail may be passing for the wrong reason. Say in the PR how you saw it fail.
- **Synthetic fixtures only.** Use `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `example.com` and invented identifiers.
- **Never commit real data.** No real logs, IP addresses, hostnames, account names, personal data, API keys, or database files. If you find any in the repository or its history, report it through [SECURITY.md](SECURITY.md) instead of opening an issue.
- **Counts come from commands.** Do not write a number in docs that you did not obtain by running something.
- **Credentials from the environment.** Config names a variable, never holds a value, and errors never contain one.
- **Passive only.** See [docs/POLICY.md](docs/POLICY.md).
- **No clean-looking empty results.** Zero records is `core.ErrNoRecords`.
- Match the existing style; `gofmt` clean.

## Proposing a source or detector

Open a feature issue first (use the template). Say what it reads or detects, what its false positives look like, which real failure it would have caught, and what the baseline is for a detector. Then follow [docs/WRITING-A-SOURCE.md](docs/WRITING-A-SOURCE.md) or [docs/WRITING-A-DETECTOR.md](docs/WRITING-A-DETECTOR.md). A new adapter needs its archtest rule, config registration, documented keys in `docs/CONFIG.md`, and tests.

## Pull requests

Fill in the template. Keep one concern per PR. Explain what the change claims and how you checked it.

By contributing you agree your work is licensed under Apache-2.0, the project license. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
