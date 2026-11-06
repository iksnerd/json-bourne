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

### The archtest trap

`internal/archtest` enforces the dependency rules by running `go list`. Go's test cache cannot see what that subprocess reads, so a cached run passes after you break a rule. Always use `-count=1`:

```sh
go test -count=1 ./internal/archtest
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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
