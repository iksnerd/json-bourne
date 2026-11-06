## What this changes and why

<!-- The claim, in a sentence or two. Link the issue. -->

## How it was checked

- [ ] I wrote the test first and saw it fail for the expected reason (say how below)
- [ ] `go vet ./...` and `go test -race -count=1 ./...` pass
- [ ] `go test -count=1 ./internal/archtest` passes (with `-count=1`, not a cached result)
- [ ] `gofmt -l .` prints nothing
- [ ] Fixtures are synthetic; no real logs, IPs, hostnames, personal data or credentials in code, tests, docs or the diff
- [ ] No credential can reach output or errors; config names environment variables only
- [ ] Zero records is `core.ErrNoRecords`, not an empty clean result
- [ ] Docs are updated, and every number or command I wrote I obtained by running it
- [ ] Nothing here sends traffic to a host the operator does not control (docs/POLICY.md)

<!-- How I saw the test fail: -->
