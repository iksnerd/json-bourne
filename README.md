# json-bourne (`jb`)

[![Go Reference](https://pkg.go.dev/badge/github.com/iksnerd/json-bourne/jb.svg)](https://pkg.go.dev/github.com/iksnerd/json-bourne/jb) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`jb` is an incident-response tool for when you are under attack. It fetches logs for a time window from your own log store, keeps them as evidence in a local DuckDB file, and runs detectors that compare that window with the one before it. Go, DuckDB, cobra.

![jb serve: one hunt on synthetic data, with two findings](docs/img/dashboard.png)

*`jb serve`, the read-only dashboard, after one hunt over synthetic events (documentation-range addresses, a local stand-in for Kibana). The [estate graph](docs/img/estate.png) is on the same dashboard.*

## Why

During an incident the failure mode that does the most damage is a wrong clean answer: a query that silently returned nothing, a detector that parsed zero records, a count with no baseline. Each looks like "nothing is happening". `jb` is built so that cannot happen quietly:

- A source or detector that finds zero records returns `core.ErrNoRecords`, and `jb hunt` reports that component as not finished.
- If any source or detector did not finish, `jb hunt` prints `INCOMPLETE`, says which one, and exits 1. A hunt is only clean when every component completed.
- Detectors judge a window against the preceding window of the same length. A raw count is never a finding, and every number in a finding was counted from the events read.
- Two logs in one config do not mix: a detector can be limited to named sources, and a source that is alive but quiet is told apart from one that is dead.
- The evidence database is opened read-only by the storage engine, not by a string check on SQL.

## Quick start

You need Go 1.25 or later and a C compiler (the DuckDB driver uses cgo).

```sh
go build -o bin/jb ./cmd/jb

cp examples/jb.example.yaml jb.yaml   # edit url and index; never put a key in this file
export JB_KIBANA_API_KEY=...          # the variable named by api_key_env
bin/jb hunt --config jb.yaml --window 60m
```

`hunt` reads the last 60 minutes and the 60 minutes before them, saves both as evidence, runs every configured detector and prints a table (`--output json` for JSON). Progress goes to stderr, results to stdout. If the source cannot be reached, the answer is explicit. With the unedited example config (the host does not exist) the run ends like this:

```
SOURCE              STATUS       EVENTS    NOTE
kibana:logs-auth-*  unavailable  0         ... dial tcp: lookup kibana.example.com: no such host

DETECTOR            STATUS       FINDINGS  NOTE
authspike           no_records   0         authspike: no records: current window had 0 events, ...

INCOMPLETE: 2 component(s) did not finish; this is not a clean result.
jb: hunt incomplete, no clean result: 2 component(s) did not finish: [...]
```

To see a hunt that finds something without a Kibana, run the end-to-end test, which serves synthetic events from a local test server: `go test -count=1 ./cmd/jb -run TestHuntEndToEnd -v`.

## Commands

| Command | What it does |
|---|---|
| `jb hunt` | Fetch a window and the one before it, store both as evidence, run the detectors. `--search TERM` looks for one address or path, `--until TIME` hunts a past window, `--no-store` leaves no evidence. |
| `jb activity` | Is the actor active from any client? `ACTIVE`, `QUIET` or `INCOMPLETE`, with what each detector judged. |
| `jb watch`, `jb watch status` | Run the hunt on an interval and alert only on what is new; say whether the watchers are alive. |
| `jb case check`, `jb case show` | Validate a case directory; print what one config of it would run. |
| `jb doctor` | Read-only check of the environment, the config and every outbound service. |
| `jb actor status` | When each user agent of each actor last matched, from the evidence store. |
| `jb intel` | Look addresses up in the configured reputation feeds. Context, not attribution. |
| `jb estate ...` | Map your own infrastructure: addresses (reverse DNS and RDAP), then `asn`, `dns` and `ct`; import facts; check it for drift with `refresh`, `diff` and `promote`. Passive only. |
| `jb db status\|usage\|reputation\|prune\|compact\|rename-source` | Inspect and maintain the evidence store. Mutating commands are a dry run unless `--apply`. |
| `jb serve` | A read-only dashboard over the evidence store: findings, watch, timeline, estate graph. Loopback only. |
| `jb mcp` | The operations as Model Context Protocol tools; read-only unless you name more. |
| `jb operations`, `jb version` | Print the definition of every operation; print the version. |

Exit codes: 0 success, 1 runtime failure or an incomplete hunt, 2 usage error. Every flag, output field and rule is in [docs/COMMANDS.md](docs/COMMANDS.md).

## Use as a library

```sh
go get github.com/iksnerd/json-bourne
```

`go get` fetches the module; the package to import is `github.com/iksnerd/json-bourne/jb`.

```go
cfg, err := jb.LoadConfig("jb.yaml")
if err != nil {
	return err
}
res, err := jb.Hunt(ctx, cfg, jb.HuntOptions{Window: time.Hour})
if err != nil {
	return err
}
if !res.Complete() {
	return fmt.Errorf("not a clean result: %v", res.Failed())
}
for _, f := range res.Findings {
	fmt.Println(f.Tag)
}
```

A nil error means the hunt ran, not that it is clean: check `Result.Complete()` first. Every command has a function and the command prints that function's result. The API is v0 and may change between minor versions. Importing the package links DuckDB, so it needs cgo. The function table, the operations API and the completeness checks are in [docs/LIBRARY.md](docs/LIBRARY.md); the plugin side is the standard-library-only package `sdk`.

## Using jb from an agent (MCP)

```json
{
  "mcpServers": {
    "jb": { "command": "jb", "args": ["mcp"], "env": { "JB_KIBANA_API_KEY": "..." } }
  }
}
```

By default the server lists only the 11 read-only operations (the other 11 of the 22 change something), and a mutating one needs both `--allow NAME` and `apply=true`. The server holds the credentials of its process and its results come from logs an attacker may have written, so keep a person able to approve each tool call. See [docs/MCP.md](docs/MCP.md).

## What is in the box

- **Source:** `kibana` (Elasticsearch through the Kibana search proxy, API key from the environment).
- **Mappers:** `default`, `nginx_ingress`, `keycloak`, `request_dump`, and `plugin:<name>` for an allowlisted external program that turns documents into events. Three configurable examples are in [examples/plugins](examples/plugins/README.md).
- **Detectors:** `authspike`, `signup`, `newkey`, `signature`, `behaviour`, `fingerprint`.
- **Reputation feeds:** `greynoise`, `sans-isc`, `dnsbl`, used by `jb intel` only.
- **Alert sink:** `webhook`, plus the append-only `watch.log`, which stays the source of truth.
- **Evidence store:** one DuckDB file. One process writes or many read, never both.
- **Dashboard:** `jb serve`, server-rendered, GET only, strict CSP, works offline.

Each component, its options and its limits: [docs/COMPONENTS.md](docs/COMPONENTS.md) and [docs/CONFIG.md](docs/CONFIG.md).

## Status

Pre-1.0 and private. The latest tag is v0.10.5 (see [CHANGELOG.md](CHANGELOG.md)). Before 1.0 there is no backward compatibility: the Go API, the flags and the file formats may change between minor versions. `jb` takes no new command, port, file format or config key before 1.0, except in `jb serve` ([the feature freeze](.github/CONTRIBUTING.md#feature-freeze-the-stable-core)). 1.0 is reached by criteria, not a date ([RFC 0018](docs/rfcs/0018-stability-policy.md)).

What it is not:

- It does not scan anything. Recon against third parties is passive only, and outward reconnaissance is done by other tools ([docs/POLICY.md](docs/POLICY.md)).
- It does not say who is behind an attack. Detectors report which keys behaved abnormally in your logs, and which events carry a user agent you wrote down as an actor's.
- It has no report generator: output is the CLI table or JSON, the DuckDB file, and the dashboard.

## Documentation

**Use it**
- [docs/COMMANDS.md](docs/COMMANDS.md): every command, flag and output.
- [docs/CONFIG.md](docs/CONFIG.md): every config key, credentials, the database path.
- [docs/BACKFILL.md](docs/BACKFILL.md): hunting a past window with `--until`.
- [docs/PLUGINS.md](docs/PLUGINS.md): mapper plugins, the allowlist and the protocol.
- [docs/POLICY.md](docs/POLICY.md): passive-only, inward-facing, and what runs on the machine.

**Understand it**
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, ports and how the dependency rules are enforced.
- [docs/CASE-SPEC.md](docs/CASE-SPEC.md) and [docs/spec/README.md](docs/spec/README.md): the case directory and each file format and protocol.
- [docs/rfcs/README.md](docs/rfcs/README.md): the RFC index; [docs/adr/](docs/adr/) for decisions that are not contracts.

**Build on it**
- [docs/LIBRARY.md](docs/LIBRARY.md), [docs/MCP.md](docs/MCP.md) and [docs/operations.json](docs/operations.json).
- [docs/WRITING-A-DETECTOR.md](docs/WRITING-A-DETECTOR.md) and [docs/WRITING-A-SOURCE.md](docs/WRITING-A-SOURCE.md).
- [contract/README.md](contract/README.md): consumer tests of the public API, a separate Go module.

**Project**
- [CONTRIBUTING](.github/CONTRIBUTING.md), [SECURITY](.github/SECURITY.md), [CODE OF CONDUCT](.github/CODE_OF_CONDUCT.md), [CHANGELOG](CHANGELOG.md), [third-party code](docs/THIRD-PARTY.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
