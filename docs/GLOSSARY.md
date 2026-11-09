# Glossary

[Back to the README](../README.md)

One meaning per term, as the code and docs use it. The Where column names the file that defines the term, and a Go identifier in that file when there is one.

| Term | Meaning | Where |
|---|---|---|
| actor | A named subject of an investigation, kept as one file with a list of indicators. A detector can read actors to match events. | [`internal/casefile/actor.go`](../internal/casefile/actor.go) `Actor` |
| adapter | Code that implements a port and talks to the outside: Kibana, DuckDB, a feed, a webhook. An adapter imports `core` and never another adapter. | [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) |
| baseline | The window of the same length that ends where the current window starts. A detector compares the current window with it. | [`internal/core/core.go`](../internal/core/core.go) `Previous` |
| case | A directory that defines one investigation as data: `case.yaml`, config, actors, estate files and the evidence store. | [`docs/CASE-SPEC.md`](CASE-SPEC.md) |
| composition root | A place that builds the adapters and passes them to the use cases. `cmd/jb`, the `jb` package and `internal/watchrun` are composition roots. | [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) |
| detector | A component that compares the current window with the baseline and returns findings. It reads stored events and nothing else. | [`internal/core/core.go`](../internal/core/core.go) `Detector` |
| doc_ident | The column of the `events` table that holds the durable identity of the source document. Two stored events with the same value count as one event. | [`internal/adapters/duckdb/migrations/0004_events_doc_ident.sql`](../internal/adapters/duckdb/migrations/0004_events_doc_ident.sql) `doc_ident` |
| ErrNoRecords / incomplete | `ErrNoRecords` means a source or detector parsed zero records. A hunt is incomplete when any source or detector ended with a status other than `ok`. | [`internal/core/core.go`](../internal/core/core.go) `ErrNoRecords` |
| estate | The set of hosts, addresses and services the case owns, kept as `jb.estate/v2` files and filled by passive lookups. | [`docs/CASE-SPEC.md`](CASE-SPEC.md) |
| event | One normalised log record with a time, a source name, a kind, fields and the raw document. | [`internal/core/core.go`](../internal/core/core.go) `Event` |
| feed | An external reputation lookup for indicators. A feed asks its own API and never contacts the indicator. Only `jb intel` uses feeds. | [`internal/core/core.go`](../internal/core/core.go) `Feed` |
| finding | One result of a detector: a tag, a severity, both windows, a summary and the numbers behind it. | [`internal/core/core.go`](../internal/core/core.go) `Finding` |
| hunt | One run of `app.Hunt`: fetch events from the sources, store them, run the detectors over the stored events, store the findings. | [`internal/app/hunt.go`](../internal/app/hunt.go) `Hunt` |
| indicator | One observation about an actor, such as an address or a user agent. In a feed, the value that is looked up. | [`internal/casefile/actor.go`](../internal/casefile/actor.go) `Indicator` |
| key | The field value a detector groups events by, for example a client address. You choose the field in the config. | [`internal/adapters/detectors/newkey/newkey.go`](../internal/adapters/detectors/newkey/newkey.go) |
| mapper | Code that turns one raw document into one event. Built-in mappers are Go code; a plugin is a mapper in a separate program. | [`internal/core/core.go`](../internal/core/core.go) `BatchMapper` |
| operation | One action defined once from a Go option struct. The Go API, the CLI flags and the MCP tools all come from that definition. | [`internal/ops/ops.go`](../internal/ops/ops.go) `Operation` |
| passive-only | The rule that `jb` reads your own logs and asks third-party registries and resolvers about an address. It sends nothing to the address. | [`docs/POLICY.md`](POLICY.md) |
| plugin | A mapper that runs as a separate executable you have put on the allowlist. The host talks to it over a line protocol. | [`docs/PLUGINS.md`](PLUGINS.md) |
| port | An interface in `core` that an adapter implements, such as `Source`, `Detector` or `Sink`. | [`internal/core/core.go`](../internal/core/core.go) `Source` |
| run | One execution that stores evidence: a hunt, an activity check, a search or a watch cycle. Saving the same run twice replaces it. | [`internal/core/core.go`](../internal/core/core.go) `Sink` |
| run id | The name of a run, such as `hunt-<stamp>`. Events are stored under `<run id>/<source name>` and findings under the run id. | [`internal/core/maintenance.go`](../internal/core/maintenance.go) `ClassifyRun` |
| severity | How urgently a person should look at a finding. The order is `info`, `check`, `activity`, `high`, `critical`. | [`internal/core/core.go`](../internal/core/core.go) `Severity` |
| sink | The port that saves events and findings for a run. The DuckDB store implements it. | [`internal/core/core.go`](../internal/core/core.go) `Sink` |
| source | The port that streams events for a window. The Kibana adapter is the one source today. | [`internal/core/core.go`](../internal/core/core.go) `Source` |
| store | The local DuckDB file that holds events, findings and run records. Detectors read from it, not from the source. | [`internal/adapters/duckdb/duckdb.go`](../internal/adapters/duckdb/duckdb.go) `Store` |
| window | A half-open time range `[From, To)`. A hunt judges the current window. | [`internal/core/core.go`](../internal/core/core.go) `Window` |
