# What is in the box

Every source, mapper, detector, feed, sink and the store, with its limits. Options for each are in [CONFIG.md](CONFIG.md).

- Source: `kibana`, which reads Elasticsearch through the Kibana search proxy (`POST /internal/search/es`) using an API key from the environment.
- Built-in mappers: `default`, `nginx_ingress`, `keycloak` and `request_dump`; see [CONFIG.md](CONFIG.md).
- Mapper plugins: `mapper: plugin:<name>` runs an allowlisted executable as a child process to turn documents into events, so parsing for a product's log format lives outside the binary. Three configurable examples (`kvlines`, `regexlines`, `jsondoc`) are in `examples/plugins/`. There is no sandbox and the OS is not asked to deny the plugin the network; see [PLUGINS.md](PLUGINS.md) for the protocol, the limits and exactly what is and is not enforced.
- Detector: `authspike`, which flags a key (for example a client address) whose share of failed requests rose against the preceding window, and also reports a key that keeps failing at a high share when there is no rise to see (tag suffix `:sustained`, one severity step lower).
- Detector: `signup`, which flags a window whose account creations (the creating endpoint, never the form render) reach a minimum and a multiple of the preceding window's, and flags creations on a disposable-domain list you supply.
- Detector: `newkey`, which flags a key (for example a client address) with no events in the preceding window that makes several requests to sensitive paths you list. With `user_agent_matches` it counts only requests from clients whose user agent matches your anchored patterns (scripted clients).
- Detector: `signature`, which flags a marker no legitimate client sets (a header or any event field, present or equal to a value you list). It raises on first sight, never prints a header value, and says in every finding that a hit shows the marker was sent, not who sent it. With the `request_dump` mapper it reads a chosen request header from an application request log; credential headers are never emitted.
- Detector: `behaviour`, which detects by what is done rather than by user agent: named actions (an exact or anchored path, optional method, status set and field equalities), each `rare` (any occurrence is notable) or `common` (only a rise in its failure share against the preceding window is). It reports how many distinct keys took part and ignores your own infrastructure.
- Detector: `fingerprint`, which flags events matching an actor described in the case's `actors/` files (exact user-agent match, scanner noise filtered, a 2xx on a token endpoint raised as critical). The indicators are case data, not tool code. See [CONFIG.md](CONFIG.md).
- Alert sink: `webhook` (`jb watch`), a POST of `{"text": ...}` to a URL read from an environment variable, capped per cycle, no redirects, https only. The log stays the source of truth. See [CONFIG.md](config/alerts.md#alert-delivery).
- Evidence store: a single DuckDB file, `~/.jb/jb.duckdb` unless `store.path` or `JB_DB` says otherwise. Saving a run replaces it in one transaction. Events fetched again by an overlapping hunt are stored again but read back once. One process writes or many read, never both; a command that meets a writer waits up to 15 s (`JB_DB_LOCK_WAIT`, see [CONFIG.md](config/store.md#locking-one-writer-or-many-readers)).
- Dashboard: `jb serve` (`internal/adapters/web`). Server-rendered with [templ](https://templ.guide) components, partial updates with vendored [htmx](https://htmx.org), the estate graph drawn with vendored [d3](https://d3js.org) over a Go graph model (`internal/estategraph`, built on `dominikbraun/graph`), styled with Tailwind from design tokens in the manner of shadcn/ui. The built CSS and the generated components are committed, so `go build` needs none of those tools; see [CONTRIBUTING.md](../.github/CONTRIBUTING.md#changing-the-dashboard). GET-only and read-only. The CSP allows script from this origin only, with no inline script and no eval, and the vendored files are version-pinned and checked by hash in a test ([THIRD-PARTY.md](THIRD-PARTY.md)).
- Config: YAML, strict. Unknown keys and unknown types fail at load.

## What exists, and nothing else

- One source type (`kibana`) and six detector types (`authspike`, `signup`, `newkey`, `signature`, `behaviour`, `fingerprint`).
- No report generator. Output is the CLI table or JSON, the DuckDB file (which you can query with the `duckdb` CLI), and `jb serve`, a local read-only dashboard with no authentication and no editing.
- Three reputation feeds (`greynoise`, `sans-isc`, `dnsbl`) behind the `Feed` port, used by `jb intel` only. `hunt` and the detectors never read reputation, and a snapshot is context, not attribution.
- No active scanning of any kind. See [POLICY.md](POLICY.md).
- The tool is inward-facing: it analyses your own logs and your own infrastructure. Outward reconnaissance and scans are done by other tools, and their output enters an estate file only through `jb estate facts import`.
- Nothing here identifies who is behind an attack. `authspike` reports which keys behaved abnormally in your logs, and `fingerprint` reports which events carry a user agent you wrote down as an actor's. Neither attributes anything to a person or an address.

[Back to the README](../README.md)
