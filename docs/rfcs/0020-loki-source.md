# RFC 0020: A Loki source, reachable through Grafana
Status: draft
Scope: how `jb` reads log lines from Loki, directly or through the data source proxy of a Grafana, as a source that obeys every rule the Kibana source obeys. Parked: nothing is built until the maintainer lifts the feature freeze.

## Summary

Grafana stores no logs. It queries data sources, and the logs an incident responder wants sit in the backend behind it, most often Loki. This RFC adds one source type, `type: loki`. It sends one kind of request, a read-only `GET <url>/loki/api/v1/query_range`, to a base `url`. The `url` is a Loki, or the data source proxy of a Grafana (`https://grafana.example.com/api/datasources/proxy/uid/<uid>`). Nothing in `jb` is specific to Grafana.

The config is data, as it is for the Kibana source: a label selector and optional line filters. `jb` compiles them to LogQL. There is no raw LogQL key. Log lines go through the mapper registry that the Kibana source already uses, plugin mappers included.

A Loki source keeps the Kibana-source rules from [WRITING-A-SOURCE.md](../WRITING-A-SOURCE.md): zero lines is `ErrNoRecords`, an unreachable or refusing backend is `ErrSourceUnavailable`, a line that cannot be parsed is counted and never dropped, and a number that was not fetched is never reported.

## Motivation

An operator keeps ingress logs in Loki and looks at them in Grafana. Today `jb hunt` has one log-store source, `kibana`, so that operator cannot hunt with `jb` at all. A second backend also shows whether the source contract in `core.Source` is as narrow as the docs claim.

The request says "Grafana". Grafana is the door and Loki is the source. A user with Loki and no Grafana needs the same code, so the type is named for what it reads.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

A *stream* is one set of Loki labels and its entries. An *entry* is a nanosecond timestamp and one log line. The *base url* is the `url` key.

## How this design was made

1. **Workflow first.** The operator writes a URL, the name of a token variable, which streams to read and which lines to keep. Those are the keys. No LogQL, no data source id and no Grafana version appears in them.
2. **One URL, no `via: grafana` switch.** A Grafana proxy path and a Loki root differ only in the prefix before `/loki/api/v1/query_range`. A mode key would add a branch for no new behaviour.
3. **Config is data.** `filterClause` in the Kibana source says why: the config is data a case carries, not a query language. A raw LogQL key would let a case file run any query the token allows and would need its own escaping rules.
4. **Reuse the mapper registry.** The Loki source builds the same raw document the Kibana mappers read and calls the same mappers. Plugin mappers work unchanged.
5. **Say what Loki cannot do.** Loki returns no total hit count and no document id. The design records that and does not invent either.

## The design

### Config

Nine keys, all new. This is not run; it is the proposed shape.

```yaml
sources:
  - type: loki
    name: loki:ingress                  # optional; default "loki:" + the selector
    url: https://grafana.example.com/api/datasources/proxy/uid/abc123
    token_env: JB_LOKI_TOKEN            # the NAME of a variable; sent as "Authorization: Bearer <value>"
    tenant: team-a                      # optional; sent as X-Scope-OrgID
    selector: {app: ingress-nginx, env: prod}
    contains: ["/login"]                # optional; every string must appear in the line (AND)
    mapper: nginx_ingress               # same registry as kibana; default "default"
    mapper_config: {}                   # only with mapper: plugin:<name>, as for kibana
    page_size: 1000
```

| Key | Type | Rule |
|---|---|---|
| `url` | string | Required. `https` unless the host is loopback. No query string, no userinfo. |
| `token_env` | string | Optional. Upper-case letters, digits, underscore, as `api_key_env`. A pasted token is refused, not echoed. |
| `tenant` | string | Optional. One tenant. The `a\|b` multi-tenant form is not supported. |
| `selector` | map | Required. 1 to 8 pairs. Names match `[a-zA-Z_][a-zA-Z0-9_]*`. Values are non-empty strings. Equality only. |
| `contains` | list | Optional. At most 8 strings, each 1 to 256 characters, no control characters. |
| `page_size` | int | Optional. 1 to 5000. Default 1000. |
| `name`, `mapper`, `mapper_config` | | As for `kibana`. |

`jb` refuses an unknown key (strict decode, as today) and a duplicate source `name` (as today).

### The request

For a window `[From, To)` the source sends

```
GET <url>/loki/api/v1/query_range?query=<logql>&start=<From ns>&end=<To ns>&limit=<page_size>&direction=forward
```

and builds `<logql>` as `{name="value",...}` followed by one `|= "text"` per `contains` entry. Label values and filter text are written as LogQL double-quoted strings: `\` and `"` are escaped, and a value with a control character is refused at load time. The Loki page says `start` is inclusive and `end` is exclusive ("Loki returns results with timestamp greater or equal to this value" and "lower than this value"), so the request matches the half-open window of `core.Window` exactly.

### Paging

One request returns at most `page_size` entries. When a page holds exactly `page_size` entries, the next request sets `start` to the greatest timestamp it has seen. That entry is returned again, and the source drops it by its document key. If a whole page has the same timestamp as `start`, the cursor cannot advance. The fetch then yields an error and stops. It does not loop and it does not skip. This rule is the part that Open question 3 can still change.

### Document identity

Loki gives an entry no id. The source sets `Event.DocKey` to `loki:` plus the SHA-256 of the stream's labels (sorted by name), the nanosecond timestamp and the line. Two entries with the same labels, timestamp and line are one document. That is a stated limit, and it matches how identity is used in the store: it decides what counts once.

### The raw document and the event

The source builds this document for the mapper, and stores it as `Raw`:

```json
{"@timestamp": "<RFC 3339 with nanoseconds>", "message": "<the line>", "labels": {"app": "ingress-nginx"}}
```

Each label is also copied to a top-level key `label.<name>`. The names `@timestamp` and `message` are the ones the Kibana mappers read from a Filebeat document; Open question 8 asks that the mappers are checked before the keys are fixed.

### Empty, dead and quiet

A fetch that yields no entry returns `core.ErrNoRecords`. The source then sends the same request with `contains` removed and `limit=1`. A result there is recorded as `Probed`, as the Kibana source does, so the status can tell a quiet filter from a dead selector. Loki gives no total, so `Stats.HitsTotal` and `Stats.IndexTotal` stay unset. The source MUST NOT put an estimate in either field.

In this RFC a Loki source is refused by `empty_is_quiet` and by a `newkey` `history` block, with a load-time error that names the source. Both need a count that Loki's `query_range` does not return. A hunt over a quiet Loki window therefore ends `INCOMPLETE`, never clean. Open question 7 covers counting later.

### Errors

| Condition | Result |
|---|---|
| Connection error, timeout (120 s, as the Kibana client), 401, 403, 429, 5xx | `core.ErrSourceUnavailable`. The message has the status code and no response body. |
| 400 | `core.ErrSourceUnavailable` with "loki refused the request; check page_size and selector". No body. |
| 2xx with a content type that is not JSON, or a body that is not the `streams` shape | `core.ErrSourceUnavailable`. This is what an expired Grafana login returns: an HTML page with a 200 or a redirect. |
| A redirect | Not followed. `core.ErrSourceUnavailable`. |
| `resultType` other than `streams` | Unavailable. |
| One entry that the mapper cannot parse | Counted in `Stats.Unparsable`, as for Kibana. |

### Read-only and credentials

The source sends only `GET` to the one path above, and a probe to the same path. It MUST NOT call any other route. The token is read from the environment, is redacted in `String()` and `%+v`, and never appears in an error or a log line. The token's own rights are the operator's to limit: see Security considerations.

## Non-goals

- Dashboards, panels, alert rules, annotations or any Grafana API other than the data source proxy path.
- Backends other than Loki. Elasticsearch, OpenSearch, Prometheus and Tempo behind a Grafana are out.
- Raw LogQL, metric queries, `count_over_time` and live tail.
- `history` and `empty_is_quiet` for Loki sources (see Open question 7).
- Several tenants in one source.
- Writing to Loki or Grafana. `jb` sends no push, no annotation and no alert.
- A Grafana sink. A webhook sink exists already.

## Drawbacks

- **Nine new config keys after the freeze.** Each is a contract. Pre-1.0 they can change, after 1.0 they cannot.
- **A weaker identity.** Entries with equal labels, timestamp and line collapse into one. A burst of identical lines at one nanosecond counts once.
- **Less than Kibana.** No total, no `history`, no `empty_is_quiet`. A quiet Loki window is `INCOMPLETE` where a quiet Kibana window can be clean.
- **A second adapter to keep.** The Kibana source is 318 lines in `source.go` and 246 in `keycount.go`, the second of which this source skips. I expect a Loki source of the same order plus its tests. I have not measured it.
- **The Grafana path is not tested here.** The proxy route is listed in Grafana's docs, but nothing in `jb` has run against one.
- **A route that may move.** Grafana's page says that, starting in Grafana 13, `/api` endpoints are being deprecated in favour of `/apis`, and that legacy APIs stay available. Because the design takes a base URL, a new path is a config change.

## Alternatives and prior art

Read on 2026-11-09: the Loki HTTP API reference (`/loki/api/v1/query_range`) and Grafana's data source HTTP API page.

- **Loki `query_range`.** The page gives `limit` (default 100), `start` (inclusive), `end` (exclusive), `direction` (`forward` or `backward`, default `backward`), and the `streams` result shape with `[ "<ns timestamp>", "<line>" ]` values. It says multi-tenancy uses `X-Scope-OrgID`. It states no maximum `limit`.
- **Grafana data source proxy.** The page lists `GET /api/datasources/proxy/uid/:uid/*` and says it "proxies all calls to the actual data source identified by the uid". It does not mention Loki on that route, and it shows no request example.
- **`POST /api/ds/query`.** Documented for "a data source having a backend implementation", with `from`, `to` and `queries[].datasource.uid`. It would also reach Elasticsearch behind Grafana. It is not chosen here: each data source has its own query model, the page does not show the response frames, and a column-oriented frame needs a second parser. It is the likely route for Open question 6.
- **A source plugin protocol.** [RFC 0002](0002-mapper-plugin-protocol-v1.md) lets a mapper run out of process, and the core adds no format. The same argument says a new backend belongs behind a source protocol, not in `internal/`. That is a new wire protocol and a new trust surface ([docs/PLUGINS.md](../PLUGINS.md)), larger than this RFC. It is Open question 5.
- **Raw LogQL in config.** Rejected for the reason in "How this design was made", item 3.
- **The Kibana source.** [`internal/adapters/kibana/source.go`](../../internal/adapters/kibana/source.go) is the model for paging, probing, stats and errors. This RFC differs where Loki differs: no id, no total.

## Compatibility

Additive. A config without `type: loki` is unchanged. An older `jb` that reads a `type: loki` source rejects it as an unknown source type, because sources are picked by `type:` and decoded strictly. Before 1.0 no backward compatibility is promised ([CONTRIBUTING.md](../../.github/CONTRIBUTING.md)). After 1.0 the nine keys would be part of the supported config surface ([RFC 0018](0018-stability-policy.md)). The goldens for config keys and the docs schema change with the code.

## Security considerations

- **Passive and read-only.** One `GET` route, to the operator's own URL. This is inward-facing: it is not third-party reconnaissance, so [docs/POLICY.md](../POLICY.md) is not the rule that applies. The URL comes from the case file, so a case from an untrusted source could point `jb` at an internal host. The Kibana source has the same exposure, and the same answer: the operator reads the config.
- **Redirects.** Not followed. An SSO redirect cannot send the token to another host.
- **Plain HTTP.** A token over `http://` to a non-loopback host is refused at load time.
- **The token's rights.** `jb` sends only `GET query_range`, but the token is a Grafana credential. A service account token can call routes that `jb` never uses, and the data source proxy forwards whatever the data source accepts. Grafana's page says some endpoints need specific permissions and does not say which. The operator SHOULD use a token that can only read the one data source. `jb` cannot enforce this. The minimum rights are Open question 6.
- **Log content is untrusted.** Lines go to mappers and into `Raw`. The dashboard's strict CSP and the rule against raw HTML apply as for every source. The 120 s timeout and the page limit bound a hostile server.
- **No secrets in output.** The token is redacted in `String()` and `%+v`, absent from errors, and covered by the redaction test that the Kibana client has.

## Conformance

All of these are proposed. None exists.

- A fake Loki server (`httptest`) drives the source: exact window bounds, a full page then a short page, a page whose entries all share one timestamp, two streams interleaved in time, a repeated boundary entry, zero entries with a live probe and with a dead probe, 401, 403, 429, 400, a 200 HTML page, a redirect, a non-`streams` result type.
- A fuzz test on LogQL assembly: no input makes a label value or a filter string end the quoted string.
- A document-key test: the same entry gives the same key; any change in labels, timestamp or line changes it.
- A redaction test, as in `internal/adapters/kibana/redact_test.go`.
- `internal/archtest`: the Loki adapter imports `core` and the standard library only.
- The mapper corpus runs through a Loki-shaped document and gives the same events as through the Kibana path.
- Config tests: unknown key, bad selector name, `empty_is_quiet` and `history` refusals, `http://` to a non-loopback host.
- The config-key golden and the docs schema are updated and read.

Before acceptance, one run against a real Loki behind a real Grafana, on synthetic data, settles Open questions 1 to 4.

## Reference implementations

Shipped: none.

Proposed:

- `internal/adapters/loki/` (client, source, stats).
- `internal/config/register_loki.go`, following `register_kibana.go`.
- A section in [docs/WRITING-A-SOURCE.md](../WRITING-A-SOURCE.md) and the config docs under `docs/config/`.

## Open questions

1. **The proxy path.** Does `<proxy>/loki/api/v1/query_range` work on a real Grafana? The docs list the proxy and do not name Loki on it. Decides: the maintainer, after a run on a local Grafana and Loki with synthetic data.
2. **The page size ceiling.** The Loki page gives a default of 100 and no maximum. What does a server answer when `limit` is above its own cap, and is 5000 a safe bound? Decides: the maintainer, after the same run.
3. **Order across streams.** With `direction=forward`, are entries from several streams merged in time order inside one page? If not, "the greatest timestamp seen" can skip entries, and the cursor needs the smallest of the streams' last timestamps. Decides: the maintainer, after the same run.
4. **Identical entries.** Does Loki keep two entries with equal labels, timestamp and line? If it drops one at ingest, the document key loses nothing.
5. **In-tree source or a source protocol.** Add `loki` to `internal/adapters`, as `kibana` is, or define a source plugin protocol first and ship Loki as its first plugin. The second matches the extension argument of RFC 0002 and costs a protocol. Decides: the maintainer.
6. **Token rights and other auth.** Which Grafana role and permission is the minimum for the proxy route? Grafana Cloud and some Loki setups use basic auth. Is `/api/ds/query` the better route for them? Decides: the maintainer.
7. **Counting.** Could `history` and `empty_is_quiet` come from `count_over_time` in a later RFC? Decides: the maintainer, after this one is built.
8. **Mapper input.** Do the shipped mappers read exactly `@timestamp` and `message`, and does `nginx_ingress` accept a bare line there? Settled by reading `internal/adapters/kibana/mappers.go` and running the corpus, before acceptance.
9. **The name.** `loki` or `grafana`. This RFC proposes `loki`. Decides: the maintainer.
10. **The freeze.** Nine config keys need the feature freeze lifted for this one change. Decides: the maintainer.

## Changes

- 2026-11-09: first draft. Not accepted.
