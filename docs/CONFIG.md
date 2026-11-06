# Configuration

[Back to the README](../README.md)

`jb` reads one YAML file, passed as `--config`. Inside a case (`jb hunt --case DIR`, [CASE-SPEC](CASE-SPEC.md) section 9) the file is one of the case's `config` entries (or another file inside the case: a relative `--config` path is looked for in the case directory first, then in the working directory, and its real path, symlinks followed, must be inside the case), and `jb case check --case DIR` validates it, and `jb case show --case DIR` prints what it would run, reading no environment variable and no credential value. [`examples/jb.example.yaml`](../examples/jb.example.yaml) is a complete starting point with placeholder values.

The loader is strict. An unknown key, an unknown `type`, a missing `type`, a file larger than 1 MiB, or an empty file is an error at load time, before any network call, so a typo cannot silently turn a safeguard off. At least one source and one detector are required.

## Top level

| Key | Type | Required | Meaning |
|---|---|---|---|
| `commands` | list of string | no | The commands this config answers, from a closed set; see [Which config answers a command](#which-config-answers-a-command). |
| `sources` | list | yes, except in a [feeds-only intel config](#a-feeds-only-intel-config) | Each element is a mapping with a `type`. |
| `detectors` | list | yes, except in a [feeds-only intel config](#a-feeds-only-intel-config) | Each element is a mapping with a `type`. |
| `store.path` | string | no | Path of the DuckDB file. |
| `feeds` | list | no | Reputation feeds for `jb intel` (`greynoise`, `sans-isc`, `dnsbl`). Each element is a mapping with a `type`. Ignored by `hunt` and `watch`, which never read a feed key. Required (at least one) in a feeds-only intel config. |
| `intel` | mapping | no | Options of `jb intel`; see [Reputation lookups](#reputation-lookups). |
| `estate` | mapping | no | Which external services `jb estate asn\|dns\|ct` and `jb estate refresh` may ask; see [Estate collectors](#estate-collectors) and [Estate drift](#estate-drift). `jb estate facts import` reads a local file and needs no entry ([Estate facts](#estate-facts)). Ignored by every other command. |
| `alerts` | list | no | Extra places `jb watch` delivers alerts, in addition to stdout and `watch.log`; see [Alert delivery](#alert-delivery). Ignored by `hunt` and `intel`. |

## Which config answers a command

A case can list several configs (a hunt, a fingerprint check, a watcher). A config says what it is for with `commands`, a list of names from this closed set: `activity`, `actor`, `estate`, `hunt`, `intel`, `rename-source`, `serve`, `watch`. `estate` covers every `jb estate` subcommand. Any other name, an empty name or a repeat is a load error. `jb doctor` is not in the set: without `--config` it checks every listed config.

```yaml
commands: [activity, actor]
```

A command that takes `--case` chooses its config in this order:

1. `--config`, when given.
2. The one listed config that declares the command.
3. When none declares it and the case lists exactly one config, that config.
4. Otherwise a usage error (exit 2) that lists every config of the case with its commands. Two configs that declare the same command give the same error.

Reading the choice needs only the `commands` key of each listed config: no source is built and no environment variable is read. The Go options `Config` follow the same rule with the command each function stands for (`HuntCase`: `hunt`, `Watch`: `watch`, `Activity`: `activity`). `examples/case` lists two configs: `config/hunt.yaml` declares `hunt` and the others, `config/fingerprint.yaml` declares `activity` and `actor`.

### A feeds-only intel config

`jb intel` reads no source: it takes its addresses from the command line, or from the latest stored hunt. A config whose `commands:` is exactly `[intel]` may therefore omit `sources` and `detectors` and hold only `feeds:`, `intel:` and optionally `store:`:

```yaml
commands: [intel]
feeds:
  - type: sans-isc
intel:
  max_indicators: 20
```

It needs at least one feed. Everything else is unchanged: a config without `commands:`, with any other list (`[intel, hunt]` included), or with `sources` but no `detectors`, still fails with `sources: at least one source is required` (or the detectors message). `jb hunt`, `jb watch` and `jb activity` (and `HuntCase`, `Watch`, `Activity`) refuse a feeds-only config with a usage error (exit 2) that names the config and the command, before any source is built or any request is sent. `jb case check` accepts it.

## Sources

### `type: kibana`

Reads Elasticsearch through the Kibana search proxy (`POST /internal/search/es`).

| Key | Default | Rules |
|---|---|---|
| `url` | none, required | Absolute `https` URL. `http` is accepted for loopback only (`localhost`, `127.0.0.0/8`, `::1`). No credentials in the URL. |
| `api_key_env` | none, required | The *name* of an environment variable holding the API key. Must match `^[A-Z][A-Z0-9_]{0,63}$`. |
| `index` | none, required | Index or pattern, for example `logs-auth-*`. Also gives the source its default name, `kibana:<index>`. |
| `name` | `kibana:<index>` | Optional name of the source, `^[a-z][a-z0-9_.:-]{0,63}$` (no slash: it is part of the run id `<run>/<name>`). It is the stored `source` column and what `jb hunt`, `jb activity` and the dashboard show. Names must be unique in one config. Two sources on the same index need a `name` each; see [Two sources on one index](#two-sources-on-one-index). |
| `time_field` | `@timestamp` | Field used for the window filter and sort. |
| `page_size` | `1000` | `0` to `10000`. `0` takes the default. |
| `search_field` | `message` | The field `jb hunt --search TERM` matches a term against (see [Ad-hoc search](#ad-hoc-search)). Same character rules as a filter `field`. |
| `mapper` | `default` | Name of the mapper that turns a document into an event, or `plugin:<name>` for an allowlisted plugin; see [Mappers](#mappers). An unknown name, or a plugin that is not in your allowlist, is an error at load. |
| `mapper_config` | none | Only with `mapper: plugin:<name>`. A YAML map (at most 64 KiB as JSON) passed to the plugin as data on every request. It can never name a path or a command. |

Caveat from the code: every built-in mapper reads the event time from the document's `@timestamp` (RFC 3339), whatever `time_field` is. `time_field` changes the query, not the mapping. A document without a parsable `@timestamp` stops the fetch with an error.

#### Filter

Without a filter the source downloads every document in the window. On a busy ingress index that is tens of thousands of documents per ten minutes, and a day is millions. `filter` narrows the query on the server. Every clause must match (AND). It is a source key:

```yaml
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
    filter:
      - match_phrase: {field: message, value: "ExampleBrowser/9.1"}
```

| Clause | Meaning |
|---|---|
| `match_phrase: {field, value}` | The analysed text field contains the phrase. Use it for a raw log line. |
| `term: {field, value}` | The keyword field equals the value exactly. It does not match analysed text. |
| `any_of: [member, ...]` | At least one member matches (OR). Each member is a plain `match_phrase` or `term`; `any_of` does not nest. |

`any_of` is how "match any of these paths" is written. It is compiled to `{"bool": {"should": [members], "minimum_should_match": 1}}` and sits inside the same AND as the other clauses, so `jb hunt --search` still narrows every alternative:

```yaml
    filter:
      - term: {field: status, value: "200"}
      - any_of:
          - match_phrase: {field: path, value: /oauth/device/code}
          - match_phrase: {field: path, value: /oauth/token}
```

Rules, checked at load: exactly one of `match_phrase`, `term` or `any_of` per clause; `any_of` has 2 to 16 members, each exactly one of `match_phrase` or `term` (a member that is an `any_of` is an error); `field` is 1 to 128 characters of letters, digits and `_ @ . -`; `value` is 1 to 512 characters with no control or format character (newline, NUL, escape, bidirectional override, zero-width space); an empty list is an error. The bound on clauses counts entries of the `filter` list: at most 8, and an `any_of` is one entry however many members it has. `jb hunt --search` terms count against the same 8. Separately, a filter holds at most 64 match clauses in all (plain clauses and `any_of` members together), so eight `any_of` of 16 members cannot send a 128-clause query. Nothing else can be written here, deliberately: a case carries this file around, and it is data, not a query language. Every value is a JSON string in the request body and is never spliced into query text.

A filter makes an empty result ordinary (an `any_of` changes nothing about this: the probe is the window alone, with no filter): on a quiet day nothing matches. So that this cannot hide a dead source, a filtered fetch that matched nothing makes one more request, a count of the same window without the filter. If that count is above zero the index is alive and the empty result is clean (`Stats.IndexTotal` holds the count, and `jb hunt` prints it: `no match; index alive`). If it is zero too, the index is silent or the source points at the wrong index, and the fetch fails with `no records` as before. A filter is a prefilter, not a judgement: keep it a superset of what the detector matches (a phrase such as `Chrome/126.0.0.0`) and let the detector apply the exact rule.

#### Two sources on one index

Two sources may read the same index with different filters, for example one for token paths and one for a user agent, if each has its own `name`:

```yaml
sources:
  - {type: kibana, name: device-paths, url: https://kibana.example.com, api_key_env: JB_KIBANA_API_KEY, index: logs-http-*, filter: [...]}
  - {type: kibana, name: curl-clients, url: https://kibana.example.com, api_key_env: JB_KIBANA_API_KEY, index: logs-http-*, filter: [...]}
```

Two sources that report the same name (two without `name` on one index, or an explicit name equal to another's) are an error at load: `sources[0] (kibana) and sources[1] (kibana) both report the name "kibana:logs-http-*"; give one a distinct name`. The names are not relaxed silently: the name is part of the run id, and a duplicate would make the second source replace the first's events.

Overlapping filters can return the same document to both sources. A run counts a document once. Each Kibana event carries the document's concrete index and `_id`; when two or more sources of one run read the same cluster URL, `jb hunt` and `jb activity` keep the first copy of each document and drop the others before they are saved. The drop is shown, not hidden: the source's `Duplicates` count (`duplicates` in the JSON, and `matched (N already returned by another source)` in the outcome column), and `events` counts kept documents only. Which of two overlapping sources keeps a shared document depends on which read it first, so its stored `source` can differ between runs; the number of distinct documents does not. A run with one source per cluster keeps no per-document memory. The same document fetched again by a later run is collapsed by the store as before (same source, time, kind and digest); two differently named sources on one index in different runs are two sources to the store.

#### Ad-hoc search

`jb hunt --search TERM` adds one more clause to every source's filter for a single run, so an analyst can look for an address, a user agent, a username or a path without editing the config:

    jb hunt --case DIR --config config/hunt.yaml --search 198.51.100.7 --window 6h

The term becomes `{"match_phrase": {"<search_field>": "<TERM>"}}` ANDed with the configured filter (and with further `--search` terms). It is a JSON string in the request body and is never spliced into query text. `match_phrase` on an analysed text field matches the tokens in order, not a raw substring. `--search-field` overrides the field for the run; otherwise the source's `search_field`, otherwise `message`.

Rules, checked before any request is made (a violation is a usage error, exit 2, and the error does not echo the term): 1 to 4 terms; each 1 to 256 bytes of valid UTF-8; no control or format character (newline, NUL, escape, bidirectional override, zero-width space); not blank; no leading or trailing whitespace; and the configured filter plus the terms at most 8 clauses. Every source of the config must support a search, or the run is refused rather than searched in part.

A search that matches nothing runs the liveness probe above, so the two zeros differ: `no match; index alive` (the probe counted documents without the term: the term is absent, exit 0) and `index empty or nothing readable` or `unreachable` (the index gave no documents or could not be asked: nothing can be said about the term, exit 1). The count printed is the probe's own answer, never a total minus anything. The detectors read the stored evidence for the window, which includes events saved by earlier runs, so their findings are not about the matches alone.

From Go, set `Search` and `SearchField` in `jb.HuntOptions` (so also `CaseHuntOptions`). The same rules apply and a refusal is a `jb.UsageError` returned before any request is sent. `Result.Search` holds the terms, and `Result.SearchAbsent()` is true for the "term is absent" answer; `Result.Complete()` is false then, because the detectors had nothing to judge, so test `SearchAbsent` first.

#### Past windows

`jb hunt --until TIME` and `jb activity --until TIME` hunt `[TIME - window, TIME)` and the same-length window before it, through the same sources, filters, scopes and detectors. The source gets the past bounds as `gte` and `lt` on the time field and pages by timestamp cursor as for any window; nothing in the request is relative to the present. Put a `filter` on the source before a backfill: without one a day is every document of the index (see [Filter](#filter)). The rules and the day-by-day loop are in [BACKFILL.md](BACKFILL.md). `jb watch` has no `--until`.

#### Mappers

A mapper turns one document's `_source` into an event. All mappers produce the same canonical field names where the data has them, so a detector's `key_field`, `status_field` and `path_field` mean the same thing on any index. The names are matched exactly, so `nginx-ingress` or `NGINX_INGRESS` is rejected.

| Mapper | Reads | Fields it emits |
|---|---|---|
| `default` | any JSON document | The whole `_source`, unchanged. Use it when the index already has top-level fields. |
| `keycloak` | the Keycloak event line in `message`, `key="value", key="value"` | `event_type`, `outcome` (`success` or `error`), `error` when present, `client_ip`, `realm`, `client_id`, and `username` and `email` only when the line has a real one. No HTTP status: a Keycloak event has none. |
| `nginx_ingress` | the nginx access line in `message` | `client_ip`, `method`, `path` (query string removed), `status` (number), `user_agent`, and `referer` when the line has one. |
| `request_dump` | an application request logged as a text dump in `message` (`=== Request Info ===`, then `method = ...`, `path = ...` and one `header = NAME    value = VALUE` line per header). Takes a `mapper_config`. | `method`, `path` (query string removed), `client_ip` (only from the header you name), `user_agent`, and one field per `header_fields` entry. No `status`: the response is another log record. |

`keycloak` notes (the exact input and output contract, the limits and the test corpus are in [WRITING-A-SOURCE.md](WRITING-A-SOURCE.md#mapper-contract)):

- There is no `status`, `method` or `path`, and none is invented. A detector judges a Keycloak event from `outcome` (`error` for any `*_ERROR` type or any event carrying an `error` string) and from `event_type`. Use `fail_values` on `authspike` and `event_field` on `signup`.
- `client_ip` is `ipAddress`, the peer Keycloak saw. The line carries no `X-Forwarded-For` value, so behind a CDN or proxy it is the edge, not the visitor, and many unrelated visitors share one. Do not read a busy edge as an attacker; treat a key on it as a lead, not attribution.
- `username` and `email` are personal data. They are fields so a detector can group on them or read an address domain, and they never appear in a finding: `authspike`, `newkey` and `behaviour` refuse `key_field: username`, `email` or `user_id` unless `hash_keys: true` (one shared list and digest, `internal/piiguard`), and `signup` reports only a listed domain and counts. A failed login for a name that does not exist has no `username` field at all, so keying on it sees only part of the failures; key on `client_ip`.
- `realm` is `realmName`, or `realmId` when the line has no name. `userId` is not read ("null" for an unknown user).
- Keycloak does not escape values, and an attacker chooses the username. The first occurrence of a key wins, so text inside a later value (`", error="none`) cannot override the type, address or error written before it. Keycloak writes its own keys (`type`, `realmId`, `realmName`, `clientId`, `userId`, `sessionId`, `ipAddress`, `error`) before any detail, so the mapper also ignores one of those keys when it appears after the first detail key. Without that rule a username of `x", error="none` on a successful login (which has no `error` of its own) made the event an error, and one carrying `ipAddress` on a line with no address supplied the client address. What stays defended and what does not is in the table below.
- A document that is not a Keycloak line (no `type`, a non-IP `ipAddress`, an unterminated value, a value or line over the size limits) is counted in `Stats.Unparsable` like any unparsable document, and a window where nothing parses is `no records`. A missing or invalid `@timestamp` stops the fetch.
- Fetch the event types you judge with a `filter` (for example `message` phrase `LOGIN_ERROR`); an index also holds client logins and admin events.

Keycloak logging settings and the mapper. The event listener writes `key=value` pairs separated by `, ` in this order: `type`, `realmId`, `realmName` (absent in older versions), `clientId`, `userId`, `sessionId` (when set), `ipAddress`, `error` (when set), then the details (where `username`, `email` and anything else the user typed appear), then `authSessionParentId` and `authSessionTabId`. Corpus cases for each row are in `internal/logmap/keycloak/testdata/corpus` (`variant_*`, `injection_*`, `limit_*`, `trace_*`, `client_login_error_*`).

| Deployment setting | Built-in `keycloak` mapper | What is defended |
|---|---|---|
| Quotes on (the default), sanitising on or off | Parses. Spaces, commas and `, error=none` inside a quoted value are part of the value. | Header keys (see above) cannot be overridden or supplied from a value, in either sanitising setting: `", error="none` and `", ipAddress="198.51.100.99` inside a value are ignored. A quote inside a value that is followed by the end of the line or by `, key="` still ends the value there; the rest is then read as pairs, which is why the header rule matters. |
| Quotes off, sanitising on | Every line is unparsable and counted (`Stats.Unparsable`); no field is taken. The mapper does not guess where an unquoted value ends. Use the `kvlines` plugin (table below). | Not applicable: sanitising removes spaces and quotes, so a value stays one token, but the built-in does not read this form. |
| Quotes off, sanitising off | Every line is unparsable and counted. A space or a comma in a username would make the end of a value a guess. | With `kvlines`, a value ends at the first space or comma and the rest is dropped (`username=Alice Example, Jr` is `Alice`), and an injected `error=none` or `ipAddress=...` on a line that lacks that key is read as a field. Do not run quotes off and sanitising off if you need to trust a detector over it. |

Other settings and event types:

- **Success events may not be logged.** Keycloak writes success events (`LOGIN`, `REGISTER`) at one level (DEBUG by default) and errors at another (WARN by default), so a deployment can log failures and no successes. Over such an index every failure share is 100%. `authspike` in `fail_values` mode then reports `success_events_cur: 0` in the finding `Detail`, appends "no successful events were logged in this window; the failure share is not meaningful" to the summary and lowers the severity one step, instead of dropping the finding, because the comparison against the rest of the population has nothing to compare with. The count is in every finding (`success_events_cur`: judged events that were not failures, over all keys). With HTTP statuses an all-failure window stays an outage and quiet. The note is in the finding only; `jb hunt` does not print a separate line for it. Fix the cause by logging successes (or by not using a rise rule on this index).
- **`realmName` is absent in older versions.** `realm` is then `realmId`. A line with neither has no `realm` field.
- **`CLIENT_LOGIN` and `CLIENT_LOGIN_ERROR` are service-account events, not logins.** They map normally (`event_type` is `CLIENT_LOGIN_ERROR`, `outcome` is `error`) and carry the service account as `username`, but they are not a person failing to log in. `path_contains: LOGIN` on `event_type` matches them too (it is a substring match); to judge people only, filter the fetch or use a `path_field` value that excludes them.
- **TRACE-level lines carry cookies and request URIs** (`cookies`, `requestUri`), which hold session identifiers and one-time codes. The mapper reads only the keys it names, so those are never emitted as fields or kept in an event field, whatever the line holds.
- **Size limits** are exact: a value of 2048 bytes is accepted and 2049 is unparsable; a message of 16384 bytes is accepted and 16385 is unparsable; 64 pairs are accepted and 65 are unparsable; an `error` over 128 bytes is unparsable. A long value is never truncated.

Using `kvlines` instead of the built-in (`mapper: plugin:example.kvlines`, config in `internal/conformance/keycloak_corpus_test.go`, `kvlinesKeycloakConfig`) is the route for a Keycloak with quoting off. It is not the same mapper. The conformance test runs the whole built-in corpus through both and fails on any difference that is not recorded, with its reason, in `internal/conformance/testdata/keycloak/kvlines_differences.json`. The differences, grouped:

| Area | Built-in `keycloak` | `kvlines` |
|---|---|---|
| Duplicate keys | First occurrence wins; the event is kept | The line is unparsable (no winner chosen), so an injected `type`, `ipAddress` or `error` that repeats a header key loses the event |
| Injection of a key the line does not have | Header keys after a detail key are ignored | Not defended: an injected `error=none` on a success event is emitted as `error`; an injected `ipAddress` on a line without one becomes `client_ip` |
| Unquoted values | Unparsable | Parsed; a value ends at a space or the separator, so `Alice Example, Jr` becomes `Alice` |
| Quote inside a quoted value | Ends at a quote followed by the end of the line or `, key="` | Ends at the first unescaped quote; the rest is skipped (`a"b` becomes `a`) |
| `outcome` | Derived: `error` for any `*_ERROR` type or any `error`, else `success` | Not emitted; cannot be derived from the config. A detector over `kvlines` events judges on `event_type` or `error` instead |
| `realm` | `realmName`, else `realmId` | One key only (`realmName` in the test config); no fallback |
| IPv4-mapped IPv6 | Unmapped (`192.0.2.9`) | Kept as written (`::ffff:192.0.2.9`) |
| Event type grammar | Upper case letters, digits and `_` | Any non-empty value |
| Limits | Document 64 KiB, message 16 KiB, value 2048, error 128, 64 pairs | Line 8 KiB by default (16 KiB in the test config), 128 pairs, no per-value or `error` limit, no document limit |
| Newline between pairs | Unparsable | Only space and tab are whitespace: the newline sticks to the next key and that pair is skipped silently (the event loses it) |
| Control character in `error` | Unparsable | Emitted as is |

Where they agree, and the test asserts it: header fields, `username` and `email` placeholders omitted, quoted values with spaces, commas and `, error=none`, `CLIENT_LOGIN_ERROR`, absent `sessionId`, trailing auth session keys, cookies and request URIs never emitted.

`nginx_ingress` notes:

- `client_ip` is the address nginx accepted the connection from, the first field of the line. Behind a CDN or load balancer that is the edge, not the visitor. The ingress log format does not carry `X-Forwarded-For`, so none is read, and the mapper does not guess a client from anything else.
- `status` is the client-facing status after the quoted request. The upstream status, the bytes and the request time that follow are not read, and a path in the quoted referer is never taken for the request path.
- `-`, nginx's empty value, is omitted rather than emitted as the string `"-"`.
- A document whose `message` is missing, is not text, or is not an access line (a JSON blob, a request logged as `"-"`, a first field that is not an IP address) is not an event. It is counted in the source's `Stats.Unparsable`, not dropped silently, and the fetch goes on. If a window has documents and none of them parse, the fetch fails with `no records` and the count, so a wrong mapper cannot look like a quiet window. `hunt` does not print `Stats` yet, so a partly unparsable window is visible to code that reads `Stats()`, not on the command line.

`request_dump` notes (the exact input and output contract, the limits and the test corpus are in [WRITING-A-SOURCE.md](WRITING-A-SOURCE.md#mapper-contract-request_dump)). It is the first built-in mapper that takes a `mapper_config` (data only; an unknown key is a load error, and every other built-in refuses one):

```yaml
mapper: request_dump
mapper_config:
  client_ip_header: x-example-edge-client   # the header your edge sets with the client address; none = no client_ip
  user_agent_header: user-agent             # default user-agent; "none" turns user_agent off
  header_fields:                            # event field -> header: the allowlist of markers to expose
    probe_marker: x-example-probe
```

- **Headers are an allowlist.** Only the user agent, the client-address header and the `header_fields` entries are read; every other header, and everything else in the dump, stays out of the event. A `header_fields` field is present whenever the header is in the request, with its value (an empty value is still present), so a detector can ask "is this header there".
- **A credential header is refused, whatever you configure.** A name containing `auth`, `cookie`, `token`, `secret`, `password`, `passwd`, `session`, `credential`, `bearer`, `jwt`, `csrf`, `xsrf`, `api-key`, `apikey`, `api_key` or `private` is a load error in `client_ip_header`, `user_agent_header` and `header_fields`. The same list redacts what the evidence store keeps: `Raw` is `@timestamp` and the dump with those header values and the query string of the path (one-time codes and reset tokens travel there) replaced by `[redacted]`. The rest of the document (pod metadata, `event.original`, a second copy of the dump) is not retained. This is a deliberate difference from the other mappers, whose `Raw` is the whole document.
- **`client_ip` is the header you name and nothing else.** The dump carries no peer address. If the header is absent, repeated, a list, or not an address, there is no `client_ip` (a repeated one is ambiguous, and picking a copy would let a request choose its own address); the event is then unkeyed for a detector. Name a header your edge sets and overwrites. A header the client can set is not an address.
- `method` and `path` are read only before the first header line, so a header value cannot supply them. A record that is not a request dump (a response record, free text) is unparsable and counted, so put a `filter` on the request banner (`match_phrase` on `=== Request Info ===`) to keep the query to request records.
- `user_agent` over 512 bytes is cut at 512, not dropped, so a long agent does not leave the log; a header value over 1024 bytes, or a marker value over 256, is not carried as a different value.

#### Plugin mappers

`mapper: plugin:<name>` hands each page of documents to an executable the **operator** allowlisted under `<name>`, in `$JB_PLUGINS_FILE` or `~/.jb/plugins.yaml`. The config carries the name only:

```yaml
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: ingress-example
    mapper: plugin:example.regexlines
    mapper_config:                # data for the plugin; see the plugin's README
      pattern: '^(?P<ip>\S+) ...'
      fields:
        client_ip: {from: ip, type: ip, required: true}
```

- `<name>` matches `^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$`. A path, a command line, an unlisted name or a name with upper-case letters is a **load error**; so is `mapper_config` on any other mapper. A source cannot carry `path:`, `command:` or an allowlist (unknown keys fail the strict load).
- One child process per source per run, ended when the run ends or `jb` is interrupted. A plugin that times out, crashes, prints invalid or oversized output, returns the wrong number of results, or fails its file checks fails the source: the hunt is INCOMPLETE and exits 1. Documents the plugin reports unparsable are counted in the source's `Stats.Unparsable`, like a built-in mapper's.
- The plugin's events replace the mapper's; `Raw` is still the whole document, and the detectors see no difference.
- `jb doctor` lists the allowlist with pin and mode checks. There is no sandbox: read [PLUGINS.md](PLUGINS.md) before allowlisting anything. Sample configs: `examples/hunt-plugin-nginx.example.yaml`, `examples/hunt-plugin-eventlog.example.yaml`, `examples/plugins.example.yaml`.

### Switching a source off: `enabled`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` switches the source off. Allowed on every source and on every detector. |

A disabled source is validated at load like any other (a typo in it is still an error), and is then **never built**: its credential variable is not read (it may be unset), no HTTP client exists, nothing is sent. A disabled detector is never built and never runs. This is how one case holds several hunt configs ("profiles") that share most of their text: flip the switch instead of keeping two diverging copies.

The value must be the YAML boolean `true` or `false`. The string `"false"`, `0`, `off` and an empty value are load errors, because a switch that is read as something other than what was written is the failure this key exists to prevent.

Nothing about a disabled thing is silent:

- `jb hunt`, `jb activity` and every `jb watch` cycle say `DISABLED: source standby, detector spike-standby (enabled: false in the config; not read, not run, and not part of any result above)`. `hunt` and `activity` print it on stderr and under the tables (and as `disabled: [{kind, name}]` in `--output json`, a key that is absent when nothing is off); `watch` prints it on the banner and puts it on **every** `CYCLE` line in `watch.log`, so a quiet cycle reads `every enabled source and detector completed ... DISABLED: ...`. `activity`'s verdict line says the verdict is about the enabled components only.
- A disabled component has no row and no status in any table, so it can never read as `ok` or `quiet`.
- `jb doctor` lists each as `SKIPPED  source standby  DISABLED: ...`, shows the service as `DISABLED`, and does not require its credential. `jb case check` reports them as `note: DISABLED: ...` and does **not** fail on them.

Rules, checked at load:

- A detector that is enabled and whose `sources:` names a disabled source is an error naming both (`detectors[1] (signup, "kc-signup"): sources: "kc" is disabled (sources[1] has enabled: false)`): it would read nothing from it and report an ordinary empty window. A detector that is itself disabled may keep its scope, so a profile can be switched as a unit.
- `empty_is_quiet` only considers enabled sources: an unfiltered source that is switched off cannot veto it, and one that is on still does.
- A config where every source is disabled, or every detector is disabled, is an error (`nothing to run`).
- Two sources still may not report the same name, enabled or not; the same holds for the stored source column.
- `--search` is applied to the enabled sources only.

Example: an attack profile and a health profile of one case. `case.yaml` lists both configs. Neither declares `commands`, so every command asks for `--config`; add `commands: [watch]` to one of them and `jb watch` no longer needs it:

```yaml
# config/attack.yaml: the hunt for the actor, on the ingress and Keycloak logs
sources:
  - {type: kibana, name: ingress, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: 'ingress-*', mapper: nginx_ingress, filter: [{match_phrase: {field: message, value: /auth/login}}]}
  - {type: kibana, name: platform-health, enabled: false, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: 'platform-*'}
detectors:
  - {type: authspike, name: login-spray, sources: [ingress], empty_is_quiet: true, key_field: client_ip, status_field: status, path_field: path, path_contains: /auth/login}
  - {type: authspike, name: platform-5xx, enabled: false, sources: [platform-health], key_field: client_ip, status_field: status, fail_statuses: [500, 502, 503]}
```

```yaml
# config/health.yaml: the same two sources and detectors with the switches the other way round
sources:
  - {type: kibana, name: ingress, enabled: false, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: 'ingress-*', mapper: nginx_ingress, filter: [{match_phrase: {field: message, value: /auth/login}}]}
  - {type: kibana, name: platform-health, url: 'https://kibana.example.com', api_key_env: JB_KIBANA_API_KEY, index: 'platform-*'}
detectors:
  - {type: authspike, name: login-spray, enabled: false, sources: [ingress], empty_is_quiet: true, key_field: client_ip, status_field: status, path_field: path, path_contains: /auth/login}
  - {type: authspike, name: platform-5xx, sources: [platform-health], key_field: client_ip, status_field: status, fail_statuses: [500, 502, 503]}
```

Run them side by side, one watcher each ([Several watchers on one case](#several-watchers-on-one-case)):

    jb watch --case . --config config/attack.yaml --name attack --every 5m
    jb watch --case . --config config/health.yaml --name health --every 15m

## Detectors

Every detector type takes two options that mean the same thing on all of them: `sources` (below) and, on `authspike`, `signup`, `newkey`, `signature`, `behaviour` and `fingerprint`, `empty_is_quiet`.

### Reading some sources only: `sources`

| Key | Default | Meaning |
|---|---|---|
| `sources` | all sources | The names of the sources this detector reads: the `name` of a source, else its default `kibana:<index>`. A list of one or more distinct names. |

Without `sources`, a detector reads the events of every source of the config, as before. That is wrong as soon as two sources hold different logs: a Keycloak detector handed nginx access lines counts them as unparsable or off-path, and a detector that counts events can mix the two logs into one number. `sources` restricts the detector to the events of the named sources, in the current window and in the preceding one alike, so the baseline is made of the same logs as the window.

Rules, checked at load: an unknown name is an error that names the detector and the name (`detectors[1] (signup): sources: unknown source "kc" (defined: ingress, keycloak)`); an empty list, a list with a repeat and a value that is not a list are errors; a misspelt key (`source:`) is an unknown key like any other. Nothing is dropped silently.

How it works: `jb hunt`, `jb watch` and `jb activity` store every source's events under the source's name and hand a scoped detector only the stored events whose source is one of its names (`app.Deps.Scopes`, built from the config). The name is stamped by the hunt on every event a source returns, whatever label a mapper put on it. A scoped detector whose sources produced nothing it can read still follows the zero-record rules: `no records`, unless `empty_is_quiet` applies. Two overlapping sources can return the same document; a run keeps the first copy (see [Two sources on one index](#two-sources-on-one-index)), so a document read by both is attributed to whichever read it first, and a detector scoped to the other source does not see it.

### Quiet hours: `empty_is_quiet`

A detector that finds nothing to judge in the current window returns `no records`, which makes the hunt `INCOMPLETE`. That is right for a source that may be broken. It is wrong for a source narrowed by a `filter` to something that legitimately does not happen every hour, such as account creations: every quiet hour would be reported as a failure.

`empty_is_quiet: true` makes "nothing to judge" a quiet, clean answer. It is only sound because a filtered source proves its index alive: when the filter matches nothing, the source counts the same window without the filter, and `jb hunt` shows `no match; index alive`; if that count is zero or fails, the source itself fails the hunt, whatever the detector says. So Parse accepts the option only when **every source the detector reads** (its `sources`, else all of them) is a kibana source with a `filter`, and refuses it otherwise naming the source.

It does not weaken the other rules:

- Events that exist but cannot be read are still `no records`. Per detector: `authspike` an on-path event whose status is not a status; `signup` an on-path event with no readable status or method, or no event type; `newkey` events with no usable key; `signature` events whose field is not text (all of them); `behaviour` events with no path. A window of garbage is a blind detector.
- A source that fails or is unreachable still fails the hunt.
- A window with something to judge is judged exactly as before. The preceding window is still read, and an empty one still lowers the severity (`baseline_empty`).
- Without the option, nothing changes.

### Example: two sources, each read by its own detectors

An ingress index and a Keycloak index. The Keycloak detector must not see nginx lines, and an hour in which nobody registers must not fail the hunt.

```yaml
sources:
  - type: kibana
    name: ingress
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: ingress-example-*
    mapper: nginx_ingress
    filter:
      - match_phrase: {field: message, value: /auth/login}
  - type: kibana
    name: keycloak
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: keycloak-example-*
    mapper: keycloak
    filter:
      - match_phrase: {field: message, value: REGISTER}   # also matches REGISTER_ERROR
detectors:
  - type: authspike
    name: ingress-stuffing
    sources: [ingress]
    empty_is_quiet: true
    key_field: client_ip
    status_field: status
    path_field: path
    path_contains: /auth/login
  - type: signup
    name: kc-signup
    sources: [keycloak]
    empty_is_quiet: true
    event_field: event_type
    create_values: [REGISTER]
    attempt_values: [REGISTER_ERROR]
    min_attempts: 20
```

In an hour with logins but no registration the `keycloak` source shows `no match; index alive`, `kc-signup` is quiet, and the hunt is complete. In an hour with 40 `REGISTER_ERROR` events against 1 before, `kc-signup:attempts` is raised, counted from Keycloak events only.

### Example: gateway and signature over an application request log

One index of application request dumps. `gateway` flags an address with no event in the preceding window that sends scripted requests to the endpoints you list; `signature` flags a request carrying a marker header. Every name here is made up.

```yaml
sources:
  - type: kibana
    name: app
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: app-example-*
    mapper: request_dump
    mapper_config:
      client_ip_header: x-example-edge-client
      header_fields:
        probe_marker: x-example-probe
    filter:
      - match_phrase: {field: message, value: "=== Request Info ==="}
detectors:
  - type: newkey
    name: gateway
    sources: [app]
    empty_is_quiet: true
    key_field: client_ip
    path_field: path
    sensitive_paths: [/v1/example/verify, /v1/example/token]
    min_hits: 3
    user_agent_field: user_agent
    user_agent_matches: ["curl/*", "python-requests/*"]
  - type: signature
    name: signature
    sources: [app]
    empty_is_quiet: true
    field: probe_marker
    present: true
    key_field: client_ip
    path_field: path
```

A new address that sends four `curl/8.4.0` requests to `/v1/example/verify` raises `gateway:198.51.100.7`; a request with an `X-Example-Probe` header raises `signature:probe_marker`, whatever its agent. Neither finding carries a header value, a cookie or a query string.

### `type: authspike`

Flags a key whose share of failed requests rose against the preceding window of the same length. Event fields are looked up as top-level keys of the event's fields (no dotted-path traversal).

| Key | Default | Meaning |
|---|---|---|
| `name` | `authspike` | Detector name; part of every tag. Names must be unique in one config. |
| `key_field` | required | Field that groups events, for example a client address. |
| `status_field` | required | Field holding the HTTP status, or, with `fail_values`, a text outcome such as `outcome`. With statuses: a number or a numeric string, 100 to 599; anything else counts as unparsable. With `fail_values`: a missing or non-text value counts as unparsable, never as a success. |
| `fail_statuses` | `[401, 403]` | Statuses counted as failures. Each must be 100 to 599. Exclusive with `fail_values`. |
| `fail_values` | none | Text values of `status_field` counted as failures, matched exactly and case-sensitively. For a log with no HTTP status, such as Keycloak: `status_field: outcome`, `fail_values: [error]`. Setting both this and `fail_statuses` is an error; setting neither means `fail_statuses: [401, 403]`. |
| `hash_keys` | `false` | Replace each key in the tag, summary and detail with `h:` and 12 hex digits of its SHA-256, stable across runs so dedupe still works. Required when `key_field` is `username`, `email` or `user_id`: such a key is personal data and may not appear in a finding. The digest is unsalted and not secret (a guessable name can be confirmed by hashing it), only absent from the text. `ignore_keys` still takes the plain value. |
| `path_field` | empty | Field holding the request path, or any field to scope the count (for Keycloak, `event_type` with `path_contains: LOGIN`). |
| `path_contains` | empty | Only events whose path contains this are counted. Requires `path_field`. |
| `min_events` | `20` | A key needs this many parsable events in the current window to be judged. Negative is an error. |
| `min_failure_share_rise` | `0.20` | Absolute rise in failure share (0.20 is 20 percentage points) needed to raise a finding. Range 0 to 1; `0` takes the default. |
| `ignore_keys` | none | Keys that are never suspects. |
| `sustained_min_share` | `0.5` | Failure share a key must hold to be reported as a continuing spray. Range 0 to 1; `0` takes the default. |
| `disable_sustained` | `false` | Turns the continuing-spray finding off. |
| `empty_is_quiet` | `false` | A current window with no event on the counted path is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (a status that is not a status or a failure value) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |

A key with a rising failure share gets a finding tagged `<name>:<key>` at severity `high` (one step lower, `activity`, when there is no preceding data at all). A key that is not raised that way but keeps failing at or above `sustained_min_share`, and exceeds the whole population by at least `min_failure_share_rise`, gets a finding tagged `<name>:<key>:sustained` at severity `activity`. One key produces at most one finding per run; the rising one wins. If every key is failing alike, no finding is raised: that is an outage, not a spray.

### `type: signup`

Flags a window in which an unusual number of accounts were created: at least `min_creations`, and at least `factor` times the creations of the preceding window of the same length. It counts the request that creates the account, never the form that precedes it. Event fields are top-level keys of the event's fields.

| Key | Default | Meaning |
|---|---|---|
| `name` | `signup` | Detector name; part of every tag. Lower case, `^[a-z][a-z0-9_-]{0,31}$`. |
| `create_paths` | required in path mode | Paths of the endpoint that creates the account. Each starts with `/`. Matched against the whole path, not as a substring, with the query string and one trailing slash ignored: `/signup` does not match `/signup/form`. |
| `path_field` | required | Field holding the request path. |
| `status_field` | required | Field holding the HTTP status (number or numeric string, 100 to 599; anything else is unparsable). |
| `event_field` | empty | Event-type mode, for a log with no path or status (Keycloak): the field holding the event type, normally `event_type`. Goes with `create_values`, and replaces `create_paths`, `path_field`, `status_field`, `success_statuses`, `method_field` and `methods`, which are then refused rather than ignored. |
| `create_values` | none | Event-type mode: the values that mean an account was created, for Keycloak `[REGISTER]`. Matched exactly. |
| `attempt_values` | none | Event-type mode: values that are attempts which did not create an account, for Keycloak `[REGISTER_ERROR]`. They count toward `attempts_*` in `Detail` and never toward creations. A value in neither list is not an event for this detector. A missing or non-text value is unparsable. |
| `success_statuses` | `[200, 201, 202, 204, 302, 303]` | Statuses that mean an account was created. Other statuses on the creating path are attempts. If a failed attempt also answers with one of these on your system (a form re-rendered with an error is often a 200), narrow the list to the status only success returns. |
| `method_field` | empty | Field holding the HTTP method. Set it when the form render (a GET) shares the creating path: without it that GET cannot be told apart and counts as a creation. |
| `methods` | `[POST]` when `method_field` is set | Methods that create an account, compared case-insensitively. Requires `method_field`. |
| `min_creations` | `5` | The fewest creations that can be a burst. Negative is an error. |
| `factor` | `3` | Multiple of the preceding window's creations a burst must reach (inclusive). Must be greater than 1; `0` takes the default. |
| `min_attempts` | `0` (off) | Turns on the failed-attempt rule below. The fewest failed attempts in the window that can be a spray. `0` leaves the rule off, so an existing config is unchanged. Negative is an error. |
| `attempt_factor` | `3` | Multiple of the preceding window's failed attempts the spray must reach (inclusive). Must be greater than 1; `0` takes the default. Refused while `min_attempts` is `0`. |
| `address_field` | empty | Field holding the new account's address. Goes with `disposable_domains`. |
| `disposable_domains` | none | Domains to flag. There is no built-in list: nothing is flagged unless you list it. An address matches when its domain equals a listed one or is a subdomain of it, never as a substring. |
| `empty_is_quiet` | `false` | A current window with no attempt to create an account is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (an on-path event with no readable status or method, or in event-type mode an event with no type) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |

In event-type mode the rule is the same: `REGISTER` is the event that creates the account and is counted; `REGISTER_ERROR` is an attempt. A burst of failed registrations is visible as `attempts_cur` against `creations_cur`, not counted as accounts. A current window with no `create_values` or `attempt_values` event is `no records`.

**Failed-attempt spray** (`min_attempts` above 0). A failed attempt is a parsable event on the creating path that did not create an account: `attempt_values` in event-type mode, a status outside `success_statuses` in path mode (a form render excluded by `methods` is not one). The creation rule above cannot see a spray of failed signups, which is many attempts and few creations. The rule raises when the window's failed attempts reach `min_attempts` AND are at least `attempt_factor` times those of the preceding window; both are required, a raw count alone is never a finding. The finding is tagged `<name>:attempts` at severity `activity` (`check` when the preceding window holds no signup event at all, with `baseline_empty` true, as for creations) and its summary states the failed attempts, the creations and the failure share, failed/(failed + creations), all counted from the events read. `Detail` carries `failed_attempts_cur` and `failed_attempts_prev`, `creations_cur` and `creations_prev`, `failure_share_cur` (and `failure_share_prev`, counted over all of the preceding window's attempts, when it had any), `min_attempts` and `attempt_factor`. Note that `attempts_cur` and `attempts_prev` stay the totals of both outcomes. It runs beside the creation rule; one window can raise both findings. A current window with no signup event is still `no records`. Example: 8 failed attempts and 5 creations in 10 hours raise nothing with `min_attempts: 10`; 30 failed attempts and 2 creations against 5 failed attempts before raise `<name>:attempts`.

A burst gets one finding tagged `<name>` at severity `activity`. When the preceding window holds no parsable event on the creating path there is nothing to compare: the finding is raised on `min_creations` alone, `baseline_empty` is true in `Detail`, and the severity is `check`. A current window with no parsable event on the creating path is `no records`, not a clean result; a window with attempts but no creations is an answer, not an error. For each listed domain with at least one creation in the window there is a finding tagged `<name>:disposable:<domain>` at severity `check` (`info` when the baseline is empty). `Detail` carries `creations_cur`, `attempts_cur` and the `_prev` counts, the number of events excluded because their method is not in `methods` (`excluded_method_cur`, `excluded_method_prev`), and for a disposable finding the listed domain and its counts. An address never appears in a finding.

### `type: newkey`

Flags a key that appears in the current window with no event at all in the preceding window of the same length, and makes at least `min_hits` requests to the sensitive paths you list. The key is whatever `key_field` names, usually a client address. A CDN or load-balancer edge address is not a client: one edge carries many unrelated visitors, so a "new" or "busy" edge says nothing about a visitor. Key on a field that identifies the client and list your own infrastructure in `ignore_keys`.

| Key | Default | Meaning |
|---|---|---|
| `name` | `newkey` | Detector name; part of every tag. Lower case, `^[a-z][a-z0-9_-]{0,31}$`. |
| `key_field` | required | Field that groups events. |
| `path_field` | required | Field holding the request path. |
| `sensitive_paths` | required | Path fragments worth waking up for. An event is a sensitive hit when its path contains one of them (case-insensitive substring). At least one; no blank entry. |
| `min_hits` | `3` | Sensitive hits a new key needs in the current window. Negative is an error. |
| `ignore_keys` | none | Keys that are never suspects and never count as history. They take the plain value even with `hash_keys`. |
| `hash_keys` | `false` | Show each key in the tag, summary and detail as `h:` and 12 hex digits of its SHA-256 (stable across runs, so dedupe still works). Required when `key_field` is `username`, `user_name`, `email`, `user_email`, `user_id` or `userid`: such a key is personal data and the config is refused at load without it. The digest is unsalted and not secret: a guessable name or address can be confirmed by hashing it. It keeps the value out of the text of a finding; it does not anonymise the key. |
| `user_agent_field` | none | Event field holding the user agent. Goes with `user_agent_matches`; one without the other is a load error. |
| `user_agent_matches` | none | Scripted-client filter. With it, a sensitive request counts toward `min_hits` only when the event's `user_agent_field` matches one of these patterns. A pattern matches the **whole** value, ignoring case, and `*` is the only wildcard (`curl/*` matches `curl/8.4.0`; `mycurl/1` and `Mozilla/5.0 curl/8.4.0` do not). It is never a substring test. At most 32 entries of 128 bytes; a blank entry or one made only of `*` (it would match everything) is refused; every other character is literal; a user agent over 1024 bytes or a missing one does not match. You write the list: nothing is built in. |
| `empty_is_quiet` | `false` | A current window with no event, or only ignored keys is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (events with no usable key) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |

| `min_severity` | none | A floor, not an override: the severity becomes the greater of the computed one and this one, applied after the empty-baseline drop. `high` or `critical`; `info`, `check`, `activity` and any unknown name are refused at load. `Detail["min_severity"]` appears only when the floor raised the result. The tag does not change, so `watch` alerts again on the raised severity. Shared with `behaviour` (`internal/severityfloor`). |
| `note` | none | Text carried in the finding as `Detail["note"]`. Required with `min_severity: critical`; an error without `min_severity`. |

A finding is tagged `<name>:<key>` at severity `high`. A key with any event on any path in the preceding window is known and is never raised, and ordinary-path traffic from a new key does not count toward `min_hits`. A current window with no event carrying a usable key is `no records`. When the preceding window holds no keyed event at all, every key is new and that is a missing baseline: the finding is still raised, `baseline_empty` is true in `Detail` and the severity is `activity`. `Detail` carries the key's events and sensitive hits, which configured entries were hit and how often (`sensitive_paths_hit`), and the population counts of both windows. Only the preceding window is read as history; a longer memory is a longer window.

**Scripted clients from addresses with no history** (the gateway rule). Point `newkey` at a source mapped by `request_dump`, key on `client_ip`, list the attack-shaped endpoints in `sensitive_paths`, and add `user_agent_field: user_agent` with `user_agent_matches: ["curl/*", "python-requests/*"]`. The finding then means: this address has no event of any kind in the preceding window and made at least `min_hits` requests to those endpoints with an agent that announces itself as a script. The user agent is chosen by the client, so the filter narrows the lead and does not define the attacker: a script that sends a browser agent is not matched, and a browser agent from a new address is never raised by this rule (nor is volume). With the filter on, `Detail` adds `user_agent_filter: true` and `key_cur_sensitive_any_agent`, the key's sensitive requests of any agent, so a reader sees what the filter set aside; `key_cur_sensitive_hits` and `sensitive_paths_hit` count the matching requests only. A finding never repeats the agent string. Keep `key_field` on an address the edge asserts, not on the edge itself.

### `type: signature`

Flags a marker no legitimate client sets: a header (or any other event field) a test harness adds to its own requests. It raises on first sight; there is no baseline to compare, because the marker should never exist.

**A hit shows that someone sent the marker, not who.** A header is text the sender chose, and anyone who has seen the marker (in a report, a ticket, a screenshot) can send it to frame someone or to find out whether you watch for it. Read a finding as "this marker was seen from these keys", and look for other evidence before it names anyone. Behind a CDN the keys may be edge addresses.

| Key | Default | Meaning |
|---|---|---|
| `name` | `signature` | Detector name. Lower case, `^[a-z][a-z0-9_-]{0,31}$`. |
| `field` | required | Event field holding the marker. For a request header, the field `request_dump` fills from `header_fields`. Parse refuses a `field` that a `request_dump` source it reads cannot emit, because a detector on a field nothing fills would stay quiet whatever the log holds; a source with another mapper is not second-guessed. |
| `present` | `false` | A hit is any event that has the field (an empty value counts). Exactly one of `present: true` and `equals` is required. |
| `equals` | none | A hit is an event whose field is exactly one of these values (case-sensitive, 1 to 128 characters on one line, at most 32). One finding per matched value. |
| `key_field` | required | Field that says who sent the request, normally `client_ip`. `username`, `email` and `user_id` need `hash_keys: true` (the digest is unsalted; see `newkey`). |
| `path_field` | none | With it a finding counts the distinct paths hit (`distinct_paths`). The paths themselves are not printed. |
| `ignore_keys` | none | Keys that never count, such as your own test machine. Counted in `ignored_events`. |
| `hash_keys` | `false` | Show keys as `h:` and 12 hex digits of their SHA-256. |
| `empty_is_quiet` | `false` | A current window with no event is a quiet answer and not `no records`. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](#quiet-hours-empty_is_quiet). Events that exist but whose `field` is not text are unreadable; if all are, the answer is still `no records`. |

A window with events and no marker is quiet: that is the normal state. A window with no event at all is `no records`, because a silent log is a blind detector, not proof nobody sent the marker.

A finding is tagged `<name>:<field>` (`present`) or `<name>:<field>=<value>` (`equals`; the value is the one you configured) at severity `high`. Nothing else is in the tag, so one ongoing condition dedupes across runs. `Detail` carries `events`, `distinct_keys`, `keys` (at most 10, with `keys_truncated`), `unkeyed_events` (marker seen, no usable key), `ignored_events`, `events_in_window`, `unreadable_events`, `first` and `last` (event times, UTC), `mode`, and `sent_not_proven`. In `present` mode it also carries `distinct_values` and `value_hashes` (at most 5, `h:` and 12 hex digits of the SHA-256 of each value): a header value is never printed. In `equals` mode `expected_value` is the configured value. Every number was counted from the events read.

### `type: behaviour`

Flags what clients DO, not what they call themselves. A user-agent string is chosen by the client and rotates freely; the path, method and status are what was asked of the platform. You list named actions, each a matcher plus a class, and every action is compared with the preceding window of the same length. Event fields are top-level keys of the event's fields.

| Key | Default | Meaning |
|---|---|---|
| `name` | `behaviour` | Detector name; part of every tag. Lower case, `^[a-z][a-z0-9_-]{0,31}$`. |
| `key_field` | required | Field that groups events (who took part). A CDN or load-balancer edge address is not a client: key on a field that identifies one. |
| `hash_keys` | `false` | The only place a key is shown is `sole_key` in a rare action's `Detail`; with `hash_keys` it is `h:` and 12 hex digits of its SHA-256, stable across runs. Required when `key_field` is `username`, `user_name`, `email`, `user_email`, `user_id` or `userid`; the config is refused at load without it. The digest is unsalted and not secret: a guessable name or address can be confirmed by hashing it. `ignore_keys` takes the plain value. |
| `path_field` | required | Field holding the request path. An event without one is unparsable and not judged. |
| `method_field` | empty | Field holding the HTTP method. Required by any action with `methods`. |
| `status_field` | empty | Field holding the HTTP status (number or numeric string, 100 to 599). Required by any action with `statuses` and by every `common` action. |
| `fail_statuses` | `[401, 403]` | Statuses that count as failures for `common` actions. Each 100 to 599. An action can override it. |
| `user_agent_field` | empty | Read only to apply `ignore_user_agents`. It never matches an action. |
| `ignore_keys` | none | Keys that are never suspects: your own gateways and scanners. Preferred way to exclude infrastructure. |
| `ignore_user_agents` | none | Events whose user agent contains one of these (case-insensitive substring) are ignored. Needs `user_agent_field`. Accepted trade-off: a client can forge a user agent to hide, so prefer `ignore_keys`; the count is reported (`ignored_ua_cur`). |
| `min_failure_share_rise` | `0.20` | Absolute rise in failure share (0.20 is 20 percentage points) needed to raise a `common` action. Range 0 to 1; `0` takes the default. |
| `max_keys` | `10000` | Distinct keys remembered per action in the current window. See the memory bound below. |
| `empty_is_quiet` | `false` | A current window with nothing to judge (no event, or only ignored ones) is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (events with no path) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |
| `actions` | required | One to 64 actions. |

Each action:

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Unique, `^[a-z][a-z0-9_-]{0,31}$`. Part of the tag. |
| `class` | required | `rare` or `common`. |
| `path` or `path_pattern` | one required | `path` is compared whole (it must start with `/`). `path_pattern` is an RE2 expression wrapped in `^(?:...)$`. Both look at the event path with the query string, fragment and one trailing slash removed, case-sensitively: `/signup` does not match `/signup/form`, `/SIGNUP` or `/v2/signup`. |
| `methods` | any | Methods, compared case-insensitively and whole. Needs `method_field`. |
| `statuses` | any | Only events with one of these statuses match (a creation is a 201, a failed attempt is not). Needs `status_field`. An event whose status cannot be read is not matched and is counted in `unparsable_cur`. |
| `fields` | none | `name: value` equalities on other event fields, whole-value, exact. |
| `field_patterns` | none | `name: pattern`, anchored as `path_pattern`. A field may not be in both. |
| `min_events` | `1` rare, `20` common | Events needed in the current window before the action is judged. Negative is an error. |
| `fail_statuses` | detector's | `common` only. |
| `min_events_per_key` | `0` (off) | `rare` only. The action fires only when at least one key (`key_field`) has this many matching events in the current window. Both conditions hold together: `cur_events >= min_events` and some key `>= min_events_per_key`. Negative is an error. See the truncation rule below. |
| `min_severity` | none | `rare` only. A floor, not an override: the severity becomes the greater of the computed one and this one. One of `activity`, `high`, `critical`; `info` and `check` are refused because they can never raise a rare finding. |
| `note` | none | `rare` only. Text carried in the finding as `Detail["note"]`. Required with `min_severity: critical`. |

There is no unanchored substring matching of an action anywhere. An event is judged against every action independently, so overlapping matchers count the same request twice.

**`rare`**: the platform's own baseline is near zero (a device-code request, an account creation). Any occurrence at or above `min_events` in the current window is a finding tagged `<name>:<action>` at severity `activity`, `check` when the preceding window holds no judged event at all. The summary and `Detail` give the current and preceding counts (`cur_events`, `prev_events`), whether it is new (`new`), and how many distinct keys took part (`keys_cur`, with `unkeyed_cur` events that carried none, and `sole_key` when there is exactly one). One key and many keys mean different things; a single edge address relaying many visitors is why the key field must identify a client.

**`common`**: a large legitimate baseline (a token endpoint carries service traffic all day). A raw count is never a finding. The action's failure share (`cur_failures/cur_events`) must rise by at least `min_failure_share_rise` over the preceding window's, with at least `min_events` events: tag `<name>:<action>`, severity `high`. If the action has no events at all in the preceding window there is nothing to compare, no rise is invented, and it is raised only when it fails at least half the time, one severity step lower (`activity`), `baseline_source` is `none`. `Detail` carries `failing_keys_cur`, the distinct keys behind the failures: failures from one key look like a spray, from many like an outage. This is an action-level rule, not per key; `authspike` is the per-key detector.

**Floor and per-key threshold (`rare` only).** `min_severity` is applied after the empty-baseline drop, so `baseline_empty` still shows in `Detail`, and `Detail["min_severity"]` appears only when the floor raised the result. The tag does not change, so the watch dedupe (`internal/app/watch.go`) treats a raised severity under the same tag as an escalation and alerts again, while a lower one stays held back. With `min_events_per_key` the finding adds `hot_key` (the key with most events, hashed like `sole_key` under `hash_keys`), `hot_key_events` and `min_events_per_key`, beside `keys_cur`. Truncation rule: if keys were dropped at `max_keys` (`keys_truncated`) and no stored key reached `min_events_per_key`, the action cannot be judged. `Detect` and `Activity` then return an error that names the action and says to raise `max_keys`. The hunt records the detector as `error`, so the run is incomplete, but it keeps the findings of the other actions (RFC 0012): they are listed, stored and alerted. `activity` reports `ACTIVE` with an incomplete note when another action fired and `INCOMPLETE` when none did, and `watch` raises an incomplete alert beside the finding alerts. It is never a quiet result. If a stored key did reach the threshold, the action fires normally.

```yaml
- type: behaviour
  key_field: client_ip
  path_field: path
  method_field: method
  status_field: status
  actions:
    - name: admin-console-login
      class: rare
      path: /admin/login
      methods: [POST]
      min_events_per_key: 3          # one client, three attempts
      min_severity: critical         # never below critical
      note: the admin console is not reachable from outside the office network
```

Windows. A current window with no judged event (one with a path that is not ignored) is `no records`, never a clean result; an all-ignored window is `no records` too. A preceding window with no judged event sets `baseline_empty` in `Detail` and lowers every severity one step. A preceding window that fails to read is an error. Every number in a finding was counted from the events read.

Memory is bounded: per action a few integer counters, plus at most `max_keys` distinct key strings for the current window only (the preceding window keeps counters, no keys). Past the bound further new keys are not stored, `keys_truncated` is true and the summary says "at least N". Counts of events stay exact. Total state is `O(actions * max_keys)`, independent of event volume.

### `type: fingerprint`

Flags events that match an actor described in a case's actor files ([CASE-SPEC](CASE-SPEC.md) section 4.4). The indicators are case data, not config: this detector only says which files to read. It runs inside a case (`jb hunt --case DIR`); without a case it fails to build with an error that says so. [`examples/case/config/fingerprint.yaml`](../examples/case/config/fingerprint.yaml) is a working example.

| Key | Default | Meaning |
|---|---|---|
| `name` | `fingerprint` | Detector name; part of every tag. Lower case, `^[a-z][a-z0-9_-]{0,31}$`. |
| `actors` | required | Actor file names, relative to the case's actors directory (`paths.actors`). Each ends in `.yaml` or `.yml`, may not use `..`, and may not leave that directory by a symlink. At least one; no repeats. |
| `ignore_ips` | none | Addresses or CIDRs of our own infrastructure (a gateway, a scanner pool). A matching event relayed by one of them is counted as ignored and is never a suspect. Do not list a CDN edge here: an edge is not a client, and no address is ever used to match an actor. |
| `empty_is_quiet` | `false` | A current window with no event for the detector is a quiet answer and not `no records`. Accepted only when every source the detector reads (`sources`, else all of them) is a kibana source with a `filter`: the filter plus the liveness count above is what separates "the actor was not seen" from "the source is broken". See [Quiet hours](#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. Without it, an empty window stays `no records`. |

Event fields are read from the event's top-level fields, by these canonical names:

| Field | Needed | Meaning |
|---|---|---|
| `user_agent` | yes | Non-empty string. |
| `path` | yes | Non-empty string; the request path, with or without a query string. |
| `status` | yes | HTTP status, 100 to 599, as a number or a numeric string. |
| `client_ip` | no | Only used to skip `ignore_ips`. Never used to match, never printed in a finding. |
| `method` | no | Not read. |

An event without a parsable `user_agent`, `path`, `status` or a time is unparsable. A current window with no parsable event at all is `no_records`, never a clean result.

How an event is judged, per actor. Each rule came from a real false result:

1. **Match.** The event's `user_agent` must equal one of the actor's `user_agent` indicators, as a whole string. A prefix or a substring does not match: a substring of a stale browser build also matches real customers and has invented successful grants. Other indicator kinds (`ip`, `asn`, `domain`, `fingerprint`) are the case's record; this detector matches on none of them.
2. **Ignored.** A match whose `client_ip` is in `ignore_ips` is counted as ignored.
3. **Noise.** A user agent alone is not a fingerprint: commodity scanners reuse it. A match is noise, counted as filtered and never as a hit, when its path contains one of the actor's `detection.noise_paths` (case-insensitive substring), or, with `detection.bare_root_4xx_is_noise` (default true), when its path is `/` and its status is 4xx. The path is judged without its query string, so `/?x=1` is still `/`.
4. **Genuine.** Every other match is genuine activity.

Findings, per actor, tagged `<name>:<actor id>`:

| Condition | Severity |
|---|---|
| Genuine events in the window | `activity`, or `check` when the preceding window holds no parsable event at all (nothing to compare with; `baseline_empty` is true in `Detail`) |
| No genuine event in the window, but genuine events in the preceding window, or matching events that were filtered or ignored | `info`. The summary says "no genuine activity in window". |
| Nothing matched in either window | no finding |

`Detail` carries `cur_genuine`, `cur_filtered`, `cur_ignored` and the `prev_` counts, so the comparison with the same-length preceding window can be checked, and `last_genuine`, the time of the latest genuine event. When the current window has none, `last_genuine` is taken from the preceding window and `last_genuine_in` says `preceding window`; when neither has one, `last_genuine` is absent and `last_genuine_in` is `neither window`. A trailing scanner probe never moves it.

The tripwire: a 2xx status on a path containing one of the actor's `detection.grant_paths` (case-insensitive substring, query string ignored), for a genuine event, raises a second finding tagged `<name>:<actor id>:grant` at severity `critical`, even when the baseline is empty. It means the actor holds a credential, and the incident changes category. A grant path that contains a noise marker is refused when the detector is built, because noise is judged first and the tripwire could never fire.

## Reputation lookups

`jb intel` asks the reputation feeds you list what they know about addresses and appends the answers to the `reputation` table. It is a separate command from `hunt`: a hunt never reads a feed or a feed key. Three feed types exist: `greynoise` and `sans-isc` (HTTP APIs) and `dnsbl` (a DNS blocklist, asked through a resolver). List as many as you like; two feeds may not report the same name (two `dnsbl` entries need different zones), because the `source` column must say who answered.

```yaml
feeds:
  - type: greynoise
    # base_url: https://api.greynoise.io
    api_key_env: JB_GREYNOISE_API_KEY   # optional; the name of a variable, never the key
    max_lookups: 10
    min_interval: 1s
    timeout: 10s
    max_response_bytes: 65536
  - type: sans-isc            # no key; see below
  - type: dnsbl               # off until enabled: true; see below
    zone: bl.example.org
    enabled: true
intel:
  ip_fields: [client_ip]
  max_indicators: 10
```

```
jb intel --case DIR                 # addresses from the latest stored hunt
jb intel --case DIR 192.0.2.7 ...   # addresses given on the command line
jb intel --config FILE [--output table|json] [IP ...]
```

With no address arguments, `jb intel` reads the distinct values of the `intel.ip_fields` event fields in the latest stored hunt (every source of that hunt), most frequent first, and ignores values that are not IP addresses (it counts them). Run `jb hunt` first. With an empty store, or a hunt with no address in those fields, it exits 1: an empty list would read as "nothing to look up".

**Several feeds in one run.** Every address is asked of every enabled feed, and each address x feed pair is its own answer, stored with the feed's name in `source`. One feed failing makes the run `INCOMPLETE` and exits 1, but the other feeds' answers are kept and stored. A feed that is listed but not enabled is named on stderr and not asked. If no listed feed is enabled, `jb intel` refuses.

### How to read the result

**A reputation snapshot is context, not attribution.** It says how a third-party sensor network saw an address at that time. It does not say who is behind your traffic. A CDN or proxy edge address carries the reputation of the edge, shared by every visitor behind it; if your `client_ip` field holds edge addresses, a "benign" or "malicious" verdict says nothing about the visitor. Reputation is never read by a detector and never changes a finding or a severity; `internal/archtest` fails the build if a detector or the hunt mentions it. Every output (table and JSON) carries this note.

**"Not found" and "could not ask" are different answers.**

| Outcome | What the feed said | Stored in `reputation` | Exit |
|---|---|---|---|
| answer | HTTP 200 with a classification | yes, verdict `classification=...;noise=...;riot=...;last_seen=...` | 0 |
| not found | HTTP 404 (or a 200 saying "not observed" / "no report"): the feed has never seen the address. For `dnsbl`: NXDOMAIN, that is "not listed" | yes, verdict `not_found` | 0 |
| failure | timeout, network error, HTTP 429, any other status, a body that is too large or not the expected JSON, a cancelled run, an address not asked because a cap was reached. For `dnsbl`: SERVFAIL, REFUSED, a timeout, a refusal code or an answer outside 127.0.0.0/8 (see below) | never | 1 |

Any failure makes the run print `INCOMPLETE`, list the addresses that got no answer and the reason, and exit 1. Answers obtained before a failure are kept. After an HTTP 429 the feed is not asked again in that run. A failure is never turned into `unknown`, `not_found` or an empty result.

Rows are appended with the time of the lookup and the feed's name (`greynoise:community`) in the `source` column; nothing is updated or deleted, so repeated runs form a time series (`jb db status` counts them). Verdict values from the feed are reduced to letters, digits and `. _ : -` and capped in length before they are stored.

**Reading reputation rows.** `jb db reputation (--config FILE | --case DIR)` lists the stored rows read-only (Go: `jb.Reputation`). A row has four fields and no run id: `indicator`, `verdict`, `observed` (UTC, RFC 3339) and `source` (the feed). Rows come back by indicator, then newest first, so a verdict change reads top to bottom. Filters: `--indicator IP` (repeat, at most 100, IP addresses only), `--source NAME`, `--since TIME` (inclusive), `--until TIME` (exclusive; each an RFC 3339 time or a `YYYY-MM-DD` date, and `--since` may not be after `--until`), and `--latest`, which keeps the newest row of each indicator from each source (with `--until`, the verdict as of that time). `--limit N` caps the rows (default 1000, at most 10000); a result cut at the cap has `"truncated": true`, `"complete": false` and exits 1. With `--case`, the config is the one that declares `commands: [intel]`. The store is opened as `jb serve` opens it: never created, and a store a writer holds is waited for (`JB_DB_LOCK_WAIT`), then refused.

### `type: greynoise`

Calls `GET <base_url>/v3/community/<ip>`, the GreyNoise community API, and nothing else. It is passive: it asks the feed about the address and never contacts the address. Only a syntactically valid IP is placed in a request. Redirects are not followed.

| Key | Default | Rules |
|---|---|---|
| `base_url` | `https://api.greynoise.io` | `scheme://host[:port]` only; `https`, or `http` for loopback only (tests use a local fake server). No credentials, path or query. |
| `api_key_env` | none (keyless) | The *name* of an environment variable, matching `^[A-Z][A-Z0-9_]{0,63}$`. The key is sent in the `key` request header and nowhere else. If you name a variable that is unset or empty, `jb intel` refuses to run; it does not fall back to the much smaller keyless quota. |
| `max_lookups` | `10` | `1` to `1000` requests per run. Addresses beyond it are not asked and are reported as failures. |
| `min_interval` | `1s` | `0` to `1h` between two requests. |
| `timeout` | `10s` | Per request, up to `1m`. |
| `max_response_bytes` | `65536` | `512` to `1048576`. A larger response is a failure, not a truncated answer. |

The keyless community endpoint allows very few lookups a week, which is why the defaults are small. Raise them only for a key whose plan allows it.

The key never appears in output, error messages, logs or the evidence store: it is scrubbed from everything that came back from the network, and a test with a sentinel key (including a server that echoes it) checks the output and the database file.

### `type: sans-isc`

Calls `GET <base_url>/api/ip/<ip>?json`, the SANS Internet Storm Center IP API, and nothing else. It needs no key and sends no credential. Passive: the ISC is asked about the address and the address is never contacted. Redirects are not followed. The address goes to the ISC, a third party; list the feed only if you accept that.

| Key | Default | Rules |
|---|---|---|
| `base_url` | `https://isc.sans.edu` | As for `greynoise`: `scheme://host[:port]`, `https` (loopback `http` for tests). |
| `max_lookups`, `min_interval`, `timeout`, `max_response_bytes` | `10`, `1s`, `10s`, `65536` | Same ranges as `greynoise`. |

An `api_key_env` is an unknown key here and fails at load. Outcomes: HTTP 404, or a 200 whose `count`, `attacks` and `threatfeeds` are all empty for exactly the address asked, is `not_found` (the ISC holds no report). A 200 that describes a different address, or has no `ip` object, is a failure. An answer is stored as `count=12;attacks=3;mindate=...;maxdate=...;feeds=name,name` (values reduced to letters, digits and `. _ : -`, at most five feed names). The source column says `sans-isc`.

### `type: dnsbl`

Looks an address up as a name under a DNS blocklist zone: `4.3.2.1.<zone>` for `1.2.3.4`, A record only. **This sends the address to a DNS resolver and, through it, to the zone's operator**, so the feed does nothing until you set `enabled: true`. A listed feed with `enabled` absent or `false` is not built, not asked, and named on stderr; `jb doctor` shows it as disabled.

```yaml
feeds:
  - type: dnsbl
    zone: bl.example.org
    enabled: true
    # resolver: 192.0.2.53:53      # default: the system resolver
    return_codes:
      "127.0.0.2": sbl
      "127.0.0.4": xbl
    # error_codes: ["127.0.9.9"]   # codes this zone uses to refuse service, besides 127.255.255.0/24
    # ipv6: false
    max_lookups: 10
    min_interval: 250ms
    timeout: 5s
```

| Key | Default | Rules |
|---|---|---|
| `zone` | none, required | A lower-case DNS name of at least two labels, no trailing dot, not an IP. Also names the feed: `dnsbl:<zone>`. |
| `enabled` | `false` | Must be `true` for the feed to be asked. |
| `resolver` | system resolver | An IP or `IP:port` (port defaults to 53). A name is refused: it would need resolving first. The pure Go resolver is always used (`PreferGo`), because the C resolver cannot tell NXDOMAIN from SERVFAIL, and "not listed" must never be a guess. |
| `return_codes` | none | Map of `127.x.y.z` to a label (`[A-Za-z0-9_.-]{1,40}`), at most 64. A listed code you did not map is recorded as `unmapped`, with the raw code. Codes in `127.255.255.0/24` cannot be mapped. |
| `error_codes` | none | Extra `127.x` addresses this zone answers when it refuses service. |
| `ipv6` | `false` | See below. |
| `max_lookups`, `min_interval`, `timeout` | `10`, `250ms`, `5s` | `1..1000`, `0..1h`, `(0, 1m]`. The timeout is per question. |

How an answer is read:

| The resolver says | Result |
|---|---|
| NXDOMAIN, or no A record | `not_found` (not listed), a real answer, stored |
| one or more `127.x.y.z` | listed: `listed=true;zone=<zone>;codes=127.0.0.2:sbl,...` (sorted, at most eight, labels from `return_codes`), stored |
| any code in `127.255.255.0/24` (`127.255.255.252` to `.255` are how Spamhaus-style lists refuse a public or open resolver or an excessive query volume), or a code in `error_codes` | **failure**, and the zone is not asked again in that run |
| an address outside `127.0.0.0/8` (a resolver rewriting NXDOMAIN into an ad server), or a mix | failure |
| SERVFAIL, REFUSED, timeout, unreachable resolver, cancelled run, cap reached | failure |

A refusal says nothing about the address, so it is neither "listed" nor "not listed". If your resolver is a public one that the zone refuses, every lookup fails and the run is `INCOMPLETE`: point `resolver` at a recursive resolver the operator allows. Known gap: if a resolver answered NXDOMAIN to everything without saying so, jb cannot tell that from a clean address; test the zone with its documented test address (usually `127.0.0.2`) before relying on a run of "not listed" answers.

IPv6: with `ipv6: true` an address is asked as 32 reversed nibbles under the zone. With the default `false`, an IPv6 indicator is a failure ("not asked"), because a zone that publishes no IPv6 data answers NXDOMAIN for every address, which would read as "not listed". An IPv4-mapped IPv6 address is asked as its IPv4 address. Questions are fully qualified (trailing dot) so the system resolver's search list cannot append a domain and send a second question.

### `intel`

| Key | Default | Rules |
|---|---|---|
| `ip_fields` | `[client_ip]` | Event fields to read addresses from in the latest hunt. 1 to 8 names, each 1 to 128 characters of letters, digits and `_ @ . -`. |
| `max_indicators` | `10` | `1` to `1000` distinct addresses per run. The rest are reported as failures (the run is `INCOMPLETE`), never dropped. |

## Estate collectors

`jb estate asn`, `jb estate dns` and `jb estate ct` ask services that are not your own machine, so each is off until the case config names it. Nothing is sent otherwise: the command refuses with a message that says what would have left the machine.

```yaml
estate:
  external: [bgp, crt.sh, dns]   # default: none
  # bgp_url: https://stat.ripe.net     # RIPEstat-style data API
  # crtsh_url: https://crt.sh          # crt.sh-style JSON search
```

| Key | Meaning |
|---|---|
| `external` | The enabled services, from `bgp` (`estate asn`), `crt.sh` (`estate ct`) and `dns` (`estate dns`). An unknown name or a duplicate is an error at load time. |
| `bgp_url` | Base URL of the BGP data API. http or https, a host, no credentials, query or fragment. Default `https://stat.ripe.net`. The adapter calls `/data/announced-prefixes/data.json`, `/data/as-overview/data.json` and `/data/prefix-overview/data.json`. |
| `crtsh_url` | Base URL of the certificate transparency search. Same rules. Default `https://crt.sh`. The adapter calls `/?q=%.<domain>&output=json`. |

```
jb estate asn --case DIR [--config FILE] [--file NAME] [--timeout 10s] [--min-interval 1s] [--max-targets 10] [--output table|json] AS64500|IP ...
jb estate dns --case DIR [...] [--resolver HOST:PORT] DOMAIN ...
jb estate ct  --case DIR [...] [--max-names 500] DOMAIN ...
```

`--config` defaults to the config that declares `estate` under `commands`, else the case's only config. The three are subcommands of `jb estate` rather than flags, because each has its own target type (AS or address, domain, domain), its own service and its own caps; `jb estate IP ...` is unchanged.

The bounds are flags: `--timeout` (1s to 2m, per request), `--min-interval` (0 to 1m between requests; defaults 1s for `asn` and `ct`, 250ms for `dns`), `--max-targets` (default 10, at most 50; more is refused, not truncated) and, for `ct`, `--max-names` (default 500, at most 2000). Responses are size-limited in the adapters (4 MiB for BGP, 16 MiB for CT).

### How to read the result

- A name from `ct` is a **candidate**: it appears on a publicly logged certificate. It may be expired, internal, never served or shared with a CDN. The edge is `domain -[ct_candidate]-> host`, `confidence: inferred`, and says so in `inferred_from`. Wildcard names (`*.example.com`) are counted and not recorded, and so are names on the same certificates that fall outside the domain.
- An address from `dns`, or a prefix or origin AS from `asn`, that belongs to a CDN, proxy or shared host identifies the **provider**, not who runs the site or the visitor behind it. The output says so every time.
- `dns` records SPF as `domain -[spf_authorises]-> ip|network` and `domain -[spf_include]-> domain`. Other TXT values are never read into the file (they can hold verification tokens). SPF says who may send mail for the domain, not where the site is served. The `a`, `mx`, `ptr` and `exists` mechanisms and macros are not followed.
- `dns` answers are one resolver's view at one time. Go's resolver can answer address and CNAME questions from the local hosts file before it asks a resolver; the recorded method says so.
- A run that was cut at a cap (`--max-names`, the prefix cap, a value cap), timed out, was rate limited, got a non-2xx answer or an unparseable body is listed, ends `INCOMPLETE` and exits 1. A failed lookup stores nothing for that target. A truncated one keeps what it read and says how much; the rest is unknown, not absent. After a 429 the service is not asked again in that run. A real "nothing there" (an empty certificate list, an unannounced address, NXDOMAIN) is recorded as an absence.

## Estate drift

The drift check reuses the `estate:` section above and adds no key. `jb estate refresh` runs the collectors for the targets the estate file already records: reverse DNS and RDAP for addresses always (as `jb estate IP` does), and BGP, DNS and certificate transparency only when `bgp`, `dns` and `crt.sh` are in `estate.external`. A service that is not listed is skipped and listed as `SKIPPED`; nothing is sent for it.

```
jb estate refresh --case DIR [--config FILE] [--file estate.yaml] [--rdap-url URL] [--resolver HOST:PORT] [--timeout 10s] [--max-targets 20] [--output table|json]
jb estate diff    --case DIR [--file estate.yaml] [--from REF] [--to REF] [--output table|json] [--alert [--config FILE] [--ttl 3h]]
jb estate promote --case DIR [--file estate.yaml] SNAPSHOT-ID
```

- `refresh` writes `<estate>/snapshots/<UTC time>.yaml` (`docs/CASE-SPEC.md` section 4.5.1) and leaves `--file` untouched. `--max-targets` (default 20, at most 100) counts distinct targets across services; a longer list is refused (exit 2) before anything is asked. Request spacing and per-service caps are the ones of `estate asn|dns|ct`. Exit 0 means a complete snapshot; exit 1 means INCOMPLETE (a failed, timed out, rate limited or cut lookup): the snapshot is kept, marked `complete: false` with the reasons, and refused by `diff` and `promote`. Use the same `--resolver` and `--rdap-url` as the baseline was made with: the resolver is part of the method, and a different one makes every DNS question not comparable.
- `diff` compares `--from` (default: `--file`, the baseline) with `--to` (default: the newest snapshot). A REF is a snapshot id, an estate file name, or `snapshots/<id>.yaml`. Exit 0 means the comparison ran, whether or not there was drift; exit 1 is a refused or unreadable input (an incomplete snapshot, a corrupt file, no baseline); exit 2 is usage, including "no snapshot yet". It sends nothing.
- `--alert` sends findings that are new to the case's alert sinks, with the same dedupe as `jb watch`: the sink is `<evidence>/estate-drift.log` (also echoed on stderr) plus any `alerts:` webhook of the chosen config, and the memory is `<evidence>/estate-drift-state.json`. A tag alerted within `--ttl` is held back unless its severity rose. The evidence git guard applies.
- `promote` archives the baseline and then replaces it with a complete snapshot. It refuses an incomplete snapshot and one that skipped a service.

### Findings

Detector `estate_drift`. The tag is `estate_drift:<class>:<subject>:<digest>`, where the digest is eight hex characters over the changed edges, so the same drift keeps its tag on every run until it is promoted, and a further change to the same subject gets a new one.

| Change | Class | Severity |
|---|---|---|
| NS record added or removed | `ns` | high |
| MX record added or removed | `mx` | high |
| Origin AS of a network added or removed (`originated_by`, source `bgp`) | `origin` | high |
| A domain's address added or removed (`resolves_to`) | `address` | activity |
| New certificate-transparency name (`ct_candidate`) | `ct` | check |

Any other change (a removed CT name, a changed organisation name, a CNAME, SPF, PTR or registration change, a node added or removed) appears in the diff and raises no finding. The summary holds the subject and counts only (`estate drift: NS records of domain:example.com changed (+1 added, -1 removed)`); the values are in the diff output, not in the alert. A CDN or shared-hosting address or origin AS changing says nothing about ownership.

### Running it on a schedule

The check is a separate command, not a step of `jb watch`. `watch` runs every few minutes against a local store; a refresh makes network requests to third-party services, spaced by the per-service interval, so putting it in the watch cycle would slow every cycle and send the same questions every five minutes. Drift in DNS, registration and certificates moves in hours or days. Run it from cron or a systemd timer at that pace:

```
# once a day, 03:10 UTC
10 3 * * *  jb estate refresh --case /path/to/case --file estate.yaml && jb estate diff --case /path/to/case --alert
```

`&&` is deliberate: when the refresh is INCOMPLETE the diff does not run against stale data, and the non-zero exit is what the scheduler should alert on. The first run needs a baseline: run `jb estate IP|asn|dns|ct` to record what to watch, then `jb estate refresh` and `jb estate promote <id>`. After a change you accept, run `jb estate promote <id>` for the snapshot you reviewed; until then the same drift is reported on every run (and held back by `--ttl`). Snapshots accumulate in `estate/snapshots/`; nothing deletes them.

## Estate facts

```
jb estate facts import --case DIR [--file estate.yaml] [--apply] [--output table|json] IMPORT-FILE
```

Adds facts to nodes of an estate file from one export file you hold. It adds no config key and needs no `estate.external` entry, because it reads one local file and sends nothing: the source `scan-cache` is a store someone else built earlier, and the target observes nothing from `jb` (`docs/POLICY.md`, "The test for a source"). The `commands:` name `estate` covers it. The import file shape, its caps (1 MiB, 5000 facts) and the rules are in `docs/CASE-SPEC.md` section 4.5.2. It is a dry run unless `--apply` is given, so `jb estate facts import` on its own writes nothing. Exit 2 is usage: no file, an unknown key, a node the estate file does not have, a file over the caps, or a result that would not load. The estate file must already exist. The diff compares facts per node, key, source and method (`docs/CASE-SPEC.md` section 4.5.1), so keep the `method` and `source_note` of an export stable between imports if you want later exports compared with it.

## Alert delivery

`jb watch` always writes each alert to stdout and appends it to `<evidence>/watch.log`. The log is the source of truth and is written first. `alerts:` adds delivery on top of it; it never replaces the log.

```yaml
alerts:
  - type: webhook
    url_env: JB_ALERT_WEBHOOK_URL   # the NAME of a variable that holds the URL
    min_severity: high
    timeout: 10s
    max_per_cycle: 10
```

### `type: webhook`

POSTs `{"text": "..."}` (`Content-Type: application/json`) to the URL, the shape Slack, Mattermost and similar incoming webhooks accept.

| Key | Default | Rules |
|---|---|---|
| `url_env` | required | The *name* of an environment variable, matching `^[A-Z][A-Z0-9_]{0,63}$`. The URL itself is a secret (it carries a token) and never goes in the file: a value that is not a variable name, such as a pasted URL, is refused at load, and the error does not repeat it. An unset or empty variable stops `jb watch` before the first hunt. |
| `min_severity` | `high` | `info`, `check`, `activity`, `high` or `critical`. Alerts below it are not sent (not an error). Outage alerts (`watch-incomplete`, `watch-cycle-error`, state and prune problems) are `high`; recoveries and the cycle line are `info`. |
| `timeout` | `10s` | Per request, up to `1m`. |
| `max_per_cycle` | `10` | `1` to `100` alerts sent per cycle. |
| `min_interval` | `1s` | `0s` to `1h` between two requests. `0s` means no pause. |
| `max_response_bytes` | `4096` | `16` to `1048576`. A larger response is a failure. |
| `allow_insecure_loopback` | `false` | Tests only: allows `http://` when the host is `localhost` or a loopback address. Without it the URL must be `https://`. |

What it sends and what it does not:

- Findings: `[severity] tag: summary (run id)`. Only the detector's summary text, the tag, the severity and the run id. Never a raw event, a log line or a field value beyond what the summary says.
- Every other kind of alert (outage, state problem, recovery, the cycle line) is a fixed sentence plus the tag and the run id, pointing at `watch.log`. Their full text is made of error messages from other components and can name internal hosts, so it stays in the log.
- Control characters, backslash, newline, bidirectional overrides and the chat markup characters `& < >` are escaped (`<!channel>` arrives as `&lt;!channel&gt;`), and the summary is cut at 500 characters. Log content cannot forge a line or a mention.
- A storm cannot flood it: after `max_per_cycle` sends, further alerts of that cycle are not sent, and one message says `N further alerts not sent to webhook, see watch.log (run ...)` when the cycle ends. A cycle whose webhook failed sends nothing more that cycle (an outage costs one timeout, not one per alert).
- No redirect is followed (the token would travel with it); a 3xx is a failure. Only the URL's host receives traffic. The one exception is a proxy named by the standard `HTTPS_PROXY` variable, which carries the connection as it does for every `jb` network adapter.

Failure rules. A timeout, a network error, any non-2xx status, a redirect and an oversized response are errors. The alert is already in the log, so it counts as delivered and is not offered again, but the cycle is `CYCLE FAILED`, the cycle line says how many alerts missed the webhook, and `--once` exits 1. A failing webhook never stops the other sinks. If the log itself cannot be written the alert counts as not delivered, the webhook is not tried for it (a retry would duplicate it there), and the next cycle offers it again.

The URL never appears in output, error messages, the log, alert text or the evidence store. Errors are built from fixed words and a status code, never from the text of a `net/http` or `net/url` error (which quotes the URL), and the sink formats as `[redacted]` under every `fmt` verb. A test with a hostile fake that echoes the URL and path in its replies, and a connection that fails, checks all of it.

## Serve

`jb serve (--case DIR | --config FILE)` shows the evidence store in a browser. It loads the config only to find the database path: it builds no source, reads no environment variable and no credential, and the pages never show a config value (a test sets `api_key_env` and its value and checks neither appears).

| Flag | Default | Meaning |
|---|---|---|
| `--case DIR` | none | A case directory. Takes the case's config (as `hunt --case`, with `--config` to choose among several), the evidence directory for `watch.log` and `watch-state.json`, and the estate directory. The evidence git guard applies as for `hunt`. |
| `--config FILE` | none | A config without a case. The watch files are looked for in the store's directory; there is no estate, and `/estate` says so. |
| `--addr` | `127.0.0.1:8090` | Listen address. `localhost` becomes `127.0.0.1`. Anything not loopback, including `:8090` and `0.0.0.0:8090`, is a usage error unless `--allow-remote`. |
| `--allow-remote` | off | Accept a non-loopback `--addr`. A WARNING is printed on stderr. **There is no authentication**: anyone who can reach the port can read the evidence store, including paths, user agents and addresses from the logs. Put it behind something that authenticates, or do not. |
| `--path-field`, `--status-field`, `--key-field` | `path`, `status`, `client_ip` | The event fields the per-run summary groups on (the default mapper emits these). Letters, digits and `_ . @ -`, at most 64. |

The page makes no request to any other origin and uses no web font; its scripts (htmx, d3 and two small files of ours) and its stylesheet are served from the binary, so it works offline. The Estate page draws an interactive graph (drag, zoom, a label on every connection); selecting a node or a connection opens its record, with its connections, in a sheet at the right. Line width is the number of distinct sources that claim a connection (1, 2, 3 or more) and a dashed line has no claim newer than 90 days; both are computed when the page loads, the estate file stores neither. A node-kind filter (checkboxes, an htmx fragment, `?kind=ip&kind=host` in the address) narrows the graph and the tables; an unknown kind is ignored. Opening the record of an `ip` node reads two overlays from the store as plain text: the latest reputation row per source, and the last time the address was a `--key-field` value in the stored events (the last 30 days, 3 second limit). Map load never queries the store. Without script the same page draws a static layered drawing and every record is an ordinary link. The Findings page filters by text and severity as you type (htmx), and falls back to an ordinary form without script; the Watch page refreshes its panel every 10 seconds (htmx) and is a normal page without it. The database file must already exist (a viewer never creates it) and be at the build's schema version. While a `jb watch` cycle is writing, a request can fail to open the file; the page then shows the error and a reload after the cycle works. Top-path rows group on the path with the query string and fragment removed; the raw events panel shows the stored fields, newest first, at most 50 rows, and not the original document.

## Checking the environment

`jb doctor [--case DIR | --config FILE] [--online] [--output table|json]` answers "will the next run work, and what would it send?" without running one. It is read-only, makes no network connection unless `--online` is given, and exits 0 only if no check failed.

| Group | What is checked | Result |
|---|---|---|
| `build` | jb version and commit, the Go version, the DuckDB driver module version and the engine version (read from a private in-memory database, so it also proves the cgo library loads) | ok, or fail if the engine does not start |
| `case` (with `--case`) | the same checks as `jb case check`: `case.yaml`, the evidence directory is ignored by git (the existing guard), actors, estate, each listed config and the case files its detectors name | fail on any problem; "not a git work tree" is a warning, not a pass |
| `config` | the config loads strictly (unknown keys and types are errors). Each source or detector with `enabled: false` gets a `skipped` line `DISABLED: ...`. With `--case`, every config the case lists, or the one `--config` chooses. A `mapper: plugin:<name>` that is not in the operator's allowlist fails here | ok or fail |
| `plugins` | the operator's allowlist (`$JB_PLUGINS_FILE` or `~/.jb/plugins.yaml`): each plugin's path, pin state (`none`, `ok`, `MISMATCH`) and the file, directory and symlink checks, without launching any. No environment value is shown | ok, fail for a plugin that would be refused, skipped when nothing is allowlisted |
| `env` | each environment variable a source, feed or alert names (`api_key_env`, `url_env`) is set and non-empty. Reported as `set` or `unset`, **never the value and never its length**; the check cannot see either, because the port that answers it returns a boolean. A variable named by a disabled service, or by a source or detector with `enabled: false`, is skipped | fail when an enabled service's variable is unset: the command that uses it would refuse to run |
| `store` | the store path (in a case, `<case>/evidence/jb.duckdb` unless the config sets one) is writable by this user, an existing file is owned by this user, is not group- or world-writable (warning), and opens read-only with a schema this build understands (an older schema is a warning, a newer one a failure). A file that does not exist yet is `skipped`: the first run creates it, and doctor creates nothing | ok, warn, fail or skipped |
| `online` | only with `--online`, see below | |

After the checks, **services** lists every outbound service the config names (kibana sources, feeds, the webhook, and the three estate collectors), each `enabled` or `disabled`, with what would leave the machine if the command that uses it ran. A `dnsbl` feed says the address goes to a resolver and the zone's operator; the estate collectors are disabled until `estate.external` lists them.

`--online` makes one TCP connect, bounded to 4 seconds, to each distinct host of an enabled service, and then closes it. **No bytes are sent**: no HTTP request, no credential, no webhook URL. For a webhook the host and port are taken from the URL held in its environment variable, and the path, query and user info are never read into output. Services that are reached through a DNS resolver over UDP (`dnsbl`, `estate dns`) are listed and not probed, because a TCP connect would not test them. A TCP connect does not use `HTTP_PROXY`: on a network where outbound traffic must go through a proxy, an unreachable result may only mean "not directly".

The `store` group also does two things that need the engine. A store another process holds read-write is waited for 3 seconds (not `JB_DB_LOCK_WAIT`), then reported as a **fail** that names the holder's executable and PID when DuckDB gives one. And when the store opens, the last 24 hours are checked for one set of documents stored under two source labels, a **warn** (never a fail) that prints the `jb db rename-source` fix ([Source labels and double counting](#source-labels-and-double-counting)).

`skipped` is not a pass. It means the thing is not configured or was not asked for (no `--case`, no store file yet, no `--online`). The result line says so, and a bare `jb doctor` with neither `--case` nor `--config` checks the environment only.

doctor does not inventory external binaries (the ProjectDiscovery tools or any other): jb wraps none, so there is nothing to find, version or wire.

## Credentials

The file never holds a credential. A source names an environment variable (`api_key_env`) and `jb` reads it when it builds the sources, in `hunt`. `db status` and `serve` load the file only to find the database path and read no credential.

- Set the variable in the environment that starts `jb`: see [Supplying credentials](#supplying-credentials). Do not export it in a file you commit.
- A missing or empty variable is an error that names the variable and never prints a value.
- A value pasted into `api_key_env` or `url_env` (lower case, `=`, `:`, `/` and so on) is refused at load without echoing it.
- The key is sent in an `Authorization: ApiKey` header only. It is not put in URLs, and the HTTP error text omits the response body.
- `.gitignore` excludes `.env`, `*.duckdb` and `/evidence/`. Keep real configs out of version control anyway: they name your hosts and indexes.

## Supplying credentials

`jb` reads a credential from its process environment and from nowhere else. It has no `--env-file` flag, does not read a `.env` file and does not take a value on the command line. The YAML holds only the variable name (`api_key_env: JB_KIBANA_API_KEY`). Whatever starts `jb` puts the value in the environment. This keeps file permissions, ownership and logging of the secret in the hands of the operator's own launcher.

When a variable is missing or empty, the error names it and says it is read from the process environment. Check the name against the config, then use one of these.

A shell, reading a file you own and keep outside the repository (mode 600):

```sh
set -a                      # export every variable the file sets
. "$HOME/.config/jb/secrets.env"
set +a
jb hunt --config jb.yaml
```

The file holds `JB_KIBANA_API_KEY=...` lines and nothing else. The variables reach `jb` and its children only.

One command, from a keychain or secret manager (the second line is an example for macOS):

```sh
JB_KIBANA_API_KEY="$(security find-generic-password -s jb-kibana -w)" jb hunt --config jb.yaml
```

A service manager. A systemd unit names the file in `EnvironmentFile=/etc/jb/secrets.env` (mode 600, owned by the service user), and `jb watch --case DIR` inherits it. Cron and containers have an equivalent: set the variable in the job's environment, not in the config.

The Go package takes the lookup as `Env` and does not touch the process environment when it is set:

```go
env := func(name string) (string, bool) {
	v, ok := secrets[name] // from your own store
	return v, ok && v != ""
}
res, err := jb.HuntCase(ctx, caseDir, jb.CaseHuntOptions{HuntOptions: jb.HuntOptions{Env: env}})
```

Rules that hold in every recipe: the YAML never holds the value, a value is never put on a command line (it shows in the process list), and `jb` never prints it.

## Watch

What `jb watch` prints and how several watchers share a case.

### Watch output

`jb watch --once --output json` prints the cycle report as one JSON document on stdout. The alert lines go to stderr instead, so stdout stays parseable; the log file and any webhook get them as always. `--output json` without `--once` is a usage error (exit 2), because a loop has no single result. A cycle that is not healthy still prints its report, then exits 1. The same fields are in the Go package as `jb.CycleReport`.

| Field | Type | Meaning |
|---|---|---|
| `run` | string | Run id of the cycle (`watch-<time>`, `watch-NAME-<time>` for a named watcher). |
| `watcher` | string | The `--name`; absent for the unnamed watcher. |
| `window` | [from, to] | RFC 3339 times; the hunt window, `[from, to)`. |
| `status` | string | `quiet`, `findings`, `incomplete` or `failed`. |
| `healthy` | bool | True only for `quiet` and `findings`. |
| `failed` | list of string | Sources and detectors that did not finish. Empty, never null. |
| `new` | int | Finding alerts delivered. |
| `suppressed` | int | Findings held back by `--ttl`. |
| `repeated` | int | Outage alerts held back by `--repeat`. |
| `recovered` | int | Recovery alerts delivered. |
| `optional_failed` | int | Alerts the log took and a webhook did not. |
| `gap` | string | Present when time went unexamined before this cycle. |
| `error` | string | Present when something broke the cycle itself. |
| `alerts` | list of alert | Everything delivered this cycle, health alerts first. Each has `kind`, `tag`, `severity`, `text`, `at`, and `detector`, `run`, `watcher` when set. |
| `pruned` | object or null | `runs`, `events`, `findings` removed by retention; null when it did not run or failed. |

`jb hunt --no-store` and `jb activity --no-store` do not use this path at all. They run the same code over a private temporary store (a `jb-nostore-*` directory, mode 0700, in `TMPDIR`) that is deleted when the command returns. The evidence database is not opened, created or changed, and a `TMPDIR` inside the case is refused. The output says `not stored: this run left no evidence` (`"stored": false` in JSON; `true` for a stored run). Detectors then see only the events this run fetched, not those saved by earlier runs, so a result can differ from a stored run. Not offered on `watch`, `db`, `actor`, `estate`, `intel` or `serve`. See [RFC 0009](rfcs/0009-no-store.md).

### Several watchers on one case

`jb watch --name NAME` (`^[a-z][a-z0-9_-]{0,31}$`) lets one case hold several watch profiles, each with its own `--config`. Without `--name` nothing changes. With it, everything the watcher owns is named after it:

| | unnamed | `--name a` |
|---|---|---|
| dedupe memory | `evidence/watch-state.json` | `evidence/watch-state.a.json` |
| log | `evidence/watch.log` | `evidence/watch.a.log` |
| single-instance lock | `evidence/watch.lock` | `evidence/watch.a.lock` |
| run id | `watch-<UTC time>` | `watch-a-<UTC time>` |

The name is on the `watching case ...` banner, on every alert (`[w:a]` after the tag) and on every `CYCLE` line (`[w:a]` after the run id), so merged logs stay attributable.

- **Dedupe is per watcher.** The state files are separate, so a finding two watchers both see alerts once in each of them. That is deliberate: two profiles are two readers of the alerts. Give them different detectors, or send them to different channels, if that is not wanted.
- **Retention is per watcher.** After a cycle, `--keep` prunes only runs shaped exactly `watch-a-<20060102T150405Z>` (and their `/source` runs), never another watcher's and never the unnamed watcher's; the unnamed watcher prunes only `watch-<stamp>`. The test is on the whole shape, not a prefix, so `watch-a-` does not reach `watch-ab-...` or `watch-a-b-...`, and `watch-` does not reach `watch-a-...`. Each watcher also keeps its own newest run, whatever its age.
- **One process per name and case.** A watcher takes an exclusive lock on its lock file before it builds anything; a second `jb watch` with the same name (or a second unnamed one) on the same case is refused at once and the message names the holder's PID. The lock is `flock(2)` on Unix, so it is released by the kernel when the holder exits however it dies; a lock file left behind by a killed process is not a held lock, and the next watcher takes it over. The file is never deleted.
- **`jb serve` shows the unnamed watcher's log and state only** (it reads `watch.log` and `watch-state.json`); a named watcher's files are read with the log itself.
- **They share only the DuckDB file.** Each opens it for one hunt at a time, and the one that arrives while the other is writing waits for it ([Locking](#locking-one-writer-or-many-readers); with `JB_DB_LOCK_WAIT=0` they would collide and a cycle would fail, which is why the default wait matters here). Keep the same `store.path` (or none) in the configs of one case, so that they share one store.

## Database path

Resolved in this order:

1. `store.path` in the config. A leading `~/` is expanded to your home directory.
2. The `JB_DB` environment variable.
3. `~/.jb/jb.duckdb`.

In `jb hunt --case DIR` the order is different: an empty `store.path` means `<case>/<paths.evidence>/jb.duckdb` (`JB_DB` is ignored), a relative `store.path` is relative to the case directory, and an absolute or `~/` path is used as written. Without `--case`, a relative `store.path` is relative to the working directory.

`hunt` creates the file and applies schema migrations. `db status` opens it read-only and fails if it does not exist.

### Locking: one writer or many readers

DuckDB lets one process open the file read-write **or** any number open it read-only, never both. A running `jb watch` opens the store once per cycle and holds it for the write phase (measured at about 2 percent of the time, a few seconds per 5 minute cycle), so a `jb serve` request, `jb doctor`, `jb actor status`, `jb db status` or a manual `jb hunt` that lands in that moment would fail with DuckDB's `Could not set lock on file ... Conflicting lock is held in ... (PID n)`.

Every open therefore **waits for that one error, and only that one**, with a bounded jittered backoff: 100 ms, doubling to a 1 s cap, each step cut to between half and all of itself, and never more than the budget in total. The default budget is **15 s**. Set it with the environment variable `JB_DB_LOCK_WAIT`:

| Value | Meaning |
|---|---|
| unset | 15s |
| `30s`, `1m`, ... | that total wait, at most `2m` (a larger value is refused with an error, not clamped) |
| `0` | no retry: fail at the first lock error |
| anything else | refused with an error naming the variable |

A corrupt file, a schema ahead of the build, a permission error or a DuckDB storage-version mismatch is **not** retried and fails at once, unchanged. An interrupt (Ctrl-C, SIGTERM) ends the wait immediately. When the budget runs out the error names the file, says another process holds it, gives the holder's executable name and PID when DuckDB names one (nothing else of DuckDB's message is repeated), and says what to do: wait for it or stop that process.

`jb doctor` keeps reporting a held lock as a **FAIL**, but only after a fixed 3 s budget (not `JB_DB_LOCK_WAIT`), so a watch cycle that happens to be writing at that instant does not make the report flap, and the failing line says who holds it.

### Source labels and double counting

An event is stored with its source **label**: the source's `name:`, or `kibana:<index>` when it has none. The label is part of the event's identity (docs/ARCHITECTURE.md, "Evidence store"), which is what makes a `sources:` scope on stored history work. The cost is that the same documents saved once under the default label and again under an explicit name are two sets, and a detector that reads both counts every document twice (found live: 77 documents read as 154). Name your sources before you backfill (docs/BACKFILL.md), and if you add or change a `name:` later, relabel what is already stored:

```sh
jb db rename-source --case DIR 'kibana:logs-ingress-*' ingress            # dry run: counts, changes nothing
jb db rename-source --case DIR 'kibana:logs-ingress-*' ingress --apply    # do it
jb db rename-source --case DIR 'kibana:logs-ingress-*' ingress --apply --merge
```

(`--config FILE` instead of `--case DIR` names the store from a config.) `OLD` is a stored label: a valid source name, or a default `kibana:<index>` label (quote it, the index may hold `*`). `NEW` must be a valid source name, the same rule as `name:` (a lower case letter, then `a-z 0-9 _ . : -`, at most 64 characters).

- **Dry run is the default.** Without `--apply` the store is opened read-only, so the engine refuses any write, and the counts are printed: events and runs under `OLD`, events already under `NEW`, documents under both, rows that would be dropped, rows that would be relabelled.
- **One transaction.** The `source` column of `events` is the only column that stores an event's source label (`runs` and `findings` are keyed by run id; `reputation.source` names a feed, a different thing). A failure half way leaves nothing changed.
- **Run ids are never touched**, so a stored run id such as `hunt-20261101T120000Z/kibana:logs-ingress-*` keeps its old text; only the events' label changes.
- **Overlap is refused.** If `NEW` already holds a document `OLD` also holds (same `ts`, `kind` and `doc_sha256`), the command refuses, dry run or not, and says how many. `--merge` allows it: in the same transaction the rows of `OLD` that `NEW` already covers are deleted (counted and printed) and the rest are relabelled. A run that holds more identical copies of a document than `NEW` does is kept whole, so real repeated lines survive.
- **Locks.** If another process holds the file the command waits as above, then reports the holder.
- **No raw document.** An event stored without a raw payload digests its label into `doc_sha256`. That digest is left as stored (the identity rule leaves stored digests alone), so such a row cannot match across labels and a later fetch of the same document under `NEW` is read as a separate event. The count of such rows is printed.

`jb hunt`, `jb activity`, `jb watch` (in each cycle) and `jb doctor` print a **WARNING** when the same documents (same `ts`, `kind` and `doc_sha256`) are stored under two labels inside the window being read (for `doctor`, the last 24 hours). It names both labels, the number of documents and the exact `jb db rename-source ... --merge` command, as a dry run. It is advice only: it never changes a verdict or an exit code, and in `doctor` it is a `warn`, not a failure. Two labels holding different documents are two sources and are not reported.

## Store maintenance

The evidence store only grows. Nothing prunes it except `jb watch --keep`, which removes its own `watch-` runs, per watcher. Everything else stays: `hunt-*`, `hunt-until-*`, `activity-*`, `activity-until-*`, `search-*`, `search-until-*`. Found live, a case store reached 1.7 GB, mostly one-off runs of those kinds. Two things made it worse:

- **Duplicates are stored per run.** The identity rule collapses the same document fetched by overlapping runs when the store is *read* (docs/ARCHITECTURE.md, "Evidence store"), not when it is written. Repeated or overlapping backfills, retried days and replays store the documents again under each run id, so the file is several times the distinct document count. A backfill loop should be followed by a prune ([docs/BACKFILL.md](BACKFILL.md#prune-after-a-backfill)).
- **DuckDB does not shrink the file after a delete.** The freed blocks are reused by later writes, but the file keeps its size. Only a copy into a new file gives the space back.

Three commands, all strict. The runbook is: **usage, prune dry run, prune `--apply`, compact `--to`, swap.**

```sh
jb db usage   --case DIR                                                              # 1. what is big (read-only)
jb db prune   --case DIR --kind hunt,activity,hunt-until --older-than 14d             # 2. dry run: what would go, what is kept and why
jb db prune   --case DIR --kind hunt,activity,hunt-until --older-than 14d --apply     # 3. do it, one transaction
jb db compact --case DIR --to DIR/evidence/jb.compacted.duckdb                        # 4. dry run: sizes and the target
jb db compact --case DIR --to DIR/evidence/jb.compacted.duckdb --apply                # 5. write and verify the copy
# 6. swap by hand (the command prints these steps with your paths): stop every `jb watch` and `jb serve`, then
#    mv jb.duckdb jb.duckdb.before-compact; mv jb.compacted.duckdb jb.duckdb; jb db usage --case DIR
#    restart the watchers; delete the old file later
```

(`--config FILE` instead of `--case DIR` names the store from a config; with `--case`, `--config` picks one of the case's configs.)

### `jb db usage`

Read-only: the store is opened with `access_mode=READ_ONLY`, so the engine refuses a write, and another process holding it read-write is waited for as in [Locking](#locking-one-writer-or-many-readers). The queries are fixed text; there is no user SQL. For each **run kind** and each **source label** it prints runs, events, raw bytes, fields bytes and the oldest and newest run time, then the file size on disk, how much of it DuckDB counts as free, and how many documents are stored under two labels (the same check as the warnings in [Source labels and double counting](#source-labels-and-double-counting), reused, capped at five label pairs). `--output json` gives the same numbers.

- **Run kind** is read from the whole shape of the run id: `watch` (one row per watcher, the unnamed one included), `hunt`, `hunt-until`, `activity`, `activity-until`, `search`, `search-until`, and `other` for anything that is not exactly one of those shapes. `hunt-` therefore never counts `hunt-until-...`, and `watch-a-` never counts `watch-ab-...`.
- **Runs** are hunts: a hunt's findings run and its `id/source` event runs count once. `EVENTS PRUNED` counts the hunts whose events `jb db prune` removed.
- **Raw and fields bytes are the uncompressed size** of the stored text (`octet_length` of the raw column, the length of the fields JSON). DuckDB compresses on disk, so these show proportions between kinds and labels, not the file size. The file size is printed separately.

### `jb db prune`

```
jb db prune (--config FILE | --case DIR) --kind K[,K...] --older-than DURATION [--keep-latest N] [--drop-findings] [--apply]
jb db prune (--config FILE | --case DIR) --run ID [--run ID ...] [--drop-findings] [--apply]
```

It deletes the stored **events**, and with them the raw documents, of old runs. Rules:

- **Dry run by default.** Without `--apply` the store is opened read-only (the engine refuses a write) and the command prints what would go (hunts, run records, events and raw bytes per kind) and what is kept and why. `--apply` opens the store read-write and does everything in one transaction.
- **`--kind` is required**, one or more of `hunt`, `hunt-until`, `activity`, `activity-until`, `search`, `search-until`. There is no `all` and no wildcard. `watch`, a `watch-...` id and a named watcher are refused with a pointer to `jb watch --keep`, which owns watch retention and keeps each watcher's newest run; this command does not duplicate it. A run whose id is not exactly one of those shapes (`other`) is never matched.
- **Matching is by the whole run-id shape**, so `--kind hunt` does not reach `hunt-until-...`, and `hunt-20261106T040000Z/ingress` (the events of one source of a hunt) belongs to the hunt `hunt-20261106T040000Z`. The prune works on hunts: the findings run and all event runs of one hunt go or stay together.
- **Age is the stored `created_at`.** A hunt is old when its newest record was created before now minus `--older-than` (`14d`, `72h`, `2w`). Saving a run again keeps its creation time. The age of the data inside is irrelevant.
- **`--keep-latest N`** (default 1) keeps the N newest hunts of **each selected kind**, whatever their age, so the latest hunt that `jb intel` reads and the latest activity check are not removed by accident. `0` is accepted only when you write `--keep-latest 0`; leaving the flag out means 1.
- **Findings and run records stay by default.** Only events are deleted. The run record is stamped `runs.pruned_at` (schema v2, docs/CASE-SPEC.md) so `jb db usage` can say the events are gone. `--drop-findings` also deletes the findings and run records of the pruned hunts. A hunt whose events are already gone is reported as such and left alone. `reputation` is never touched.
- **`--run ID` removes exactly the runs you name.** It is the other way to choose, for a one-off run that `--keep-latest` would keep (the newest runs are the ones you want gone). Repeat it, at most 20 times. It cannot be combined with `--kind`, `--older-than` or `--keep-latest` (exit 2): the age and keep-latest rules do not apply to a run you named. The id is the hunt id as the dry run prints it, compared whole, never as a prefix or a pattern; `hunt-20261106T040000Z/ingress` (one source of a hunt), a wildcard and an id of no prunable kind are refused. Watch ids are refused as `--kind watch` is. An id that is not in the store is an error that names it, and then nothing is deleted. An id given twice counts once. Everything else on this list (dry run by default, one transaction, checked counts, findings kept unless `--drop-findings`, no shrink, no reputation) holds for `--run` too, and the plan and `--output json` list each named run with its kind, events and bytes (`"by_run_id": true`).
- **Counts are checked.** The plan is counted inside the transaction, the deletes' row counts are compared with it, and any difference rolls everything back. What it prints after `--apply` is the engine's count.
- **Locking.** `--apply` needs the store to itself. It waits `JB_DB_LOCK_WAIT`, then refuses and names the holder (a running `jb watch` holds the file only for the write phase of each cycle). A missing store is never created.
- The output has counts and run ids, which can hold index patterns. It never prints a stored document or an address from one.

Example: remove two comparison runs and nothing else.

```
jb db prune --case DIR --run hunt-20261106T040000Z --run hunt-20261106T041500Z           # dry run
jb db prune --case DIR --run hunt-20261106T040000Z --run hunt-20261106T041500Z --apply   # do it
```

The file does **not** shrink. The command says so after `--apply`; go on to `compact`.

### `jb db compact`

```
jb db compact (--config FILE | --case DIR) --to FILE [--apply] [--allow-outside-evidence]
```

DuckDB keeps the space of deleted rows inside the file. `compact` writes a **new file**: it creates the schema in it from this build's migrations (so `schema_migrations` and the `runs.pruned_at` column carry over exactly) and copies the five tables with `INSERT ... SELECT`, inside a private directory next to the target. It then verifies the copy and only then puts it at `--to`.

- **Dry run by default.** Read-only open; prints the source size, the blocks DuckDB counts as in use and as free, an estimate for the copy (the blocks in use; the copy is recompressed, so it can differ) and the target.
- **`--apply` needs the store to itself.** It opens it read-write, which no other process can share, so it is refused while *anything* holds it (`jb watch`, `jb serve`, another `jb` command) and names the holder. Stop watchers first. It writes nothing to the original.
- **`--to` must not exist** (never overwritten), its directory must exist (it is not created), and it must be inside the case's evidence directory, which git ignores (with `--config` alone: the store's own directory), or `--allow-outside-evidence` must be given. Its directory must also pass the same git-ignore guard as evidence (`jb case check`), with or without that flag. Mode `0600`.
- **Verified before it appears.** Rows per table equal to the source, the sum of raw document sizes equal, the schema version, and a fresh read-only open of the file as written. A copy that fails is deleted and never appears at `--to`.
- **It never replaces the original.** Swapping is the operator's step, printed with your paths. Stop every watcher and `jb serve` first (a watcher that opens the store between the two `mv` commands would create an empty database), keep the old file until the new one has served a cycle, and check with `jb db usage`.
- **Disk.** The copy needs room for the compacted size beside the original. The command does not check free space. Only the five tables of this schema are copied; a table someone added to the file by hand is not.

A store older than this build's schema (`jb db usage` and a prune dry run refuse it read-only) is migrated by the next `jb hunt`, `jb watch` cycle or `jb db prune --apply`.
