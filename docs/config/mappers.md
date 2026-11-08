# Mappers

This page covers the mappers that turn a document into an event, and plugin mappers.

A mapper turns one document's `_source` into an event. All mappers produce the same canonical field names where the data has them, so a detector's `key_field`, `status_field` and `path_field` mean the same thing on any index. The names are matched exactly, so `nginx-ingress` or `NGINX_INGRESS` is rejected.

| Mapper | Reads | Fields it emits |
|---|---|---|
| `default` | any JSON document | The whole `_source`, unchanged. Use it when the index already has top-level fields. |
| `keycloak` | the Keycloak event line in `message`, `key="value", key="value"` | `event_type`, `outcome` (`success` or `error`), `error` when present, `client_ip`, `realm`, `client_id`, and `username` and `email` only when the line has a real one. No HTTP status: a Keycloak event has none. |
| `nginx_ingress` | the nginx access line in `message` | `client_ip`, `method`, `path` (query string removed), `status` (number), `user_agent`, and `referer` when the line has one. |
| `request_dump` | an application request logged as a text dump in `message` (`=== Request Info ===`, then `method = ...`, `path = ...` and one `header = NAME    value = VALUE` line per header). Takes a `mapper_config`. | `method`, `path` (query string removed), `client_ip` (only from the header you name), `user_agent`, and one field per `header_fields` entry. No `status`: the response is another log record. |

`keycloak` notes (the exact input and output contract, the limits and the test corpus are in [WRITING-A-SOURCE.md](../WRITING-A-SOURCE.md#mapper-contract)):

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

`request_dump` notes (the exact input and output contract, the limits and the test corpus are in [WRITING-A-SOURCE.md](../WRITING-A-SOURCE.md#mapper-contract-request_dump)). It is the first built-in mapper that takes a `mapper_config` (data only; an unknown key is a load error, and every other built-in refuses one):

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

## Plugin mappers

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
- `jb doctor` lists the allowlist with pin and mode checks. There is no sandbox: read [PLUGINS.md](../PLUGINS.md) before allowlisting anything. Sample configs: `examples/hunt-plugin-nginx.example.yaml`, `examples/hunt-plugin-eventlog.example.yaml`, `examples/plugins.example.yaml`.

[Back to the configuration index](../CONFIG.md)
