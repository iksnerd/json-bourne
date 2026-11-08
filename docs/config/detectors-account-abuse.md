# Detectors: account abuse

This page covers the `authspike`, `signup` and `newkey` detectors, including the `newkey` history.

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
| `empty_is_quiet` | `false` | A current window with no event on the counted path is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (a status that is not a status or a failure value) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](detector-scoping.md#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |

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
| `empty_is_quiet` | `false` | A current window with no attempt to create an account is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (an on-path event with no readable status or method, or in event-type mode an event with no type) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](detector-scoping.md#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |

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
| `empty_is_quiet` | `false` | A current window with no event, or only ignored keys is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (events with no usable key) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](detector-scoping.md#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |

| `min_severity` | none | A floor, not an override: the severity becomes the greater of the computed one and this one, applied after the empty-baseline drop. `high` or `critical`; `info`, `check`, `activity` and any unknown name are refused at load. `Detail["min_severity"]` appears only when the floor raised the result. The tag does not change, so `watch` alerts again on the raised severity. Shared with `behaviour` (`internal/severityfloor`). |
| `note` | none | Text carried in the finding as `Detail["note"]`. Required with `min_severity: critical`; an error without `min_severity`. |
| `history` | none | `{lookback, min_events, max_candidates}`. Replaces the preceding-window baseline with a count of every event of the key over a longer lookback, asked of the sources. See [History](#history-longer-memory-than-the-window). An unknown key, a missing required key or a value out of range is an error at load. |

A finding is tagged `<name>:<key>` at severity `high`. A key with any event on any path in the preceding window is known and is never raised, and ordinary-path traffic from a new key does not count toward `min_hits`. A current window with no event carrying a usable key is `no records`. When the preceding window holds no keyed event at all, every key is new and that is a missing baseline: the finding is still raised, `baseline_empty` is true in `Detail` and the severity is `activity`. `Detail` carries the key's events and sensitive hits, which configured entries were hit and how often (`sensitive_paths_hit`), and the population counts of both windows. Only the preceding window is read as history; a longer memory is a longer window.

**Scripted clients from addresses with no history** (the gateway rule). Point `newkey` at a source mapped by `request_dump`, key on `client_ip`, list the attack-shaped endpoints in `sensitive_paths`, and add `user_agent_field: user_agent` with `user_agent_matches: ["curl/*", "python-requests/*"]`. The finding then means: this address has no event of any kind in the preceding window and made at least `min_hits` requests to those endpoints with an agent that announces itself as a script. The user agent is chosen by the client, so the filter narrows the lead and does not define the attacker: a script that sends a browser agent is not matched, and a browser agent from a new address is never raised by this rule (nor is volume). With the filter on, `Detail` adds `user_agent_filter: true` and `key_cur_sensitive_any_agent`, the key's sensitive requests of any agent, so a reader sees what the filter set aside; `key_cur_sensitive_hits` and `sensitive_paths_hit` count the matching requests only. A finding never repeats the agent string. Keep `key_field` on an address the edge asserts, not on the edge itself.

#### History: longer memory than the window

A one hour window calls every address that was idle for the previous hour new. `history` asks instead: how many events of any kind did this key have in the `lookback` before the window?

```yaml
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-web-*
    filter:
      - match_phrase: {field: path, value: /verify-phone-and-code}
    key_match: {field: message, mode: phrase}   # required for history; mode has no default
detectors:
  - type: newkey
    key_field: client_ip
    path_field: path
    sensitive_paths: ["/verify-phone-and-code", "/customers/switch-profile"]
    min_hits: 3
    history: {lookback: 168h, min_events: 50, max_candidates: 50}
```

| `history` key | Default | Rule |
|---|---|---|
| `lookback` | required | At most 31 days, and longer than the window (checked at run time, a usage error otherwise). The interval is `[window.From - lookback, window.From)`. |
| `min_events` | required | 1 or more. A key with at least this many events of any kind in the lookback is known. |
| `max_candidates` | `50` | At most `100`. |

How it runs. A candidate is a key that meets `min_hits` on the sensitive paths and is not in `ignore_keys`. Candidates are ordered by hits, most first, then by key, and the first `max_candidates` are judged; the rest are not judged. jb sends each distinct index one count request that counts all judged candidates at once, with the source's own `filter` removed (the store holds only what the filter matched, so only the source can count "any kind"). A judged candidate under `min_events` is a finding, at the severity `newkey` gives (and the `min_severity` floor). `Detail` adds `history_lookback`, `history_count`, `history_min_events` and `history_mode`, and `Baseline` is the lookback interval. The history **replaces** the preceding-window baseline for a candidate: a key seen once an hour ago and fewer than `min_events` times in the lookback is still new. For two baselines, run two detectors. With `user_agent_matches`, candidates count only the matching hits, while history counts every agent ("hits of any kind").

Never quiet. Before counting keys, jb asks each index how many events of any kind it holds in the lookback. Zero means that index cannot show history (a typo in the field, an index that keeps less than `lookback`), and the detector is incomplete, not new-for-everyone. A probe that fails, or candidates beyond `max_candidates`, keep the findings already proven and make the run `INCOMPLETE`; the error says how many candidates were not judged and the first cause. Plain `Detect` on a detector with `history` is an error and never falls back to the preceding window.

Where it works. Every source the detector reads (its `sources`, else all of them) must be a kibana source with `key_match`; Parse refuses anything else naming the source, and `jb case check` validates this with no network and no environment. Two sources on the same cluster and index are counted once; different indices add up.

Limits to know.
- `phrase` can over-count: an IPv6 address splits into several tokens, and an address can appear as a hop in a forwarded-for chain or in the body of the text. Over-counting makes a key look known, so it errs toward quiet and never creates a false alarm. The finding records the mode. Use `term` on a keyword field when the index has one.
- A key may use only letters, digits and `. : @ _ -`, at most 256 bytes. Any other candidate key (a forwarded-for chain with spaces, for example) is refused on its own before a request is sent: it counts as not judged and makes the run incomplete, naming the count and never the key, while the other candidates are judged normally.
- The key is sent in the body of a request to the index the detector already reads, never in a URL, and it appears in no finding (with `hash_keys` the finding shows the hash and the probe uses the plain value), log line or error.
- The previous cycle's attack events count as history, so a persistent attacker becomes known after enough cycles. `watch` suppresses repeat alerts by tag, which hides this, but a `hunt --until` replay can differ from live behaviour.
- The cost is one count request per distinct index per run, plus one liveness count. On one measured production index (about 14 million documents a day) 8 to 10 phrase buckets over 7 days took under a second. A heavy-hitter address has not been measured.

[Back to the configuration index](../CONFIG.md)
