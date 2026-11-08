# Detectors: markers, behaviour and actors

This page covers the `signature`, `behaviour` and `fingerprint` detectors.

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
| `empty_is_quiet` | `false` | A current window with no event is a quiet answer and not `no records`. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](detector-scoping.md#quiet-hours-empty_is_quiet). Events that exist but whose `field` is not text are unreadable; if all are, the answer is still `no records`. |

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
| `empty_is_quiet` | `false` | A current window with nothing to judge (no event, or only ignored ones) is a quiet answer (no findings) and not `no records`. Events that exist but cannot be read (events with no path) are still `no records`: that is a blind detector, not a quiet one. Accepted only when every source the detector reads is a kibana source with a `filter`; see [Quiet hours](detector-scoping.md#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. |
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

Flags events that match an actor described in a case's actor files ([CASE-SPEC](../CASE-SPEC.md) section 4.4). The indicators are case data, not config: this detector only says which files to read. It runs inside a case (`jb hunt --case DIR`); without a case it fails to build with an error that says so. [`examples/case/config/fingerprint.yaml`](../../examples/case/config/fingerprint.yaml) is a working example.

| Key | Default | Meaning |
|---|---|---|
| `name` | `fingerprint` | Detector name; part of every tag. Lower case, `^[a-z][a-z0-9_-]{0,31}$`. |
| `actors` | required | Actor file names, relative to the case's actors directory (`paths.actors`). Each ends in `.yaml` or `.yml`, may not use `..`, and may not leave that directory by a symlink. At least one; no repeats. |
| `ignore_ips` | none | Addresses or CIDRs of our own infrastructure (a gateway, a scanner pool). A matching event relayed by one of them is counted as ignored and is never a suspect. Do not list a CDN edge here: an edge is not a client, and no address is ever used to match an actor. |
| `empty_is_quiet` | `false` | A current window with no event for the detector is a quiet answer and not `no records`. Accepted only when every source the detector reads (`sources`, else all of them) is a kibana source with a `filter`: the filter plus the liveness count above is what separates "the actor was not seen" from "the source is broken". See [Quiet hours](detector-scoping.md#quiet-hours-empty_is_quiet). Parse refuses it otherwise, naming the source. Without it, an empty window stays `no records`. |

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

[Back to the configuration index](../CONFIG.md)
