# Detectors

This page covers what every detector takes (`sources`, `empty_is_quiet`) and two worked examples.

Every detector type takes two options that mean the same thing on all of them: `sources` (below) and, on `authspike`, `signup`, `newkey`, `signature`, `behaviour` and `fingerprint`, `empty_is_quiet`.

## Reading some sources only: `sources`

| Key | Default | Meaning |
|---|---|---|
| `sources` | all sources | The names of the sources this detector reads: the `name` of a source, else its default `kibana:<index>`. A list of one or more distinct names. |

Without `sources`, a detector reads the events of every source of the config, as before. That is wrong as soon as two sources hold different logs: a Keycloak detector handed nginx access lines counts them as unparsable or off-path, and a detector that counts events can mix the two logs into one number. `sources` restricts the detector to the events of the named sources, in the current window and in the preceding one alike, so the baseline is made of the same logs as the window.

Rules, checked at load: an unknown name is an error that names the detector and the name (`detectors[1] (signup): sources: unknown source "kc" (defined: ingress, keycloak)`); an empty list, a list with a repeat and a value that is not a list are errors; a misspelt key (`source:`) is an unknown key like any other. Nothing is dropped silently.

How it works: `jb hunt`, `jb watch` and `jb activity` store every source's events under the source's name and hand a scoped detector only the stored events whose source is one of its names (`app.Deps.Scopes`, built from the config). The name is stamped by the hunt on every event a source returns, whatever label a mapper put on it. A scoped detector whose sources produced nothing it can read still follows the zero-record rules: `no records`, unless `empty_is_quiet` applies. Two overlapping sources can return the same document; a run keeps the first copy (see [Two sources on one index](sources.md#two-sources-on-one-index)), so a document read by both is attributed to whichever read it first, and a detector scoped to the other source does not see it.

## Quiet hours: `empty_is_quiet`

A detector that finds nothing to judge in the current window returns `no records`, which makes the hunt `INCOMPLETE`. That is right for a source that may be broken. It is wrong for a source narrowed by a `filter` to something that legitimately does not happen every hour, such as account creations: every quiet hour would be reported as a failure.

`empty_is_quiet: true` makes "nothing to judge" a quiet, clean answer. It is only sound because a filtered source proves its index alive: when the filter matches nothing, the source counts the same window without the filter, and `jb hunt` shows `no match; index alive`; if that count is zero or fails, the source itself fails the hunt, whatever the detector says. So Parse accepts the option only when **every source the detector reads** (its `sources`, else all of them) is a kibana source with a `filter`, and refuses it otherwise naming the source.

It does not weaken the other rules:

- Events that exist but cannot be read are still `no records`. Per detector: `authspike` an on-path event whose status is not a status; `signup` an on-path event with no readable status or method, or no event type; `newkey` events with no usable key; `signature` events whose field is not text (all of them); `behaviour` events with no path. A window of garbage is a blind detector.
- A source that fails or is unreachable still fails the hunt.
- A window with something to judge is judged exactly as before. The preceding window is still read, and an empty one still lowers the severity (`baseline_empty`).
- Without the option, nothing changes.

## Example: two sources, each read by its own detectors

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

## Example: gateway and signature over an application request log

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

[Back to the configuration index](../CONFIG.md)
