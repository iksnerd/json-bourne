# Switching a source off: `enabled`

This page covers the `enabled` switch on sources and detectors.

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

Run them side by side, one watcher each ([Several watchers on one case](watch.md#several-watchers-on-one-case)):

    jb watch --case . --config config/attack.yaml --name attack --every 5m
    jb watch --case . --config config/health.yaml --name health --every 15m

[Back to the configuration index](../CONFIG.md)
