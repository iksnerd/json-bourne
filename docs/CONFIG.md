# Configuration

[Back to the README](../README.md)

`jb` reads one YAML file, passed as `--config`. Inside a case (`jb hunt --case DIR`, [CASE-SPEC](CASE-SPEC.md) section 9) the file is one of the case's `config` entries (or another file inside the case: a relative `--config` path is looked for in the case directory first, then in the working directory, and its real path, symlinks followed, must be inside the case), and `jb case check --case DIR` validates it, and `jb case show --case DIR` prints what it would run, reading no environment variable and no credential value. [`examples/jb.example.yaml`](../examples/jb.example.yaml) is a complete starting point with placeholder values.

The loader is strict. An unknown key, an unknown `type`, a missing `type`, a file larger than 1 MiB, a mapping of more than 1000 keys, or an empty file is an error at load time, before any network call, so a typo cannot silently turn a safeguard off. At least one source and one detector are required.

Credentials come from the environment. The file holds the name of a variable, never its value; see [Environment and credentials](config/environment.md).

## Topics

| Page | Covers |
|---|---|
| [Top level and choosing a config](config/top-level.md) | The top-level keys, `commands`, and the feeds-only intel config. |
| [Sources](config/sources.md) | The `kibana` source: keys, `filter`, two sources on one index, `--search`, past windows. |
| [Mappers](config/mappers.md) | `default`, `keycloak`, `nginx_ingress`, `request_dump` and plugin mappers. |
| [Switching off](config/switching-off.md) | The `enabled` switch on sources and detectors. |
| [Detector scoping](config/detector-scoping.md) | `sources`, `empty_is_quiet` and two worked examples. |
| [Detectors: account abuse](config/detectors-account-abuse.md) | `authspike`, `signup`, `newkey` and its history. |
| [Detectors: markers, behaviour, actors](config/detectors-markers-and-actors.md) | `signature`, `behaviour`, `fingerprint`. |
| [Reputation](config/reputation.md) | `jb intel`, the `greynoise`, `sans-isc` and `dnsbl` feeds, `intel`. |
| [Estate](config/estate.md) | Collectors (`estate.external`), the drift check, fact import. |
| [Alerts](config/alerts.md) | The `alerts` list and the `webhook` sink. |
| [Serve](config/serve.md) | `jb serve`, its flags and the Timeline page. |
| [Environment and credentials](config/environment.md) | `jb doctor`, and how credentials reach `jb`. |
| [Watch](config/watch.md) | `jb watch` output and several watchers on one case. |
| [Store](config/store.md) | Database path, locking, source labels, `jb db usage`, `prune` and `compact`. |
