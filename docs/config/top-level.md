# Top level and choosing a config

The top-level keys of the config file, and how a command picks which of a case's configs answers it.

## Top level

| Key | Type | Required | Meaning |
|---|---|---|---|
| `commands` | list of string | no | The commands this config answers, from a closed set; see [Which config answers a command](#which-config-answers-a-command). |
| `sources` | list | yes, except in a [feeds-only intel config](#a-feeds-only-intel-config) | Each element is a mapping with a `type`. |
| `detectors` | list | yes, except in a [feeds-only intel config](#a-feeds-only-intel-config) | Each element is a mapping with a `type`. |
| `store.path` | string | no | Path of the DuckDB file. |
| `feeds` | list | no | Reputation feeds for `jb intel` (`greynoise`, `sans-isc`, `dnsbl`). Each element is a mapping with a `type`. Ignored by `hunt` and `watch`, which never read a feed key. Required (at least one) in a feeds-only intel config. |
| `intel` | mapping | no | Options of `jb intel`; see [Reputation lookups](reputation.md#reputation-lookups). |
| `estate` | mapping | no | Which external services `jb estate asn\|dns\|ct` and `jb estate refresh` may ask; see [Estate collectors](estate.md#estate-collectors) and [Estate drift](estate.md#estate-drift). `jb estate facts import` reads a local file and needs no entry ([Estate facts](estate.md#estate-facts)). Ignored by every other command. |
| `alerts` | list | no | Extra places `jb watch` delivers alerts, in addition to stdout and `watch.log`; see [Alert delivery](alerts.md#alert-delivery). Ignored by `hunt` and `intel`. |

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

[Back to the configuration index](../CONFIG.md)
