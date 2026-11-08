# Estate

This page covers the estate collectors, the drift check and estate fact import.

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
- `promote` archives the baseline and then replaces it with a complete snapshot. It refuses an incomplete snapshot and one that skipped a service. It also refuses, touching no file, a snapshot whose baseline was changed since the refresh (`baseline changed since the snapshot; refresh again`; for example by a hand edit or `jb estate facts import`) and a snapshot written before it recorded a baseline digest.

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

[Back to the configuration index](../CONFIG.md)
