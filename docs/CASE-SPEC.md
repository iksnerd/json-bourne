# Case specification v1

[Back to the README](../README.md)

Status: draft. Scope: how one investigation is defined as data, so the tool stays separate from any one incident.

| Part | State |
|---|---|
| `case.yaml` loader, validation, path confinement, credential refusal, `Guard` (`internal/casefile`) | **Implemented** |
| JSON Schema (`schemas/case.schema.json`), kept equal to the loader by a test | **Implemented** |
| Conformance corpus (`internal/casefile/testdata`) | **Implemented** |
| `jb case check --case DIR` | **Implemented** (`cmd/jb/case.go`). Section 9. |
| `jb case show --case DIR` | **Implemented** (`cmd/jb/caseshow.go`, `internal/config/describe.go`). Section 9. |
| `jb hunt --case DIR`: guard, config choice, default window, store under the case | **Implemented** (`cmd/jb/casehunt.go`). Section 9. |
| `jb watch --case DIR`: the same hunt on an interval, with dedupe memory, an alert log and retention | **Implemented** (`cmd/jb/watch.go`, `internal/app/watch.go`). Sections 3 and 9. |
| `jb hunt --search`, `jb activity --case DIR`, `jb actor status --case DIR` | **Implemented** (`cmd/jb/hunt.go`, `cmd/jb/activity.go`, `cmd/jb/actor.go`, `internal/app/activity.go`). Section 9. |
| `--window NAME`, assets as detector ignore lists | **Proposed.** `--window` is still a duration; only `windows.default` is read. |
| `jb.actor/v1` file format: strict loader, size cap, path confinement (`internal/casefile/actor.go`), JSON Schema (`schemas/actor.schema.json`) kept equal to the loader by a test | **Implemented.** Section 4.4. |
| `jb case check` loads every file in `actors/` and builds each listed config's detectors | **Implemented.** Section 9. |
| `jb.estate-snapshot/v2` snapshots and the estate drift check, facts included (`jb estate refresh`, `diff`, `promote`; `internal/casefile/estate_snapshot.go`, `internal/app/estate_diff.go`, `estate_refresh.go`) | **Implemented.** Section 4.5.1. No JSON Schema yet (the loader is the specification). |
| `jb.estate/v2` file format: strict loader, size cap, path confinement, source allowlist, `service` nodes, facts and assessments (`internal/casefile/estate.go`), JSON Schema (`schemas/estate.schema.json`) kept equal to the loader by a test; `jb case check` loads every file in `estate/`. `jb.estate/v1` is removed. | **Implemented.** Sections 4.5 and 9. [RFC 0001](rfcs/0001-estate-v2.md). |
| `jb estate facts import FILE`: facts from an export file you hold, source `scan-cache` (`internal/casefile/estate_facts_import.go`, `estate_facts_import.go`) | **Implemented.** Section 4.5.2. |
| `jb estate --case DIR IP...`: passive reverse-DNS and RDAP collector that merges into an estate file | **Implemented** (`cmd/jb/estate.go`, `internal/app/estate.go`, `internal/adapters/rdap`, `internal/adapters/dnsptr`). Section 9. |
| `type: fingerprint` detector reading actor files (`docs/CONFIG.md`) | **Implemented** (`internal/adapters/detectors/fingerprint`). |
| `jb.assets/v1` file format (section 4.3) | **Proposed.** The example file shows it; no code parses it. The fingerprint detector takes its own `ignore_ips` setting until it does. |
| Scope enforcement (refusing out-of-scope targets) | **Proposed.** `scope` is loaded and validated; nothing consults it yet. |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.

## 1. Purpose

`jb` is a tool; an incident is data. A case is a directory that holds everything specific to one incident: which logs to read, which addresses are ours, which indicators belong to the actor, what the people involved wrote down, and the raw evidence. The tool holds none of it. Two consequences:

- The tool's repository can be public or shared without leaking an incident. Fixtures, docs and examples in the tool are synthetic.
- A case can be archived, handed over or deleted as a unit, and its safety rules (section 6) travel with it.

## 2. Non-goals

- Not a database. Findings live in the evidence store (`docs/ARCHITECTURE.md`); the case only says where.
- Not a case-management system: no assignment, tickets or workflow.
- Not a way to relax the tool's safety posture. A case may only narrow what `jb` does (`docs/POLICY.md`).
- v1 does not parse the contents of `assets/`, `notes/` or `reports/`, and does not read `evidence/`. It parses `actors/` (section 4.4) and `estate/` (section 4.5).

## 3. Directory layout

```
my-case/                 # its own private repository is typical; never inside the tool's repo
  case.yaml              # required; section 5
  .gitignore             # MUST cover evidence/ when the case is in a git work tree
  config/                # jb hunt config files (docs/CONFIG.md)
  assets/                # our own addresses and keys that are never suspects
  actors/                # indicator and actor files
  estate/                # infrastructure relationship maps, from passive sources (section 4.5)
    snapshots/           # dated drift-check snapshots (section 4.5.1), not read as maps
    archive/             # baselines replaced by `jb estate promote`
  notes/                 # human documents, free form
  reports/               # human documents, free form
  evidence/              # raw logs and exports; may hold personal data
    jb.duckdb            #   the evidence store (jb hunt, jb watch), when store.path is empty
    watch-state.json     #   jb watch: what it has already alerted (section 3.1)
    watch.log            #   jb watch: every alert and cycle line, append-only
    watch.lock           #   jb watch: the single-instance lock (section 3.1)
    watch-status.json    #   jb watch: the status record a program reads (section 3.1)
                         #   with --name NAME: watch-state.NAME.json, watch.NAME.log, watch.NAME.lock,
                         #   watch-status.NAME.json
```

Only `case.yaml` is required. Every directory name is the default of a key in `paths` and can be changed. A tool MUST NOT read `evidence/` for documentation, indexing or search; only an explicit hunt or import reads it.

### 3.1 Files `jb watch` keeps in `evidence/`

`jb watch` writes four small files next to the store. All are evidence in the sense of this section: they name addresses and tags from the logs, so they stay inside the ignored directory and a tool MUST NOT read them for documentation or search.

**`watch-state.json`** is the dedupe memory, replaced atomically (temp file in the same directory, sync, rename) after every cycle. It is strict JSON: an unknown field, trailing data, a different `version`, an unknown severity, an empty key or a missing time all make it corrupt. A corrupt file is renamed to `watch-state.json.corrupt`, the cycle raises a `watch-state-load` alert, and the watch carries on with an empty memory, so the cost is repeated alerts and never a stopped watcher. A missing file is a cold start.

```json
{
  "version": 1,
  "seen":   { "authspike:192.0.2.7": { "at": "2026-11-05T12:00:00Z", "severity": "high" } },
  "health": { "watch-incomplete|source kibana:logs-auth-*": { "at": "2026-11-05T12:00:00Z", "fingerprint": "unavailable: ..." } }
}
```

- `seen`: key is a finding tag; `at` is when it was last alerted, `severity` is `info`, `check`, `activity`, `high` or `critical`. An entry older than `--ttl` is dropped on the next save. A finding whose tag is present and inside `--ttl` is held back unless its severity is higher than the recorded one. A finding without a tag is never held back.
- `health`: optional, omitted while nothing is down. Key is `<alert tag>|<component>`; `fingerprint` is the failure text with the run id and timestamps removed. An identical failure inside `--repeat` of `at` is held back; a different fingerprint, or the component finishing again, alerts at once and (for a recovery) removes the entry. Findings never use this section.
- A build that predates `health` rejects a file that has it as corrupt (it keeps it as `.corrupt`); a file without it loads in any build.

**`watch.log`** is append-only, one line per alert or cycle line, each synced before the alert counts as delivered. Control characters in an alert text are escaped, so a log line cannot be forged by log content. Alerts also go to stdout; nothing goes over a network.

**`watch.lock`** is the single-instance lock: an exclusive `flock(2)` held for as long as the watcher runs, with the holder's PID written in it. A second `jb watch` for the same case is refused, naming that PID. The kernel drops the lock when the holder exits however it dies, so a file that still holds a dead PID is stale and is taken over; the file is never removed. On Unix it is emptied when the holder ends normally; where `flock` is not available the file is removed instead. Where `flock` is not available the lock is an exclusive-create file that a crash leaves behind.

**`watch-status.json`** (`apiVersion: jb.watch-status/v1`) is the machine-readable health record, for a program that needs to know whether the watcher is alive and what it runs without parsing `watch.log` or running `ps`. `jb watch` writes it when it starts and again when every cycle ends, replaced atomically like the state file (temp file in the same directory, sync, rename; mode 0600). It holds names, counts and times, never an error text or a credential. A reader MUST accept only the version it knows and MUST treat an unknown field, trailing data, no `pid`, no `started` or a non-positive `everySeconds` as an unreadable record.

```json
{
  "apiVersion": "jb.watch-status/v1",
  "name": "edge",
  "pid": 4242,
  "started": "2026-11-05T09:00:00Z",
  "updated": "2026-11-05T12:00:03Z",
  "config": "config/hunt.yaml",
  "everySeconds": 300,
  "windowSeconds": 3600,
  "ttlSeconds": 10800,
  "keepSeconds": 172800,
  "repeatSeconds": 1800,
  "lastCycle": {
    "run": "watch-edge-20261105T120000Z",
    "verdict": "INCOMPLETE",
    "ended": "2026-11-05T12:00:03Z",
    "windowFrom": "2026-11-05T11:00:00Z",
    "windowTo": "2026-11-05T12:00:00Z",
    "new": 1, "suppressed": 0, "repeated": 2, "recovered": 0,
    "failed": ["source kibana:logs-auth-*"]
  },
  "nextDue": "2026-11-05T12:05:00Z"
}
```

- `name` is the watcher name, `""` for the unnamed one; it MUST equal the name in the file name. `pid` is the process that wrote the record. `config` is the config's path relative to the case with `/` separators, `""` when it is not inside the case. The five `...Seconds` keys are the run's `--every`, `--window`, `--ttl`, `--keep` and `--repeat`.
- `lastCycle` is absent until the first cycle ends. `verdict` is `QUIET`, `FINDINGS`, `INCOMPLETE` or `FAILED` (the `CYCLE` line's word, section 9). `failed` lists the components that did not finish and is `[]`, never `null`. `ended` is when the cycle finished, not when its window ended.
- `nextDue` is when the next cycle starts: the start of the previous cycle plus `--every`, or now when that has passed. It is absent for `--once`. Before the first cycle it is the start time.
- The record outlives the process. A record with no process behind it means the watcher stopped, not that it is healthy; judge liveness with the lock as `jb watch status` does.
- A failed write of the record raises a `watch-status-save` alert and does not stop the watcher or change the cycle's verdict.

**Is a watcher alive?** `jb watch status` (section 9) decides it, and a program MAY apply the same rule: the lock is held (a non-blocking shared `flock(2)` request on `watch.lock` is refused; the probe takes no exclusive lock and drops its own at once, and a file that does not exist is free) and the last cycle ended no more than 3 x `everySeconds` ago (before the first cycle, counted from `started`). Held and recent is `running`; held and not recent is `stale`; not held, with a record, is `stopped`; no readable record is `unknown`. A PID in `watch.lock` is not proof of a live holder, because a killed watcher leaves it behind.

**Named watchers.** `jb watch --name NAME` (`^[a-z][a-z0-9_-]{0,31}$`) replaces the four names above with `watch-state.NAME.json`, `watch.NAME.log`, `watch.NAME.lock` and `watch-status.NAME.json`, all in the same `evidence/` directory, and names its runs `watch-NAME-<UTC time>`. Every format in this section is unchanged; only the file names and run ids differ, and each alert line and `CYCLE` line carries `[w:NAME]`. Dedupe memory is per file, so the same finding may alert once per named watcher. Without `--name` the files and run ids are exactly the ones above.

**`jb.duckdb`** grows by a window and its baseline per cycle. `--keep` removes watch runs older than it (section 9).

## 4. File formats

### 4.1 `case.yaml`

Section 5.

### 4.2 `config/`

Files listed under `config` are ordinary `jb` configs: the format of `docs/CONFIG.md` (`sources`, `detectors`, `store`). The case loader checks that each listed file exists and stays inside the case. It does not parse them; `internal/config` does, in `jb case check` (load only, no credential read) and again at hunt time. `examples/case/config/hunt.yaml` is validated by `internal/config` in `internal/casefile/example_test.go`.

### 4.3 `assets/` (proposed, `jb.assets/v1`)

Things that MUST never be reported as suspects: the gateway, scanners, staff networks. A mapping with `apiVersion` and `never_suspects`, a list of `{kind, value, why}`. `why` is required, so the next reader knows whether an entry is still true. This is the case-level form of the detector `ignore_keys` setting. A gateway that appears as the client in upstream logs is the usual reason.

### 4.4 `actors/` (`jb.actor/v1`, implemented)

One file per actor, `.yaml` or `.yml`, directly inside `paths.actors`. The loader is `casefile.LoadActors` / `LoadActorFile`; `schemas/actor.schema.json` mirrors it. Keys are lower-case except `apiVersion`; an unknown key is an error, at any depth.

| Key | Type | Required | Rules |
|---|---|---|---|
| `apiVersion` | string | yes | MUST be `jb.actor/v1`. Checked before the other keys. |
| `id` | string | yes | `^[a-z0-9][a-z0-9-]{0,62}$`. Unique across the actors directory; it is part of every finding tag. |
| `label` | string | yes | One line, 1 to 200 bytes. |
| `confidence` | string | yes | `low`, `medium` or `high`. A label for the reader; the detector does not read it. |
| `indicators` | list | yes | 1 to 1000 entries. No two entries with the same kind, value and method. |
| `detection.noise_paths` | list of string | no | Case-insensitive substring markers of scanner traffic, each 2 to 256 bytes with no surrounding space (a one-character marker such as `/` would call every path noise). At most 200. |
| `detection.bare_root_4xx_is_noise` | bool | no | Default `true`: a 4xx on `/` is a scanner probe. |
| `detection.grant_paths` | list of string | no | Substrings of a token endpoint's path, each starting with `/`, no query string. At most 200. |

Each indicator has `kind` and `value` (required), `first_seen` (`YYYY-MM-DD`) and `note` (one line, 300 bytes) for any kind, and `type`, `method`, `probe_target` for `fingerprint` only (any of them on another kind is an error). `value` is kept as the text written in the file: a run of digits is not turned into a number.

| `kind` | `value` |
|---|---|
| `user_agent` | 1 to 1024 bytes, no control character, no leading or trailing space. Compared in full by the `fingerprint` detector. |
| `ip` | An IP address in canonical form. A CIDR or a zoned address is refused. |
| `asn` | Digits only, 1 to 4294967295. |
| `domain` | A lower-case DNS name. |
| `fingerprint` | 1 to 512 bytes, no whitespace. `type` (`jarm`, `ja3`, ...) and `method` are required; `probe_target` SHOULD be given. |

Rules:

- A `fingerprint` indicator MUST name its `method` (how it was probed). Two fingerprints taken by different methods MUST NOT be compared: a TLS fingerprint taken against `host:443` and against `<ip>:443` can differ because the server selects a configuration by name. A comparison across methods reports a change that did not happen.
- A user agent is matched as a whole string, never by prefix or substring. A substring of a stale browser build also matches real customers.
- A user agent alone is not a fingerprint: commodity scanners reuse it. `detection` is how the file says what is noise, and what a success looks like.
- An IP address is an observation, not an identity. A CDN edge address is not a client. Nothing matches on an `ip`, `asn` or `domain` indicator; they are the case's record. An indicator file SHOULD say so in `note` rather than imply attribution.
- The credential scan of section 6.3 applies to the whole file except the `value` of a `fingerprint` indicator, which legitimately looks like a secret (a JARM hash is 62 hex characters). A fingerprint's `note` and every other string is still scanned.
- The file is at most 1 MiB, a single YAML document, and must resolve inside the actors directory (section 6.2 applies, and a symlink to another directory of the case is refused too).

The `fingerprint` detector (`docs/CONFIG.md`) turns an actor file into findings. Its judgement of an event (match, ignored, noise, genuine, grant) and its severities are specified there.

### 4.5 `estate/` (`jb.estate/v2`, implemented)

An estate file is the case's map of infrastructure: which addresses, hosts, domains, networks and organisations relate to which, as public registries and DNS describe them. It is data. Drawing it is not core's job: a viewer reads the file. One file per map, `.yaml` or `.yml`, directly inside `paths.estate`. The loader is `casefile.LoadEstates` / `LoadEstateFile`; `schemas/estate.schema.json` mirrors it. An unknown key is an error, at any depth. `jb.estate/v1` is removed: a v1 file is refused with an error that names both versions and says to rewrite it. The migration is one line, changing `apiVersion` to `jb.estate/v2`; the file stays valid.

| Key | Type | Required | Rules |
|---|---|---|---|
| `apiVersion` | string | yes | MUST be `jb.estate/v2`. Checked before the other keys. |
| `id` | string | yes | `^[a-z0-9][a-z0-9-]{0,62}$`. Unique across the estate directory. |
| `caveat` | string | yes | Not empty and not only space; one line of up to 2000 bytes. It MUST say that the map shows infrastructure ownership and relationships, not who typed the commands. The loader checks that it is present, not what it says. |
| `nodes` | list | yes | 1 to 5000 entries. |
| `edges` | list | no | At most 20000. |
| `absences` | list | no | At most 5000. |
| `assessments` | list | no | At most 2000. An empty list is valid. |

Every node, edge, absence and fact MUST carry `source`, `method` and `observed`. A claim missing any of them is a load error, not a gap to fill later: two observations taken by different methods cannot be compared, and a comparison across them reports a change that did not happen.

| Field | Rules |
|---|---|
| `source` | One of the sources in `docs/POLICY.md` (`rdap`, `rdns`, `dns`, `whois`, `crt.sh`, `ct-log`, `bgp`, `passive-dns`, `scan-cache`). Any other value, in particular the name of a scanner, is refused. |
| `method` | How it was obtained, for example the exact query: one line, 1 to 500 bytes. |
| `observed` | An RFC 3339 timestamp with a zone, for example `2026-11-06T10:00:00Z`. |

A **node** has `id`, `kind` (`ip`, `host`, `domain`, `asn`, `org`, `network`, `service`) and `label` (one line, up to 255 bytes; an `ip` node's label is the address in canonical form). The `id` is lower case, matches `^[a-z0-9_][a-z0-9._:/_-]{0,253}$` and starts with the kind and a colon (`ip:192.0.2.10`, `host:edge.example.com`). Ids are unique within a file. A `service` node names a third-party service that infrastructure talks to (`service:dns-provider`); its `source` is the source that observed the relationship. There is no node kind for a person.

A node MAY carry `facts`, a list of at most 50 entries (an empty list is valid), and a file holds at most 20000 facts in total. A **fact** is an observation about the node, a claim like any other: `key` (`^[a-z][a-z0-9_.-]{0,63}$`; recommended: `port.open`, `os`, `tls.cn`, `cpe`, `vuln`, `tech`), `value` (text read as written, so `22` is the text `22`; a list or a map is an error; one line, 1 to 500 bytes), and `source`, `method`, `observed` as above. Two facts of one node MAY share a `key`, because a host has many open ports. Two facts are identical, and a duplicate and an error, when `key`, `value`, `source` and `method` are equal byte for byte; `observed` is not compared. A fact SHOULD NOT hold a judgement: a key such as `classification` or `verdict` belongs in an assessment, and the loader cannot enforce that.

An **assessment** is one author's judgement about one node. It is opinion, not a claim, and it never sits on a node. Fields: `id` (`^[a-z0-9][a-z0-9-]{0,62}$`, unique among the assessments of the file), `subject` (a node id in the file), `label` (`^[a-z][a-z0-9_-]{0,31}$`, lower case), `by` (who decided: a role or a handle, one line, up to 128 bytes), `decided` (RFC 3339 with a zone; a time in the future is allowed), `basis` and optionally `note` (one line, up to 500 bytes). `by` and `basis` are REQUIRED. `basis` lists 1 to 20 references without duplicates; each is a node id of the file, or `<node id>#<fact key>`, which resolves only when that node has a fact with that key (the loader splits at the first `#`; a node id cannot contain one). A reference that does not resolve is a load error. The `caveat` of a v2 file SHOULD also say that assessments are the opinion of their author; the dashboard prints a fixed notice with every assessment and does not rely on the caveat.

An **edge** has `from`, `to` (node ids in the same file), `relation` (`^[a-z][a-z0-9_-]{0,63}$`, for example `ptr`, `within`, `registered_to`), and optionally `confidence`: `stated` (read straight from the record) or `inferred`. An `inferred` edge MUST give `inferred_from`, one line saying what it was inferred from; `inferred_from` on any other edge is an error. An edge with no `confidence` is allowed and claims neither. A dangling endpoint and a self edge are errors. Two edges with the same `from`, `to`, `relation`, `source` and `method` are a duplicate and an error; the same endpoints seen by another source or method are a second observation and are allowed.

An **absence** has `subject` (a node id), `source`, `method`, `observed` and `answer: not_found`. It records that a source was asked and really said it holds nothing (an RDAP 404, an NXDOMAIN). It is an answer. A lookup that failed, timed out, was rate limited or returned a non-2xx status is not an answer and is never written to an estate file, in any form.

Rules:

- An address is an observation. A CDN or proxy edge address's registration and reverse name describe the CDN, not the visitor behind it. An estate MUST NOT be read as attribution.
- The credential scan of section 6.3 applies to every string in the file.
- The file is at most 4 MiB, a single YAML document, and must resolve inside the estate directory (section 6.2 applies, and a symlink to another directory of the case is refused too).
- Rewriting a file (`jb estate`) does not preserve comments.
- The collectors write no facts and no assessments. `jb estate refresh` carries both through (see 4.5.1); `jb estate facts import` adds facts (4.5.2).
- Relations the collectors write: `ptr`, `within`, `registered_to` (`jb estate IP`); `originated_by`, `announced_in`, `held_by` (`jb estate asn`, source `bgp`); `resolves_to`, `cname`, `mx`, `ns`, `spf_authorises`, `spf_include`, `spf_redirect` (`jb estate dns`, source `dns`); `ct_candidate` (`jb estate ct`, source `crt.sh`, always `inferred` with `inferred_from`: a name on a certificate is a candidate host, not a confirmed one). The relation list is open; the loader checks the shape, not the vocabulary.
- `bgp`, `crt.sh` and `dns` collectors are off until the case config enables them, and a result cut at a cap or any lookup that failed ends the run incomplete (`docs/POLICY.md`, `docs/CONFIG.md`).

#### 4.5.1 Estate snapshots (`jb.estate-snapshot/v2`, implemented)

A snapshot is one dated run of the passive collectors over the targets an estate file already records (`jb estate refresh`). It is how the estate drift check (`jb estate diff`) has two states to compare. Snapshots live in `<paths.estate>/snapshots/<id>.yaml`, where `<id>` is the UTC time of the run, `20261106T100000Z` (`YYYYMMDDThhmmssZ`). A file in `estate/snapshots/` is never read as an estate map: the estate loader reads only files directly inside `paths.estate`, so `jb case check` and the dashboard do not see snapshots.

Loader: `casefile.LoadEstateSnapshot` / `ListEstateSnapshots`. An unknown key is an error at any depth, and `complete` must be written out (a missing flag is neither value). A missing, corrupt, unknown-version or misnamed file is an error that names it, never an empty baseline; a corrupt newest snapshot is never skipped in favour of an older one. The file is at most 6 MiB, one YAML document, confined to the snapshot directory like an estate file (section 6.2; a symlinked `snapshots` directory is refused), and the credential scan of section 6.3 applies to every string.

| Key | Type | Required | Rules |
|---|---|---|---|
| `apiVersion` | string | yes | MUST be `jb.estate-snapshot/v2`. A `jb.estate-snapshot/v1` file is refused with an error that says to rewrite it or regenerate it with `jb estate refresh`. |
| `id` | string | yes | `^[0-9]{8}T[0-9]{6}Z$`; MUST equal `taken` in UTC and the file name. |
| `taken` | string | yes | RFC 3339 with a zone. |
| `complete` | bool | yes | `true` only when every lookup got a full answer and no claim was dropped. `true` with a listed failure, or `false` with none, is an error. |
| `based_on` | string | no | The estate file the targets were read from (one line). |
| `note` | string | no | One line. |
| `targets` | map | no | `domains`, `addresses`, `asns`: what was asked, for the reader. |
| `services` | list | yes | One entry per collector: `name` (`rdap` covers reverse DNS and RDAP, `bgp`, `dns`, `crt.sh`), `state` (`ran`, `skipped`, `none`), `targets` (count) and an optional `reason`. A service the case config does not enable is `skipped`, never absent. |
| `failures` | list | no | `target`, `lookup`, `reason` (one line each, at most 500 bytes, at most 500 entries): every lookup that failed, timed out, was rate limited, was cut at a cap or was not asked, and every claim dropped because it conflicted with another in the same run. |
| `estate` | map | yes | A `jb.estate/v2` body (section 4.5), validated as one. An incomplete snapshot in which every lookup failed may have no nodes. |

Rules:

- **An incomplete snapshot is a record of a run, never a state of the estate.** `jb estate diff` refuses it on either side and `jb estate promote` refuses it. A snapshot that skipped a service is complete for what it asked but cannot be promoted, because the baseline would silently lose that service's claims.
- **A snapshot is never overwritten.** It is written to a temporary file in its directory and hard-linked to its final name, which fails when the name exists; a second run in the same second fails with `snapshot already exists`. The estate file is not touched by a refresh.
- **Targets are read back from the claims, not guessed.** A domain is a `dns` target if it has an edge or absence from source `dns` (or is a `dns` node that no `spf_include`/`spf_redirect` edge points at), a `ct` target if it has a `ct_candidate` edge, an absence or a node from `crt.sh`; an address is an rdns/rdap target if it has an edge, absence or node from those sources, a BGP address target if it has an `announced_in` edge or a `bgp` absence; an AS is a BGP target if it has a `bgp` absence or an `originated_by` edge whose method no `announced_in` edge shares (an address question writes both). A name that only appeared as an answer (an SPF include, a PTR name, the origin AS of an address) was not asked about and is not a target.
- **Facts and assessments.** The collectors write neither, so a refresh copies the facts of the baseline onto the same nodes of the snapshot unchanged (value, source, method and time); it does not ask them again. A node the snapshot does not name takes its facts with it: the diff lists that group of facts as not comparable, and promotion archives the old file. An assessment is carried when its subject and every basis reference still resolve in the snapshot, and otherwise is left out of the snapshot (it stays in the archive). `diff` compares facts as a set per node, key, source and method: a value that appears or disappears is a change of type `fact` (subject `<node id>#<key>`, the `value`, and both observation times, the earlier side's being the latest time of that group). A group that exists on one side only is listed as not comparable with its `subject` and is never drift. A port list that gains an entry is one added value, not a replaced list. Fact changes raise no finding. Assessments are opinion and are not compared.
- **Promotion** (`jb estate promote`) writes the snapshot's `estate` body over the baseline file after copying the baseline, unchanged, to `<paths.estate>/archive/<stem>-<id>.yaml` (never overwritten; the archive is not read as a map either). Nothing else changes the baseline.
- **What a comparison means.** Every claim carries `source` and `method`; two claims are comparable only when both are equal. The method is the exact question, so another resolver, another RDAP or BGP service URL or another query is a different method. A question present on one side only is *not comparable*, is listed with its claim count and observed time, and is never counted as drift. An absence is an answer: *was present, now absent* and *was absent, now present* are changes. A node is unique by id within a file, so it carries the source and method of the question that first named it; it is compared only when both sides name it through the same question and counted as added or removed only when that question is comparable. A baseline that was built by merging several runs (`jb estate dns` into an existing file) may hold claims of the same question from different times; take the baseline from a promoted snapshot to keep one question's claims from one run.

#### 4.5.2 Facts import (`jb.estate-facts/v1`, implemented)

`jb estate facts import --case DIR [--file NAME] [--apply] FILE` adds facts to the nodes of an estate file from one export file the operator already holds. It reads that one file from disk. It never contacts the network, so it needs no `estate.external` switch; `docs/POLICY.md` ("The test for a source") explains why the role `scan-cache` is passive. jb reads no vendor format: the operator converts an export to this shape with a script they control.

The import file is one JSON object, at most 1 MiB, with at most 5000 facts (values) in all. An unknown key is an error at any depth, and so is a second JSON value after the first.

| Key | Required | Rules |
|---|---|---|
| `apiVersion` | yes | MUST be `jb.estate-facts/v1`. |
| `method` | yes | How the data was obtained, for example the export and the script that converted it. One line. |
| `source_note` | yes | Where the data came from: the store and the date of the export. One line. |
| `observed` | yes | RFC 3339 with a zone: when the store observed the data. |
| `facts` | yes | A non-empty list of entries. |

An entry has `node` (a node id that is already in the estate file), `key` (the fact key rule above), `values` (a non-empty list of strings, each one line of 1 to 500 bytes, no duplicates; a number is an error, so the script writes `"22"`) and optionally `observed`, which replaces the file's time for this entry. Every string goes through the credential scan of section 6.3.

Each value becomes one fact with `source: scan-cache`, the entry's `key`, and `method` set to `<method> (source: <source_note>)`. The method is part of the identity of a question, so an export taken by other means is a different method and its facts are not compared with these. A fact already recorded (same key, value, source and method) is left as it is, with its original time, so importing the same export twice changes nothing.

The command is a dry run unless `--apply` is given, and says what it would add. The whole import is refused and the estate file left as it was when a node is not in the file, when a node would hold more than 50 facts or the file more than 20000, or when the result would not load. The target file must exist: an import adds facts to nodes recorded first. Rewriting the file does not preserve comments. The library function is `jb.EstateFactsImport` with `EstateFactsImportOptions{Apply}`.

## 5. `case.yaml` reference

All keys are lower-case, except `apiVersion`. Unknown keys are errors (section 6.1).

| Key | Type | Required | Default | Rules |
|---|---|---|---|---|
| `apiVersion` | string | yes | none | MUST be `jb.case/v1`. |
| `id` | string | yes | none | `^[a-z0-9][a-z0-9-]{0,62}$`. |
| `title` | string | yes | none | One line, 1 to 200 bytes. |
| `status` | string | yes | none | `open`, `monitoring` or `closed`. |
| `opened` | date | yes | none | `YYYY-MM-DD`. |
| `classification` | string | no | `internal` | Free string, one line, up to 64 bytes. The tool attaches no meaning to it. |
| `owners` | list of string | no | empty | Roles, not people: `^[a-z][a-z0-9_-]{0,63}$`. An email or a name does not match. |
| `scope.domains` | list of string | no | empty | Lower-case DNS names. A name covers itself and its subdomains. |
| `scope.hosts` | list of string | no | empty | Lower-case DNS names or IP literals; exact match. |
| `scope.asns` | list of integer | no | empty | 1 to 4294967295. |
| `scope.cidrs` | list of string | no | empty | Masked CIDRs, for example `192.0.2.0/24` (`192.0.2.1/24` is refused). |
| `windows` | map name to duration | no | `{default: 24h}` | Name `^[a-z][a-z0-9_-]{0,31}$`; value `^[1-9][0-9]{0,3}[hd]$`. Named lookback windows for hunts. |
| `retention.evidence_days` | integer | no | `90` | 1 to 3650. |
| `retention.findings_days` | integer | no | `365` | 1 to 3650. |
| `paths.assets` `.actors` `.estate` `.notes` `.reports` `.evidence` | string | no | the key name | Section 6.2. The six MUST be distinct. |
| `config` | list of string | no | empty | Case-relative files; each MUST exist and be a regular file. |
| `handling.passive_only` | bool | no | `true` | MUST be `true` in v1. `false` is refused. |
| `handling.redact_in_reports` | list | no | `[email]` | Any of `ip`, `email`, `hostname`, `account_id`, `user_agent`; no duplicates. An explicit `[]` redacts nothing. |

`scope` is how out-of-scope work will be refused: an empty scope covers nothing. In v1 the loader validates it and no command consults it (proposed).

`retention` states a policy. Nothing deletes anything in v1 (proposed).

## 6. Safety rules

Each rule is checked by the loader and has a corpus case in `internal/casefile/testdata/invalid`.

1. **Strict keys.** An unknown key MUST be an error. Forward compatibility comes from an `apiVersion` bump (section 7), never from ignoring a key: a silently ignored `passive_only`-style key is a safeguard that is not there.
2. **Paths are confined.** Every path in `paths` and `config` MUST be relative, MUST use `/`, MUST NOT contain a `..` element, MUST NOT be empty or name the case directory itself, and MUST resolve inside the case directory after symlinks (`filepath.EvalSymlinks` on the longest existing prefix). A dangling symlink is refused: it cannot be shown to stay inside. A symlink that stays inside is allowed.
3. **No credentials.** A value shaped like a key or token in any string field of `case.yaml` MUST be refused. A case names an environment variable (as `api_key_env` does in `docs/CONFIG.md`) and never holds the value. The check is a heuristic backstop: private-key headers, common vendor token prefixes, JWTs, bearer values, URLs with a password, hex runs of 40 or more, and mixed-case alphanumeric runs of 32 or more with high entropy. It favours refusing a doubtful string. The error names the field and line and MUST NOT echo the value. `case.yaml` is scanned in full. An actor file is scanned too, except the `value` of a `fingerprint` indicator (section 4.4); `assets/` is not scanned yet (open question 3).
4. **Passive only.** `handling.passive_only` MUST be `true`. A case cannot enable active scanning of third-party hosts. v1 has no key that could.
5. **Evidence is ignored by git.** When the case directory is inside a git work tree, `paths.evidence` MUST be ignored by git, and git MUST track nothing under it except `.gitkeep`. `casefile.Guard(dir)` returns `(GuardStatus, error)`:
   - `GuardIgnored`, nil: inside a work tree, ignored, nothing tracked.
   - `GuardNotWorkTree`, nil: not inside a work tree. This is **not** a pass for the future: if the case is put under git later, run the guard again. The two results are distinct so a caller can say so.
   - an error: inside a work tree and not ignored; a tracked file under the directory; `git` failed, timed out or answered something unreadable; `git` is missing while a `.git` exists above. An answer that cannot be read is an error, never a pass.

   `Guard` asks git (`git check-ignore -q` on a probe path inside the directory, so a directory-only pattern such as `evidence/` and a missing directory both work), so global excludes and nested ignore files count. `Load` does not run git, so loading a case never starts a subprocess. A caller that is about to write evidence MUST call `Guard(c.EvidenceDir())` first. The one `os/exec` use in the package is `guard.go`.

Also: `case.yaml` MUST be a single YAML document and at most 1 MiB; `Load` refuses an empty file.

## 7. Versioning

- `apiVersion` is `jb.case/v1`. A reader MUST refuse any other value, with an error that names the value and the version it reads and tells the writer to rewrite the file to the current version. The version is checked before the other keys, so an old file reports "unsupported apiVersion", not the first key it does not know.
- The number increments when the format changes incompatibly: a new key, a new enum value, or a looser or stricter rule. `jb` and one other program are the only users and nothing is public, so there is no support for old versions. A tool reads only the current version and MUST NOT guess: a file is read by the rules of its own `apiVersion`.
- The schema and the loader move together. `schema_test.go` fails when a property name, a required key, an enum or `additionalProperties: false` differs. The schema cannot express the filesystem and credential rules; the corpus covers those.

## 8. Evidence and personal data

- `evidence/` may hold personal data. It is never committed, never read by docs tooling, and never quoted into notes or reports beyond what `handling.redact_in_reports` allows.
- `notes/` and `reports/` are human documents. They MAY be committed to the case repository, so they MUST NOT contain evidence content. A report that cites an address does so as an indicator, redacted per `redact_in_reports` when it leaves the team.
- `retention` is the stated lifetime; deleting expired evidence is the owner's job until a command does it (proposed). The one exception is `jb watch --keep`, which prunes its own `watch-*` runs from the store (section 9); it never deletes files and does not read `retention`.
- A case repository SHOULD be private. `classification` is a label for the reader; it grants nothing.

## 9. Commands

**`jb case check --case DIR [--output table|json]`.** Runs `casefile.Load`, then `Guard` on the evidence directory (`paths.evidence`), then `casefile.LoadActors` (every actor file in `paths.actors`; one FAIL line names each file that does not load), then `casefile.LoadEstates` (every estate file in `paths.estate`, reported as `estate`, same rule), then `config.Load` on every `config` entry followed by building its detectors against the case (`File.UseCase`, `File.BuildDetectors`). That proves a file a detector names, such as the actor files of a `type: fingerprint` detector, exists, loads and passes the detector's own checks. Neither step reads an environment variable, so no API key is needed and none is printed. It never reads `evidence/`. The report gives id, title, status, opened, the guard result (`ignored` or `not a git work tree`, kept distinct; the second prints a reminder that it is not a pass for later), the actors (count and ids) and OK or FAIL per config. A config that is not listed under `config` is not checked. Exit 0 only when everything passes, 1 on any failure (a case that does not load, a guard error, a config that does not load), 2 for a usage error. With `--output json` the report is on stdout in both cases, with `ok` true or false.

**`jb case show --case DIR [--config NAME] [--output table|json]`.** Prints the effective configuration of one config of the case, chosen as `jb hunt --case` chooses it (`--config` names a listed config or a file inside the case; the only config otherwise). It loads `case.yaml` and the config, places the store as a hunt would, and prints plain data built by `File.Describe` (`internal/config/describe.go`): each source (type, name, URL without query, index, the name of its credential variable, other options), each detector (type, name, the options the file sets, its `sources:` scope, the sources it reads, enabled), the store path (`~/` unexpanded; an empty `store.path` outside a case prints as the default), and each alert sink (type, the name of the variable that holds the address, options). A webhook's host is not shown, because it is the value of that variable. An option the file does not set takes the detector's own default and is not listed. It reads no environment variable, runs no `git` command, makes no connection and never opens the store or `evidence/`. Exit 0, 1 when the case or config does not load, 2 for a usage error. The Go function is `jb.CaseShow`.

**`jb estate --case DIR [--file NAME] [--rdap-url URL] [--resolver HOST:PORT] [--timeout D] [--max-ips N] [--output table|json] IP...`.** The passive collector for `estate/`. For each address it asks a DNS resolver for the PTR record and an RDAP service (default the `rdap.org` bootstrap, or `--rdap-url`) for the registration of the range that covers it, and merges the answers into `<paths.estate>/<NAME>` (default `estate.yaml`, created with `id: estate` and a default `caveat` if missing). Every node, edge and absence carries `source`, `method` (the exact query) and `observed`.

- Passive. Queries go to the resolver and the RDAP service, never to an address under investigation. The HTTP dialer refuses a connection whose resolved address is the target, a redirect to a bare IP address is refused, and a `--resolver` that is one of the addresses is a usage error. `net/http` is confined to the `rdap` adapter (with the other remote adapters) by `internal/archtest`; DNS is a `net.Resolver` behind the `core.PTRResolver` port.
- Bounded. `--timeout` (1s to 1m, default 10s) per lookup, at most 1 MiB read per RDAP response, at most three redirects, and at most `--max-ips` addresses (default 20, at most 100). More addresses than the cap is a usage error; the list is not truncated.
- A lookup that failed, timed out, was rate limited (HTTP 429; the registry is not asked again in that run) or got a non-2xx status is never data. It is listed, the run ends with `INCOMPLETE` and exit status 1, and nothing is stored for it. Answers that did arrive are kept. A real 404 or NXDOMAIN is recorded as an `absences` entry.
- Merge, never overwrite. A node with a known id but a different kind or label, or an edge with the same key but a different confidence or basis, is reported as a `CONFLICT`; the recorded claim stays, edges and absences that would attach to the conflicting node are dropped, and the run exits 1. Identical claims are left as they are (their `observed` is not refreshed). A file that exists but does not load is never replaced: the command exits 1.
- Every result, in either format, carries the note that an estate map shows ownership and relationships, not who typed the commands, and that a CDN or proxy edge address says nothing about the visitor.
- Exit 0 only when every question got an answer and nothing conflicted; 1 otherwise; 2 for a usage error.

**`jb hunt --case DIR [--config FILE] [--window DURATION] [--until TIME]`.**

1. Loads the case and runs the guard as `case check` does. A load error or a guard error stops the hunt with exit 1 before any config is read or any request is made. `passive_only: false` therefore never reaches a hunt: the loader refuses it.
2. Chooses the config. `--config` must be one of the case's `config` entries (compared as case-relative `/` paths) or a file that resolves inside the case directory (a relative path is tried against the case directory first, then the working directory; the real path, symlinks followed, must be inside the case); anything else is a usage error. Without `--config`, the one listed config whose `commands` key declares the command (`hunt`); else the case's only config; else a usage error that lists every config with its commands (docs/CONFIG.md, "Which config answers a command"). Two configs that declare the command are that error too.
3. `--window`: when the flag is not given, the duration comes from `windows.default` (`24h` is 24 hours, `7d` is 168). An explicit `--window` wins. A case whose `windows` has no `default` key keeps the flag's own default (1h).
4. Store: an empty `store.path` means `<case>/<paths.evidence>/jb.duckdb`, in the ignored directory, and `JB_DB` is not consulted. A relative `store.path` is relative to the case directory, not the working directory. An absolute path or `~/` path is used as written. A store that ends up outside the evidence directory is used, with a note on stderr that git ignore rules are not checked for it.

5. Hands the case to the config (`File.UseCase`), so a detector can read the case's data files. A `type: fingerprint` detector needs this.
6. `--until TIME` hunts a past window: `[TIME - window, TIME)`, with the baseline the same length immediately before it (`Window.Previous`), exactly as a live hunt but anchored at TIME instead of now. TIME is RFC 3339 and MUST carry a zone (`2026-10-01T00:00:00Z`, `2026-10-01T02:00:00+02:00`): a time without one is a usage error, because the same text names different instants on different machines and the window would move silently. Fractions of a second are refused (the edges are not rounded). A TIME after now is a usage error. A TIME older than the window is fine. `--window` is at most 31d with `--until`. Everything else is unchanged: the guard, the INCOMPLETE rule, the liveness probe, `empty_is_quiet`, `sources:` scopes, filters and `--search`. The detectors read the stored events whose timestamps fall in the two windows, including events stored by earlier runs and none after the window: no detector reads the clock. The run id is `hunt-until-<end, 20060102T150405Z>-w<window seconds>` (`search-until-...` with `--search`): it cannot collide with a live `hunt-<time>` run, and hunting the same window again replaces that run and counts no event twice, because the store collapses an event fetched by two runs. The header and the JSON state the window and baseline as absolute times and carry `until`. `jb watch` has no `--until`: a watch cycle always ends now. A backfill is a run like another, so a later `jb intel` without addresses reads the run stored last, by creation time, and names it. See [BACKFILL.md](BACKFILL.md).

Without `--case`, `hunt --config FILE` is unchanged: no guard, relative paths against the working directory. A `type: fingerprint` detector then fails to build, saying it reads actor files from a case.

**`jb activity --case DIR [--config FILE] [--window DURATION] [--until TIME] [--output table|json]`.** Steps 1, 2 and 4 of `jb hunt --case` apply (the guard, the config choice, the store under the case) and the detectors get the case. `--window` defaults to 24h (not to `windows.default`, so the same command always asks the same question). It runs only the detectors that can say whether something is active, the fingerprint and behaviour detectors, and names the others on stderr as skipped; a config with none is a usage error. The sources are fetched for the window and the one before it and saved as run `activity-<time>` (`activity-until-<end>-w<seconds>` with `--until TIME`, which asks the same question of the past window `[TIME - window, TIME)` under the rules of step 6 above), then each detector reports, per actor or action, the events in the window and before it (a genuine event for an actor or rare action; routine traffic for a common action), the last genuine event, and the events it set aside. The table's last line gives the last genuine event of an `ACTIVE` verdict with its age, counted from the end of the window and not from the wall clock (`last activity 2026-11-05T11:09:00Z (51m ago)`); the JSON carries the timestamps only.

- Verdict, last line: `ACTIVE` (a detector found a genuine event in the window), `QUIET` (every source and detector finished over the whole window, nothing was truncated, no source or detector could not read 20% or more of what it received, and nothing genuine was found) or `INCOMPLETE` (nothing genuine was found, but a component did not finish or was mostly unreadable; exit 1; never printed as quiet). `ACTIVE` stands when a component also failed, with a `NOTE` line naming it, because a genuine event that was read cannot be undone by one that was not; `complete: false` in the JSON says so, and the exit status is 0.
- Genuine means what the detector's own rules call genuine: a fingerprint actor is an exact user agent whose event is not scanner noise (the actor file's `noise_paths`, a bare `/` answered with 4xx) and not relayed by `ignore_ips`; a behaviour action is a rare action at or above `min_events`, or a common action whose failure share rose, from a key and a user agent that are not in the ignore lists. `Detect` and the activity report read through one code path, so they cannot disagree.
- No address is used to attribute an event and none is printed. A CDN edge address is not a client; the fingerprint detector never matches on one, and the behaviour detector's key is counted, never named.
- The last line states the window, the sources read with the events each fetched (which cover the window and the one before it), the detectors, and per detector what it judged: `judged: <detector> read N events in the window, actor/rare-action events: M (window), K (preceding)`, plus `common-action events (ordinary traffic): X (window), Y (preceding)` when it read any. Routine traffic of a common action is never called a genuine event: a QUIET line can carry a large common-action count. A common action that the detector marked active (its failure share rose) is named at the end of an ACTIVE line. Then the last activity, or why the answer is not QUIET. Every number is counted from the events read. The JSON keeps `genuine_events_window` and `genuine_events_preceding` for the actor and rare-action counts only, and adds `common_action_events_window`, `common_action_events_preceding` and `common_actions_flagged`. A source that returned documents another source of the run already returned reports them as `duplicates` and does not count them in `events`.

**`jb actor status --case DIR [--config FILE] [--output table|json]`.** Builds the config's detectors without reading the environment, opens the case's store read-only, and for each user agent of each fingerprint actor reads stored events newest first through one fixed parameterised query until the first genuine one (same noise and `ignore_ips` rules as the detector). Prints the time, or `never`, with the count of newer events set aside. A store with no events is an error. A scan that hit its cap (100000 events) before a genuine one is `INCOMPLETE` and exits 1. Indicators other than user agents (addresses, ASNs, domains, probe fingerprints) are not matched against events and are not listed.

**`jb watch status --case DIR [--config FILE] [--name NAME] [--output table|json]`.** Says whether the case's watchers are alive and what they run. It loads `case.yaml` (no evidence guard: it writes nothing), finds every watcher in the evidence directory from its `watch*.lock` and `watch-status*.json` files, reads each status record (section 3.1) and probes each lock without taking it, so it is safe while a watcher runs. Each watcher is `running`, `stale`, `stopped` or `unknown`, by the rule in section 3.1 ("Is a watcher alive?"); the reason is printed for every state but `running`. `--name NAME` reports one watcher (`--name ""` the unnamed one; a named watcher with neither lock nor record is `unknown`); `--config` keeps the watchers whose record names that config. A record that cannot be read (another `apiVersion`, a damaged file, or a name that is not the file's) makes that watcher `unknown` with the error as the reason. `--output json` prints `{"checked": ..., "watchers": [...]}`, each entry carrying `name`, `state`, `reason`, `lockHeld`, `pid`, `started`, `config`, the five `...Seconds` options, `lastCycle` and `nextDue` as the record spells them; `watchers` is `[]` when none is found. The exit status is 0 whatever the states, 2 for a usage error and 1 when the case cannot be loaded. The Go package offers the same as `jb.WatchStatus`.

**`jb hunt --search TERM`** is described in [docs/CONFIG.md](CONFIG.md#ad-hoc-search). It changes nothing about the case checks above.

**`jb watch --case DIR [--config FILE] [--name NAME] [--every 5m] [--window DURATION] [--ttl 3h] [--keep 48h] [--repeat 30m] [--once]`.** Steps 1 to 5 of `jb hunt --case` apply unchanged (the guard, the config choice, the window default from `windows.default`, the store under the case, `UseCase`), after which the hunt runs every `--every`. `--window` MUST be at least `--every`, or events between cycles would never be examined; `--keep` MUST be at least twice the window and defaults to 48h, or to twice the window when that is longer. All durations accept `90s`, `5m`, `1h`, `7d`.

- Each cycle's run id is `watch-<UTC time>`, or `watch-NAME-<UTC time>` with `--name`. Alerts go to stdout and to `evidence/watch.log` (`watch.NAME.log`); the dedupe memory is `evidence/watch-state.json` (`watch-state.NAME.json`) (section 3.1). Two watchers of one case need different names and may have different `--config`s; two with the same name are refused (`watch.lock`, section 3.1).
- Outcome per cycle, on the last line of its output: `CYCLE QUIET`, `CYCLE FINDINGS`, `CYCLE INCOMPLETE` (a source or detector did not finish, or time went unexamined) or `CYCLE FAILED` (the cycle itself broke: hunt error, state or log write failure, failed prune). Only the first two are a clean result. A failing cycle does not stop the loop.
- A source that stays down alerts at once, then, while its failure text is unchanged, at most every `--repeat`. Every cycle in between still prints `CYCLE INCOMPLETE ... still down`. A changed failure text or a recovery alerts immediately. Findings are never held back by `--repeat`.
- When the source reports unparsable documents the cycle line says how many and what share (and `HIGH` at or above 20%). `jb hunt` prints the same under its source table and in `--output json`. It does not change the verdict.
- After each cycle, retention deletes the events, findings and run records of watch runs older than `--keep`, in one transaction, and the cycle line says how many runs, events and findings went. A watcher prunes only its own runs, recognised by their whole shape (`watch-<stamp>` unnamed, `watch-NAME-<stamp>` named, a stamp being `20060102T150405Z`), so neither another watcher's runs nor a name that merely starts the same way is reachable; runs whose id is not of that shape and the newest run of the watcher are never touched. A failed prune raises a `watch-prune` alert and the cycle is `FAILED`.
- A source or detector with `enabled: false` is neither read nor run (docs/CONFIG.md, [Switching a source off](CONFIG.md#switching-a-source-off-enabled)). The banner and every `CYCLE` line say `DISABLED: ...` and, when anything is disabled, `every enabled source and detector completed`.
- `--once` runs one cycle and exits 0 when it was clean, 1 otherwise. Without it the watch runs until SIGINT or SIGTERM; either ends it with exit 0 and without a verdict for a cycle in progress, leaving the state file whole (it is only ever replaced by rename).
- The store is opened for the length of one hunt and closed again, so `jb db status` works between cycles. A command that arrives while a cycle is writing waits for it (up to 15 s, `JB_DB_LOCK_WAIT`) rather than failing. When the cycle finds one set of documents stored under two source labels it prints a WARNING with the `jb db rename-source` fix; the cycle's outcome does not depend on it (docs/CONFIG.md, [Source labels and double counting](CONFIG.md#source-labels-and-double-counting)).
- `runs.pruned_at` (schema v2, nullable `TIMESTAMPTZ`): set by `jb db prune` on the run records of a hunt whose events were deleted while its findings and run records were kept. NULL means the events are as saved. A hunt is the run id before the first `/` (its findings) plus `id/source` (its events); all of them are stamped. `jb db prune --drop-findings` deletes the findings and run records instead, so there is nothing to mark. Run kinds are read from the whole shape of the run id: `hunt-<stamp>`, `hunt-until-<stamp>-w<seconds>s`, `activity-...`, `activity-until-...`, `search-...`, `search-until-...`, `watch-<stamp>`, `watch-<name>-<stamp>`; anything else is `other` and no maintenance command removes it. Only `jb watch --keep` removes watch runs. See docs/CONFIG.md, [Store maintenance](CONFIG.md#store-maintenance).

Not implemented: applying `never_suspects` assets as detector ignore lists, refusing a target outside `scope`, `--window NAME`. A case remains usable without them.

Dependency rule wanted in `internal/archtest` (not added; that package is not part of this change): `internal/casefile` may import the standard library and `gopkg.in/yaml.v3` only; it MUST NOT import anything under this module, `github.com/spf13/cobra`, `net/http` or any adapter; `os/exec` is allowed in `guard.go` alone. `archtest` checks package-level imports, so the `guard.go`-only half needs a file-level check (`go list -f '{{.GoFiles}}'` plus `go/parser`, or a grep test).

## 10. Open questions

1. Should unknown keys under an `x-` prefix be allowed for local notes? It would weaken rule 6.1 for convenience; v1 says no.
2. Should `Load` refuse a `paths.evidence` that is also an ancestor or descendant of another section (not only equal)?
3. The credential scan covers `actors/` with an exemption for fingerprint values. Should it cover `assets/` when that format exists?
4. Does `scope.domains` need an exact-only form, as `hosts` has?
5. Is a per-case store path (`store.path` under the case) a case key, or only a config key?
6. A `case.lock` that pins the tool version a case was last worked with, for handover.
