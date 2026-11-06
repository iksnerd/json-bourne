# RFC 0016: Inventory of the operator's own cloud
Status: draft
Scope: how `jb` learns which hosts and addresses the case owner operates in their own cloud accounts, creates estate nodes for them, and marks them as operated. Parked: nothing is built until the maintainer takes it up.

## Summary

`jb` is inward-facing. It analyses the operator's own logs and the operator's own infrastructure. Outward reconnaissance and every active scan is done by another runner outside `jb`, and its output enters `jb` only through `jb estate facts import`.

That leaves one gap on the inward side. `jb` cannot say which hosts and addresses in an estate file the case owner actually operates. `jb estate facts import` adds facts to nodes that already exist and never creates a node. An inventory of the operator's own cloud accounts, such as `cloudlist` produces, lists assets that are not yet estate nodes.

This RFC adds one inward collector for that inventory:

- **Contract.** A new command, `jb estate inventory import`, reads a neutral file (`jb.estate-inventory/v1`) that lists assets from the operator's cloud accounts. It creates `host` and `ip` nodes and marks each as operated by the case owner. It sends nothing over a network and starts no process.
- **Layer.** It writes only an estate file whose `subject` is `operated` ([RFC 0015](0015-estate-subject.md)).
- **Marker.** The mark is a fact `operated` with source `own-cloud`, a new source role. It is the scope data any later active tool needs, and this RFC says what it may and may not be trusted for.
- **Export, not runner.** `jb` does not run `cloudlist`. The operator runs it and converts its output. A confined runner was designed and set aside; see "Running `cloudlist` from `jb`: set aside".
- **Outward recon.** A short section gives the recipe and a table for feeding the passive ProjectDiscovery (PD) tools through `jb estate facts import`.

## Motivation

An operator under attack asks two questions about the estate file. What do the attackers use? What is ours? The first comes from passive collectors and from outward recon. The second has no source. The operator's cloud accounts know the answer: the instances, load balancers, buckets, DNS records and addresses they run.

Two things depend on that answer:

- A reader of the estate map can tell the operator's own hosts from third-party ones. Today an own host and a hostile host look alike.
- Any later active check (a port check, an HTTP probe of a host) needs a statement of scope: "this host is operated by the case owner". `CASE-SPEC.md` marks scope enforcement as proposed, and [POLICY.md](../POLICY.md) ("Changing the policy") demands a scope check. No such data exists in an estate file today.

A concrete case: the operator runs `example.com` on a cloud account. The account lists `www.example.com` on `192.0.2.10` and `api.example.com` on `192.0.2.11`. After an import, both are nodes, each with the fact `operated`. Logs from `192.0.2.10` and an attacker address `198.51.100.7` can then be told apart on the map.

`cloudlist` is the PD tool for this job. Its README (read on 2026-11-06) says it lists assets from cloud providers, writes JSON with `-json`, and takes credentials from a provider config file or, with `-auto-discovery`, from environment credentials of AWS, GCP, Azure and Kubernetes.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Asset" means one host name or address that a cloud account reports. "Inventory" means a list of assets from one provider and one account. "Operated" means that the operator's own cloud account reports the asset. All examples use `example.com`, RFC 5737 addresses and invented account labels. Anything marked **unverified** was not confirmed in `cloudlist`'s README on 2026-11-06 and MUST be confirmed against a real binary before acceptance.

## How this design was made

1. **Inward only.** The owner decided on 2026-11-06 that `jb` analyses the operator's own logs and infrastructure, and that outward recon runs elsewhere. A cloud inventory is the operator's own data, read with the operator's own credentials. It fits. `subfinder`, `asnmap`, `uncover`, `vulnx`, `urlfinder` and `chaos-client` do not, because they ask third parties about names that may not be the operator's.
2. **Import is the contract.** `jb` reads no vendor format ([CASE-SPEC.md](../CASE-SPEC.md) 4.5.2): the operator converts an export to a neutral shape with a script they control. The same holds here. `cloudlist` does not document its JSON fields, so a parser inside `jb` would rest on a guess. A neutral shape does not.
3. **A new command, not a wider facts import.** `jb estate facts import` never creates a node, and that is a safety rule: a fact cannot invent a host. Creating nodes from an import is a different act, with its own file, its own caps and its own role. It gets its own command. The facts import command is not changed by this RFC.
4. **The mark is a fact, not a new key.** The v2 loader rejects unknown keys, so a node field `operated: true` would need a new `apiVersion`. A fact has a source, a method and a time already, which is what a scope claim needs. No format change.
5. **Export over runner.** A runner puts cloud credentials into `jb`'s process and widens the `os/exec` confinement for one tool. The reasons are in "Running `cloudlist` from `jb`: set aside".

## The design

Everything in this section is a proposal. None of it is implemented.

### The inventory import

#### The command

```
jb estate inventory import --case DIR [--file NAME] [--apply] [--include-private] INVENTORY-FILE
```

It follows `jb estate facts import`: it reads one file from disk (or standard input when the argument is `-`, once the facts import command has the same convention; that work is separate and not part of this RFC), is a dry run unless `--apply`, validates the result as a `jb.estate/v2` file before writing and writes nothing if it would not load. It needs no `estate.external` switch because nothing leaves the machine.

#### The file: `jb.estate-inventory/v1`

One JSON object, at most 2 MiB, at most 5000 assets. An unknown key is an error at any depth, and so is a second JSON value after the first. Every string goes through the one-line check and the credential scan of [CASE-SPEC.md](../CASE-SPEC.md) 6.3.

| Key | Required | Rules |
|---|---|---|
| `apiVersion` | yes | MUST be `jb.estate-inventory/v1`. |
| `provider` | yes | `^[a-z][a-z0-9-]{0,31}$`, for example `aws`. |
| `account` | yes | A label for the account, one line, at most 128 bytes. A label the operator chooses is RECOMMENDED over a raw account number. |
| `method` | yes | How the inventory was made: the tool, its version and the converting script. One line, at most 500 bytes. |
| `observed` | yes | RFC 3339 with a zone: when the provider API was read. |
| `complete` | yes | `true` only if the producer listed everything it was asked to list. A producer that cannot tell MUST write `false`. |
| `assets` | yes | A non-empty list. |

An asset has `kind` (`host` or `ip`), `value`, and optionally `service` (`^[a-z0-9][a-z0-9.-]{0,63}$`, for example `ec2`), `region` (one line, at most 64 bytes) and `public` (a boolean). A `host` value is a lower-case DNS name. An `ip` value is an address. A number where a string belongs is an error.

#### Which file it writes

It writes only an estate file whose `subject` is `operated` ([RFC 0015](0015-estate-subject.md)). It creates the file with `subject: operated` when it does not exist. It refuses an existing file that is `adversary`, and an unclassified file that already has nodes: the operator classifies that file first, by hand, so no existing map changes layer silently. Its default `--file` is `operated.yaml`, not the default estate file.

#### What the import does

- **Nodes.** For each asset it makes one node: `host:<name>` or `ip:<address>`, source `own-cloud`, `method` from the file, `observed` from the file. If the node already exists (from `dns`, `ct` or anything else), it keeps its first source and method, because a node is unique by id ([CASE-SPEC.md](../CASE-SPEC.md) 4.5), and only gains facts.
- **Facts on every node**, source `own-cloud`: `operated` with value `cloud:<provider>`; `cloud.account` with the label; `cloud.service` and `cloud.region` when present. A node reported by two accounts gets two `operated` facts and two `cloud.account` facts, because two facts may share a key.
- **Edges.** For an asset with a `service`, a `service:<provider>-<service>` node (for example `service:aws-ec2`) and an edge from the asset to it, relation `hosted_on`, `stated`, source `own-cloud`. The relation list is open; the loader checks shape, not vocabulary.
- **Dropped and counted.** A wildcard name (leading `*`). A private or link-local address (RFC 1918, RFC 4193, `169.254.0.0/16`, loopback), unless `--include-private`. A name that is not a valid DNS name. An address that does not parse. The result lists the counts. A dropped asset makes the run neither more nor less complete, because it is a rule, not a failure, and the counts are shown.
- **Merge rules** are the collectors': an identical claim is "already recorded", a claim that conflicts with a recorded one is reported and not overwritten, and the file is written only if something was added. An import that would pass the node cap (5000) is refused, not truncated.
- **Outcomes.** The import is `ok` only if the file is valid, `complete` is `true` and at least one asset was kept. A file with `complete: false` is applied for what it lists and the run ends INCOMPLETE (exit 1): the assets are real, the rest is unknown. A file whose assets are all dropped, or empty, is an error with `core.ErrNoRecords` semantics. It never means "the operator operates nothing". A refused file writes nothing. Exit 0 only for `ok`.

#### The `own-cloud` role and the `operated` marker

`own-cloud` is added to `casefile.EstateSources`, to `schemas/estate.schema.json` and to the list between the `estate-sources` markers in [POLICY.md](../POLICY.md), in one commit. `TestEstateSourcesMatchPolicy` and the schema enum tests keep the three equal. The policy text for it: "`own-cloud`: assets that the operator's own cloud accounts report about themselves, read from an export file the operator holds. `jb` has no network code for it; `jb estate inventory import FILE` reads the file from disk and nothing leaves the machine."

By the test in POLICY.md ("a source is passive when the target observes nothing from `jb`"), it passes trivially: no target is contacted, and the question went to the operator's own provider, outside `jb`.

What the marker means, and does not mean:

- `operated` from source `own-cloud` says: **an account the operator controls reported this asset, at that time.** It is the only scope claim `jb` makes.
- It does not prove the operator controls the name. A DNS record in the operator's zone can point at an address someone else now holds (a dangling record). A name can be in an inventory and no longer be live.
- Any later active tool MUST read scope as follows, and MUST refuse otherwise: the node is in a file whose `subject` is `operated` ([RFC 0015](0015-estate-subject.md)); the node carries a fact with key `operated` and source `own-cloud`; the fact's `observed` is not older than a limit the operator sets; and the import that wrote it was `complete`. A hand-written fact with key `operated` and another source is not scope. The loader cannot stop a person from writing one (the same limit as RFC 0001's "facts SHOULD NOT hold judgements"); the scope check reads the source, and the `own-cloud` source is accepted from the import only because a hand-edited file could still carry it. That residual risk is named in Security considerations and Open questions.
- The marker is per node, never inherited. A host in a zone the operator owns is not marked by that fact. An address in a prefix is not marked by the prefix.

No active tool is added by this RFC. The marker is written now so the data exists when a later RFC needs it.

#### How an inventory is made (outside `jb`)

The operator runs `cloudlist` where their credentials are, and converts. The `jq` line is illustrative, not run, and uses a field name that is **unverified** because the README documents no output fields:

```sh
cloudlist -p aws -json -silent > cloudlist.jsonl   # exit status checked by the script
# a script the operator owns turns each line into an asset and writes jb.estate-inventory/v1
jb estate inventory import --case DIR --apply inventory.json
```

The script sets `complete` to `true` only if `cloudlist` exited 0. Credentials stay with the operator's tool and the operator's environment. `jb` never sees them.


### Running `cloudlist` from `jb`: set aside

A confined runner was designed in the first draft of this RFC and is set aside for now. It would add a package allowed to use `os/exec` (a third reason after the case git guard and the mapper plugin host), a tool file with a pinned sha256, a private `HOME` and a declared set of credential variables, caps and a process-group kill, a doctor section, and a parser for `cloudlist`'s JSON, which its README does not document. The reasons for the export:

- No credential enters `jb`. Cloud credentials are the most sensitive ones in this tool's world. With the export they stay with the operator's own tool and shell.
- No change to the `os/exec` confinement, no tool file, no pin to maintain, no new switch.
- `cloudlist` documents no JSON fields. A parser in `jb` rests on an unverified shape; a neutral shape rests on `jb`'s own definition. The operator's script absorbs a change in the tool.
- Other sources of the same data (a Terraform state, a hand-made CSV, another cloud tool) use the same import.

What the runner would buy: a citation of the tool, version and argv on `jb`'s own authority, a one-command refresh, and a `complete` flag from a real exit status instead of a script's word. These matter once an active tool relies on the marker. If that happens, a new RFC can take the runner up, and nothing in the import changes.

## Outward recon: not run by `jb`

`jb` does not run `subfinder`, `asnmap`, `uncover`, `vulnx`, `urlfinder` or `chaos-client`, or any active tool. Another runner does, outside `jb`. Their output reaches the estate file through `jb estate facts import`:

```sh
<tool> -json | jq -c '...' | jb estate facts import --case DIR -
```

The line is a recipe, not a promise. Reading standard input and JSON-lines is being added to the facts import command separately, and its exact shape is not part of this RFC. The `jq` program is the operator's.

Facts import adds facts to nodes that already exist, and tags every fact with source `scan-cache` (`casefile.FactsImportSource`). Each fact also carries the operator's `method` and `source_note`, where the true origin (the tool, version and command) goes. Whether names from passive enumerators fit the text of `scan-cache` is open question 5.

Estate keys each tool would map to. Fields marked documented come from the tool's README on 2026-11-06; the others are **unverified** and the operator reads them from a real run.

| Tool | What it returns | Node it attaches to | Key | Value | Fields |
|---|---|---|---|---|---|
| `subfinder` | passive subdomain names | `domain:example.com` | `subdomain.candidate` | the name | `-json` is JSONL; field names **unverified** |
| `chaos-client` | subdomains from the Chaos DB | `domain:example.com` | `subdomain.candidate` | the name | `-json` shape **unverified**; plain text with `-silent` is documented |
| `urlfinder` | passive URLs for a domain | `domain:example.com` or `host:www.example.com` | `url.seen` | the URL, at most 500 bytes | `url`, `input`, `source` documented |
| `asnmap` | network ranges of an AS or organisation | `asn:as64496` | `net.range` | a CIDR | `as_number`, `as_name`, `as_country`, `as_range` (array of CIDR), `input`, `timestamp` documented |
| `uncover` | hosts that search engines hold | `ip:192.0.2.10` | `port.open` | the port, as text | `-j` JSONL; field names **unverified**; default field `ip:port` documented |
| `vulnx` | vulnerability records | the node the operator chooses | `vuln` | a CVE id | `--json`; field names **unverified** |

What leaves the machine, per tool, is a matter for the outward runner's policy and not for `jb`'s. The facts for this RFC's record: `subfinder`, `chaos-client`, `uncover`, `vulnx`, `urlfinder` and `asnmap` each send the searched domain, address or query to third-party data services (and `uncover` and `asnmap`, `chaos-client` and optionally `vulnx` send an API key). They are passive with respect to the target and not private. The key `PDCP_API_KEY` is documented for `asnmap`, `chaos-client` and `vulnx`; `uncover` names one or more variables per engine. A URL with a token-shaped query string is refused by the credential scan of [CASE-SPEC.md](../CASE-SPEC.md) 6.3 when imported.

`cloudlist` is the one PD tool that is inward and is covered by this RFC.

## Non-goals

- No outward recon in `jb`. No run of `subfinder`, `asnmap`, `uncover`, `vulnx`, `urlfinder` or `chaos-client`.
- No active tool: `httpx`, `dnsx`, `tlsx`, `naabu`, `nuclei`, `katana`, `cdncheck`. See Open questions.
- No Go import of any PD library.
- No active check against an asset on the strength of `operated`. The marker is data. A check that uses it needs its own RFC and a policy change.
- No live call to a cloud API from `jb`.
- No sandbox, no tool download or update, and no provider config file written by `jb`.
- No new node field, and no `apiVersion` change.
- No attribution and no verdict: `operated` says whose account reported the asset, not who typed what.

## Drawbacks

- The marker depends on a script the operator writes. A wrong script, or a lying `complete`, produces a wrong marker. `jb` can check the shape and the caps, not the truth.
- `operated` is a fact that a hand-edited estate file can also carry. The loader cannot tell a human's `operated` from an import's, except by `method` and `source`.
- An asset in an inventory may be stale, and a name may no longer point where the cloud says. The marker has a time and nothing more.
- A new role and a new file format add surface to every reader of the estate file.
- Dropping private addresses by default hides internal topology from the map. `--include-private` brings it back.
- The export gives no citation of the tool on `jb`'s own authority; `jb` records what the script wrote in `method`.
- The operator needs `jq` or another script for both the inventory and the outward recipe.

## Alternatives and prior art

- **Run `cloudlist` from `jb`.** Set aside; see above.
- **Read cloudlist's JSON directly.** One fewer step for the operator. It makes `jb` depend on an undocumented format and on one tool's field names, against the rule in [CASE-SPEC.md](../CASE-SPEC.md) 4.5.2 that `jb` reads no vendor format.
- **Widen `jb estate facts import` to create nodes.** One command. It removes the rule that a fact cannot invent a host, and it lives in code another change is editing now.
- **A node field `operated`.** Direct. It needs a new `apiVersion` and drops the source, method and time of the claim.
- **A role per provider** (`aws`, `gcp`, ...). More precise. A role names what kind of source answered, and the provider goes in the fact `cloud.account` and the `method`. A closed list that grows with every provider is the wrong shape for `casefile.EstateSources`.
- **Let the operator list their own hosts by hand in the estate file.** Works today, with any source from the list. It gives no provenance of the claim "ours", and every edit is manual. It stays possible beside this design.
- **Prior art in this repository.** The scan-cache import ([RFC 0001](0001-estate-v2.md), `internal/casefile/estate_facts_import.go`) for the file shape, caps and dry-run rule. The plugin host (`internal/adapters/plugin`, [PLUGINS.md](../PLUGINS.md)) for the process group, empty environment, per-launch digest check and limits, which a runner would reuse.
- **Prior art outside.** The READMEs of the seven PD tools (github.com/projectdiscovery, read 2026-11-06) and `cloudlist`'s PROVIDERS.md. The author read no source code of the tools and no other project's wrapper.

## Compatibility

`jb` is pre-1.0. This RFC adds a command, a file format and one source role, and changes no existing behaviour. An older `jb` that meets an estate file with source `own-cloud` refuses it with its existing "not on the passive-source allowlist" error.

## Security considerations

- The import file is untrusted text. Every string is checked for one line, length and credentials. The dashboard escapes it like all stored text ([RFC 0003](0003-dashboard-security-model.md)). Caps (2 MiB, 5000 assets, node cap) bound a hostile file.
- Nothing is sent and no process starts. The file is read from disk or standard input.
- A hostile or mistaken inventory can mark a third-party host as operated. A later scope check that trusts `operated` would then act on it. For that reason the marker is not scope by itself (see "What the marker means"), and an active tool is not added here.
- Account labels and numbers are sensitive. They live in the case's private repository and not in this one. Examples here are invented.
- A private-address drop and a wildcard drop are counted and shown, so a reader sees what the import removed.

## Conformance

Proposed. None of these exist yet.

- `schemas/estate-inventory.schema.json`, kept equal to the loader by tests that mirror `TestEstateSchemaMatchesStruct` and `TestEstateSchemaMatchesLoaderRules`.
- `TestInventoryCorpus`: synthetic files under `internal/casefile/testdata/inventory/`, valid ones and one invalid file per rule (unknown key, second JSON value, number for string, bad `kind`, bad name, credential-shaped string, oversize file, 5001 assets, empty `assets`, missing `complete`), each with the substring its error must contain.
- `TestInventoryCreatesNodesAndMarks`: golden result for a synthetic file (`www.example.com`, `192.0.2.10`, `192.0.2.11`, `service: ec2`): the nodes, the `operated`, `cloud.account` and `cloud.service` facts, the `hosted_on` edge, and the sources.
- `TestInventoryKeepsFirstSource`: a node already present from `dns` keeps source `dns` and gains the facts; two accounts give two `operated` facts.
- `TestInventoryDropsAndCounts`: wildcard, RFC 1918, link-local and loopback addresses, and invalid names are dropped and counted; `--include-private` keeps the private ones.
- `TestInventoryOutcomes`: `complete: true` exits 0; `complete: false` applies and exits 1; all-dropped and empty are errors that write nothing; a file that would fail the v2 loader writes nothing.
- `TestInventoryDryRun`: no write without `--apply`, and the result says so.
- `TestInventoryStartsNothing`: the command imports no `net` and starts no process (the archtest rules for `casefile` and `app` already cover this; a planted import is seen to fail).
- `TestEstateSourcesMatchPolicy` and the schema enum tests, extended with `own-cloud`.
- `TestInventoryParity`: the command, `jb.EstateInventoryImport` and the `estate_inventory_import` operation give the same result; over MCP `apply=false` writes nothing.
- A test that a drifted `operated` fact is carried by `jb estate refresh` unchanged, and that `jb estate diff` lists a lost or gained `operated` value as a fact change, never as scope.

## Reference implementations

Shipped: none.

Proposed:

- `jb estate inventory import`, `jb.EstateInventoryImport`, and the operation `estate_inventory_import`.
- The loader and schema for `jb.estate-inventory/v1` in `internal/casefile`, and the use case in `internal/app`.
- The role `own-cloud` in `casefile.EstateSources`, `schemas/estate.schema.json` and [POLICY.md](../POLICY.md); the relation `hosted_on` and the fact keys `operated`, `cloud.account`, `cloud.service` and `cloud.region` in [CASE-SPEC.md](../CASE-SPEC.md) 4.5 and a new subsection after 4.5.2.

## Open questions

1. **Parked.** The maintainer decided on 2026-11-06 to take the subject key ([RFC 0015](0015-estate-subject.md)) now and park this command until the cloud inventory is actually needed. Decides: the maintainer, when to take it up.
2. **Active tools: another runner, not `jb`.** `httpx`, `dnsx`, `tlsx`, `naabu`, `nuclei`, `katana` and `cdncheck` send traffic to a host. The owner's direction is that `jb` stays inward and another runner runs them. If any of them ever came into `jb`, it would be a policy change: a rewrite of the passive-only policy, a written scope rule, a per-run authorisation and its own RFC. The proposed scope rule for that RFC: allowed only against assets that carry a complete, recent `operated` fact from source `own-cloud`; refused before any packet is sent; never against a third-party or attacker host. Decides: the maintainer.
3. **`scan-cache` for outward facts.** Facts import tags every fact `scan-cache`, whose policy text is a store of past observations read from an export file. Names from a passive enumerator are not quite that. Should outward facts get their own role, or is `scan-cache` plus the `source_note` enough? Decides: the maintainer.
4. **A second source of scope.** `operated` from `own-cloud` covers cloud assets. A bare-metal host has no way to be marked. A role such as `operator-declared` could cover it, with the weaker meaning that a person said so. Decides: the maintainer.
5. **Guarding the marker.** A hand-edited file can carry an `operated` fact from `own-cloud`. Should `jb case check` compare it with an import record and warn on a fact with no matching import? Decides: the author, then the maintainer.
6. **Names and freshness.** `own-cloud`, `operated`, `hosted_on`, the keys in the outward table, and how old an `operated` fact may be and still count as scope. Decides: the maintainer.
7. **Unverified facts about `cloudlist`.** The JSON field names, whether `$VAR` placeholders in a provider config expand from the environment, which GCP and Azure variables `-ad` reads, the version output, and whether the tool phones home. Decides: the author, by running the real binary on a test host, before any converter recipe is published.

## Changes

None yet. The RFC is a draft and is parked.
