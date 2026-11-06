# RFC 0015: Inventory of the operator's own cloud
Status: draft
Scope: how `jb` learns which hosts and addresses the case owner operates in their own cloud accounts, creates estate nodes for them, and marks them as operated; and whether `jb` runs `cloudlist` itself or only reads its export.

## Summary

`jb` is inward-facing. It analyses the operator's own logs and the operator's own infrastructure. Outward reconnaissance (subdomain enumeration, search-engine discovery, URL gathering, and every active scan) is done by another runner outside `jb`. Its output enters `jb` only through `jb estate facts import`.

That leaves one gap on the inward side. `jb` cannot say which hosts and addresses in an estate file the case owner actually operates. `jb estate facts import` adds facts to nodes that already exist and never creates a node. An inventory of the operator's own cloud accounts, such as `cloudlist` produces, lists assets that are not yet estate nodes.

This RFC adds one inward collector for that inventory. It decides:

- **Contract.** A new command, `jb estate inventory import`, reads a neutral file (`jb.estate-inventory/v1`) that lists assets from the operator's cloud accounts. It creates `host` and `ip` nodes and marks each as operated by the case owner. It sends nothing over a network and starts no process.
- **Subject (maintainer decision pending).** An estate file gets an optional `subject`, `operated` or `adversary`, so the operator's own infrastructure and the attacker's are separate files and separate layers. The inventory writes only an `operated` file. See "Subject of an estate file".
- **Marker.** The mark is a fact `operated` with source `own-cloud`, a new source role. It is the scope data that any later active tool needs, and this RFC says exactly what that data may and may not be trusted for.
- **Runner or export.** The RFC recommends the export. `jb` does not run `cloudlist` in the first cut. The design of a confined runner is written down (Part B) so that the maintainer can accept it later without a new design.
- **Outward recon.** A short section says what `jb` does not run, and gives the recipe and a table for feeding the passive ProjectDiscovery (PD) tools through `jb estate facts import`.

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
5. **Recommend the export over the runner.** The reasons are in "Runner or export". In short: a runner puts cloud credentials into `jb`'s process and widens the `os/exec` confinement for one tool.

## The design

Everything in this section is a proposal. None of it is implemented.

### Subject of an estate file (maintainer decision pending)

**Status of this section: the maintainer has not decided it.** The rest of the RFC reads the same if the maintainer rejects it, except where a sentence says "operated file"; in that case the marker rules fall back to the fact alone and the weaker guarantee is stated in Security considerations.

The question the owner asked: is the estate the attacker's infrastructure, and do we keep it apart from our own? Today one map holds both. The passive collectors profile addresses seen in the logs, which are third-party and adversary infrastructure. `jb estate refresh` and `diff` watch "your own estate" ([POLICY.md](../POLICY.md)). A case can already hold several estate files (`--file`). Nothing records which kind a file is.

**Decision proposed.** An estate file gets an optional top-level key `subject`, with two values:

| Value | Meaning |
|---|---|
| `operated` | The nodes are infrastructure the case owner operates. |
| `adversary` | The nodes are infrastructure of an attacker or of a third party seen in the evidence. |

A file with no `subject` is **unclassified**. Every file that exists today is unclassified, and stays valid.

**Load-time rules** (`casefile.LoadEstate`):

- `subject` is `operated`, `adversary` or absent. Any other value is an error that lists the two.
- An `adversary` file that carries a fact with key `operated` is refused. This is the mixed-file rule that the loader can check: the marker belongs to one layer only.
- An `operated` file with any fact from source `scan-cache`, `passive-dns` or another outward source is NOT refused. The operator may import the open ports of their own host. The loader cannot tell outward recon from that, and a rule it cannot check is not written (RFC 0001 says the same of `classification`).
- A file's nodes are not split. The loader never moves a node between files. A node id may appear in two files of one case. That is a warning of `jb case check`, not an error: a compromised host of the operator is in both layers for a real reason. The warning names the two files, and says the layers are not merged.
- `schemas/estate.schema.json` gets the key, with the two-value enum, and the schema tests keep it equal to the loader.

**Who may write where:**

- `jb estate inventory import` writes only an `operated` file. It creates the file with `subject: operated` when it does not exist. It refuses an existing file that is `adversary`, and an unclassified file that already has nodes (the operator classifies it first, by hand, so no existing map changes layer silently). Its default `--file` is `operated.yaml`, not the default estate file.
- Outward recon imports (`jb estate facts import`) go, by the recipe in "Outward recon", to an `adversary` file. `facts import` is not changed by this RFC and cannot know that its data is outward, so this is a convention in the recipe, not a check. The one check `jb` makes is the one above: the marker cannot sit in an `adversary` file.
- The passive collectors (`estate IP|asn|dns|ct`) keep writing to the file you name. They do not set `subject`. A new file they create is unclassified.
- A later active tool, if one is ever added elsewhere, may target only nodes of an `operated` file that carry a complete, recent `operated` fact from `own-cloud`. An unclassified or `adversary` file gives no target. The check reads the file's `subject` and the fact.

**Effect on drift.** `jb estate refresh`, `diff` and `promote` read and write one file. Proposed:

- They run on `operated` files and, as today, on unclassified files.
- On an `adversary` file they refuse unless the caller passes `--adversary`. The reason: `refresh` asks third parties again about the names in the file. For an adversary map that is a deliberate act, because it repeats a lookup that tells those services you are still looking. For an operated map it is routine monitoring of what you run.
- `diff` compares two files only if they have the same `subject` (absent equals absent). A snapshot copies the `subject` of its baseline; `promote` keeps it.
- Whether the default for an `adversary` file should be "refuse" or "allow" is open question 10.

**Effect on the dashboard** (`internal/adapters/web`). The Estate page already draws one graph per file. Proposed: the page groups the graphs under two headings, "Operated" and "Adversary and third-party", with unclassified files under a third, "Unclassified". The viewer MUST NOT merge nodes or edges across files, and MUST NOT count corroboration across files, so the edge weight of RFC 0001 is computed per file. An `ip` node that appears in two layers is drawn in each, with no line between them. The node-kind filter applies within a layer. The text of the heading is fixed and not taken from the file.

**What it costs.** One new optional key in `jb.estate/v2`. It edits the file table of [RFC 0001](0001-estate-v2.md) when accepted. An older `jb` rejects a file that has it with its existing unknown-key error. A person can still write `subject: operated` on a file that is not; the loader cannot check the claim, only the marker rule above and the importer rules. It is data a person asserts, like `by` in an assessment.

### Part A: the inventory import (recommended, first)

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
- Any later active tool MUST read scope as follows, and MUST refuse otherwise: the node is in a file whose `subject` is `operated` (see the pending decision above; without it, this line is dropped and the check rests on the fact alone); the node carries a fact with key `operated` and source `own-cloud`; the fact's `observed` is not older than a limit the operator sets; and the import that wrote it was `complete`. A hand-written fact with key `operated` and another source is not scope. The loader cannot stop a person from writing one (the same limit as RFC 0001's "facts SHOULD NOT hold judgements"); the scope check reads the source, and the `own-cloud` source is accepted from the import only because a hand-edited file could still carry it. That residual risk is named in Security considerations and Open questions.
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

### Part B: running `cloudlist` from `jb` (proposed, conditional)

Part B is written so the maintainer can choose it. It is not recommended for the first cut. If accepted, it produces the same `jb.estate-inventory/v1` value that Part A reads, in memory, and then applies the same import code. The tool is run as a separate process, never imported as a Go library (the owner's decision).

#### What `cloudlist` is, as far as its README says

Flags (README of github.com/projectdiscovery/cloudlist, 2026-11-06): `-config` (flag config file), `-p, -provider` (providers, comma-separated), `-id` (ids), `-s, -service` (services), `-json`, `-silent`, `-ip`, `-host`, `-exclude-private`, `-version`, `-pc, -provider-config` (default `$HOME/.config/cloudlist/provider-config.yaml`), `-ad, -auto-discovery` ("discover providers from environment credentials (aws, gcp, azure, kubernetes) instead of the provider config").

Provider config keys (PROVIDERS.md): AWS `aws_access_key`, `aws_secret_key`, `aws_session_token`, `assume_role_arn`, `external_id`, `account_ids`; GCP `gcp_service_account_key`, `project_ids`, `organization_id`; Azure `client_id`, `client_secret`, `tenant_id`, `subscription_id`, `use_cli_auth`; DigitalOcean `digitalocean_token`; Cloudflare `email`, `api_key`, `api_token`. The README's examples use `$VAR` placeholders for these values. Whether `cloudlist` expands them from the environment is **unverified**. Environment variables the README names for keyless AWS: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and for IRSA `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`. No GCP or Azure variable name is given: **unverified**. The JSON field names are not documented: **unverified**.

Consequence for a runner: the first cut could use `-ad` with the providers `aws`, `gcp`, `azure` and `kubernetes` only, and credentials only from environment variables. DigitalOcean and Cloudflare need a provider config file and would wait for open question 3.

#### Where it lives, and `os/exec`

A new package `internal/adapters/toolrun`, depending on `core` and the standard library. It does not import `net`, `net/http`, `os/signal`, another adapter, `internal/app`, `internal/casefile` or `internal/config`. It reads no environment itself; the caller passes `Env func(string) (string, bool)`, as the plugin host does. Only `cmd/jb` imports it.

`TestOSExecIsConfined` allows `os/exec` in two packages today. The change is explicit: `toolrun` is added to `osExecAllowed` with a comment naming the third reason; the failure text, which says "only the plugin host (and the case git guard)", is rewritten; [POLICY.md](../POLICY.md) ("A process is started only for two reasons") becomes three; the `internal/adapters/plugin` line of [CLAUDE.md](../../CLAUDE.md) is updated. Each new archtest rule gets a planted-fault test ("a rule is not done until you have seen it fail").

#### The tool file and the pin

The binary path lives in jb's own file, `$JB_TOOLS_FILE`, else `~/.jb/tools.yaml`, never in the case. Strict YAML, at most 1 MiB, not writable by group or others, credential-scanned. A missing file means no tool runs.

```yaml
# ~/.jb/tools.yaml (a proposal)
tools:
  - name: cloudlist                 # the only compiled-in name
    path: /opt/pd/cloudlist         # optional, absolute and clean; omitted: found on PATH
    sha256: 9f2c...64 hex digits... # REQUIRED to run
    env: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN]   # names only
```

Every launch: the path resolves to a regular file, executable by its owner, neither it nor its directory writable by group or others; its sha256 equals the pin. A missing or wrong pin refuses the run. Each name in `env` must be on `cloudlist`'s compiled-in list of allowed credential variables; any other name is a load error. The file holds names, never values. A case may narrow with a `tools:` list in the case config; it can never add a path, a flag or an environment name. The pin is required, unlike a plugin's, because the binary is downloaded and the digest is the only link to a binary the operator reviewed.

#### Invocation, environment, limits

- `exec.Command(path, args...)`. No shell. The argv is compiled in: `-ad -p PROVIDER -json -silent`, where `PROVIDER` is one of the four names, validated. No `-o`, `-config`, `-pc`, `-proxy` or update flag is ever passed. The operator supplies no flag.
- The child's environment is `PATH`, `LANG`, `TMPDIR`, a private `HOME` (an empty 0700 directory made for the run and removed after it) and only the declared credential variables from the compiled-in list. No other key of `jb` reaches it. A key is never in argv, a file or a method string. The private `HOME` stops `cloudlist` from reading a default `provider-config.yaml` under the real `HOME` (**unverified** that it derives the path from `HOME`; a conformance test checks it).
- Own process group, killed whole on a break. Standard input is `/dev/null`. Standard error: the last 4 KiB, credential-scrubbed, used in error text only.
- Wall-clock timeout 120 s (hard maximum 600 s). Standard output 8 MiB (maximum 32 MiB), one line 64 KiB, 5000 records. Providers per command 4. Spacing between runs 2 s. A longer list of providers is refused, not truncated.
- The tool is run once with `-version` first, under the same limits. If no version can be read the run fails: a claim with an unknown tool version cannot be cited. The method string is one line, at most 500 bytes: `tool=cloudlist version=vX path=... sha256=... argv=[...]`. The version is illustrative here.

#### Outcomes

| State | When | Stored | Exit |
|---|---|---|---|
| `ok` | exit status 0, at least one record, every line parsed, no cap hit | the assets | 0 |
| `no-records` | exit status 0 and zero records | nothing | 1 |
| `failed` | non-zero exit; crash or signal; a line that is not valid JSON or lacks a required field; a refused launch (bad pin, mode, missing binary or credential) | nothing | 1 |
| `cut` | time, byte, line or record cap hit | whole records read before the cut, with `complete: false` | 1 |

Zero records is `no-records`, never "the operator operates nothing": a wrong key, a missing permission or an empty region prints nothing as well. A `failed` run discards records printed before the failure. A partial line at a cut is dropped. A provider that fails stops that provider only; others still run, the command exits 1, and the result lists every failure. Three provider failures in a row stop the command and the rest are listed as `not run`.

#### Command, library, MCP, doctor

- Command: `jb estate inventory run cloudlist --case DIR [--file NAME] [--config PATH] [--timeout D] [--print-command] [--output table|json] PROVIDER [PROVIDER ...]`. It follows the collectors: it writes the estate file when the run added something, with no `--apply`, because running the tool is the act. `--print-command` is the preview: it validates, resolves the binary, checks the pin and prints the argv and the names (not values) of the variables that would be passed. It starts nothing.
- Library, in the style of [RFC 0013](0013-library-surface.md): `EstateInventoryRun(ctx, caseDir string, providers []string, opts EstateInventoryRunOptions) (*EstateInventoryResult, error)`, with `Env` and `Now` fields, `*jb.UsageError` for caller mistakes, and a result whose `Complete()` is false when anything failed. The import has `EstateInventoryImport` with an `Apply bool` whose zero value is a dry run.
- Operations ([RFC 0010](0010-operations.md)): `estate_inventory_import` and `estate_inventory_run` are mutating (`readOnly` false). Neither is listed over MCP by default. Each appears only when named by `--allow`, and still needs `apply=true`. For the run, `apply=false` means `--print-command`. The path, digest and credential values are not arguments; an agent cannot supply them.
- `jb doctor`: [CONFIG.md](../CONFIG.md) says doctor "does not inventory external binaries". With Part B that sentence changes. A **tools** section lists, per compiled-in tool: the entry (or `none`), the resolved path, the pin state (`ok`, `MISMATCH`, `missing pin`), the mode checks, whether the case enables it, the digest of an unpinned binary so the operator can copy it, and each declared variable as `set` or `unset` (never the value). It starts nothing unless `--tools-version` is passed. Without Part B the sentence stays true.
- The case config gains `estate.tools: [cloudlist]`, off by default, on the pattern of `estate.external`. `cloudlist` sends requests to the operator's own cloud provider, so it is switched like any service that leaves the machine. Both switches are needed: a pinned binary in the operator's file and the name in the case config.

### Runner or export: the recommendation

**Recommend the export (Part A) as the first and only cut.**

For the export:

- No credential enters `jb`. Cloud credentials are the most sensitive ones in this tool's world: they read the operator's cloud. In Part A they stay with the operator's own tool and shell.
- No change to `os/exec` confinement, no tool file, no pin management, no new switch, no doctor change. The smallest surface that creates nodes and the marker.
- `cloudlist` documents no JSON fields. A parser in `jb` rests on an unverified shape; a neutral shape rests on `jb`'s own definition. The operator's script absorbs a change in the tool.
- Other sources of the same data (a Terraform state, a hand-made CSV, another cloud tool) use the same import. Part B serves one tool.
- The outward runner outside `jb` already runs PD tools. It can run `cloudlist` as well, in the same place and under the same operator control.

Against the export, and what Part B would buy:

- `jb` cannot cite the tool, its version and argv on its own authority; it records what the script wrote in `method`. A runner records them itself and pins the binary.
- A refresh would be one command with no script to write.
- A producing script can lie about `complete`. A runner knows the exit status.

These are real. They matter once the marker is relied on by an active tool. If that happens, the maintainer can take Part B, and nothing in Part A changes. Decides: the maintainer (open question 1).

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
- No change to `jb estate facts import`.
- No Go import of any PD library.
- No active check against an asset on the strength of `operated`. The marker is data. A check that uses it needs its own RFC and a policy change.
- No live call to a cloud API from `jb` in Part A.
- No sandbox, no tool download or update, and no provider config file written by `jb`.
- No new node field, and no `apiVersion` change.
- No attribution and no verdict: `operated` says whose account reported the asset, not who typed what.

## Drawbacks

- The marker depends on a script the operator writes. A wrong script, or a lying `complete`, produces a wrong marker. `jb` can check the shape and the caps, not the truth.
- `operated` is a fact that a hand-edited estate file can also carry. The loader cannot tell a human's `operated` from an import's, except by `method` and `source`.
- An asset in an inventory may be stale, and a name may no longer point where the cloud says. The marker has a time and nothing more.
- A new role and a new file format add surface to every reader of the estate file.
- Dropping private addresses by default hides internal topology from the map. `--include-private` brings it back.
- Part A gives no citation of the tool on `jb`'s own authority. Part B costs a third `os/exec` importer, a pin to maintain, cloud credentials in `jb`'s environment and a parser against an undocumented JSON format.
- The operator needs `jq` or another script for both the inventory and the outward recipe.

## Alternatives and prior art

- **Run `cloudlist` from `jb` first (Part B).** Gives a cited, pinned run and a one-command refresh. Costs listed under Drawbacks. Kept as a conditional part.
- **Read cloudlist's JSON directly.** One fewer step for the operator. It makes `jb` depend on an undocumented format and on one tool's field names, against the rule in [CASE-SPEC.md](../CASE-SPEC.md) 4.5.2 that `jb` reads no vendor format.
- **Widen `jb estate facts import` to create nodes.** One command. It removes the rule that a fact cannot invent a host, and it lives in code another change is editing now.
- **A node field `operated`.** Direct. It needs a new `apiVersion` and drops the source, method and time of the claim.
- **A role per provider** (`aws`, `gcp`, ...). More precise. A role names what kind of source answered, and the provider goes in the fact `cloud.account` and the `method`. A closed list that grows with every provider is the wrong shape for `casefile.EstateSources`.
- **Let the operator list their own hosts by hand in the estate file.** Works today, with any source from the list. It gives no provenance of the claim "ours", and every edit is manual. It stays possible beside this design.
- **Prior art in this repository.** The scan-cache import ([RFC 0001](0001-estate-v2.md), `internal/casefile/estate_facts_import.go`) for the file shape, caps and dry-run rule. The plugin host (`internal/adapters/plugin`, [PLUGINS.md](../PLUGINS.md)) for the process group, empty environment, per-launch digest check and limits in Part B.
- **Prior art outside.** The READMEs of the seven PD tools (github.com/projectdiscovery, read 2026-11-06) and `cloudlist`'s PROVIDERS.md. The author read no source code of the tools and no other project's wrapper.

## Compatibility

`jb` is pre-1.0. This RFC adds a command, a file format, one source role and (in Part B) one config key, and changes no existing behaviour. An older `jb` that meets an estate file with source `own-cloud` refuses it with its existing "not on the passive-source allowlist" error.

## Security considerations

**Part A.**

- The import file is untrusted text. Every string is checked for one line, length and credentials. The dashboard escapes it like all stored text ([RFC 0003](0003-dashboard-security-model.md)). Caps (2 MiB, 5000 assets, node cap) bound a hostile file.
- Nothing is sent and no process starts. The file is read from disk or standard input.
- A hostile or mistaken inventory can mark a third-party host as operated. A later scope check that trusts `operated` would then act on it. For that reason the marker is not scope by itself (see "What the marker means"), and an active tool is not added here.
- Account labels and numbers are sensitive. They live in the case's private repository and not in this one. Examples here are invented.
- A private-address drop and a wildcard drop are counted and shown, so a reader sees what the import removed.

**Part B, if accepted.**

Enforced: a closed tool name and compiled-in argv; no shell; targets validated and never starting with `-`; a required sha256 checked at every launch; the operator's file, not the case's; an environment of `PATH`, `LANG`, `TMPDIR`, a private `HOME` and declared variables from a compiled-in list; no key in argv or files; timeout, output, line and record caps with a process-group kill; scrubbed errors; `os/exec` confined to three packages, with no networking in `toolrun`.

Not enforced, stated plainly as [PLUGINS.md](../PLUGINS.md) does: there is no sandbox. The child has the user's filesystem and network access, and the private `HOME` only hides default config from a well-behaved tool. `jb` does not stop the tool from contacting anything. The tool may check for updates or send telemetry (**unverified**; the README lists update flags). The pin and the launch are not one atomic step; the directory mode check closes the gap. Scrubbing is a heuristic. The credentials passed here read the operator's cloud: the operator SHOULD use read-only keys scoped to listing, and `jb` cannot check that. The runner checks that output is well formed, not that it is true.

## Conformance

Proposed. None of these exist yet.

Part A:

- `schemas/estate-inventory.schema.json`, kept equal to the loader by tests that mirror `TestEstateSchemaMatchesStruct` and `TestEstateSchemaMatchesLoaderRules`.
- `TestInventoryCorpus`: synthetic files under `internal/casefile/testdata/inventory/`, valid ones and one invalid file per rule (unknown key, second JSON value, number for string, bad `kind`, bad name, credential-shaped string, oversize file, 5001 assets, empty `assets`, missing `complete`), each with the substring its error must contain.
- `TestInventoryCreatesNodesAndMarks`: golden result for a synthetic file (`www.example.com`, `192.0.2.10`, `192.0.2.11`, `service: ec2`): the nodes, the `operated`, `cloud.account` and `cloud.service` facts, the `hosted_on` edge, and the sources.
- `TestInventoryKeepsFirstSource`: a node already present from `dns` keeps source `dns` and gains the facts; two accounts give two `operated` facts.
- `TestInventoryDropsAndCounts`: wildcard, RFC 1918, link-local and loopback addresses, and invalid names are dropped and counted; `--include-private` keeps the private ones.
- `TestInventoryOutcomes`: `complete: true` exits 0; `complete: false` applies and exits 1; all-dropped and empty are errors that write nothing; a file that would fail the v2 loader writes nothing.
- Subject tests (if the decision is adopted): a file with `subject: operated`, `adversary` and none loads; any other value fails with the two named; an `adversary` file with an `operated` fact fails; an unclassified file with one loads; the schema enum equals the loader; inventory import refuses an `adversary` file and an unclassified file with nodes, and creates a new file with `subject: operated`; `refresh` refuses an `adversary` file without `--adversary`; `diff` refuses two files of different subjects; a snapshot keeps its baseline's subject; `jb case check` warns for a node id in an `operated` and an `adversary` file; a dashboard test that the two layers render under their fixed headings, that no edge set and no corroboration count crosses files, and that a hostile `subject` value never reaches the heading.
- `TestInventoryDryRun`: no write without `--apply`, and the result says so.
- `TestInventoryStartsNothing`: the command imports no `net` and starts no process (the archtest rules for `casefile` and `app` already cover this; a planted import is seen to fail).
- `TestEstateSourcesMatchPolicy` and the schema enum tests, extended with `own-cloud`.
- `TestInventoryParity`: the command, `jb.EstateInventoryImport` and the `estate_inventory_import` operation give the same result; over MCP `apply=false` writes nothing.
- A test that a drifted `operated` fact is carried by `jb estate refresh` unchanged, and that `jb estate diff` lists a lost or gained `operated` value as a fact change, never as scope.

Part B, if accepted. All use a fake tool: a small Go program built by the test into `t.TempDir()` and run as the real child behind the real runner. It uses no shell and no Python.

- **hangs**: the run ends at the wall-clock limit, the process group (including a forked grandchild) is gone, and nothing partial is stored.
- **floods output**: killed at the byte cap, memory bounded, state `cut`.
- **one huge line** with no newline: killed at the line cap.
- **exits non-zero** after valid records: state `failed`, records discarded, scrubbed stderr tail in the reason.
- **exits zero with no output**: state `no-records`, exit 1, nothing stored.
- **prints invalid JSON** on one line among valid ones, or omits a required field: state `failed`.
- **reads an env var `jb` did not declare**: the fake prints a sentinel the parent set and a declared variable; the test asserts the first is empty, the second is the declared value, and `HOME` is not the parent's.
- **looks for a default provider config** under the user config directory while the test plants one under the real `HOME`: it must not find it.
- **writes a credential-shaped string to stderr**: the error text has the scrubbed form only.
- **forks a child that outlives it**: killed with the group.
- `TestToolArgvIsFixed`: the argv for each provider equals the expected list byte for byte; a provider name with a leading `-`, a space, a newline or `;` is refused before any process starts.
- `TestToolFileRules`: one test per row of the tool-file rules, including a pin checked at every launch (the test swaps the file between two runs).
- `TestOSExecIsConfined` with `toolrun` added, and a planted-fault test that a fourth importer fails it; `TestToolrunHasNoNetwork` and `TestOnlyCmdImportsToolrun`, each seen to fail on a planted import.
- `TestDoctorTools`: states listed, no value printed, no process started without `--tools-version`.
- A recorded-sample test with real `cloudlist` output, converted to synthetic names, in `testdata/`. It settles the **unverified** JSON fields and the `$VAR` and `-ad` behaviour. The RFC does not move to `accepted` for Part B while the sample is absent.

## Reference implementations

Shipped: none.

Proposed, Part A:

- `jb estate inventory import`, `jb.EstateInventoryImport`, and the operation `estate_inventory_import`.
- The loader and schema for `jb.estate-inventory/v1` in `internal/casefile`, and the use case in `internal/app`.
- The role `own-cloud` in `casefile.EstateSources`, `schemas/estate.schema.json` and [POLICY.md](../POLICY.md); the relation `hosted_on` and the fact keys `operated`, `cloud.account`, `cloud.service` and `cloud.region` in [CASE-SPEC.md](../CASE-SPEC.md) 4.5 and a new subsection after 4.5.2.
- The "Outward recon" paragraph in [POLICY.md](../POLICY.md): `jb` does not run outward or active tools.

Proposed, Part B (only if accepted): `internal/adapters/toolrun`, the tool file loader, `estate.tools`, `jb estate inventory run`, `jb.EstateInventoryRun`, the doctor tools section, and the archtest and policy changes described above.

## Open questions

1. **Runner or export.** The RFC recommends the export. Does the maintainer want Part B now, later, or never? Decides: the maintainer.
2. **Active tools: another runner, not `jb`.** `httpx`, `dnsx`, `tlsx`, `naabu`, `nuclei`, `katana` and `cdncheck` send traffic to a host. The owner's direction is that they are not run by `jb` but by another runner, and `jb` stays inward. The maintainer is asked to confirm. If any of them ever came into `jb`, it would be a policy change and not a code detail. It would need a rewrite of the passive-only policy, a written scope rule, a per-run authorisation and a record of who authorised what ([POLICY.md](../POLICY.md), "Changing the policy"), and its own RFC. The proposed scope rule for that RFC: allowed only against assets that carry a complete, recent `operated` fact from source `own-cloud`; refused before any packet is sent; never against a third-party or attacker host. Decides: the maintainer.
3. **Provider config files.** DigitalOcean and Cloudflare, and any key that only a provider config file can take, would need a file with a secret on disk for the length of a run (Part B only). Is that acceptable? Decides: the maintainer.
4. **Unverified facts about `cloudlist`.** The JSON field names, whether `$VAR` placeholders in a provider config expand from the environment, which GCP and Azure variables `-ad` reads, whether `-p` narrows `-ad`, the version output, and whether the tool phones home. Decides: the author, by running the real binary on a test host; the maintainer reviews.
5. **`scan-cache` for outward facts.** Facts import tags every fact `scan-cache`, whose policy text is a store of past observations read from an export file. Names from a passive enumerator are not quite that. Should outward facts get their own role, or is `scan-cache` plus the `source_note` enough? This touches the facts import work in progress. Decides: the maintainer.
6. **A second source of scope.** `operated` from `own-cloud` covers cloud assets. A bare-metal host, or a name in an operator's zone with no cloud account, has no way to be marked. A role such as `operator-declared` could cover it, with the weaker meaning that a person said so. Decides: the maintainer.
7. **Guarding the marker.** A hand-edited file can carry an `operated` fact from `own-cloud`. Should `jb case check` compare it with the import record (a run record under `estate/`) and warn on a fact with no matching import? Decides: the author, then the maintainer.
8. **Role and key names.** `own-cloud`, `operated`, `hosted_on`, and the keys in the outward table. Decides: the maintainer.
9. **Freshness of the marker.** What age of `operated` still counts as scope, and who sets it: a config key, or the later RFC? Decides: the maintainer, with the active-tool RFC.
10. **Subject of a file (maintainer decision pending).** Adopt `subject: operated | adversary` as described? And should `refresh`, `diff` and `promote` refuse an `adversary` file by default, or allow it? Should unclassified files be an error after some date, or stay valid? Decides: the maintainer.

## Changes

None yet. The RFC is a draft. It was narrowed on 2026-11-06 on the owner's direction that `jb` is inward-facing and that outward and active tools run outside it.
