# RFC 0001: Estate v2
Status: draft
Scope: a `jb.estate/v2` file format that carries per-host facts and separate assessments, and a dashboard that shows them with live overlays from the evidence store.

## Summary

`jb.estate/v1` maps which addresses, hosts, domains, networks and organisations relate to which, from passive sources. It cannot carry what an operator learns about one host: open ports, operating system, certificate names, known vulnerabilities. It also has no place for an operator's judgement about a host, such as "this one looks malicious".

This RFC replaces `jb.estate/v1` with `jb.estate/v2`, which keeps the v1 data model and adds three things. A node may carry `facts`, each with the same source, method and time as any other claim. A file may carry `assessments`, a separate list of judgements, each with an author and the evidence it rests on. A new node kind, `service`, names a third-party service that infrastructure talks to.

The file stays factual. Judgements never sit on a node, and the viewer marks them as opinion. Live signals, such as whether an address is on a blocklist or when it last appeared in the evidence, are not written into the file. The dashboard reads them from the evidence store when it draws the page.

One limit stays. The usual sources of host facts, such as port and vulnerability data, are not on the passive-source list. Until the maintainer decides that (open question 1), a v2 file can cite only the eight listed sources, so those facts cannot yet be written. The format ships first, and the policy decision decides when they can be.

`jb.estate/v1` is removed. There is no compatibility path, because `jb` and one other program are the only users. The loader reads only v2. The example files and the snapshot code move to v2 in the same change. A v1 file gets an error that says to rewrite it. The drift check covers facts too.

## Motivation

An operator who investigates an attack keeps a graph of the attacker's and the victim's infrastructure. In the graphs we have seen, each host carries more than `jb.estate/v1` allows: open ports, operating system, certificate common name, known vulnerabilities, a role, and a classification such as malicious or suspicious. Edges differ in how much evidence they give: a DNS record is strong, shared hosting is weak.

Today that graph cannot live in a `jb` case. The operator has to keep it in another tool, so the one place where `jb` draws the estate shows less than the operator knows. The graph in `jb serve` is also static data: it does not show which addresses the evidence store has seen or which a reputation feed has flagged, although `jb` holds both.

Two limits in v1 cause this:

- The loader rejects any key it does not know, at any depth. A tool cannot add a field and stay valid.
- Every claim needs a source from a closed list of passive sources. A fact about a host has no place that satisfies this rule, and a judgement is not a claim about the world at all.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Claim" means a node, an edge, an absence or a fact. Every claim carries `source`, `method` and `observed`, as in [CASE-SPEC.md](../CASE-SPEC.md) section 4.5. An "assessment" is a judgement by an author. It is not a claim.

## How this design was made

1. **One current version.** The loader rejects unknown keys, so new keys need a new `apiVersion`. The version is checked before the other keys (CASE-SPEC section 4.5), so an old file gets a clear error and not a misreading. The loader reads only the current version. Nothing outside `jb` and one other program depends on v1, so keeping a v1 reader would cost code and buy nothing.
2. **Facts keep the claim rule.** A fact is an observation, so it carries `source`, `method` and `observed`. This is the rule that lets two observations be compared. A fact without it would be a claim nobody can check.
3. **Judgements go in a separate list.** CASE-SPEC section 4.5 says an estate MUST NOT be read as attribution. A classification on a node would break that sentence for every reader of the node. A separate list with an author and a basis keeps the node factual and the opinion visible.
4. **No person node.** A named individual does not belong in a format that ships in an open-source repository. The data of a real case lives in the case's own private repository. The format needs no person kind to describe infrastructure.
5. **Strength is derived.** The weight of an edge follows from its `relation`. The viewer reads one documented table. The file needs no new key, and the table can change without rewriting files. A change to the table also changes how every existing file looks (see Drawbacks).
6. **Overlays are read, not stored.** A reputation verdict and a last-seen time change daily. Written into the file they would be stale and would look like observations. The evidence store already holds both.

## The design

Everything in this section is a proposal. None of it is implemented. The Reference implementations section lists what exists today.

### File

A v2 file is the v1 file with `apiVersion: jb.estate/v2` and the additions below. Every v1 rule carries over except two: the `apiVersion` value is `jb.estate/v2`, and the set of known keys widens as described here. These rules stay: the 4 MiB cap on the file in bytes, the caps on nodes, edges and absences, and the credential scan. The YAML rules stay too. A file is one document, an unknown key is an error at any depth, and a scalar is read as its text. A number or a boolean in a text field is therefore read as written (`value: 22` is the string `22`), and a list or a map in a text field is an error.

A `service` node counts toward the cap of 5000 nodes. For every cap, "at most N" means that entry N+1 is the error. The loader checks `apiVersion` first and then reports every problem it finds, as the v1 loader does.

| Key | Type | Required | Rules |
|---|---|---|---|
| `apiVersion` | string | yes | MUST be `jb.estate/v2`. |
| `assessments` | list | no | At most 2000 entries. An empty list is valid. |

A v1 file with only its `apiVersion` changed to `jb.estate/v2` is a valid v2 file. That edit is the whole migration. The loader MUST refuse `jb.estate/v1` with an error that names both versions and says to rewrite the file.

### Node kinds

v2 adds one kind to the six of v1: `service`, a third-party service that infrastructure talks to. Its `id` starts with `service:` and the rest follows the v1 id grammar. Its `label` follows the v1 label rule. Its `source` is one of the allowed sources, for example `dns`, `ct-log` or `passive-dns`, whichever observed the relationship. A `service` node takes part in edges like any node, with any relation. v2 MUST NOT define a kind for a person. A loader MUST refuse any other kind, as v1 does.

### Facts

A node of any kind MAY carry `facts`, a list of at most 50 entries. An empty list is valid.

| Field | Rules |
|---|---|
| `key` | `^[a-z][a-z0-9_.-]{0,63}$`. |
| `value` | Text, read as written. The v1 one-line check applies: not empty or only space, at most 500 bytes, no carriage return or line feed. |
| `source` | A source on the allowlist (see Sources). |
| `method` | As in v1: how it was obtained, under the same one-line check. |
| `observed` | An RFC 3339 timestamp with a zone. |

Two facts of one node MAY share a `key`, because a host has many open ports. Only an identical pair is a duplicate. Two facts are identical when `key`, `value`, `source` and `method` are equal byte for byte. `observed` is not compared. A duplicate is a load error. A file holds at most 20000 facts in total.

Facts SHOULD NOT hold judgements. A key such as `classification` or `verdict` belongs in an assessment. The loader cannot enforce this, and Drawbacks says so.

The following keys are RECOMMENDED so that tools agree. They are examples of the vocabulary, not a closed list: `port.open`, `os`, `tls.cn`, `cpe`, `vuln`, `tech`. Only `tls.cn` has a source on the list today (`ct-log` records certificate names). The others wait for open question 1.

### Sources

The source list of v1 applies to every claim in v2: `rdap`, `rdns`, `dns`, `whois`, `crt.sh`, `ct-log`, `bgp`, `passive-dns`. Any other source is refused, as in v1. The v1 error lists the allowed sources.

Facts such as open ports and known vulnerabilities usually come from a cached third-party database, not from the eight sources above. Whether such a database counts as passive, and what name it would get on the list, is a change to [POLICY.md](../POLICY.md), not to the code (the comment on `EstateSources` in `internal/casefile/estate.go` says the same). This RFC does not decide it. See Open questions.

### Assessments

An assessment is one author's judgement about one node.

| Field | Rules |
|---|---|
| `id` | `^[a-z0-9][a-z0-9-]{0,62}$`. Unique among the assessments of the file. Assessment ids and node ids are separate namespaces, and an assessment id is not checked against other files. |
| `subject` | A node id in the same file. |
| `label` | `^[a-z][a-z0-9_-]{0,31}$`. Lower case only. The case chooses the vocabulary, for example `suspicious`. |
| `by` | Who decided. A role or a handle. The v1 one-line check applies, with a limit of 128 bytes. |
| `decided` | An RFC 3339 timestamp with a zone. A time in the future is allowed, as it is for `observed` in v1. |
| `basis` | A list of 1 to 20 references, without duplicates. Each is a node id in the file, or `<node id>#<fact key>`. The reference may name any node of the file and need not include the subject. |
| `note` | Optional. The v1 one-line check applies, with a limit of 500 bytes. |

`by` and `basis` are REQUIRED. An assessment without a basis is a load error. A reference is resolved as follows. A loader splits it at the first `#`, which is safe because node ids cannot contain `#`. A bare node id resolves when that node exists. A reference with `#` resolves when the node exists and has at least one fact with that key. A reference that does not resolve is a load error. Two assessments with the same `subject`, `label` and `by` are allowed: the ids tell them apart.

The `caveat` of a v2 file SHOULD also say that assessments are the opinion of their author and not a fact. The loader checks that the caveat is present, as in v1, and not what it says. The viewer MUST NOT rely on the caveat for this. It MUST show a fixed notice with every assessment section (see Dashboard).

### Edge strength and overlays

The viewer derives the strength of an edge, `strong`, `moderate` or `weak`, from its `relation` alone. A later RFC MAY add the `source` as a second input. The initial table is below. It is a starting point for review, not a measured result.

| Strength | Relations |
|---|---|
| strong | `resolves_to`, `cname` |
| moderate | `ptr`, `mx`, `ns`, `registered_to`, `spf_authorises`, `spf_include`, `spf_redirect` |
| weak | `within`, `originated_by`, `announced_in`, `held_by`, `ct_candidate` |

Any other relation is `weak`. The table covers every relation that the collectors write, which [CASE-SPEC.md](../CASE-SPEC.md) section 4.5 lists. The file stores no strength.

The viewer MAY draw two overlays on an `ip` node. The viewer reads both from the evidence store when it builds the page. It never reads them from the file.

- The latest reputation verdict for the address. `jb intel` records these snapshots.
- The time the address last appeared in the stored events. The viewer finds it through the key field that `jb serve` already takes (`--key-field`, default `client_ip`; see [CONFIG.md](../CONFIG.md), "serve").

An overlay is labelled with its source and time. A page that cannot read the store shows no overlay and says so. It never shows an empty overlay as "clean".

### Drift

The drift check (CASE-SPEC section 4.5.1) moves to v2 with the format. `jb estate refresh`, `diff` and `promote` read and write v2, and a snapshot embeds a v2 body (`jb.estate-snapshot/v2`).

A fact is a claim, so `diff` compares facts as it compares other claims. Two facts are comparable when the node id, `key`, `source` and `method` are equal. For one such group, `diff` compares the set of values. A value that appears or disappears is a change, with both observation times. A group that exists on one side only is not comparable and is listed, never counted as drift, as for any claim. A port list that gains an entry is one added value and not a replaced list.

Assessments are opinion and are not compared.

The collectors write no facts, so `refresh` carries the facts of the baseline file through unchanged and does not re-ask them. A later RFC may add a collector.

### Dashboard

The Estate page MUST show facts and assessments in the record sheet. Assessments MUST sit in their own section with the heading `Assessments (opinion)` and a fixed notice that an assessment is its author's opinion and not an observation. Each shows `by`, `decided` and its basis. The graph SHOULD draw edge strength as line weight and SHOULD offer a filter by node kind. The page MUST escape the text of every new field like all stored text, and MUST show at most 300 characters of one stored string, as it does today ([RFC 0003](0003-dashboard-security-model.md)).

## Non-goals

- v2 does not add a collector for facts. The drift check compares them and the collectors do not write them.
- v2 does not add a collector for ports, operating systems or vulnerabilities. A file is authored by an operator or another tool.
- v2 does not define a person, an alias or an identity of an attacker.
- v2 does not store reputation, last-seen times or any value that changes without a new observation.
- v2 does not allow an active probe as a source.
- v2 does not make the estate an attribution tool. The v1 rule stands.

## Drawbacks

- Every existing v1 file must be edited to v2. That is one line per file, and there are two example files and the case's own estate files.
- The snapshot format changes with it (`jb.estate-snapshot/v2`), and any snapshot already written has to be regenerated or rewritten.
- Facts need sources. Most useful facts about a host come from tools `jb` does not run. The provenance rule makes that visible, and it does not make the facts true.
- A list of assessments next to a list of facts invites readers to merge them. The separation is a convention, held only by the schema, the viewer and the caveat.
- `by`, `note`, every `label` and every fact `value` are free text. A case author can write a person's name in any of them, and can put a judgement in a fact with a key such as `classification`. The format cannot prevent either. The file is a case's private data and not part of this repository, and the viewer shows every fact with its source so that a reader can tell.
- Derived strength puts an opinion inside the viewer. A change to the table changes how every existing file looks.

## Alternatives and prior art

- **Keep the graph in the operator's own tool.** Nothing changes in `jb`, and `jb serve` keeps showing less than the operator knows. This stays the right answer for data that names a person or carries judgements the operator will not publish.
- **A separate case-side format for judgements, with its own file.** It keeps the estate untouched. It also splits one picture across two files, and it needs its own loader, schema and viewer. v2 keeps one file and one loader, with the separation inside the file.
- **Widen v1 in place, with no new version.** It is the least work. It breaks the rule that an unknown key is an error, because a new `jb` would write files that an old one misreads without saying so. The version bump is cheap and keeps that guard.
- **Keep v1 readable next to v2.** It spares two files an edit. It costs two loaders, two schemas and the drift check for both, and nobody needs it.
- **A free `attributes` map on every node.** It is simple. It drops the source, method and time of each value, which is the rule that makes two observations comparable.
- **External graph formats.** This RFC does not compare itself with published formats for threat or infrastructure graphs, because the author did not read any for this draft. The reviewer is asked to name one worth comparing. See Open questions.

## Compatibility

`jb` and one other program are the only users and nothing is public, so there is no compatibility path. This section says what breaks and what each user changes.

- The v1 loader, `schemas/estate.schema.json`, the v1 corpus and the v1 tests are replaced by the v2 ones.
- A file with `apiVersion: jb.estate/v1` is refused with an error that names both versions and says to rewrite it. An older `jb` that meets a v2 file stops at its own `apiVersion` check with its existing error: `unsupported apiVersion "jb.estate/v2": this build reads only jb.estate/v1`.
- `jb case check` loads every file in `estate/` (CASE-SPEC section 9) and checks them as v2.
- A snapshot (`jb.estate-snapshot/v1`) is replaced by `jb.estate-snapshot/v2`. A baseline file and its snapshots are rewritten by changing the `apiVersion` lines, or regenerated with `jb estate refresh`.
- Migrating a file: change `apiVersion` to `jb.estate/v2`. The file stays valid. Add facts and assessments when you have them.
- The other program changes its estate files the same way. It pins an exact `jb` version, so it moves when it chooses.

## Security considerations

- Every string a v2 file adds (`key`, `value`, `label`, `by`, `note`) is untrusted text. The dashboard MUST escape it as it escapes all stored text, and MUST show at most 300 characters of one string. The existing rule that bans raw-HTML escape hatches covers the new templates.
- The credential scan of CASE-SPEC section 6.3 applies to every string in the file, including facts and assessments.
- Caps limit the size of what a hostile file can make the loader or the browser handle: 50 facts per node, 20000 facts and 2000 assessments per file, 4 MiB per file.
- A fact about a host can come from a third party. The format records the source and the time. It does not make the value true, and the viewer shows the source with the value.
- A cached third-party database receives the address when it is queried. A source of that kind therefore needs the same check as the other external services in [POLICY.md](../POLICY.md): what leaves the machine, and whether it announces the investigation. That check belongs to the policy change in Open questions.
- Assessments are opinions about a node that may be a real person's device. The format cannot judge fairness. The caveat, the label "opinion" in the viewer and the required basis make the claim and its support visible to the reader. The data of a real case stays in the case's own repository, never in this one.

## Conformance

Proposed. None of these exist yet.

- `schemas/estate-v2.schema.json`, kept equal to the loader by tests that mirror `TestEstateSchemaMatchesStruct` and `TestEstateSchemaMatchesLoaderRules`.
- A corpus of synthetic files under `internal/casefile/testdata/estate-v2/`: valid files, and one invalid file for each rule above. Each invalid file names a substring that the error MUST contain. The tests compare the substring, not the whole message.
- A test that a v1 file with only the `apiVersion` changed loads as v2 with the same nodes and edges.
- A test that a file with `apiVersion: jb.estate/v1` is refused with the rewrite message.
- Drift tests: a gained value, a lost value and a group present on one side only, for facts, and a test that an assessment change is not drift.
- A test that every assessment `basis` reference resolves, and that an assessment without `by` or `basis` fails.
- Dashboard tests, three of them. An assessment renders under the "opinion" heading and not in the node table. Every new field is escaped: the existing hostile-text tests cover the new fields. An overlay is absent, with a note, when the store cannot be read.
- A test that the strength table covers every relation that CASE-SPEC section 4.5 lists as written by the collectors, and that an unknown relation is `weak`.
- A test that the viewer shows the fixed assessment notice whatever the `caveat` says.

### Examples

Each example starts from this base file, called P:

```yaml
id: t
caveat: "Ownership and relationships, not who typed the commands."
nodes:
  - id: ip:192.0.2.10
    kind: ip
    label: 192.0.2.10
    source: dns
    method: "synthetic example"
    observed: 2026-11-06T10:00:00Z
```

The examples are test vectors for the proposed loader. They are not run today.

| File | Result |
|---|---|
| P with `apiVersion: jb.estate/v1` | error: unsupported apiVersion, rewrite to `jb.estate/v2` |
| P with `apiVersion: jb.estate/v2` and a misspelt key | error: unknown key |
| P with `apiVersion: jb.estate/v2` and nothing else | valid |
| P as v2, the node has a fact `{key: tls.cn, value: a.example.com, source: ct-log, method: m, observed: 2026-11-06T10:00:00Z}` | valid |
| the same fact with `source: nmap` | error: source not on the allowlist |
| two facts equal in `key`, `value`, `source` and `method` | error: duplicate fact |
| two facts with the same `key` and different `value` | valid |
| an assessment `{id: a1, subject: ip:192.0.2.10, label: suspicious, by: analyst, decided: 2026-11-06T10:00:00Z}` | error: missing `basis` |
| the same assessment with `basis: ["ip:192.0.2.10#port.open"]` and no such fact | error: reference does not resolve |
| the same assessment with `basis: ["ip:192.0.2.10"]` | valid |
| a node with `kind: person` | error: unknown kind |
| a node `{id: service:dns-provider, kind: service, ...}` | valid |

## Reference implementations

Shipped:

- The v1 file format: `internal/casefile/estate.go`, `schemas/estate.schema.json`, and the tests named in [docs/spec/README.md](../spec/README.md).
- The estate view of the dashboard: `internal/adapters/web`, `internal/estategraph`.
- Reputation snapshots: `jb intel` writes them and the dashboard's `LatestReputation` reads them (`internal/core/dashboard.go`).
- A way to find the events that carry a given field value, newest first: `FieldEventFinder` in `internal/core/activity.go`, used today by `jb actor status`.

Proposed:

- The v2 loader, schema and corpus.
- The `service` node kind, `facts` and `assessments` in the loader and in the view types.
- The strength table and the overlays in the Estate page.
- A read port for the overlays, if `FieldEventFinder` does not fit.
- The POLICY.md change for a cached third-party source, if the maintainer accepts one.

## Open questions

1. **A cached third-party database as a source.** Decided on 2026-11-06 by the maintainer: it is passive when the target observes nothing from `jb`, and a store of past scan results passes. The test is in [POLICY.md](../POLICY.md), section "The test for a source". Each such source joins the list under its own name, is off by default, and needs the `estate.external` switch. Still open: what the first one is called. Decides: the maintainer.
2. **Edges in `basis`.** Edges have no ids. Should an assessment be able to cite an edge, and by what address? Decides: the maintainer, with the author.
3. **The strength table.** Are the values in the table right, and who may change them? Decides: the maintainer.
4. **Set comparison for facts.** Is comparing the set of values per group right for keys where order or multiplicity matters? Decides: the author, after a test on a synthetic port history.
5. **Free text in `by`.** Is a role or handle enough, or should the format limit it further? Decides: the maintainer.
6. **A published format to compare with.** Which one should the next draft read? Decides: the reviewer.
7. **The overlay key.** The last-seen overlay uses `--key-field`. Is one field enough for a case whose events carry the address in more than one? Decides: the author, after a test on a synthetic case with two fields.

8. **Which facts ship first.** The format can ship before open question 1 is decided, and only facts from the eight listed sources can be written until then. Should the format wait for the decision? Decides: the maintainer.

## Changes

- 2026-11-06: first draft.
- 2026-11-06: revised for one current format: v1 is removed, drift covers facts, and the compatibility section lists what the two users change. This follows the owner's decision that `jb` has no backward compatibility before a public release.
- 2026-11-06: revised after a clean-room read: the loader rules that v1 already defines are stated, the contradictions in the wording are removed, and the proposal is separated from the present throughout.
