# RFC 0015: Subject of an estate file
Status: accepted
Scope: an optional `subject` key on a `jb.estate/v2` file, `operated` or `adversary`, so the case owner's own infrastructure and an attacker's are separate files and separate layers on the map.
Accepted: 2026-11-06 by the maintainer

## Summary

One estate map holds two different things today. The passive collectors profile addresses seen in the logs, which are third-party and often adversary infrastructure. `jb estate refresh` and `diff` watch the operator's own estate. A reader cannot tell which a file is, and the viewer draws both in one graph.

This RFC adds an optional top-level key `subject` to `jb.estate/v2` with two values, `operated` and `adversary`. A file without it is *unclassified* and stays valid. The loader checks the value. The dashboard draws one layer per subject and never merges nodes, edges or corroboration across files. `jb estate diff` compares only two files of the same subject.

## Motivation

An operator under attack asks two questions about the map. What do the attackers use? What is ours? Both are answered from estate files, and today nothing tells them apart. The owner decided on 2026-11-06 that `jb` is inward-facing: it analyses the operator's own logs and infrastructure, and outward reconnaissance runs elsewhere and enters through `jb estate facts import`. That decision needs a place in the data. A later check that must act only on the operator's own assets (any scope rule, in this RFC or another) needs a file that says it holds those assets.

A concrete case: a case holds `operated.yaml` (the operator's cloud hosts) and `adversary.yaml` (addresses from the logs, with their RDAP and reverse DNS). The map shows two layers. An address in both is drawn in each, with no line between them.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

1. **A key on the file, not on the node.** A node is unique by id inside a file, and the same address can be both ours and a visitor's in different cases. The layer is a property of the whole map.
2. **Optional, so nothing existing breaks.** Every file written so far is unclassified and valid. Pre-1.0 a required key would be possible; it would force a decision on every existing map for no gain.
3. **Only what the loader can check is checked.** A person can write `subject: operated` on a file that is not. The loader cannot know. It checks the value and the layer rules it can enforce (diff, viewer). It does not guess from the contents. RFC 0001 says the same of `classification`.
4. **No second set of commands.** The collectors keep writing to the file you name. They do not set `subject`; a file they create is unclassified. No `--adversary` flag and no refusal by default: drift commands work on any file, as today.
5. **Two layers in the viewer, never merged.** Merging would count corroboration across what are different claims about different things.

## The design

### The key

`jb.estate/v2` gets an optional top-level `subject`. Values: `operated` (the nodes are infrastructure the case owner operates) and `adversary` (the nodes are infrastructure of an attacker or a third party seen in the evidence). Absent means unclassified. Any other value is a load error that names the two valid ones. `schemas/estate.schema.json` gets the key with the two-value enum, and the schema tests keep it equal to the loader.

### Rules

- A file's nodes are never moved between files by `jb`. A node id MAY appear in two files of one case. A compromised host of the operator is in both layers for a real reason.
- `jb estate refresh`, `diff` and `promote` read and write one file as they do today and keep its `subject`. A snapshot copies the `subject` of its baseline.
- `jb estate diff` compares two files only if they have the same `subject` (absent equals absent). Otherwise it refuses with a usage error that names both.
- A future importer that creates nodes the operator runs (RFC 0016, parked) writes only an `operated` file. That rule belongs to that RFC.
- A later active tool, if one is ever added, may target only nodes of an `operated` file. That belongs to its own RFC. This RFC only makes the data exist.

### The dashboard (`internal/adapters/web`)

The Estate page already draws one graph per file. It groups the graphs under three fixed headings: "Operated", "Adversary and third-party", "Unclassified". The text of a heading is fixed in the code and never taken from the file. The viewer MUST NOT merge nodes or edges across files and MUST NOT count corroboration across files, so the edge weight of RFC 0001 is computed per file. An `ip` node in two layers is drawn in each, with no line between them. The node-kind filter applies within a layer.

## Non-goals

- No check that a file's contents match its `subject`. The loader cannot tell.
- No new command and no new flag.
- No change to the collectors or to `jb estate facts import`.
- No source role, no marker fact and no scope rule. Those belong to RFC 0016 and to a future active-tool RFC.
- No rule that unclassified files become an error later.

## Drawbacks

- `subject` is data a person asserts, like `by` in an assessment. A wrong value shows a node in the wrong layer.
- A node in two files shows twice. That is intended, and it can look like duplication.
- Another key on the format, and another layer in the viewer, for every reader of the estate file.

## Alternatives and prior art

- **A per-node field.** Rejected: see design 1.
- **A role per file by name** (`operated.yaml`). Rejected: a convention a person can break without the loader noticing.
- **Refuse drift on an `adversary` file unless `--adversary` is passed.** Drafted and cut for a stable core: it adds a flag and a state for an unverified claim.
- **A required key.** Rejected: design 2.
- **Prior art in this repository.** RFC 0001's `classification` (a value the tool attaches no meaning to) and its per-file graphs.

## Compatibility

`jb` is pre-1.0. One optional key is added. An older `jb` rejects a file that has it with its existing unknown-key error. Every file without it behaves as before.

## Security considerations

`subject` is untrusted text in a file. The loader accepts two values, so a hostile value is a load error and never reaches the viewer. The headings are fixed in code. The key grants no authority: a later scope check MUST NOT treat `subject` alone as proof that an asset is operated, only as one required condition beside a source-backed fact (RFC 0016). A hand-edited `subject: operated` on an attacker's map would otherwise turn it into a target list.

## Conformance

- A file with `subject: operated`, `adversary` and none loads; any other value fails with the two valid ones named.
- The schema enum equals the loader (mirror `TestEstateSchemaMatchesLoaderRules`).
- `diff` refuses two files of different subjects and accepts two of the same, and two unclassified ones.
- A snapshot keeps its baseline's `subject`, and `promote` keeps it.
- A dashboard test that the three layers render under their fixed headings, that no edge set and no corroboration count crosses files, and that a hostile `subject` value never reaches the page.
- `jb case check` and the library load a case with a mix of subjects.

## Reference implementations

Built, not yet released: the key in `internal/casefile` (loader and schema), the diff and snapshot rules in `internal/app`, the grouping in `internal/adapters/web`, and the table in [CASE-SPEC.md](../CASE-SPEC.md) 4.5.

## Open questions

Decided by the author on 2026-11-06 when the maintainer chose to take the subject key and park the rest; the maintainer may revise:

1. No refusal by default for drift on an `adversary` file. Revisit only if the repeated lookups prove a problem.
2. Unclassified files stay valid.
3. No warning for a node id in two files.

## Changes

- Build note: `subject: ""` (key present, empty) is a load error, like any other value. The dashboard prints a layer heading only when it holds a graph, and a graph whose subject is not one of the two valid values (possible only for a caller that bypasses the loader) falls under Unclassified without printing the value.
