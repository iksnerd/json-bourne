# RFC 0002: Mapper plugin protocol v1
Status: implemented
Scope: the design, limits and trust model of the mapper plugin protocol at `v: 1`, and the rule for changing it.
Accepted: 2026-11-06 by the maintainer

This is a back-fill RFC. The protocol was built before the RFC process existed. This document records the reasons and the checks of what already ships. It changes no behaviour.

## Summary

A mapper turns one raw log document into one event. A mapper plugin is a separate executable that does this job for a `kibana` source named `mapper: plugin:<name>`. `jb` starts the executable once per source per run and talks to it in newline-delimited JSON over stdin and stdout.

[docs/PLUGINS.md](../PLUGINS.md) is the specification. It holds the handshake line, the request and response lines, the allowlist file format and the limits table. This RFC does not repeat that text and does not override it. If the two differ, PLUGINS.md and the code decide, and this RFC is corrected.

This RFC holds what PLUGINS.md does not: the scope, the reasons for each choice, the non-goals, the drawbacks, the security considerations, the compatibility rule and the conformance evidence. The compatibility rule is that the protocol is `jb`'s own and carries no compatibility promise. An incompatible change is a new `v` ([ADR 0001](../adr/0001-relationship-to-other-plugin-specifications.md), point 3, revised).

## Motivation

The built-in mappers (`default`, `nginx_ingress` and others) are Go code inside the `jb` binary. Parsing the log format of one product then means changing the core binary. An operator who hunts across a product that `jb` does not know has two choices: wait for a release, or fork.

A plugin lets the operator add a parser without a release. It also puts untrusted code next to evidence. The log documents hold personal data and attacker-controlled text. The design therefore has two jobs at once: make a parser easy to add, and make a wrong or hostile parser unable to turn a missing document into a clean result.

The last point is the one this tool exists for. A hunt that skips documents can print "no findings" while the attack sits in the skipped lines.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

**One slot per document.** The response carries exactly one slot for each input document, in order. A slot is an event or `null`. The alternative was a response that lists only the events it produced. That form lets a plugin drop a document without anyone noticing. With one slot per document, the host can count and compare. A count mismatch is a failure.

**An explicit `unparsable` list.** A `null` slot is only valid when its index is also in the `unparsable` list. A `null` that is not listed, or an event that is listed, breaks the call. The alternative was to treat every `null` as "unparsable". That would let a plugin that crashed halfway, or a bug that left holes, look like a format it does not read. The list makes "I do not read this line" a statement the plugin must make on purpose. The host counts these in `Stats.Unparsable`, the same counter the built-in mappers use.

**Any fault fails the source.** A timeout, a crash, invalid JSON, a wrong id, a wrong slot count, an oversized line and a bad handshake all fail the source for the run. The hunt then reports incomplete and exits 1, as it does for an unreachable Kibana. The alternative was to skip the bad batch and go on. That produces a result that looks complete and is not.

**A breaker after three breaks.** After three consecutive breaks in one run the host stops launching the plugin and fails further calls at once. The alternative was to retry without limit, which spends the operator's time and the plugin's deadline on a plugin that will not recover. A successful call resets the count. A cancelled context, such as an operator interrupt, is not a break.

**Newline-delimited JSON over stdio, one request in flight.** This needs no socket, no port and no library in the plugin. A plugin in any language can read lines and write lines. Serial requests keep the host simple and keep memory bounded. The cost is no parallelism inside one source.

**An allowlist file that belongs to `jb`, not to the case.** The operator names plugins in `$JB_PLUGINS_FILE`, else `~/.jb/plugins.yaml`. A case or hunt config can only name an entry by name. The alternative was to let the case carry a path or command. A case is a file that can arrive from someone else, so it must not be able to choose what runs.

**A sha256 pin, checked on every launch.** The pin is optional. The alternative was to check once at load. A check at load leaves a window in which the file can be replaced. Checking at every launch narrows it, and the mode check on the directory narrows it further.

**A stripped environment.** The child gets `PATH`, `HOME`, `LANG` and `TMPDIR` only, when `jb` has them. The alternative was to pass the whole environment. `jb` holds API keys in its environment, so the child must never receive them. The real defence against a leaked secret is that the child never has it.

**No sandbox.** The host does not confine the child. A portable sandbox for Go on Linux and macOS is a large project with its own failure modes. PLUGINS.md says so in plain words so that no operator assumes confinement that does not exist.

**No data other than raw documents.** A plugin receives raw log documents and its own `mapper_config`. It never receives findings, runs or estate data. This keeps what a reviewer has to trust small, as ADR 0001 point 7 states.

## The design

The normative text is [docs/PLUGINS.md](../PLUGINS.md), sections "The protocol", "Trust: only you allow a plugin", "Limits", "A plugin never produces a pass" and "Environment, directory, shutdown". This section lists the rules that carry the design. Each rule names the check that holds it.

### Protocol rules

- **Handshake.** A plugin MUST print one manifest line before any request. `v` MUST be `1` and `role` MUST be `mapper`. Held by `TestHandshakeRoleAndVersionAreChecked` and `TestHandshakeDeadline` in `internal/adapters/plugin/host_test.go`.
- **One slot per document.** A response MUST carry exactly one slot per input document, in order. Held by `TestWrongResultCountIsABreak`.
- **Unparsable list.** A `null` slot MUST be listed in `unparsable`. A listed index MUST be in range and appear once, and a listed slot MUST be `null`. Held by `TestNullSlotNotListedUnparsableIsABreak` and `TestUnparsableListIsValidated`.
- **Request id.** A response `id` MUST equal the request `id`. Held by `TestResponseForAnotherRequestIsABreak`.
- **Event shape.** An event MUST carry an RFC 3339 `ts` and a `fields` object. Held for `ts` by `TestBadEventTimestampIsABreak`. The missing-`fields` case is in `decodeEvent` and has no test of its own.
- **Unknown fields.** A host MUST ignore unknown fields in the manifest, response and event. Held by `TestUnknownFieldsAreIgnored`.
- **No partial answer.** A failed call MUST return no results. The `mustFail` helper in `host_test.go` asserts this in each test that uses it.
- **Plugin-reported error.** A non-empty `error` MUST fail the source. Held by `TestPluginReportedErrorFailsAndIsScrubbed`.

### Limits

The numbers below come from the constants in `internal/adapters/plugin/host.go` and `allowlist.go`. The Limits table in PLUGINS.md has seven rows: documents per request, deadline, response line, request line, `mapper_config`, stderr and breaks. The other four limits are not in that table. "Open questions" notes the places where its wording differs from the code.

| Limit | Value in the code | Constant | Where it applies |
|---|---|---|---|
| Documents per request | 200 | `DefaultMaxDocs` | The host splits a larger batch into several requests. |
| Deadline per request, and for the handshake | 10 s | `DefaultDeadline` | The process group is killed. A break. |
| One response line | 4 MiB | `DefaultMaxResponseBytes` | Reading stops as soon as the line is too long. A break. |
| One request line | 8 MiB | `DefaultMaxRequestBytes` | A request is split by size too. One document that does not fit fails the source. |
| `mapper_config` | 64 KiB | `maxConfigBytes`; a literal `64<<10` in `validateMapper` | Refused at config load (`internal/config/register_kibana.go`) and again by `plugin.NewHost`. |
| Stderr kept | last 4 KiB | `DefaultStderrBytes` | Older output is discarded. The plugin is never blocked. |
| Consecutive breaks | 3 | `DefaultMaxBreaks` | The breaker opens. |
| Shutdown grace | 2 s | `shutdownGrace` | The process group is killed after stdin closes. |
| Manifest line | 16 KiB | `maxManifestBytes` | A break. |
| Manifest `name` | 64 bytes | literal in `handshake` | A break. |
| Allowlist file | 1 MiB | `maxAllowlistBytes` | Refused at load. |

The limits can be set through `plugin.Limits` in the Go API of the host. The `jb` command line and config do not expose them, so these are the values every operator gets. The limit tests (`TestBatchesAreCappedAtMaxDocs`, `TestOversizedResponseIsABreak`, `TestUnterminatedFloodIsBoundedAndKilled`, `TestOneDocumentOverTheRequestLimitFailsInsteadOfBeingSkipped`, `TestStderrIsBoundedAndScrubbed`, `TestDeadlineKillsTheWholeProcessGroup`) pass smaller values in `Limits` to run quickly. The default values are pinned separately: `TestPluginWireProtocolV1HostSideIsUnchanged` (`internal/adapters/plugin/wire_test.go`) compares the host against `testdata/wire-v1.golden`, which holds the `Default*` limits, `maxConfigBytes`, `maxManifestBytes` and `shutdownGrace`. A change to one of those values fails a test.

### Trust rules

- **Allowlist.** The allowlist MUST be a regular file that group and others cannot write. It MUST parse as strict YAML of one document. A missing file MUST mean an empty allowlist. Held by `TestAllowlistIsStrict` and `TestAllowlistFileMustNotBeWritableByOthersAndMissingMeansEmpty`.
- **Name only.** A case config MUST name a plugin by `plugin:<name>` and by nothing else. Held by `TestHostileCaseConfigsCannotReachAnythingButAnAllowlistedName` in `internal/config/plugin_test.go`.
- **Verified file.** Before every launch the host MUST check three things. The path resolves to a regular file in the allowlisted directory. Neither the file nor the directory is writable by group or others. The owner can execute the file. Held by the `TestVerify...` tests in `internal/adapters/plugin/trust_test.go`.
- **Pin.** When an entry has a `sha256`, the host MUST refuse a file whose digest differs, on every launch. Held by `TestVerifyRefusesAPinMismatch` and `TestPinIsCheckedBeforeEveryLaunch`.
- **Environment.** The child MUST receive only `PATH`, `HOME`, `LANG` and `TMPDIR`. Held by `TestChildEnvironmentIsEmptyPlusFour`, which sets a sentinel secret in the parent and checks that the child never sees it.
- **Working directory.** The child MUST run in the plugin's own directory. Held by `TestChildRunsInThePluginsOwnDirectory`.
- **Process group.** On Unix the host MUST start the child in its own process group and kill the group on a break. Held by `TestDeadlineKillsTheWholeProcessGroup`.
- **Breaker.** After three consecutive breaks the host MUST NOT launch the plugin again in that run. A success MUST reset the count, and a cancelled context MUST NOT count. Held by `TestBreakerOpensAfterThreeBreaksInARow`, `TestSuccessResetsTheBreakerCount` and `TestCancelledContextKillsTheChildAndIsNotABreak`.
- **Shutdown.** The host MUST close stdin and kill the group if the child is still running after two seconds. Held by `TestCloseStopsTheChildAndIsIdempotent`, `TestCloseKillsAChildThatIgnoresEndOfInput` and, for `jb watch`, `TestWatchSignalLeavesNoPluginProcess` in `cmd/jb/plugin_test.go`.

### Isolation of the code

- **Only the host starts processes.** Only `internal/adapters/plugin` and `internal/casefile` (the git guard) MAY import `os/exec`. Held by `TestOSExecIsConfined`.
- **Plugins are inert.** Example plugins and the `sdk` package MUST import the standard library and `sdk` only, and MUST NOT import `os/exec`, `net`, `net/http`, `syscall`, `plugin` or `unsafe`. Held by `TestPluginsAreStdlibOnlyAndInert`.
- **Nothing links a plugin.** No package outside `examples/plugins/` MAY import a package under `examples/plugins/`. Held by `TestNothingImportsThePlugins`.
- **The host has no network and no log.** `internal/adapters/plugin` MUST NOT import `net` or `log`. Held by the dependency rule for that package in `internal/archtest/archtest_test.go`.

## Non-goals

- **A sandbox.** The host does not confine the filesystem or the network of the child. PLUGINS.md lists this under "What `jb` does not enforce".
- **Compatibility with another project's plugin protocol.** A plugin written for another host does not run here. ADR 0001 records why.
- **Other roles.** There is one role, `mapper`. Plugins that add pages, act on systems or serve data are out of scope.
- **Parallel requests.** One request is in flight at a time, per source.
- **Proof that a plugin is truthful.** The host checks that an answer is well formed and complete. It cannot check that the events are true.
- **Plugin distribution.** `jb` does not download, install or update plugins. The operator builds, places and allowlists the file.
- **Atomic verify-and-exec.** The digest check and the launch are two steps. See "Drawbacks".

## Drawbacks

- **No isolation.** An allowlisted plugin runs as the operator, with the operator's files and network. A pin proves that the file is the one the operator chose. It does not make that file safe.
- **A window between check and launch.** Go cannot portably execute a file descriptor. The host checks the digest, then starts the path. The mode check on the directory limits who can replace the file in between. It does not check the ancestors of the directory and does not check who owns the file.
- **Personal data leaves the process.** Every document the source fetches is written to the plugin's stdin, personal data included. `jb doctor` says so, but the operator must still trust the plugin.
- **A heuristic scrub.** The host removes control characters and credential-shaped text from the plugin's stderr and error text, and cuts it to 400 characters. A plugin that wants to leak can encode around it. The scrub stops accidents only.
- **Serial and chatty.** One request at a time, JSON encoded and decoded for every document. A heavy mapper costs throughput.
- **No process groups off Unix.** On a platform without them, a deadline kills only the plugin itself. A plugin that forks can outlive it. Only `procgroup_unix.go` and `procgroup_other.go` implement this.
- **A change breaks every plugin.** There is no compatibility path. With three example plugins and no outside author, the cost is three edits.
- **Two ways to write a mapper.** A format can be a built-in mapper or a plugin. The conformance corpus keeps the two equal for the cases it covers, and no further.

## Alternatives and prior art

**Compile plugins in.** Loading plugin code into the `jb` process would put untrusted code inside the evidence process with no limits. It was not used.

**A scripting language inside the binary.** Embedding an interpreter would avoid a child process. It would add a large dependency, a second language to review and no process boundary at all. It was not used.

**Declarative mapping only.** A config-only mapper needs no plugin. The three example plugins show how far that goes: they are configured entirely by `mapper_config`. A format that needs code still needs somewhere to run it.

**An RPC protocol over a socket.** gRPC or HTTP between host and plugin brings generated code, ports and a listener. Lines over stdio need none of that and work in any language.

**Prior art.** The line-oriented, handshake-first shape resembles the plugin protocols of other host programs that run long-lived child processes. This RFC does not claim that `jb` follows or implements any of them. ADR 0001 states that the protocol is `jb`'s own. No external specification was read for this back-fill, and none is cited.

## Compatibility

The protocol is `jb`'s own and carries no compatibility promise (ADR 0001, point 3, revised on 2026-11-06). `jb` and one other program are the only users. The rule:

- **A new incompatible protocol is a new `v`.** A host reads only the current `v`. A host that meets a manifest with another `v` fails the handshake with a message that names both versions. Held by `TestHandshakeRoleAndVersionAreChecked`, which runs a plugin that announces version 2.
- **A host ignores unknown fields** in the manifest, response and event, so a plugin can add data without a version change.
- **Changing the protocol needs an RFC.** Any change to the wire format, the limits or the trust rules goes through the process in [docs/rfcs/README.md](README.md).

The Go package `sdk` is the plugin side. It is public and v0, and its API MAY change in any release (`sdk/serve.go` says so; so does CHANGELOG.md). Its wire behaviour is bound by this RFC and PLUGINS.md, not by its own version. RFC 0018 (accepted) pins the sdk surface and the wire protocol with golden tests: `TestAPISurface` (`jb/testdata/api/sdk.txt`), `TestPluginWireProtocolV1PluginSideIsUnchanged` (`sdk/testdata/wire-v1.golden`) and the host-side golden above.

Changing the limits is not a protocol change, but it changes what a plugin can rely on. A plugin SHOULD be written to the limits in the table, not to the sdk's own bound (`sdk.MaxRequestLine`, 16 MiB, above the host's 8 MiB request limit).

## Security considerations

**What an attacker can do.** The threat has three parts.

- **A hostile case.** A case file tries to make `jb` run something. The case can name an allowlisted plugin by name and can pass `mapper_config` as data. It cannot add a path, a command, an argument or an allowlist entry. Names such as `plugin:/tmp/x`, `plugin:../x` and `plugin:sh -c id` are load errors. `TestHostileCaseConfigsCannotReachAnythingButAnAllowlistedName` covers these.
- **A swapped file.** Someone replaces the plugin binary. The pin and the mode checks refuse a file that changed or that others can write. A user who can write as the operator is outside the model.
- **A hostile or buggy plugin.** The plugin returns oversized, malformed, slow or false output. The limits, the deadline, the slot rules and the breaker bound the damage to a failed source. A false event cannot be detected.

**What the design assumes.** The operator controls the allowlist file and the plugin directory. The operator trusts the plugin author with every document. The platform has process groups for the kill to reach children.

**What it guarantees.** A plugin never produces a pass. Every failure listed in PLUGINS.md fails the source and makes the hunt incomplete. No failure becomes an empty clean result, and no document is silently skipped. PLUGINS.md also states that error text never contains a document or a response. I found no test that asserts this.

**What it does not guarantee.** There is no sandbox. Confinement of the network and the filesystem is the operator's job, for example by running `jb` somewhere that confines the network.

**Further risks.**

- **Stripping the environment is a courtesy.** The child can read `~/.jb`, `~/.ssh` and shell history as the operator can. It does not protect files.
- **Output is evidence.** A malicious plugin can emit any events. Findings rest on that data.
- **Plugins SHOULD emit only the fields the operator maps.** A plugin that copies the whole document into `fields` writes personal data into the evidence store. The host cannot stop this.

## Conformance

A plugin or host is checked against these tests. Each runs in this repository.

- **Host tests.** `internal/adapters/plugin/host_test.go` and `trust_test.go` run the host against fake plugins (compiled into the test binary) for each failure and trust rule above.
- **Config tests.** `internal/config/plugin_test.go` covers name validation, allowlist lookup, one host per source and the shipped examples (`TestShippedPluginExamplesLoad`). `cmd/jb/plugin_test.go` covers a hunt through a plugin, a broken plugin ending incomplete and never clean (`TestHuntWithABrokenPluginIsIncompleteNeverClean`), an unlisted plugin, signal handling and `jb doctor`.
- **SDK tests.** `sdk/sdk_test.go` covers the plugin side: the manifest then one response per request, per-document unparsable reporting, a panic reported without the document, a wrong version answered with an error, and an overlong request line ending the process.
- **Conformance corpus.** `internal/conformance` runs synthetic documents from `internal/conformance/testdata` through each example plugin as a real child process behind the real host. For the nginx access line it also runs the built-in `nginx_ingress` mapper, and both must give the same events (`TestCorpus`). `TestKeycloakCorpusBuiltinAndKvlines` runs the built-in `keycloak` corpus through `kvlines` and records every difference with its reason in `testdata/keycloak/kvlines_differences.json`.
- **Wire goldens.** `TestPluginWireProtocolV1HostSideIsUnchanged` and `TestPluginWireProtocolV1PluginSideIsUnchanged` compare the host and the sdk against `wire-v1.golden` files. The host golden holds the manifest, response and event structs, the `Default*` limits, `maxConfigBytes`, `maxManifestBytes`, `shutdownGrace` and a request transcript. `contract/sdk_test.go` pins the sdk constants (`ProtocolVersion`, `MaxRequestLine` and the line-size limits).
- **Architecture rules.** `TestOSExecIsConfined`, `TestPluginsAreStdlibOnlyAndInert` and `TestNothingImportsThePlugins` in `internal/archtest/archtest_test.go`.

Not checked by a test: the 64-byte manifest `name` limit, the refusal of an oversized `mapper_config` (at either check, and the `64<<10` literal in `validateMapper`), and behaviour on platforms without process groups. The values of the other limits are pinned by the wire golden. The 1 MiB allowlist cap has a test (`allowlist_shape_test.go`). The untested items are listed in "Open questions".

## Reference implementations

**Shipped**

- Host: `internal/adapters/plugin` (`host.go`, `allowlist.go`, `trust.go`, `scrub.go`, `procgroup_unix.go`, `procgroup_other.go`).
- Port: `core.BatchMapper` in `internal/core`.
- Config wiring: `internal/config/register_kibana.go`.
- Doctor section: `cmd/jb/doctor.go`.
- Plugin side: `sdk/serve.go` and `sdk/mapping.go`.
- Example plugins: `examples/plugins/kvlines`, `examples/plugins/regexlines`, `examples/plugins/jsondoc`.
- Specification: [docs/PLUGINS.md](../PLUGINS.md).
- Corpus: `internal/conformance`.

**Proposed**

None.

## Open questions

The maintainer decides each one. None is fixed by this RFC, which changes no behaviour.

- **`mapper_config` limit has two copies and no test.** The 64 KiB limit is a literal in `validateMapper` (config load) and a constant in `host.go` (`NewHost`). The two agree today. The golden pins the constant. Nothing pins the literal, and no test sends an oversized `mapper_config` to either check. Decide whether to share one constant and add a test.
- **Manifest limits missing from PLUGINS.md.** The host refuses a manifest line over 16 KiB and a `name` longer than 64 bytes. PLUGINS.md says only that `name` is required. Decide whether to document them.
- **`config_schema` type.** PLUGINS.md calls it free text. The host reads it as any JSON value. The sdk always sends a string. Decide whether to say "string" in the spec.
- **Request size and the document cap.** PLUGINS.md says a single document too large to fit fails the source. It does not say the host also splits a batch by size before the 200-document cap. The code does both. Decide whether to say so.
- **Limits are not operator-tunable.** The `Limits` struct exists, but no config key sets it. Decide whether an operator ever needs to.
- **Non-Unix platforms.** The fallback in `procgroup_other.go` kills the plugin only. No test covers it. Decide whether to support those platforms or refuse them.
- **Ownership and ancestor checks.** The host does not check file ownership or the ancestors of the plugin directory. PLUGINS.md says so. Decide whether to add them.

## Changes

- 2026-11-06: back-filled from the shipped protocol, `docs/PLUGINS.md` and ADR 0001. Status `implemented`.
- 2026-11-06: the freeze at `v: 1` is removed. The protocol is versioned by `v` and a host reads only the current one (ADR 0001, point 3, revised).
- 2026-11-09: straightened against the code. The Summary no longer says the protocol is frozen. The wire golden tests are named, and the claim that default limits are untested is removed. The `mapper_config` and Limits notes say what is really untested. The sdk stability note points to RFC 0018. The PLUGINS.md limits table is described as seven rows.
