# RFCs

[Back to the README](../../README.md)

For a contributor who wants to change a public contract of `jb`. After reading, you can decide whether you need an RFC, write one, and follow it to acceptance.

An RFC is a written design that the maintainer accepts before the code is built. It records the problem, the design, the costs and what is left out. It stays in the repository, so the reasons outlive the chat or the pull request where they were first discussed.

## Freeze

Since v0.7.0 `jb` takes no new command, port, file format or config key before 1.0 ([CONTRIBUTING.md](../../.github/CONTRIBUTING.md), "Feature freeze"); `jb serve` is the exception. A new draft RFC for a feature is parked, not built, until the maintainer lifts the freeze. RFC 0016 is parked. The stability policy for 1.0, and what 1.0 means, is [RFC 0018](0018-stability-policy.md).

Accepted RFCs stay `accepted` here when only part of them is built (for example RFC 0017, steps 1 and 6); the Reference implementations section of each file says what exists.

## When you need one

Write an RFC when a change touches a public contract:

- a file format that other tools read (`case.yaml`, an actor file, an estate file),
- the mapper plugin wire protocol,
- the exported Go API (`jb`, `sdk`),
- a config key, a CLI flag or an exit code,
- the security policy of the dashboard or the passive-only policy,
- a new dependency.

Do not write one for a bug fix, a refactor, an internal rename or a change that no outside reader or program can observe. Use the pull request description for those.

A decision that is not a contract, such as how `jb` relates to another project, goes in an [ADR](../adr/).

## Statuses

| Status | Meaning | Who sets it |
|---|---|---|
| `draft` | Under review. Nothing in it is a promise. | The author |
| `accepted` | The maintainer approved the design. Code may start. | The maintainer, with a date |
| `implemented` | The code and its tests exist. The RFC names them. | The author, with a date |
| `superseded` | A later RFC replaced it. The header names that RFC. | The author |
| `withdrawn` | Dropped before acceptance. The file stays, so the reasons are kept. | The author |

No code for an RFC's behaviour is merged before the status is `accepted`. Only the maintainer accepts. The header line is `Accepted: YYYY-MM-DD by the maintainer`.

## How to write one

1. Copy [0000-template.md](0000-template.md) to `NNNN-short-title.md`. Use the next free number.
2. Set `Status: draft` and fill in every section. A section with nothing to say gets one sentence that says so, not a blank.
3. Check each claim about the current code. Search the repository for every file, flag, test and command you name. A claim that is not true today goes in the proposal, not in the description of what exists.
4. Name the test that will check each rule. A rule that no test can check says why.
5. Run `go test -count=1 ./internal/archtest -run RFC`. It checks the header, the sections and the links.
6. Open a pull request. Discuss changes in the pull request. The maintainer accepts by changing the status line and adding the date.
7. After the code lands, set `Status: implemented`. Move each item from "proposed" to "shipped" in the Reference implementations section, with its path.

## Rules for the text

- Use MUST, SHOULD and MAY only in capitals, only as defined in the Conventions section, and only for a rule a test or a reviewer can check.
- Use one term for one thing. Define it once.
- Use only synthetic examples: documentation-range addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.com` and invented names. No real log line, host, user, client or organisation from a real case.
- Describe what other projects do only as prior art, with a source you read. Do not claim that `jb` follows a draft specification.
- Keep each file readable on its own. Link to a section of a spec by file and heading.

## How it is enforced

`internal/archtest/rfc_test.go` fails the build when an RFC has a wrong file name, a title number that differs from the file name, an unknown status, no acceptance date where one is required, a missing required section, or a relative link that does not resolve. A unit test in the same file plants each fault and checks the test catches it.

## Specs and RFCs

An RFC is the proposal and its reasons. A spec is the normative text of a format or protocol as it is now. When an RFC is implemented, the spec carries the rules and the RFC keeps the reasons. [docs/spec/README.md](../spec/README.md) lists each spec with its loader and its tests.

## Index

| RFC | Title | Status |
|---|---|---|
| [0001](0001-estate-v2.md) | Estate v2 | accepted |
| [0002](0002-mapper-plugin-protocol-v1.md) | Mapper plugin protocol v1 | implemented |
| [0003](0003-dashboard-security-model.md) | Dashboard security model | implemented |
| [0004](0004-stability-policy.md) | Stability policy | withdrawn |
| [0005](0005-caller-errors-and-output.md) | Caller errors and output | accepted |
| [0006](0006-watch-status.md) | Watcher status | accepted |
| [0007](0007-case-show.md) | Case show | accepted |
| [0008](0008-config-commands.md) | Config commands | accepted |
| [0009](0009-no-store.md) | Hunt and activity without storing | accepted |
| [0010](0010-operations.md) | Operations | accepted |
| [0011](0011-behaviour-severity-and-per-key.md) | Behaviour severity floor and per-key threshold | accepted |
| [0012](0012-partial-findings.md) | Partial findings | accepted |
| [0013](0013-library-surface.md) | Library surface | implemented |
| [0014](0014-newkey-history.md) | History probe for the newkey detector | accepted |
| [0015](0015-estate-subject.md) | Subject of an estate file | accepted |
| [0016](0016-own-cloud-inventory.md) | Inventory of the operator's own cloud | draft (parked) |
| [0017](0017-public-api-owns-its-types.md) | Public API owns its types | accepted |
| [0018](0018-stability-policy.md) | Stability policy for 1.0 | accepted |
| [0019](0019-serve-timeline.md) | Timeline page for `jb serve` | accepted |
