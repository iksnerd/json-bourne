# RFC 0008: A config says which commands it answers
Status: accepted
Scope: a new optional `commands` key in the config file, and the rule by which a command chooses one of a case's configs.
Accepted: 2026-11-06 by the maintainer

## Summary

A case can list several configs in `case.yaml`: a hunt, a fingerprint check, a watcher. Today a command given no `--config` fails when the case lists more than one, and nothing says which config answers the question.

This RFC adds one optional key to the config file, `commands`, a list of command names from a closed set. A command that takes `--case` then chooses its config in this order: the `--config` flag; else the one listed config that declares the command; else the only listed config; else a usage error that lists every config with its commands.

The config says what it is for. `case.yaml` does not change.

## Motivation

`jb activity --case DIR` on a case that lists five configs fails with `case X lists 5 configs, pass --config with one of: ...`. The caller sees five paths and no way to tell which one holds the fingerprint detectors. A program that drives `jb` for a case has the same problem and asked for a `defaults:` map in `case.yaml`, from command to config.

The chooser is `ChooseCaseConfig` in `internal/config/casehunt.go`. Each command that takes `--case` and reads a config reaches it through `planCase` or `chooseCaseConfig` in `cmd/jb/casehunt.go`, and three library functions (`HuntCase`, `Activity`, `Watch`) reach it through `config.PlanCase`.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

The cause is that the purpose of a config is written nowhere near the config. A caller has to know it from outside. The fix puts the purpose in the config file, next to the sources and detectors it describes.

A `defaults:` map in `case.yaml` was considered and declined, for three reasons. It keeps one fact in two places: the config's purpose would live in `case.yaml`, and a rename or a new config would need two edits that can drift apart. It adds a key to the case format, which is meant to stay as it is for now. And `case.yaml` is data about the case (scope, windows, owners), not about what each config does.

The set of names is closed and small, taken from the commands that take `--case` and read a config. A free-form `purpose:` string was rejected: nothing could check it and a program could not read it.

The key is plain data. It has no patterns, no priority and no fallback chain beyond the four steps below.

## The design

### The key

`commands` is an optional top-level key of the config file ([docs/CONFIG.md](../CONFIG.md)). Its value is a list of strings. Each string MUST be one of:

`activity`, `actor`, `estate`, `hunt`, `intel`, `rename-source`, `serve`, `watch`.

`estate` stands for every `jb estate` subcommand that reads the case's config (`asn`, `dns`, `ct`, `refresh`, `diff`). `actor` stands for `jb actor status`. `jb doctor` is not in the set: without `--config` it checks every listed config, so it never chooses. The loader MUST refuse a name outside the set, an empty name, a repeated name and a value that is not a list. The error for an unknown name lists the set.

### The choice

A command that takes `--case` and reads a config MUST choose it as follows:

1. `--config`, when given. This is the rule today and it does not change.
2. Otherwise, among the case's listed configs, the one that declares the command in `commands`.
3. Otherwise, if no listed config declares it and the case lists exactly one config, that config.
4. Otherwise a usage error (exit 2). It lists every listed config with the commands it declares. It is also the error when more than one config declares the command.

A case that lists no config keeps today's usage error.

### Reading the key cheaply

The chooser needs `commands` of each listed config and nothing else. It MUST read that key alone: no adapter is built and no environment variable is read. It does not read any config when the case lists one config. A listed config that cannot be read, or whose `commands` is invalid, is an error that names the file. It is not a usage error.

### The library

The `Config` field of `CaseHuntOptions`, `ActivityOptions` and `WatchOptions` follows the same rule, with the command the function stands for: `hunt`, `activity`, `watch`. `config.PlanCase` and `config.ChooseCaseConfig` take the command name as a new parameter. A call with an empty flag and a name outside the set is an error, not a guess.

### Example

```yaml
# config/fingerprint.yaml
commands: [activity, actor]
sources: [...]
```

`examples/case` lists `config/hunt.yaml` (declares `hunt`, `watch`, `serve`, `intel`, `estate`, `rename-source`) and `config/fingerprint.yaml` (declares `activity`, `actor`). `jb activity --case examples/case` then uses the second without `--config`.

### What `jb doctor` and `jb case check` should report

Proposed, not built here, because `jb case check` is in a file this change does not touch.

- `jb case check` SHOULD warn when two listed configs declare the same command, naming the command and both files. That case is an error at run time, so it is better caught at check time. It is a warning, not a failure, because a case may keep an unused second config on purpose.
- `jb case check` SHOULD note a case with several listed configs where a command has no declaring config and no single config. It is only a note, since not every command is used.
- `jb doctor --case` without `--config` keeps checking every listed config and needs no change. With `--config` it keeps today's behaviour.

## Non-goals

- A `defaults:` map or any new key in `case.yaml`.
- Patterns, priorities or inheritance between configs.
- Choosing among configs by what they contain (for example, "the config with a fingerprint detector").
- A different config for each `jb estate` subcommand.
- Any change to `--config` itself.

## Drawbacks

- Every config in a multi-config case needs the key, or the user passes `--config` again. A command a config forgot to declare fails with the list, which is the old failure with more information.
- The key is metadata the config does not use itself. A wrong declaration is not checked against the content: a config that declares `activity` but has no fingerprint or behaviour detector is accepted, and `jb activity` then fails with its own usage error.
- The closed set grows with the commands. A new command that chooses a config adds a name to it.
- Choosing reads each listed config twice in a multi-config case: once for `commands`, once to load it fully.

## Alternatives and prior art

- `defaults:` in `case.yaml`: declined above.
- Name by convention (`config/activity.yaml` serves `activity`): rejected. It ties the answer to file names, which `case.yaml` lets the user choose, and it cannot give one file two commands.
- A `--config` default in the user's launcher or shell: this works for one user but not for a program that calls the library, and the answer is not written down for the next reader of the case.
- Prior art: this repo's own `enabled:` key and `sources:` scoping on a detector, each of which says in the config what a part is for ([docs/CONFIG.md](../CONFIG.md)).

## Compatibility

Nothing is kept for the old behaviour. `jb` and one other program are the only users.

- The error for a multi-config case with no `--config` changes text and now lists the commands of each config. Exit code 2 is the same.
- A case that lists several configs and was run without `--config` for a command will start to work when exactly one config declares it, and fails as before when none does.
- A config file with `commands` is refused by an older `jb` as an unknown key. The config format has no `apiVersion` field today, so this RFC adds none.
- `config.PlanCase` and `config.ChooseCaseConfig` change signature. They are in `internal/`.
- `examples/case/case.yaml` now lists `config/fingerprint.yaml`. Anyone with a copy of the old example should add `commands` to each config or keep passing `--config`.

## Security considerations

The key chooses a file among those the case already lists, and the existing confinement of `--config` to the case directory is unchanged. Reading `commands` opens only listed files under the case and size-limits them as `Load` does. It reads no environment variable, so no credential is touched or printed. A config that declares a command it does not suit can only make a command fail or run a config the case's owner listed. Nothing in this change widens what a command may contact.

## Conformance

Tests in `internal/config/casecommands_test.go`:

- `TestChooseCaseConfigByDeclaredCommand`: rule 2, and that `--config` wins.
- `TestChooseCaseConfigNoDeclarationListsEveryConfig`: rule 4 lists every config and its commands.
- `TestChooseCaseConfigTwoDeclareTheSameCommand`: more than one declaring is rule 4.
- `TestChooseCaseConfigSingleConfigNeedsNoDeclaration`: rule 3.
- `TestChooseCaseConfigUnreadableListedConfig`: a broken listed config names the file and is not a usage error.
- `TestChooseCaseConfigRefusesACommandOutsideTheSet`: the closed set.
- `TestLoadCommandsReadsOnlyThatKey` and `TestParseCommandsKey`: the cheap read and the loader rules.

`cmd/jb` tests run the example case with both configs listed and no `--config` (`fingerprint_test.go`, `search_test.go`). The warnings for `jb case check` have no test yet.

## Reference implementations

Shipped: none.

Proposed:

- `internal/config/casecommands.go` (`CaseCommands`, `LoadCommands`) and the `Commands` field of `File` in `internal/config/config.go`.
- The four-step choice in `internal/config/casehunt.go`.
- The command parameter threaded through `cmd/jb/casehunt.go`, `jb.go`, `activity.go` and `watch.go`.
- `examples/case` with two listed configs.
- The `jb case check` warning.

## Open questions

- Should `jb case check` fail, not warn, on a command declared twice? The maintainer decides.
- Should `estate` split into one name per subcommand? Wait for a case that needs two estate configs. The maintainer decides.
- Should the flag help texts that say "default: the case's only config" be reworded? The owner of those files decides.

## Changes

None yet.
- 2026-11-06: accepted by the maintainer. The code is merged; the status becomes `implemented` when the Reference implementations section is moved from proposed to shipped.
