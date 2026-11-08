# RFC 0007: jb case show and a uniform --case flag
Status: implemented
Scope: a command and a Go function that print what one config of a case would run, a reusable `Describe` in `internal/config`, and `--case DIR` on `jb case check` in place of its positional argument.
Accepted: 2026-11-06 by the maintainer

## Summary

`jb case show --case DIR [--config NAME] [--output table|json]` prints the effective configuration of one config of a case: sources, detectors, store path and alert sinks. It reads no environment variable and makes no connection. `jb.CaseShow` returns the same data to a Go program. Both are built on `File.Describe`, which turns a parsed config into plain data. `jb case check` takes `--case DIR` like every other command, and the positional form is removed.

## Motivation

A person who asks "what does the attack watcher run" must read the YAML by hand: the scope of each detector, which sources are disabled, and where the store lands inside the case. A program that needs the same answer would have to parse the YAML again, and a second parser drifts from the loader. The loader already knows the answer.

`jb case check DIR` is the one command that takes the case directory as a positional argument. Every other command takes `--case DIR` (checked with `grep -n 'StringVar(&caseDir, "case"' cmd/jb/*.go`).

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

The description is built in `internal/config`, from the parsed `File`, and not in the command. The command and `jb.CaseShow` both call `config.ShowCase`, so there is one implementation and the CLI and the library cannot disagree.

Detector and alert specs report their options through one small interface, `options() any`, which each spec implements. The built-in detectors use it like any other. A test fails when a detector type is registered without it. The alternative, a type switch in the describer, would give built-ins a path that a new type would have to remember to extend.

The options are the keys the file sets, read back through the same YAML tags the loader decodes with. Unset keys are left out. The describer does not resolve defaults, because the defaults live inside each detector and are not exposed. The command says so in its help. Resolving them would need a new method on every detector, which is a larger change than this RFC.

The brief asked for a webhook's host. The host is the value of the environment variable the alert names (`url_env`), and reading it is forbidden here. The description shows the variable's name only.

Config choice calls `config.ChooseCaseConfig` unchanged. The store is placed with `config.PlaceCaseStore`, as a hunt places it.

## The design

Implemented. `File.Describe() Description` returns plain data with JSON tags:

- `sources[]`: `type`, `name`, `enabled`, `url` (scheme, host and path only: query, fragment and user info are dropped), `index`, `credential_env` (the variable name), `options` (time field, page size, mapper, filter, search field, and the key names of `mapper_config` without its values).
- `detectors[]`: `type`, `name`, `enabled`, `sources` (the scope as written, absent for all), `reads` (the enabled sources the detector reads, absent when disabled), `options`.
- `store`: `path` (as given; `~/` is not expanded) and `default` (true when `store.path` is empty, which means `$JB_DB`, then `~/.jb/jb.duckdb`; neither is read).
- `alerts[]`: `type`, `credential_env`, `options`. No host.

`config.ShowCase(dir, configFlag)` loads the case, chooses the config, loads it, calls `UseCase`, places the store and describes it. It adds `case`, `config` (relative to the case directory) and `notes` (the store-outside-evidence note of `PlaceCaseStore`). It runs no `git` command, so unlike `jb hunt` it does not run the evidence guard. It reads nothing under `evidence/`.

`jb case show` prints a table or, with `--output json`, the `CaseShow` value. Exit 0 on success, 1 when the case or config does not load, 2 for a usage error (no `--case`, a stray argument, a bad `--output`, a `--config` that is not a listed config or a file inside the case, or several configs and no `--config`).

`jb.CaseShow(caseDir string, opts CaseShowOptions) (*CaseShowResult, error)` lives in the root file `caseshow.go`. `CaseShowOptions` has one field, `Config`. The result and its parts are aliases of the config types.

`jb case check` takes `--case DIR` (required) and `--output`. A positional argument is a usage error (exit 2). Its output and its other exit codes do not change.

The loader still validates a plugin mapper name against the operator's plugin allowlist when a source uses `mapper: plugin:NAME`. That is existing behaviour of `config.Load`, shared with `jb case check`, and `case show` adds nothing to it.

## Non-goals

- Resolving detector defaults into the output.
- Describing feeds, `intel:` and `estate:` settings.
- Showing a webhook host, or any value read from the environment.
- Checking the evidence guard, or that the environment variables are set (`jb case check` and `jb doctor` do that).
- Changing how a default config is chosen.

## Drawbacks

An option left at its default does not appear, so a reader must know the defaults, or read the detector's documentation, to know the threshold in force. Each new detector or alert type needs one `options()` method. The describer shows the file as the loader understood it and does not prove the config would build: a fingerprint detector whose actor file is missing still describes.

## Alternatives and prior art

Printing the YAML back (a `cat` of the config) shows no scope resolution, no disabled state in effect and no case-relative store. Parsing the YAML again in the command was rejected as a second source of truth. A method on every detector that returns its resolved config would show defaults; it is left to a later RFC. `terraform show` and `kubectl config view` print resolved state with secrets redacted, which is the same idea; neither was read for this RFC.

## Compatibility

Breaking: `jb case check DIR` no longer works. The two users change every call to `jb case check --case DIR`. A call that keeps the positional form exits 2 with a usage error. No alias is kept. A program that called the command with a directory argument (shell scripts, CI) is the only place affected; the Go API did not expose `case check`.

Nothing else breaks. `jb case show` and `jb.CaseShow` are new.

Other commands checked for a positional case directory: `jb db rename-source` takes `OLD NEW` (source labels), `jb estate promote` a snapshot id, `jb estate` and `jb intel` addresses, `jb estate asn|dns|ct` targets. None is a case directory. `jb case check` was the only inconsistent command, and it is under `jb case`, so it is fixed here.

## Security considerations

The description is the new place a credential could leak, so it is built from names and structure only. The checks: `credential_env` holds a variable name that the loader already restricts to upper-case letters, digits and underscore; a URL is stripped of query, fragment and user info; `mapper_config` appears as key names; a webhook shows no host. The code reads no environment, and a test sets the credential variables to sentinel values and fails if one reaches the JSON.

`case show` makes no network connection and does not open the store, so it cannot be used to probe a source.

## Conformance

- `internal/config/describe_test.go`: the described fields, scope and reads, the disabled entries, the store default, the absence of a value, a URL query and a webhook host, and a test that every registered detector type implements `options()`.
- `cmd/jb/caseshow_test.go`: the table and JSON output, the exit codes, the unknown and ambiguous `--config`, and that a set credential never appears.
- `caseshow_test.go` (root): `jb.CaseShow` on `examples/case`.
- `cmd/jb/case_test.go`: `case check` takes `--case`, and the positional form and a missing flag exit 2.

## Reference implementations

Shipped: yes. The list below is where it lives.

Implemented in: `internal/config/describe.go` (`Describe`, `ShowCase`), `cmd/jb/caseshow.go`, `caseshow.go` (root), `--case` on `cmd/jb/case.go`.

## Open questions

- Should `case show` list defaults that the file did not set? The maintainer decides, after the detectors expose them.
- Should it also describe feeds and `estate:`? The maintainer decides.
- Should `case show` also run the evidence guard, so one command answers both questions? The maintainer decides; it would need `git`.

## Changes

None yet.
- 2026-11-06: accepted by the maintainer. The code is merged; the status becomes `implemented` when the Reference implementations section is moved from proposed to shipped.
