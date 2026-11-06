# RFC 0005: Caller errors, output formats and credential hints
Status: accepted
Scope: one typed usage error shared by the CLI and the Go package, `--output` on every command that prints a result, and the wording of the error for an unset credential.
Accepted: 2026-11-06 by the maintainer

## Summary

A program that drives `jb` must tell three things apart without reading error text: the caller made a mistake, the run was incomplete, or the run found something. This RFC proposes three changes.

1. One exported error type, `jb.UsageError`, with `jb.IsUsage(err)`. Every function of the Go package returns it for a caller mistake, and the CLI exits 2 on the same type.
2. `--output table|json` on every command that prints a result. `jb watch --once --output json` prints the cycle report.
3. An unset credential error that says the variable is read from the process environment and points to a new section of `docs/CONFIG.md`. No `--env-file` flag is added.

It also makes the help text of `jb activity` say why its default window is 24 hours.

## Motivation

A downstream program drives `jb` as a library and as a CLI. In blind tests it reported four gaps.

It could not tell its own mistake from a failure. `jb.Hunt` returned `fmt.Errorf("jb: window must be positive, got -5m0s")`, and the only way to know that was a caller mistake was to match the text. The CLI knew: it exits 2 for the same mistake. The class existed only in `cmd/jb`.

`jb watch --once` printed a cycle line and had no `--output json`, although every other result command had one. Four more commands lacked the flag as well (see the table in the design).

An unset `JB_KIBANA_API_KEY` produced `environment variable JB_KIBANA_API_KEY is not set`. The caller asked for an `--env-file` flag.

`jb activity --help` said "default 24h" and not why it differs from the `windows.default` of the case, which `hunt` and `watch` use.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

A usage error is a failure that the caller can remove by changing the request. A runtime failure is any other failure.

## How this design was made

The usage type lives in `internal/core`. That package is standard library only and every other package may import it (`internal/archtest`, rule for `internal/core`). The CLI and `internal/config` already import it, so neither needs a new dependency. `internal/config` cannot import `cmd/jb` and `cmd/jb` should not own a type the library needs, so the type has to sit below both. Two private copies existed before this RFC: `usageError` in `cmd/jb/execute.go` and `UsageError` in `internal/config/casehunt.go`, joined by a translation function, `asUsage`. One type removes the translation.

The Go package exports the type as an alias (`type UsageError = core.UsageError`) and the check as `IsUsage`. The check uses `errors.As`, so a caller that wraps the error with `%w` keeps the class. A sentinel value would not carry the message, and a bool return from each function would change every signature.

The rule for what is a usage error is the one the CLI already followed: the request was malformed or not allowed. A case that cannot be found, a source that is down, a credential that is not set and a config file that does not parse are runtime failures, because the request was well formed. Exit codes do not change.

For `--output`, a test walks the command tree. A rule written in prose would not catch the next command that forgets the flag. The test has a short exception list, and the list itself is checked, so it cannot name a command that no longer exists.

For credentials, the process environment is already the interface. A launcher, a shell or the Go `Env` option supplies it. The change is in the message and the documentation, not in a new input path.

## The design

### Usage errors

`internal/core/usage.go` defines:

```go
type UsageError struct{ Msg string }
func (e *UsageError) Error() string
func Usagef(format string, a ...any) error
func IsUsage(err error) bool // errors.As to *UsageError
```

The root package exports `type UsageError = core.UsageError` and `func IsUsage(err error) bool` in `errors.go`.

These failures of the Go package are usage errors:

| Function | Mistake |
|---|---|
| `Hunt` | nil config; negative `Window`; `Until` with fractions of a second, in the future, or with a `Window` over `MaxHistoricalWindow` |
| `HuntCase` | the same window and `Until` rules; a `Config` that is not one of the case's configs, is outside the case, or is missing when the case lists none or several |
| `Activity` | the same window and `Until` rules; a `Config` mistake as in `HuntCase`; a config with no fingerprint or behaviour detector |
| `Watch` | an invalid `Name`; a negative `Every`, `Window`, `TTL`, `Keep` or `Repeat`; a `Window` shorter than `Every`; a `Keep` shorter than twice the `Window`; a `Config` mistake as in `HuntCase` |

These are not usage errors: a case directory that cannot be loaded, an evidence directory that fails the git guard, a config file that fails to load, an unset credential, a second watcher holding the lock (`ErrWatcherRunning`), and every source or detector failure.

The CLI maps an error to exit 2 with `core.IsUsage`. The helper `usageErrorf` in `cmd/jb` stays as a one-line constructor over `core.Usagef`; it is no longer a type.

### Output coverage

A command that prints a result takes `--output table|json`, default `table`, and refuses any other value as a usage error before it does work. The walk of the command tree on the branch this RFC was written against found these leaf commands without the flag:

| Command | JSON form |
|---|---|
| `jb watch` | with `--once`, the cycle report (below); without `--once`, `--output json` is a usage error |
| `jb db status` | `path`, `schema_version`, `build_schema_version`, `runs`, `events`, `findings`, `reputation`, `first_seen`, `last_seen` (the last two null when there are no events) |
| `jb db rename-source` | `store`, `old`, `new`, `applied`, `events`, `runs`, `new_events`, `overlap`, `dropped`, `relabelled`, `no_raw` |
| `jb db compact` | the engine's compact result: `applied`, `target`, `source_file_bytes`, `engine_used_bytes`, `engine_free_bytes`, `estimated_copy_bytes`, `target_file_bytes`, `schema_version`, `source_rows`, `copy_rows`; the swap advice is table text only |
| `jb estate promote` | `promoted`, `baseline`, `archived` |

`jb serve` and `jb version` stay without the flag: `serve` prints no result and `version` prints one fixed line. The group commands (`jb`, `actor`, `case`, `db`, `estate`) print help only. The test names `serve` and `version` as exceptions. cobra adds `help` and `completion` after the tree is built, and the test does not see them.

The cycle report of `jb watch --once --output json` has these fields, all lower case:

| Field | Type | Source in `app.CycleReport` |
|---|---|---|
| `run` | string | `Run` |
| `watcher` | string, omitted when unnamed | the `--name` |
| `window` | [from, to] times | `Window` |
| `status` | `quiet`, `findings`, `incomplete`, `failed` | `Status` |
| `healthy` | bool | `Status.Healthy()` |
| `failed` | list of string, never null | `Failed` |
| `new`, `suppressed`, `repeated`, `recovered`, `optional_failed` | int | the counters of the same names |
| `gap`, `error` | string, omitted when empty | `Gap`, `Err` |
| `alerts` | list of alert | `Surfaced` |
| `pruned` | `runs`, `events`, `findings`, or null | `Pruned` |

With `--output json`, the alert lines go to stderr, so stdout holds one document. The log file and any webhook receive them as before. An unhealthy cycle prints its report and then exits 1, as before.

### Credential hints

The error for an unset or empty variable is built in one place, `errEnvNotSet` in `internal/config/config.go`, and used by the Kibana, GreyNoise and webhook builders. It names the variable, states that `jb` reads it from the process environment and not from the config file or a `.env` file, and names the section "Supplying credentials" of `docs/CONFIG.md`. It never contains a value.

That section gives three recipes (a shell that exports from a file the operator controls, a one-command launcher or service manager, and the Go `Env` option) and three rules: the YAML holds only the variable name, a value is never put on a command line, and `jb` never prints it.

### Help text

`jb activity --help` says the default window is 24 hours and that it is fixed so the same call always asks the same question, and that the `windows.default` of the case applies to `hunt --case` and `watch`, not to `activity`. The `--window` help of `hunt` and `watch` states the plain default (60m) and the case rule.

## Non-goals

- A new exit code. Exit 2 stays "usage", 1 stays "runtime failure".
- A second error type for runtime failures. A caller reads `Result.Complete()`, `Verdict` and `CycleReport.Status`, as before.
- An `--env-file` flag, or any file reader for secrets.
- Changing the table output of any command.
- `--output` for `serve`, `version`, and the commands cobra adds.

## Drawbacks

- The Go package gains an exported type that it must keep. Its fields are the one `Msg` string.
- The message text of every error is unchanged, so a caller that matches text keeps working. That is also the habit this RFC wants callers to drop: they should switch to `IsUsage`.
- Five commands gain a flag and a JSON shape, and each shape is a contract with the downstream program.
- `--output json` for `watch` sends alert lines to stderr, which differs from the table form. A caller that read alerts from stdout in JSON mode must read stderr or the log.
- The credential error is longer. A script that prints it shows a long line.

## Alternatives and prior art

`--env-file FILE`. Declined. The process environment is already the interface: a shell, `systemd` `EnvironmentFile=`, a container runtime or a launcher sets it, and the Go package takes an `Env`. A secrets reader in `internal/core` or the CLI would add policy that `jb` would then own and test: file permission and ownership checks, symlink handling, parsing rules (quoting, comments, `export`), precedence against the real environment, and what to log when the file is world readable. It adds no capability that a one-line `set -a; . FILE; set +a` does not give. It would also be a second place where a secret can leak into a log or an error. The caller keeps its secrets file and its permission policy.

A typed error per mistake (`ErrNegativeWindow` and so on). Rejected: callers need the class, not each case, and each new sentinel is a new exported name to keep.

A `Kind` field on one general error. Rejected for now: only two classes exist that a caller must tell apart, and the runtime class is already visible through result statuses.

Leaving `--output` as a convention. Rejected: five commands drifted without the flag, and a prose rule did not stop it.

Prior art: the standard library's `*exec.ExitError` and `*os.PathError` are types a caller finds with `errors.As`. `UsageError` follows that pattern.

## Compatibility

This is a breaking change for the two users of `jb`, with no compatibility layer.

- Go callers: errors that were plain strings are now `*jb.UsageError`, wrapped or not. A caller that compared the error type or text must call `jb.IsUsage`. The message text is unchanged except where noted in Drawbacks.
- Callers of `internal/config`: `config.UsageError` is removed. Use `core.IsUsage` inside the module.
- CLI callers: exit codes are unchanged. `jb watch --output json` without `--once` now exits 2. `jb db status`, `db compact`, `db rename-source` and `estate promote` accept `--output`; their table output is unchanged.
- The unset-credential message changed, so a script that matched `is not set` at the end of the line must match the beginning.

No file format changes, so no `apiVersion` changes.

## Security considerations

The credential message names the variable only. A test sets an empty value and checks the error never contains a value. The new JSON forms print store paths and counts that the table forms already print. The cycle report carries the alerts that `watch.log` already holds. Their text can contain content from the evidence, so a consumer of the JSON SHOULD treat `alerts[].text` as untrusted data, as it treats the log. The credential section tells operators to keep secret files outside the repository with mode 600 and to avoid command-line values.

## Conformance

- `internal/core/usage_test.go`, `TestIsUsageSeesThroughWrapping`: the class survives `%w`, double wrapping and `errors.Join`, and plain errors are not usage errors.
- `cmd/jb/usage_parity_test.go`, `TestUsageClassMatchesExitCode`: a table of fifteen mistakes and failures. For each, the CLI exits 2 exactly when `jb.IsUsage` is true for the same mistake through the Go function. Case-not-found, an unreachable source and a missing credential are rows that must be false.
- `cmd/jb/output_test.go`, `TestEveryResultCommandTakesOutput`: walks the command tree and fails when a runnable leaf has no `--output` flag and is not in the named exception list. It also fails when the list names a command that does not exist or has the flag.
- `cmd/jb/output_test.go`, `TestOutputFlagRejectsUnknownFormatEverywhere`: every command with the flag exits 2 for `--output yaml`.
- `cmd/jb/output_test.go`: `TestWatchOnceJSONIsTheCycleReport`, `TestWatchJSONNeedsOnce`, `TestDBStatusJSON`, `TestDBRenameSourceJSON`, `TestDBCompactJSON`, `TestEstatePromoteJSON`.
- `internal/config/credhint_test.go`: `TestUnsetCredentialErrorsSayWhereTheVariableIsRead` and `TestEmptyCredentialIsMissingAndNeverPrinted`.
- The help text has no test; a reviewer checks `jb activity --help`.

## Reference implementations

Shipped: none yet. This RFC is a draft.

Proposed:

- `internal/core/usage.go`, `errors.go` (root package).
- Usage returns in `jb.go`, `activity.go`, `watch.go`.
- `--output` in `cmd/jb/db.go`, `dbmaint.go`, `dbrename.go`, `estate_drift.go`, `watch.go`, and `cmd/jb/watchjson.go`.
- `errEnvNotSet` in `internal/config/config.go`.
- The sections "Supplying credentials" and "Watch output" in `docs/CONFIG.md`.

## Open questions

- Whether `jb version` should take `--output json` for a launcher that wants the build string. The maintainer decides.
- Whether a case that fails to load because `case.yaml` is invalid should be a usage error. Today it is not, because the file is the fault, not the request. The maintainer decides.
- Whether `watch --output json` should one day stream one document per cycle without `--once`. It needs a line-delimited form. The maintainer decides when a caller asks.
- 2026-11-06: accepted by the maintainer. The code is merged; the status becomes `implemented` when the Reference implementations section is moved from proposed to shipped.
