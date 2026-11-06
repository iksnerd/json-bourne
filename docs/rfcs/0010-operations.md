# RFC 0010: Operations
Status: draft
Scope: define each `jb` operation once, as data, so that the command line, the JSON output, the Go functions and a later MCP tool all come from one definition and one check of the arguments.

## Summary

`jb` offers each operation twice. A command such as `jb hunt` declares its flags by hand in cobra. The Go function `jb.Hunt` takes an options struct. The two keep separate copies of every name, default and rule, and a test is the only thing that holds them together. A third surface, an MCP server, would be a third copy.

This RFC defines an operation once, as a JSON object with a name, a description, an input schema, an output schema and a command line form. The shape is the one in the maintainer's draft RFC for operations (RFC 0013 of that draft). From that one definition `jb` gets:

- the command and its flags, parsed by one small parser with fixed rules;
- one check of the arguments, run the same way for a command line and for a tool call;
- the JSON output, which is the object the operation returns;
- the tool entry an MCP server lists.

`jb` stops using cobra. The operations are the contract, and `jb operations` prints them as JSON. The MCP server itself is a later RFC. This RFC makes it a small one.

## Motivation

A caller that drives `jb` sees every inconsistency. In blind tests the other user of `jb` found that only some commands take `--output json`, that `jb case check DIR` takes a positional directory where every other command takes `--case DIR`, that a window is a string in one tool and a duration in another, and that the library lacks options the CLI has. RFC 0005 and RFC 0007 fix three of these one at a time. The cause is that nothing holds the surfaces to one definition.

Counted on 2026-11-06 in `cmd/jb`: about a hundred flags declared one by one, twelve separate JSON encoders, and a test (`TestLibraryDefaultsAreTheCLIDefaults`) that exists only because the CLI and the library keep separate defaults.

An agent that calls `jb` through MCP needs the same operations with typed arguments and a typed result. Writing those tool definitions by hand would copy every flag a third time.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Operation" means a request that takes arguments and returns one result. "Surface" means a way to call an operation: the command line, the Go function, an MCP tool. "The spec" means the maintainer's draft RFC for operations, which is private and not approved. `jb` follows its model as `jb`'s own design (see ADR 0001, point 8, revised) and claims no conformance to it.

## How this design was made

1. **The workflow first.** A person types `jb hunt --case DIR --window 2h`. An agent calls the tool `hunt` with `{"case": "DIR", "window": "2h"}`. Both mean the same, both get the same check, and both receive the same JSON object. Nothing in that workflow mentions cobra.
2. **One definition, and the CLI is a client of it.** The command line has no private path. It parses argv into arguments and calls the operation, as an MCP server will. If the command needed something the operation lacks, the operation gains it.
3. **A flat input schema.** The spec limits an operation's input to four shapes: a string, an integer, a boolean and an array of strings. Each has exactly one flag form, so two parsers agree. A window is a string that the handler parses, which is why `7d` works. A rule like "give `--case` or `--config`, not both" is a check in the handler, because a flat schema cannot say it.
4. **Our own parser, not cobra.** Cobra reads `--x=false` for a boolean, splits a list on commas and accepts short flags. The spec reads none of those. Bending cobra to the spec's rules costs more than the 100 lines of the rules, and the rules are small enough to hold in one place.
5. **The Go functions stay and become the handlers.** `jb.Hunt`, `jb.Watch` and the others already hold the logic. An operation's handler calls one. `jb.Call` is the one entry that a command line and an MCP server both use.
6. **What is not an operation.** `jb watch` runs until stopped, `jb serve` runs a server and `jb version` prints a string. None returns one result. They stay as plain host commands, dispatched before the operation parser.

## The design

Everything in this section is a proposal. None of it is implemented. The spec describes its rules; this section states the rules `jb` adopts, so that `jb` can be read without the spec.

### An operation

An operation is a JSON object. In Go it is a value that marshals to this shape.

| Field | Required | Rules |
|---|---|---|
| `name` | yes | `^[a-z][a-z0-9_]{0,63}$`. Unique. This is the MCP tool name. |
| `title` | no | A non-empty string. |
| `description` | yes | A non-empty string. It is also the first line of the command's help. |
| `inputSchema` | yes | The subset below. |
| `outputSchema` | yes | A JSON Schema whose root has `"type": "object"`. |
| `cli` | no | `command` (a list of words), `positional` (property names in order) and `only` (properties accepted only by the command line). |

`jb` checks its operations when it builds and when it starts, and refuses to run if a check fails. The check reports every problem with a code and a reference, as the spec does.

### The input schema

The input schema is an object with `type: "object"`, `additionalProperties: false`, `properties` and `required`, and no other keys.

A property name matches `^[a-z][a-z0-9]*(_[a-z0-9]+)*$`, does not start with `no_`, and is not `help`. The flag for a property is its name with each `_` replaced by `-`.

A property has one of four shapes:

| Type | Extra keywords |
|---|---|
| `string` | `enum`, a list of distinct strings |
| `integer` | `minimum`, `maximum` |
| `boolean` | none |
| `array` | `items`, exactly `{"type": "string"}` |

Each property MAY carry `description` and `default`. A default is documentation: the check never fills it in, and the handler applies it. This is why the CLI and the library cannot disagree about a default.

### Parsing argv

The words after the program name pick the operation by its command words. The rest are read left to right:

- `--` makes every later token positional.
- A token that starts with `--` is a flag. The text up to the first `=` is the name.
- A boolean `--x` is true and `--no-x` is false. A boolean given with `=` is an error.
- A string or an integer takes the value after `=`, or else the next token, whatever it starts with.
- An array appends one string per use. A value is never split on commas.
- A repeated flag other than an array is an error.
- Any other token is the next positional.

An integer matches `^-?(0|[1-9][0-9]*)$` and is at most 2^53 - 1 in size. The first problem ends the parse.

### One check

The arguments, whether parsed from argv or received in a tool call, go through one function. It reports every problem, each with the property as reference: arguments not an object, an unknown argument, a missing required argument, a wrong type, a value outside an enum, an integer outside its range. A command line reports the problems as a usage error with exit code 2 and a tool call reports them as a tool error. RFC 0005 defines the typed error.

### Handlers, results and exit codes

An operation's handler is a function from checked arguments to a result object. The result is exactly what `--output json` prints and what a tool call returns as structured content. `--output table` renders the same object for a person.

A result that says the work was incomplete (a source did not finish) is still a result. The command line exits 1, as today. A tool call returns it as a normal result with `"complete": false`, and reports a tool error only when the handler fails or the arguments are wrong. This keeps "the answer is unknown" from looking like "the call failed".

### Host flags

Two flags are read on every command and belong to no operation: `--output` (a string, `table` or `json`) and `--help`. No operation may have a property of either name.

### The registry

The root package `jb` gets two functions:

- `Operations() []Operation` returns every definition.
- `Call(ctx context.Context, name string, arguments map[string]any, env Env) (Result, error)` checks the arguments and runs the handler.

`jb operations [--tool]` prints the definitions as JSON. With `--tool` it prints each entry as an MCP `tools/list` entry, without `cli` and without the properties named in `cli.only`. A committed copy, `docs/operations.json`, is checked against the output by a test.

### Operations

The first table is the proposal for the commands that return one result. Names and command words are final only when the RFC is accepted.

| Operation | Command | Replaces |
|---|---|---|
| `hunt` | `jb hunt` | `jb hunt`, with `--config` or `--case` |
| `activity` | `jb activity` | `jb activity` |
| `actor_status` | `jb actor status` | `jb actor status` |
| `case_check` | `jb case check` | `jb case check` |
| `case_show` | `jb case show` | RFC 0007 |
| `doctor` | `jb doctor` | `jb doctor` |
| `intel` | `jb intel` | `jb intel` |
| `estate_ip`, `estate_asn`, `estate_dns`, `estate_ct` | `jb estate ip`, `jb estate asn`, `jb estate dns`, `jb estate ct` | `jb estate IP...` and the three collectors |
| `estate_refresh`, `estate_diff`, `estate_promote` | `jb estate refresh`, `diff`, `promote` | the same commands |
| `db_status`, `db_usage`, `db_prune`, `db_compact`, `db_rename_source` | `jb db ...` | the same commands |
| `watch_status` | `jb watch status` | RFC 0006 |
| `watch_cycle` | `jb watch cycle` | `jb watch --once` |

Operations that change something take a boolean `apply` whose default is false, so a call without it is a dry run. This is already how `db prune`, `db compact`, `db rename-source` and `estate promote` work.

### What moves out of cobra

- The `--no-store` flag of RFC 0009 is the boolean property `store` with default true. `--no-store` is its false form and `--store` its true form, which the parser gives for free.
- `db prune --kind` takes a comma list today. It becomes an array, repeated: `--kind hunt --kind search`.
- `jb intel IP ...` and `jb estate ... IP ...` take a list of positionals today. An array cannot be positional, so they take repeated `--ip`.
- Duration flags become strings that the handler parses, so `--window 7d` stays valid.

### MCP, later

An MCP server needs three things: `tools/list` (from `Operations()` with the tool projection), `tools/call` (a call to `Call`) and a rule about which operations it exposes. The first two follow from this RFC. The third is a security decision for the RFC that adds the server, see Security considerations.

## Non-goals

- This RFC does not add an MCP server.
- It does not change what any operation computes.
- It does not remove the typed Go functions, which stay as the handlers and as a direct API.
- It does not add authorisation. Who may call an operation is the caller's concern.
- It does not claim that `jb` conforms to the spec. The spec is a draft.

## Drawbacks

- It rewrites the flag declarations of every command. The risk of a behaviour change on a rarely used flag is real, and the tests that walk the commands are the defence.
- Dropping cobra drops shell completion and its help formatting. The help text is generated from the definitions, and completion is lost.
- The spec is a draft. If it changes, `jb` has to follow or diverge on purpose.
- A flat schema forces some arguments to strings and moves their checks into the handlers. A window, a duration and a path are strings that the handler validates.
- Variadic positionals go. `jb intel 192.0.2.1 192.0.2.2` becomes `jb intel --ip 192.0.2.1 --ip 192.0.2.2`. It is longer to type and equal for a program.
- `jb` would own a parser. Two other implementations of the same rules exist in the maintainer's private repository, and a bug fixed there has to be considered here.

## Alternatives and prior art

- **Keep cobra and add a JSON entry.** A command `jb call NAME --args '{...}'` would be small. It leaves the flags declared twice and does not give the one check.
- **Generate the MCP tools by hand.** It is the least work now and the most drift later, which is the problem this RFC exists to remove.
- **Use the reference Go implementation of the spec as a module.** It lives in a private repository and a public repository cannot depend on it. `jb` ports the rules and, where the maintainer's corpus is on the machine, runs it.
- **A different tool-definition standard.** This RFC does not compare `jb` with other formats for describing tools, because the author read none for this draft. The reviewer is asked to name one worth reading.
- **Prior art in the spec.** The spec's own motivation section records the same failure in other tools: the CLI and the tool defined twice, and defaults that differ. This RFC takes its solution. It does not cite that section as proof, because the author read only the spec text.

## Compatibility

There is no compatibility path, because `jb` and one other program are the only users and nothing is public. The breaking changes are:

- Booleans no longer accept `=false`. Use `--no-x`.
- Arrays append and are never split on commas.
- Flags must come after the command words.
- No short flags. None exist today.
- `jb watch --once` becomes `jb watch cycle`.
- Variadic positionals become repeated flags.
- The help text changes.
- Cobra and shell completion are removed.

The other program changes its calls to `jb` accordingly. It pins an exact version, so it moves when it chooses. The changelog lists each item under "Breaking" with its replacement.

## Security considerations

- Arguments are untrusted on both surfaces. A person can type anything and a model chose what an MCP client sends. The one check is the only place the schema is enforced, and a handler still checks what the schema cannot say: a path stays inside its root, an id exists.
- The parser never runs a shell and never expands a value. A value such as `$HOME` or `*` reaches the handler as written.
- No operation takes a secret as an argument. Credentials come from the environment, as today. An MCP server runs with the environment of its process, so it holds whatever credentials that process holds. That is a reason to give the server only the credentials it needs.
- Some operations change the evidence store or the estate. Over MCP, a model could call `db_prune` with `apply: true`. The MCP RFC MUST decide which operations a server exposes by default, and this RFC recommends that the default exposes only operations that do not change anything.
- The tool entry for an operation omits `cli.only` properties. A tool call that supplies one is refused as unknown, even if its value would pass the command's schema.

## Conformance

Proposed. None of these exists yet.

- **Load check.** A test that every operation passes the load check, and that each rule fails on a planted fault.
- **Parser corpus.** A corpus of argv cases for each parsing rule, with the expected arguments or the expected problem. The corpus is `jb`'s own, kept in the repository. When the environment variable `JB_OPERATIONS_CORPUS` names a directory that holds the maintainer's operations corpus, a test also runs its load, argv, arguments and tool cases. The test is skipped otherwise.
- **Round trip.** For every operation, a test parses a sample argv, runs the handler against synthetic data, and checks the result against the output schema.
- **Golden file.** `docs/operations.json` equals the output of `jb operations`.
- **No second surface.** A test fails if a package other than the registry imports cobra, and the module no longer depends on it.
- **Defaults.** `TestLibraryDefaultsAreTheCLIDefaults` is deleted, because the defaults live in one place.

## Reference implementations

Shipped:

- The CLI as it is: cobra commands in `cmd/jb`, with JSON writers in `activity.go`, `actor.go`, `case.go`, `dbmaint.go`, `doctor.go`, `estate.go`, `estate_drift.go`, `estate_ext.go`, `hunt.go` and `intel.go`.
- The Go functions `jb.Hunt`, `jb.HuntCase`, `jb.Watch` and `jb.Activity`, and the usage error of RFC 0005 once merged.

Proposed, in this order, each step ending in something that runs:

1. `internal/ops`: the types, the load check, the argv parser, the argument check and the tool projection. Standard library only.
2. The registry in the root package, `Operations` and `Call`, with one operation (`case_show`) end to end.
3. The main entry point: host commands first, then the operation parser, then `Call` and the renderer.
4. The remaining operations, one group at a time.
5. Removal of cobra from the module.
6. `jb operations` and `docs/operations.json`.

## Open questions

1. **Does `jb` drop cobra?** The recommendation is yes, for one set of rules. Decides: the maintainer.
2. **Variadic positionals.** Is repeated `--ip` acceptable for `intel` and `estate`? Decides: the maintainer, with the other user.
3. **`watch --once` as `watch cycle`.** Is a separate operation better than a flag on a command that otherwise runs forever? Decides: the maintainer.
4. **Annotations.** The spec lets a host add MCP annotations to a tool entry. Should `jb` mark the operations that change state (`destructiveHint`, `readOnlyHint`) now, so an MCP server can filter them? Decides: the maintainer.
5. **How strictly to check output schemas.** A small checker for the four shapes in a test, or a JSON Schema library as a test dependency? Decides: the author.
6. **The spec corpus.** Is a skipped-when-absent test the right way to use a private corpus? Decides: the maintainer.
7. **A published tool-definition standard to compare with.** Which one should the next draft read? Decides: the reviewer.

## Changes

- 2026-11-06: first draft.
