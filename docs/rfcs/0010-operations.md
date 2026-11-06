# RFC 0010: Operations
Status: accepted
Scope: define each `jb` operation once, from its Go option struct, so that the command line, the JSON output, the Go function and an MCP tool come from one definition and one check of the arguments.
Accepted: 2026-11-06 by the maintainer

## Summary

`jb` offers each operation more than once. A command such as `jb hunt` declares its flags by hand in cobra. The Go function `jb.Hunt` takes an options struct. The two keep separate copies of every name, default and rule, and a test is the only thing that holds them together. An MCP server would be a third copy.

This RFC makes the option struct the single definition. A small reflector reads the struct tags (name, description, default, enum, range) and produces an operation: a name, a description and an input schema in a deliberately small subset of JSON Schema. From that one operation `jb` gets:

- the cobra command and its flags, registered by a builder, with a test that fails when a command differs from its operation;
- one check of the arguments, run on the parsed flags and on the JSON of a tool call;
- the JSON result, which is the object the operation returns;
- the entry an MCP server lists, served by a new `jb mcp` command that exposes only read-only operations unless told otherwise.

The shape of an operation follows the maintainer's draft RFC for operations. `jb` keeps cobra, and adopts the schema subset and the single argument check, not that draft's command-line grammar.

## Motivation

A caller that drives `jb` sees every inconsistency. In blind tests the other user of `jb` found that only some commands took `--output json`, that `jb case check DIR` took a positional directory where every other command took `--case DIR`, and that the library lacked options the CLI had. RFC 0005 and RFC 0007 fixed three of these one at a time. The cause is that nothing holds the surfaces to one definition.

Counted on 2026-11-06 in `cmd/jb`: about a hundred flags declared one by one and twelve separate JSON encoders. A test, `TestLibraryDefaultsAreTheCLIDefaults`, exists only because the CLI and the library keep separate defaults.

An agent that calls `jb` through MCP needs the same operations with typed arguments and a typed result. Writing those tool definitions by hand would copy every flag a third time.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Operation" means a request that takes arguments and returns one result. "Surface" means a way to call an operation: the command line, the Go function, an MCP tool. "The spec" means the maintainer's draft RFC for operations, which is private and not approved. `jb` follows its model as `jb`'s own design (ADR 0001, point 8) and claims no conformance to it.

## How this design was made

The owner and the author went through the first draft with Hashimoto's tests on 2026-11-06. Four decisions changed it.

1. **The workflow first.** A person types `jb hunt --case DIR --window 2h`. An agent calls the tool `hunt` with `{"case": "DIR", "window": "2h"}`. Both mean the same, both get the same check, and both receive the same JSON object.
2. **MCP does not parse argv.** A tool call arrives as a JSON object. A grammar for argv matters only when two independent command-line implementations must agree, and `jb` has one. The first draft replaced cobra to adopt the spec's grammar. That paid for a benefit that does not exist here, and it broke `--x=false`, comma lists, variadic positionals and shell completion. The decision is to keep cobra and register its flags from the operation.
3. **The option struct is the source of truth.** `HuntOptions`, `ActivityOptions` and the rest already exist and are what the Go caller uses. Tags on their fields carry the name, description, default, enum and range. A hand-written schema would duplicate every field, which is the drift this RFC removes. The reflector refuses a field outside the four allowed shapes at build time.
4. **The MCP server is a surface, so it is built in and safe by default.** `jb mcp` lists tools from the registry and calls the same handler as the command. It exposes only operations marked read-only. A mutating operation needs an explicit allow flag naming it, and still takes `apply=true` to act.

## The design

Everything in this section is a proposal. None of it is implemented.

### An operation

An operation is a value that marshals to this JSON shape.

| Field | Required | Rules |
|---|---|---|
| `name` | yes | `^[a-z][a-z0-9_]{0,63}$`. Unique. It is the MCP tool name. |
| `title` | no | A non-empty string. |
| `description` | yes | A non-empty string. It is also the first line of the command's help. |
| `inputSchema` | yes | The subset below, derived from the option struct. |
| `outputSchema` | no | Not generated in the first cut. The result types already marshal to keys that parity tests pin (RFC 0013); a schema can be derived from those tests later if a client needs one. |
| `readOnly` | yes | True when the operation changes nothing. Only these are exposed over MCP by default. |
| `cli` | no | `command` (a list of words), `positional` (property names in order) and `only` (properties accepted only by the command line). |

`jb` checks its operations in a test and refuses to start if a check fails. The check reports every problem with a code and a reference.

### The input schema

The input schema is an object with `type: "object"`, `additionalProperties: false`, `properties` and `required`, and no other keys. A property name matches `^[a-z][a-z0-9]*(_[a-z0-9]+)*$`, does not start with `no_`, and is not `help`. The flag for a property is its name with each `_` replaced by `-`.

A property has one of four shapes:

| Type | Extra keywords |
|---|---|
| `string` | `enum`, a list of distinct strings |
| `integer` | `minimum`, `maximum` |
| `boolean` | none |
| `array` | `items`, exactly `{"type": "string"}` |

A property MAY carry `description` and `default`. The check never fills a default in. The handler applies it, so the CLI and the library cannot disagree about one. A window, a duration and a path are strings that the handler validates.

### The reflector

The reflector reads a Go option struct and its tags and returns the input schema. It maps `string`, `int`, `bool` and `[]string` to the four shapes. It refuses any other field type, an untagged exported field and a name that breaks the rules. Separate tags spell out what a field means, in the style of `encoding/json`: `jb:"window" default:"1h" desc:"Size of the window, e.g. 1h"`. A comma or an equals sign in a description cannot break the parse. Further tags carry `enum:"a,b"`, `min:"1"` and `max:"31"`.

### The flag builder

A builder registers one cobra flag per property, with the type, default and help text from the operation. If `cli.positional` ends with an array property, the remaining arguments fill it, so `jb intel 192.0.2.1 192.0.2.2` keeps working and a tool call sends `{"ips": [...]}`. Only the last positional may be an array. A cobra command that is not built this way is an error in a test. The named exceptions are `serve`, `watch`, `version` and the generated `help` and `completion`. A second test compares every built command's flags with its operation's properties.

### One check

The arguments, whether read from cobra flags or received as a tool call, go through one function. It reports every problem with the property as reference: arguments not an object, an unknown argument, a missing required argument, a wrong type, a value outside an enum, an integer outside its range. A command line reports the problems as a usage error (exit code 2, RFC 0005). A tool call reports them as a tool error.

### Handlers, results and exit codes

An operation's handler is a function from checked arguments to a result object. The result is what `--output json` prints and what a tool call returns as structured content. `--output table` renders the same object for a person.

A result that says the work was incomplete is still a result. The command line exits 1, as today. A tool call returns it as a normal result with `"complete": false`. A tool error means the handler failed or the arguments were wrong. That keeps "the answer is unknown" from looking like "the call failed".

### The registry and `jb mcp`

The root package `jb` gets two functions:

- `Operations() []Operation` returns every definition.
- `Call(ctx context.Context, name string, arguments map[string]any, env Env) (Result, error)` checks the arguments and runs the handler.

`jb operations` prints the definitions as JSON, and a committed copy, `docs/operations.json`, is checked against the output by a test. `jb mcp` serves the Model Context Protocol over standard input and output. `tools/list` returns the read-only operations without `cli`. `tools/call` goes to `Call`. A mutating operation appears only when named by `--allow NAME`, and it still needs `apply=true` in the call.

### Operations

The proposal for the operations that return one result:

| Operation | Command | Read-only |
|---|---|---|
| `activity`, `hunt` | `jb activity`, `jb hunt` | yes over MCP, with `store` forced to false (below) |
| `actor_status`, `case_check`, `case_show`, `doctor` | `jb actor status`, `jb case check`, `jb case show`, `jb doctor` | yes |
| `db_reputation` | `jb db reputation` | yes |
| `estate_diff` | `jb estate diff` | yes, without `--alert` |
| `watch_status` | `jb watch status` | yes |
| `db_status`, `db_usage` | `jb db status`, `jb db usage` | yes |
| `intel` | `jb intel` | no: it appends reputation rows to the store and asks a third-party feed |
| `estate_ip`, `estate_asn`, `estate_dns`, `estate_ct` | `jb estate ...` | no: they write the estate file and contact third-party services |
| `estate_refresh`, `estate_promote` | the same commands | no: a snapshot, and the baseline |
| `estate_facts_import` | `jb estate facts import` | no: writes the estate file (RFC 0001); a dry run unless `apply` |
| `db_prune`, `db_compact`, `db_rename_source` | the same commands | no |

`jb watch` and `jb serve` run until stopped and are not operations.

`hunt` and `activity` write a run to the evidence store unless `store` is false (RFC 0009). On the command line they keep storing by default. Over MCP the `store` property is a `cli.only`-style exception in reverse: the tool projection removes it and fixes it to false, so the tool provably leaves no evidence and is listed in the read-only default set. A caller who wants a stored run uses the command line or the Go API.

A tool entry carries MCP's `readOnlyHint` and `destructiveHint`, derived from `readOnly`, so a client can tell the operations apart without reading the descriptions.

## Non-goals

- It does not change what any operation computes.
- It does not remove the typed Go functions, which stay as the handlers and as a direct API.
- It does not replace cobra or change any flag spelling, default or exit code.
- It does not add authorisation. Who may call an operation is the launcher's concern.
- It does not claim that `jb` conforms to the spec.

## Drawbacks

- The reflector and the tag syntax are new code that every option struct depends on. A mistake there is a mistake everywhere.
- A flat schema forces some arguments to strings and moves their checks into the handlers.
- Some commands do not fit the model. Variadic positionals (`jb intel IP IP`) cannot be an array property, so they keep a hand-written flag until a later change decides.
- `jb mcp` is a new surface with a new protocol to keep current. A bug there is a bug in an agent-facing interface.
- The spec is a draft. If it changes, `jb` has to follow or diverge on purpose.

## Alternatives and prior art

- **Replace cobra with a parser that follows the spec's grammar.** This was the first draft. It needs a second implementation of the grammar to be worth it, breaks `--x=false`, comma lists and completion, and was declined.
- **One comma-separated tag.** Shorter, but a comma in a description needs quoting rules that must be designed and tested. Declined for separate tags.
- **A repeated `--ip` flag only, or hand-written flags for the variadic commands.** The first breaks the form a person types. The second leaves drift in two commands. Declined for the last-positional-array rule.
- **List `hunt` and `activity` as mutating tools, or not at all.** The first stops an agent asking the central question without opening a mutating tool. The second removes the reason for the server. Declined for the forced `store=false` projection.
- **Hand-written schemas as JSON-shaped literals.** Explicit, but they copy every field of the option structs and drift from them. Declined.
- **A separate MCP program on the public Go API.** It keeps the protocol out of `jb`, but it cannot see the operation registry unless that is public, and it adds a second thing to version. Declined for now.
- **Expose everything over MCP with a dry-run default.** Simpler, but one injected `apply: true` from deleting evidence. Declined.
- **Write tool definitions by hand.** The least work now and the most drift later.
- **Prior art.** The spec's own motivation records the same failure: a CLI and a tool defined twice, with defaults that differ. This RFC takes its solution and changes where the source of truth lives. The author read only the spec text and no MCP implementation. The reviewer is asked to name one worth reading.

## Compatibility

There is no compatibility path, because `jb` and one other program are the only users and nothing is public. The proposal is mostly additive:

- New: `jb operations`, `jb mcp`, `jb.Operations`, `jb.Call` and the `jb:` struct tags.
- Changed only where the builder exposes an existing inconsistency, such as a command whose default differs from its option struct. Each such fix is listed under "Breaking" in the changelog with the old and the new value.
- No flag is renamed or removed by this RFC.

## Security considerations

- Arguments are untrusted on both surfaces. A person can type anything and an MCP client passes what a model chose. The one check enforces the schema, and a handler still checks what the schema cannot say: a path stays inside its root, an id exists.
- No operation takes a secret as an argument. Credentials come from the process environment. `jb mcp` runs with the environment of its process, so it holds whatever credentials that process holds. The launcher SHOULD give it only the credentials it needs.
- Read-only is the default. A mutating operation needs `--allow NAME` and `apply=true`. A model that is tricked into calling a mutating tool still cannot reach one the operator did not name.
- A tool call that supplies a `cli.only` property is refused as unknown, even if its value would pass the command's schema.
- Tool results include data from the evidence store, which comes from third-party logs: paths, user agents and names that an attacker chose. In the MCP projection only, a string value that came from evidence is cut at 256 characters and stripped of control characters, and each description says that values taken from logs are untrusted data. The command line and the Go API are unchanged. This does not stop a short injected sentence. The control that matters is the client's: the MCP specification asks a client to keep a human able to deny tool calls, and a client MUST treat result text as data, never as instructions.
- `intel` and the estate collectors contact third-party services and write local state, so they are listed as mutating and need `--allow NAME` like the other writers. The default tool list contains only operations that write nothing local and contact no third party.

## Conformance

Proposed. None of these exists yet.

- **Load check.** A test that every operation passes the check, and that each rule fails on a planted fault.
- **Reflector tests.** A struct with each of the four shapes maps to the expected schema. A field of another type, an untagged exported field and a bad name each fail.
- **Command equals operation.** For every built command, the flags equal the operation's properties, with the same defaults.
- **Round trip.** For every operation, a test calls the handler with a sample on synthetic data and checks that the result marshals to the keys the parity tests pin.
- **Read-only holds.** A test lists the tools of `jb mcp` and asserts that no mutating operation appears without `--allow`, and that a call to a mutating operation without `apply` changes nothing.
- **Golden file.** `docs/operations.json` equals the output of `jb operations`.
- **Defaults.** `TestLibraryDefaultsAreTheCLIDefaults` is deleted, because the defaults live in one place.

## Reference implementations

Shipped: the cobra commands in `cmd/jb`, the option structs in the root package (`jb.go`, `activity.go`, `watch.go`), the usage error of RFC 0005, and steps 1 and 2 of the plan: `internal/ops` (the types, the reflector, the check, the tool projection and the decode step; standard library only, with an archtest rule), and the registry in the root package (`jb.Operations`, `jb.Call`) with `case_show` and `case_check` end to end, `jb operations [--tool]` and the committed `docs/operations.json`. Step 4: `internal/mcp` (the stdio server of revision 2025-11-25: initialize, ping, tools/list, tools/call, cancellation; standard library and `internal/ops` only, with an archtest rule) and `jb mcp [--allow NAME]` in `cmd/jb/mcp.go`, which lists read-only operations, adds the named mutating ones, forces `store=false` on `hunt` and `activity`, refuses `cli.only` properties, and cuts and strips result strings.

- `internal/ops`: the types, the reflector, the check, the tool projection (with `toolFixed`, which removes a property from the tool and runs every call with its value) and the decode step; standard library only, with an archtest rule.
- The registry in the root package (`jb.Operations`, `jb.Call`, `jb.CallTool`) with all 22 operations of the table: `activity`, `actor_status`, `case_check`, `case_show`, `db_compact`, `db_prune`, `db_rename_source`, `db_reputation`, `db_status`, `db_usage`, `doctor`, `estate_asn`, `estate_ct`, `estate_diff`, `estate_dns`, `estate_facts_import`, `estate_ip`, `estate_promote`, `estate_refresh`, `hunt`, `intel` and `watch_status`. `hunt` and `activity` carry `store` (default true), which the tool fixes to false. `estate_diff` takes `alert`, `config` and `ttl` from the command line only (`cli.only`). `jb operations [--tool]` and the committed `docs/operations.json`.
- The flag builder (`cmd/jb/opflags.go`), used by `case show`, `case check`, `actor status`, `doctor`, `intel`, `watch status`, `estate promote` and the six `db` commands; a test pins every command's flags (names, types, defaults, help text) against a recorded set, and a test compares every command's flags with its operation's properties.

Commands still hand-written, each because the builder would change what a person sees: `hunt` and `activity` (the flag is `--no-store`, and `--window` is a duration flag that accepts `7d`), `estate` (the IP form), `estate asn|dns|ct|refresh` (duration flags with a non-zero default, shown as `duration`) and `estate diff` (`--ttl`). They agree with their operations in a test that maps `--no-store` to `store` and a duration flag to a string property.

## Open questions

1. **Prior art.** The author has read the spec text and no MCP implementation. Before acceptance the author reads the MCP tools specification and one published server, and records what differs. Decides: the author, with the maintainer reviewing.
2. **A stored run over MCP.** If a client later needs a stored hunt, is a separate allowlisted tool better than lifting the forced `store=false`? Decides: the maintainer, when a client needs it.

## Changes

- 2026-11-06: first draft.
- 2026-11-06: third grill, and a correction: `intel` and the estate collectors write local state and contact third parties, so they are mutating (the draft had listed them read-only); results from evidence are capped and stripped in the MCP projection; no output schema in the first cut.
- 2026-11-06: second grill: separate struct tags; the last positional may be an array; `hunt` and `activity` are listed over MCP with `store` forced to false; MCP annotations come from `readOnly`.
- 2026-11-06: revised after a Hashimoto-rigor grill with the owner. Cobra stays, the option struct is the source of truth, `jb mcp` is built in, and the default exposure is read-only.
- 2026-11-06: accepted by the maintainer after three Hashimoto-rigor grills. Code may start; the status becomes `implemented` when the Reference implementations section is moved from proposed to shipped.
