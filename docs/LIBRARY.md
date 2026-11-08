# Using jb as a Go library

The README has the short example. This page has the rest of the public API: the command-to-function table, the operations API and the completeness checks.

To write a mapper plugin, import `github.com/iksnerd/json-bourne/sdk` (standard library only, none of the host code) and see [PLUGINS.md](PLUGINS.md). Not public yet: the host side of plugins and a protocol conformance corpus.

The API is v0 and may change between minor versions. Every command has a function, and the command prints the function's result:

| Command | Function |
|---|---|
| `jb hunt` | `Hunt`, `HuntCase` (with `HuntOptions.Search` for `--search`) |
| `jb activity` | `Activity` |
| `jb watch`, `jb watch status` | `Watch`, `WatchStatus` |
| `jb case check`, `jb case show` | `CaseCheck`, `CaseShow` |
| `jb doctor` | `Doctor` (read-only; sends nothing unless `Online` is set) |
| `jb actor status` | `ActorStatus` |
| `jb db status`, `jb db usage` | `DBStatus`, `DBUsage` |
| `jb db reputation` | `Reputation` (read-only; a result cut at the row cap has `Truncated` set and `Complete()` false) |
| `jb db prune`, `compact`, `rename-source` | `DBPrune`, `DBCompact`, `DBRenameSource` (a dry run unless `Apply` is set) |
| `jb intel` | `Intel` |
| `jb estate ...` | `EstateIP`, `EstateASN`, `EstateDNS`, `EstateCT`, `EstateRefresh`, `EstateDiff`, `EstatePromote`, `EstateFactsImport` |
| `jb serve` | `DashboardHandler`, `Serve` (keeps the read-only, loopback and CSP rules of RFC 0003; read the doc comment before mounting the handler) |

Operations (RFC 0010): `jb.Operations()` lists the definition of each of the 22 operations (everything but `watch` and `serve`, which run until stopped), derived from its option struct's `jb:` tags, and `jb.Call(ctx, name, arguments, env)` checks a JSON-shaped arguments map against that definition and runs the typed function. A bad argument is a `UsageError` that lists every problem. A window, a time and a duration are strings in the arguments (`"window": "2h"`), read by the same code as the flags. `hunt` and `activity` take `store` (default true; the flag `--no-store` is its false form), and an MCP tool runs them with `store` fixed to false: `jb.CallTool` checks a tool call against the tool's schema and adds the fixed values. `jb operations` prints the definitions as JSON (`docs/operations.json` is the committed copy) and `jb operations --tool` prints the entries an MCP `tools/list` result carries. Thirteen commands (`case show`, `case check`, `actor status`, `doctor`, `intel`, `watch status`, `estate promote` and the six `db` commands) register their flags from their operation, so their flags, defaults and help text cannot drift from it.

Check completeness before calling anything clean: `Result.Complete()` (and `SearchAbsent()` for a search), `CycleReport.Status.Healthy()`, `ActivityResult.Verdict`, `DoctorResult.OK()` and `Complete()`. A caller's mistake returns an error for which `IsUsage` is true. `Config` is opaque (build it with `LoadConfig`); `Result` is an alias of an internal type, so its exported fields are part of the API. Importing the package links DuckDB, so it needs cgo and a C compiler. The exported surface is pinned by `testdata/api/` and, from the outside, by the [contract module](../contract/README.md), which also parses the table above.

[Back to the README](../README.md)
