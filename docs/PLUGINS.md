# Plugins: mappers that live outside the binary

[Back to the README](../README.md)

A mapper turns one raw document into an event. The built-in mappers (`default`, `nginx_ingress`, `keycloak`, `request_dump`) are Go code compiled into `jb`. A **plugin** is the same job done by a separate executable that you have allowlisted, so parsing for one product's log format does not have to live in the core binary.

> **Not another project's plugin protocol.** The protocol below is `jb`'s own. It has the shape of a long-lived plugin protocol (a handshake line, one request in flight, a deadline, the process group killed on a break, a breaker after three breaks), but it is not an implementation of any published one, and a plugin written for another host will not run here. It is versioned by the `v` field: a host reads only the current version, and the number increments when the protocol changes incompatibly. Why `jb` keeps its own protocol is in [adr/0001-relationship-to-other-plugin-specifications.md](adr/0001-relationship-to-other-plugin-specifications.md).

There is one plugin role, `mapper`, and one place a plugin is used: a `kibana` source with `mapper: plugin:<name>`. Hunt, watch and activity behave exactly as with a built-in mapper: the host hands the source events, and the source counts what the plugin could not parse in the same `Stats.Unparsable` the built-ins use.

## What runs on your machine

When a source names a plugin, `jb` starts that executable **as a child process, as you**, once per source per run, and keeps it for the whole run. Every document the source fetches is written to the plugin's stdin as JSON. That includes everything in the document, personal data included. The plugin is code you chose to trust; read it, pin it (below), and prefer one you compiled yourself.

`jb doctor` lists every outbound service and, for a source with a plugin, says that the documents go to the local plugin. `docs/POLICY.md` lists what `jb` sends where.

### What `jb` does not enforce

Say this plainly, because the controls below are real but small:

- **There is no sandbox.** The child has your user's filesystem and network access. The operating system is not asked to deny it anything. `jb` grants a plugin no network, and does not stop a plugin that opens a socket anyway. Run plugins you trust, or run `jb` itself somewhere that confines the network.
- **The environment is stripped, but that is a courtesy, not a boundary.** A plugin can read your files (including `~/.jb`, `~/.ssh` and shell history) as you can.
- **The sha256 pin and the digest check are not one atomic step with the launch.** What closes the gap is the mode check on the directory: only its owner can replace the file in between. Ancestors of the plugin directory are not checked.
- **File ownership is not checked.** A file owned by another user that is not group/other writable passes.
- **Scrubbing a plugin's stderr and error text is a heuristic.** It stops accidents. The real defence is that the child never receives a secret.
- **On platforms without process groups** (not Unix) only the plugin itself is killed on a deadline; a plugin that forks can outlive it.
- **The plugin's output is data, but it is the data your findings rest on.** A malicious plugin can emit any events it likes. The host checks that the answer is well formed and complete; it cannot check that it is true.

## Trust: only you allow a plugin

The operator's allowlist is a file that is **jb's own, not the case's**: `$JB_PLUGINS_FILE`, else `~/.jb/plugins.yaml`. A missing file is an empty allowlist, so no plugin is allowed.

```yaml
# ~/.jb/plugins.yaml - strict YAML, one document, unknown keys are an error
plugins:
  - name: acme.kvlines                  # dotted, lower case: ^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$
    path: /opt/jb-plugins/kvlines/kvlines   # absolute and clean (no .., no //)
    sha256: 9f2c...64 hex digits...     # optional pin, lower case
```

Rules, each enforced in `internal/adapters/plugin` and each with a test that fails when the rule is broken:

| Rule | Where |
|---|---|
| The allowlist file is not writable by group or others, is a regular file, is at most 1 MiB, has no mapping of more than 1000 keys, and parses strictly. | load |
| The path resolves (symlinks followed) to a regular file whose directory is the directory of the allowlisted path. A symlink out of the plugin directory is refused. | every launch |
| Neither the file nor its directory is writable by group or others, and the file is executable by its owner. | every launch |
| With a `sha256`, the file's digest equals it. A pinned file that changed is refused. | **every launch**, not once |
| A case or hunt config names a plugin by name only. | config load |

A case can never add a path, a command, an argument or an allowlist entry. In a config the plugin is `mapper: plugin:<name>`; the name must match the pattern above, so `plugin:/tmp/x`, `plugin:../x`, `plugin:sh -c id` and `plugin:UPPER.case` are load errors. A name that is not in your allowlist is a load error too. `mapper_config:` is only valid with a plugin mapper and is passed to the plugin as **data**: it is JSON on the wire and never reaches a shell or an argument list. Extra keys in a source (`path:`, `command:`, a top-level `plugins:`) are unknown keys, which the strict config loader already refuses.

`jb doctor` shows each allowlisted plugin, its path, its pin state (`none`, `ok`, `MISMATCH`) and whether the file and directory checks pass. It launches nothing and prints no environment value.

### Allowing a plugin

```sh
go build -o /opt/jb-plugins/kvlines/kvlines ./plugins/kvlines
chmod 755 /opt/jb-plugins/kvlines /opt/jb-plugins/kvlines/kvlines
shasum -a 256 /opt/jb-plugins/kvlines/kvlines          # put this in the allowlist as sha256
$EDITOR ~/.jb/plugins.yaml && chmod 600 ~/.jb/plugins.yaml
jb doctor
```

Pin it. A rebuilt plugin has a new digest, so rebuilding means editing the allowlist, which is the point.

## The protocol

Newline-delimited JSON over the child's stdin and stdout. One request is in flight at a time. Stderr is for humans.

**Lifecycle.** `jb` starts the process in its own process group, with the plugin's directory as the working directory, then reads one line:

```json
{"v":1,"role":"mapper","name":"kvlines","version":"0.1.0","config_schema":"free text describing mapper_config"}
```

`v` must be `1` and `role` must be `mapper`; `name` is required and informational (the allowlist name is the identity); `version` and `config_schema` are optional. Anything else in the line is ignored. Then, for each batch, `jb` writes a request line and reads one response line.

**Request**

```json
{"v":1,"id":7,"config":{"...":"mapper_config as data"},"docs":[{"...raw _source..."},{"...":"..."}]}
```

**Response**

```json
{"id":7,"events":[{"ts":"2026-11-05T12:00:00Z","fields":{"client_ip":"192.0.2.1","status":401}}, null],"unparsable":[1],"error":""}
```

- `id` must equal the request's.
- `events` has **exactly one slot per input document, in order**. A slot is an event object, or `null`.
- An event is `{"ts": <RFC 3339>, "fields": {...}}`. `fields` is an object; whole numbers become integers, so `"status": 401` equals what a built-in mapper emits. Emit the canonical field names (`client_ip`, `method`, `path`, `status`, `user_agent`, `referer`) where your data has them, so a detector's `key_field` means the same thing on every index.
- A `null` slot must be listed in `unparsable` (by index). That is how a plugin says "this document is not in the format I read". It is counted in `Stats.Unparsable` like a built-in mapper's refusals. A `null` that is **not** listed, an event that **is** listed, an index out of range or repeated, all break the call: otherwise a document could vanish.
- `error` non-empty means the plugin could not do its job (bad config, a fault in the document set, such as an unparsable `@timestamp`). It fails the source. Do not use it for one odd line.
- Unknown fields anywhere in the manifest, response or event are ignored, so a v1 host accepts a plugin that adds data later.

**Shutdown.** `jb` closes the plugin's stdin. A plugin should exit when stdin ends. One that has not exited after two seconds has its process group killed. Its exit status after a requested shutdown is not looked at.

## Limits

| Limit | Default | What happens past it |
|---|---|---|
| Documents per request | 200 | the host sends more requests; a page of 1000 documents is five |
| Deadline per request, and for the handshake | 10 s | the process group is killed; a break |
| One response line | 4 MiB | killed as soon as the line is known to be too long, so memory is bounded; a break |
| One request line | 8 MiB | a single document that does not fit fails the source (it is never skipped) |
| `mapper_config` | 64 KiB | refused at load |
| Stderr kept | the last 4 KiB | older output is discarded; the plugin is never blocked |
| Consecutive breaks | 3 | the breaker opens (below) |

## A plugin never produces a pass

All of these fail the **source** for the run, which makes the hunt INCOMPLETE (exit 1), the same as an unreachable Kibana. None becomes an empty clean result, and none skips documents:

a timeout; a crash or exit at any point (including exit 0 before the handshake, or in the middle of a line); invalid JSON; a response for another request id; the wrong number of slots; an unlisted `null`; an oversized line; a bad handshake (wrong version or role); a plugin that is not allowlisted, whose file changed since it was pinned, or whose file or directory is writable by others.

An error names the plugin, what went wrong, and the last of its stderr with control characters removed and anything credential-shaped replaced. It never contains a document or a response.

**Breaker.** Every failure above is a *break*: the child is killed and the call fails. The next call starts a fresh process (the allowlist checks run again). After **three breaks in a row** in one run the plugin is not called again: further calls fail at once without launching it. A successful call resets the count, but an open breaker stays open for the rest of the run: there is no half-open probe, and the error says so. A caller deadline or cancellation, and `Close`, are not breaks. An operator interrupt (SIGINT/SIGTERM) is not a break.

## Environment, directory, shutdown

- The child's environment is empty except `PATH`, `HOME`, `LANG` and `TMPDIR`, copied from `jb`'s own when set. Nothing else reaches it: not `JB_KIBANA_API_KEY`, not any other API key. A test starts `jb`-side code with a sentinel secret in the parent and asserts the child never sees it.
- The working directory is the plugin's own directory. No extra file descriptors are passed.
- `jb` ends the child when the run ends (`Runtime.Close`) and when it is interrupted, including `jb watch` on SIGINT or SIGTERM: the context ends the in-flight request, which kills the process group, and the deferred close handles the idle child between cycles.

## Writing a plugin

A plugin is any program that speaks the protocol above on standard input and output. In Go, use [`sdk`](../sdk), which is the stdio loop and the mapping code; the three plugins under `plugins/` are complete examples.

Rules for a plugin you write:

- Write to stdout only the manifest and the responses, one JSON object per line, flushed.
- Answer every request, with one slot per document.
- Treat every document as hostile: bound the work per line (reject lines over a size cap; use a linear-time regular expression engine), bound allocation, never panic on odd input.
- Emit only fields the operator's `mapper_config` maps. A plugin that copies the whole document into `fields` leaks personal data into the evidence store.
- Do not open the network. `jb` does not stop you; the operator is trusting you not to.
- Exit when stdin ends.

## The examples

`plugins/` holds three plugins that know no product. Each is configured entirely by `mapper_config`, and each has a README with the config reference and a sample.

| Plugin | Reads | Config maps |
|---|---|---|
| [`kvlines`](../plugins/kvlines/README.md) | `key=value` and `key="quoted value"` lines | source keys to event fields; types; the time key or the document timestamp; required keys |
| [`regexlines`](../plugins/regexlines/README.md) | lines matched by an RE2 pattern with named groups | groups to event fields, same options |
| [`jsondoc`](../plugins/jsondoc/README.md) | a JSON document | JSON paths to event fields, same options |

They share `sdk` (`github.com/iksnerd/json-bourne/sdk`, public: write your own plugin with it), which is the stdio loop and the mapping code, and import the standard library only. `internal/archtest` fails the build if a plugin imports anything else, the network, `os/exec`, or `syscall`, and if `jb` itself imports a plugin.

The conformance corpus (`internal/conformance/testdata`) runs synthetic documents through each example **as a real child process behind the real host** and, for the nginx access line, also through the built-in `nginx_ingress` mapper. Both must give the same events. The corpus shows an nginx-style access line (`regexlines`) and a Keycloak-style `type=LOGIN_ERROR realmId=... ipAddress=...` event line (`kvlines`) expressed purely as configuration. All values are synthetic (`example.com`, RFC 5737 and RFC 3849 addresses, made-up realm and client names). The built-in `keycloak` mapper's whole corpus also runs through `kvlines` (`internal/conformance/keycloak_corpus_test.go`); every place the two differ is recorded with its reason in `testdata/keycloak/kvlines_differences.json`, and the table is in [CONFIG.md](CONFIG.md#mappers).

Sample allowlist and source configs: [`examples/plugins.example.yaml`](../examples/plugins.example.yaml), [`examples/hunt-plugin-nginx.example.yaml`](../examples/hunt-plugin-nginx.example.yaml), [`examples/hunt-plugin-eventlog.example.yaml`](../examples/hunt-plugin-eventlog.example.yaml).

## Where the code is

- `internal/adapters/plugin`: the host. The one package that starts a process for a plugin (`internal/archtest` `TestOSExecIsConfined`).
- `internal/core`: `BatchMapper`, the port the Kibana source calls with a page of documents.
- `internal/config/register_kibana.go`: `mapper: plugin:<name>` validation and building.
- `cmd/jb/doctor.go`: the allowlist section of `jb doctor`.
