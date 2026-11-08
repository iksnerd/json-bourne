# Example plugins

Three mapper plugins for `jb`, each a separate `package main`, standard library only. None knows a product: the operator's `mapper_config` says what to read and what to emit. The protocol, the limits and the trust model are in [docs/PLUGINS.md](../../docs/PLUGINS.md).

    go build ./examples/plugins/...                          # builds all three (and discards the binaries)
    go build -o /opt/jb-plugins/kvlines/kvlines ./examples/plugins/kvlines

| Plugin | Reads |
|---|---|
| [kvlines](kvlines/README.md) | `key=value` and `key="quoted value"` lines |
| [regexlines](regexlines/README.md) | lines matched by an RE2 pattern with named groups |
| [jsondoc](jsondoc/README.md) | JSON documents, by path |

`internal/` is the code they share (the stdio loop and the mapping and coercion rules). It is not part of the protocol; a plugin in another language needs none of it.

## Configuration shared by all three

Every key below goes in the source's `mapper_config:`. Unknown keys are an error: the plugin answers the first request with a config error and the source fails.

| Key | Default | Meaning |
|---|---|---|
| `fields` | required, 1 to 64 entries | Event field name (`^[a-z][a-z0-9_]{0,63}$`) to a field spec. **Only mapped values are emitted.** An unmapped key, group or path (a username, an email, a card number) never reaches the evidence store. |
| `time` | the document's `@timestamp`, RFC 3339 | Where the event time comes from; see below. |
| `required` | none | Source names that must be present and non-empty, else the document is unparsable. |

A field spec:

| Key | Default | Meaning |
|---|---|---|
| `from` | required | The key (kvlines), group name (regexlines) or JSON path (jsondoc). |
| `type` | `string` | `string`, `int`, `bool`, `time` or `ip`. `ip` accepts IPv4 and IPv6 and emits the canonical text. `time` emits UTC RFC 3339. An object or array is never coerced into a string. |
| `layout` | `rfc3339` | `time` only: `rfc3339`, `rfc3339nano`, `unix` (seconds), `unix_ms`, or a Go time layout such as `2006-01-02 15:04:05`. |
| `omit` | none | Source values treated as absent, such as `["-"]`. An empty value is always absent. |
| `required` | `false` | An absent value makes the document unparsable. |

A value that cannot be coerced (`type: int` on `abc`) makes the document **unparsable**, which the source counts in `Stats.Unparsable`. It is never emitted as a different type and never dropped silently.

`time`:

- `time: {doc_field: "event.created", layout: rfc3339}` takes the time from a path in the document (default `@timestamp`). A missing or invalid value is a fault in the document set, not an odd line: the plugin returns an error and the source fails, as the built-in mappers do.
- `time: {from: at, layout: "2006-01-02 15:04:05"}` takes it from the parsed text (a kvlines key, a regexlines group, a jsondoc path). An invalid value makes that one document unparsable.

## Hostile input, for all three

- A line over `max_line_bytes` (default 8192, at most 65536) is unparsable and is not parsed. jsondoc has `max_doc_bytes` (default 1 MiB, at most 8 MiB).
- regexlines uses Go's `regexp`, which is RE2: matching time is linear in the line, so a catastrophic pattern cannot hang it. The pattern is capped at 4 KiB; backreferences do not exist.
- kvlines reads at most 128 pairs and 64-character keys per line, and a duplicate key makes the line unparsable (see its README for why).
- A JSON path has at most 8 segments. At most 64 fields and 64 KiB of config.
- A panic while mapping is reported as an error that names no document, which fails the source. It is not swallowed as an odd line.
