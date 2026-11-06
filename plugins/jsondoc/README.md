# jsondoc

Maps a document that is already JSON to an event: `from` is a path in the document. Product-agnostic: the mapping is `mapper_config`. Shared options (`fields`, `time`, `required`, types, limits) are in [../README.md](../README.md).

Paths are dotted: `source.ip`. A numeric segment indexes an array (`tags.0`). At each object the longest literal key is tried first, so a flattened key such as `log.level` is found as well as `log: {level: ...}`. At most 8 segments.

Options beyond the shared ones:

| Key | Default | Meaning |
|---|---|---|
| `max_doc_bytes` | `1048576` | At most 8 MiB. A larger document is unparsable. |

Numbers keep their exact value (no float round trip), and `type: int` accepts a whole JSON number or a numeric string.

## Sample

Document:

```json
{"event":{"created":"2026-11-05T12:00:00Z","action":"login-failed"},"source":{"ip":"192.0.2.60"},
 "http":{"response":{"status_code":401}},"tags":["auth","x"],"log.level":"warn","user":{"email":"dana@example.com"}}
```

Config:

```yaml
mapper: plugin:example.jsondoc
mapper_config:
  time: {doc_field: event.created}
  required: [event.action]
  fields:
    action:    {from: event.action, required: true}
    client_ip: {from: source.ip, type: ip}
    status:    {from: http.response.status_code, type: int}
    first_tag: {from: tags.0}
    level:     {from: log.level}
```

Event: `action login-failed`, `client_ip 192.0.2.60`, `status 401`, `first_tag auth`, `level warn`. `user.email` is not mapped and is not emitted.
