# kvlines

Maps `key=value` log lines to events. The line is a text field of the document (default `message`). Product-agnostic: every name comes from `mapper_config`. Shared options (`fields`, `time`, `required`, types, limits) are in [../README.md](../README.md).

Line grammar:

- A pair is `key=value`. A key is 1 to 64 characters of letters, digits and `_ . : @ / -`.
- A value is either `"double quoted"` (the escapes `\"` and `\\` only; an unterminated quote makes the line unparsable) or runs to the next whitespace or separator.
- A word that is not a pair is skipped.
- **A duplicate key makes the line unparsable.** If a value can carry user-chosen text, a later `key=` inside it could otherwise impersonate a field. The line is counted as unparsable, visibly, instead of choosing a winner.
- At most 128 pairs.

Options beyond the shared ones:

| Key | Default | Meaning |
|---|---|---|
| `line_field` | `message` | Document path holding the line. A missing or non-text value is unparsable. |
| `max_line_bytes` | `8192` | At most `65536`. |
| `separators` | none | Up to 8 characters that end an unquoted value besides whitespace, and are skipped between pairs: `","` for `a=1, b=2`. |

## Sample: an event line

Document `message`:

    type=LOGIN_ERROR, realmId=example-realm, clientId=example-app, userId=null, ipAddress=192.0.2.44, error=invalid_user_credentials, username="alice@example.com"

Config:

```yaml
mapper: plugin:example.kvlines
mapper_config:
  separators: ","
  required: [type, realmId]
  fields:
    event_type: {from: type, required: true}
    realm:      {from: realmId}
    client_id:  {from: clientId}
    client_ip:  {from: ipAddress, type: ip}
    error:      {from: error}
```

Event (time from the document's `@timestamp`):

```json
{"event_type":"LOGIN_ERROR","realm":"example-realm","client_id":"example-app","client_ip":"192.0.2.44","error":"invalid_user_credentials"}
```

`userId` and `username` are in the line and are not mapped, so they are not emitted. Add them to `fields` only if you mean to store them.

The corpus in `internal/conformance/testdata/kvlines_*.json` has more cases, including a time taken from a key with a layout.
