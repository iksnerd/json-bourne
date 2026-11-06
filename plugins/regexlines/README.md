# regexlines

Maps log lines matched by a regular expression with named groups to events. The line is a text field of the document (default `message`). Product-agnostic: the pattern and the mapping are `mapper_config`. Shared options (`fields`, `time`, `required`, types, limits) are in [../README.md](../README.md).

The pattern is Go `regexp` syntax (RE2): linear-time matching, no backreferences, no lookaround. It is searched in the line, so anchor it with `^` and `$` when the whole line must match. A line that does not match is unparsable. A group that did not take part in the match is absent.

Options beyond the shared ones:

| Key | Default | Meaning |
|---|---|---|
| `pattern` | required | RE2, at most 4 KiB, at least one named group `(?P<name>...)`. |
| `line_field` | `message` | Document path holding the line. |
| `max_line_bytes` | `8192` | At most `65536`. Longer lines are unparsable and not matched. |

Each field's `from` must be a named group in the pattern; the plugin refuses the config otherwise.

## Sample: an nginx-style access line

```yaml
mapper: plugin:example.regexlines
mapper_config:
  pattern: '^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>[^?#\s]*)\S* [^"]+" (?P<status>\d{3}) (?:\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
  fields:
    client_ip:  {from: ip, type: ip, required: true}
    method:     {from: method, required: true}
    path:       {from: path, required: true}
    status:     {from: status, type: int, required: true}
    user_agent: {from: ua, omit: ["-"]}
    referer:    {from: referer, omit: ["-"]}
```

For the line

    192.0.2.10 - - [05/Nov/2026:12:00:01 +0000] "POST /auth/login?x=1 HTTP/1.1" 401 52 "-" "ExampleAgent/1.0" 310 0.004 [example-svc-80] [] 10.0.0.5:8080 52 0.004 401 req0001

it emits `client_ip 192.0.2.10`, `method POST`, `path /auth/login` (the query string is not in the `path` group), `status 401` and `user_agent ExampleAgent/1.0`. This is the same event the built-in `nginx_ingress` mapper produces; `internal/conformance` runs both on the same documents and requires them to agree, including on the lines neither accepts.
