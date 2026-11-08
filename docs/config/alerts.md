# Alert delivery

This page covers the `alerts` list and the `webhook` sink of `jb watch`.

`jb watch` always writes each alert to stdout and appends it to `<evidence>/watch.log`. The log is the source of truth and is written first. `alerts:` adds delivery on top of it; it never replaces the log.

```yaml
alerts:
  - type: webhook
    url_env: JB_ALERT_WEBHOOK_URL   # the NAME of a variable that holds the URL
    min_severity: high
    timeout: 10s
    max_per_cycle: 10
```

## `type: webhook`

POSTs `{"text": "..."}` (`Content-Type: application/json`) to the URL, the shape Slack, Mattermost and similar incoming webhooks accept.

| Key | Default | Rules |
|---|---|---|
| `url_env` | required | The *name* of an environment variable, matching `^[A-Z][A-Z0-9_]{0,63}$`. The URL itself is a secret (it carries a token) and never goes in the file: a value that is not a variable name, such as a pasted URL, is refused at load, and the error does not repeat it. An unset or empty variable stops `jb watch` before the first hunt. |
| `min_severity` | `high` | `info`, `check`, `activity`, `high` or `critical`. Alerts below it are not sent (not an error). Outage alerts (`watch-incomplete`, `watch-cycle-error`, state and prune problems) are `high`; recoveries and the cycle line are `info`. |
| `timeout` | `10s` | Per request, up to `1m`. |
| `max_per_cycle` | `10` | `1` to `100` alerts sent per cycle. |
| `min_interval` | `1s` | `0s` to `1h` between two requests. `0s` means no pause. |
| `max_response_bytes` | `4096` | `16` to `1048576`. A larger response is a failure. |
| `allow_insecure_loopback` | `false` | Tests only: allows `http://` when the host is `localhost` or a loopback address. Without it the URL must be `https://`. |

What it sends and what it does not:

- Findings: `[severity] tag: summary (run id)`. Only the detector's summary text, the tag, the severity and the run id. Never a raw event, a log line or a field value beyond what the summary says.
- Every other kind of alert (outage, state problem, recovery, the cycle line) is a fixed sentence plus the tag and the run id, pointing at `watch.log`. Their full text is made of error messages from other components and can name internal hosts, so it stays in the log.
- Control characters, backslash, newline, bidirectional overrides and the chat markup characters `& < >` are escaped (`<!channel>` arrives as `&lt;!channel&gt;`), and the summary is cut at 500 characters. Log content cannot forge a line or a mention.
- A storm cannot flood it: after `max_per_cycle` sends, further alerts of that cycle are not sent, and one message says `N further alerts not sent to webhook, see watch.log (run ...)` when the cycle ends. A cycle whose webhook failed sends nothing more that cycle (an outage costs one timeout, not one per alert).
- No redirect is followed (the token would travel with it); a 3xx is a failure. Only the URL's host receives traffic. The one exception is a proxy named by the standard `HTTPS_PROXY` variable, which carries the connection as it does for every `jb` network adapter.

Failure rules. A timeout, a network error, any non-2xx status, a redirect and an oversized response are errors. The alert is already in the log, so it counts as delivered and is not offered again, but the cycle is `CYCLE FAILED`, the cycle line says how many alerts missed the webhook, and `--once` exits 1. A failing webhook never stops the other sinks. If the log itself cannot be written the alert counts as not delivered, the webhook is not tried for it (a retry would duplicate it there), and the next cycle offers it again.

The URL never appears in output, error messages, the log, alert text or the evidence store. Errors are built from fixed words and a status code, never from the text of a `net/http` or `net/url` error (which quotes the URL), and the sink formats as `[redacted]` under every `fmt` verb. A test with a hostile fake that echoes the URL and path in its replies, and a connection that fails, checks all of it.

[Back to the configuration index](../CONFIG.md)
