# Reputation lookups

This page covers `jb intel`, the reputation feeds and the `intel` options.

`jb intel` asks the reputation feeds you list what they know about addresses and appends the answers to the `reputation` table. It is a separate command from `hunt`: a hunt never reads a feed or a feed key. Three feed types exist: `greynoise` and `sans-isc` (HTTP APIs) and `dnsbl` (a DNS blocklist, asked through a resolver). List as many as you like; two feeds may not report the same name (two `dnsbl` entries need different zones), because the `source` column must say who answered.

```yaml
feeds:
  - type: greynoise
    # base_url: https://api.greynoise.io
    api_key_env: JB_GREYNOISE_API_KEY   # optional; the name of a variable, never the key
    max_lookups: 10
    min_interval: 1s
    timeout: 10s
    max_response_bytes: 65536
  - type: sans-isc            # no key; see below
  - type: dnsbl               # off until enabled: true; see below
    zone: bl.example.org
    enabled: true
intel:
  ip_fields: [client_ip]
  max_indicators: 10
```

```
jb intel --case DIR                 # addresses from the latest stored hunt
jb intel --case DIR 192.0.2.7 ...   # addresses given on the command line
jb intel --config FILE [--output table|json] [IP ...]
```

With no address arguments, `jb intel` reads the distinct values of the `intel.ip_fields` event fields in the latest stored hunt (every source of that hunt), most frequent first, and ignores values that are not IP addresses (it counts them). Run `jb hunt` first. With an empty store, or a hunt with no address in those fields, it exits 1: an empty list would read as "nothing to look up".

**Several feeds in one run.** Every address is asked of every enabled feed, and each address x feed pair is its own answer, stored with the feed's name in `source`. One feed failing makes the run `INCOMPLETE` and exits 1, but the other feeds' answers are kept and stored. A feed that is listed but not enabled is named on stderr and not asked. If no listed feed is enabled, `jb intel` refuses.

## How to read the result

**A reputation snapshot is context, not attribution.** It says how a third-party sensor network saw an address at that time. It does not say who is behind your traffic. A CDN or proxy edge address carries the reputation of the edge, shared by every visitor behind it; if your `client_ip` field holds edge addresses, a "benign" or "malicious" verdict says nothing about the visitor. Reputation is never read by a detector and never changes a finding or a severity; `internal/archtest` fails the build if a detector or the hunt mentions it. Every output (table and JSON) carries this note.

**"Not found" and "could not ask" are different answers.**

| Outcome | What the feed said | Stored in `reputation` | Exit |
|---|---|---|---|
| answer | HTTP 200 with a classification | yes, verdict `classification=...;noise=...;riot=...;last_seen=...` | 0 |
| not found | HTTP 404 (or a 200 saying "not observed" / "no report"): the feed has never seen the address. For `dnsbl`: NXDOMAIN, that is "not listed" | yes, verdict `not_found` | 0 |
| failure | timeout, network error, HTTP 429, any other status, a body that is too large or not the expected JSON, a cancelled run, an address not asked because a cap was reached. For `dnsbl`: SERVFAIL, REFUSED, a timeout, a refusal code or an answer outside 127.0.0.0/8 (see below) | never | 1 |

Any failure makes the run print `INCOMPLETE`, list the addresses that got no answer and the reason, and exit 1. Answers obtained before a failure are kept. After an HTTP 429 the feed is not asked again in that run. A failure is never turned into `unknown`, `not_found` or an empty result.

Rows are appended with the time of the lookup and the feed's name (`greynoise:community`) in the `source` column; nothing is updated or deleted, so repeated runs form a time series (`jb db status` counts them). Verdict values from the feed are reduced to letters, digits and `. _ : -` and capped in length before they are stored.

**Reading reputation rows.** `jb db reputation (--config FILE | --case DIR)` lists the stored rows read-only (Go: `jb.Reputation`). A row has four fields and no run id: `indicator`, `verdict`, `observed` (UTC, RFC 3339) and `source` (the feed). Rows come back by indicator, then newest first, so a verdict change reads top to bottom. Filters: `--indicator IP` (repeat, at most 100, IP addresses only), `--source NAME`, `--since TIME` (inclusive), `--until TIME` (exclusive; each an RFC 3339 time or a `YYYY-MM-DD` date, and `--since` may not be after `--until`), and `--latest`, which keeps the newest row of each indicator from each source (with `--until`, the verdict as of that time). `--limit N` caps the rows (default 1000, at most 10000); a result cut at the cap has `"truncated": true`, `"complete": false` and exits 1. With `--case`, the config is the one that declares `commands: [intel]`. The store is opened as `jb serve` opens it: never created, and a store a writer holds is waited for (`JB_DB_LOCK_WAIT`), then refused.

## `type: greynoise`

Calls `GET <base_url>/v3/community/<ip>`, the GreyNoise community API, and nothing else. It is passive: it asks the feed about the address and never contacts the address. Only a syntactically valid IP is placed in a request. Redirects are not followed.

| Key | Default | Rules |
|---|---|---|
| `base_url` | `https://api.greynoise.io` | `scheme://host[:port]` only; `https`, or `http` for loopback only (tests use a local fake server). No credentials, path or query. |
| `api_key_env` | none (keyless) | The *name* of an environment variable, matching `^[A-Z][A-Z0-9_]{0,63}$`. The key is sent in the `key` request header and nowhere else. If you name a variable that is unset or empty, `jb intel` refuses to run; it does not fall back to the much smaller keyless quota. |
| `max_lookups` | `10` | `1` to `1000` requests per run. Addresses beyond it are not asked and are reported as failures. |
| `min_interval` | `1s` | `0` to `1h` between two requests. |
| `timeout` | `10s` | Per request, up to `1m`. |
| `max_response_bytes` | `65536` | `512` to `1048576`. A larger response is a failure, not a truncated answer. |

The keyless community endpoint allows very few lookups a week, which is why the defaults are small. Raise them only for a key whose plan allows it.

The key never appears in output, error messages, logs or the evidence store: it is scrubbed from everything that came back from the network, and a test with a sentinel key (including a server that echoes it) checks the output and the database file.

## `type: sans-isc`

Calls `GET <base_url>/api/ip/<ip>?json`, the SANS Internet Storm Center IP API, and nothing else. It needs no key and sends no credential. Passive: the ISC is asked about the address and the address is never contacted. Redirects are not followed. The address goes to the ISC, a third party; list the feed only if you accept that.

| Key | Default | Rules |
|---|---|---|
| `base_url` | `https://isc.sans.edu` | As for `greynoise`: `scheme://host[:port]`, `https` (loopback `http` for tests). |
| `max_lookups`, `min_interval`, `timeout`, `max_response_bytes` | `10`, `1s`, `10s`, `65536` | Same ranges as `greynoise`. |

An `api_key_env` is an unknown key here and fails at load. Outcomes: HTTP 404, or a 200 whose `count`, `attacks` and `threatfeeds` are all empty for exactly the address asked, is `not_found` (the ISC holds no report). A 200 that describes a different address, or has no `ip` object, is a failure. An answer is stored as `count=12;attacks=3;mindate=...;maxdate=...;feeds=name,name` (values reduced to letters, digits and `. _ : -`, at most five feed names). The source column says `sans-isc`.

## `type: dnsbl`

Looks an address up as a name under a DNS blocklist zone: `4.3.2.1.<zone>` for `1.2.3.4`, A record only. **This sends the address to a DNS resolver and, through it, to the zone's operator**, so the feed does nothing until you set `enabled: true`. A listed feed with `enabled` absent or `false` is not built, not asked, and named on stderr; `jb doctor` shows it as disabled.

```yaml
feeds:
  - type: dnsbl
    zone: bl.example.org
    enabled: true
    # resolver: 192.0.2.53:53      # default: the system resolver
    return_codes:
      "127.0.0.2": sbl
      "127.0.0.4": xbl
    # error_codes: ["127.0.9.9"]   # codes this zone uses to refuse service, besides 127.255.255.0/24
    # ipv6: false
    max_lookups: 10
    min_interval: 250ms
    timeout: 5s
```

| Key | Default | Rules |
|---|---|---|
| `zone` | none, required | A lower-case DNS name of at least two labels, no trailing dot, not an IP. Also names the feed: `dnsbl:<zone>`. |
| `enabled` | `false` | Must be `true` for the feed to be asked. |
| `resolver` | system resolver | An IP or `IP:port` (port defaults to 53). A name is refused: it would need resolving first. The pure Go resolver is always used (`PreferGo`), because the C resolver cannot tell NXDOMAIN from SERVFAIL, and "not listed" must never be a guess. |
| `return_codes` | none | Map of `127.x.y.z` to a label (`[A-Za-z0-9_.-]{1,40}`), at most 64. A listed code you did not map is recorded as `unmapped`, with the raw code. Codes in `127.255.255.0/24` cannot be mapped. |
| `error_codes` | none | Extra `127.x` addresses this zone answers when it refuses service. |
| `ipv6` | `false` | See below. |
| `max_lookups`, `min_interval`, `timeout` | `10`, `250ms`, `5s` | `1..1000`, `0..1h`, `(0, 1m]`. The timeout is per question. |

How an answer is read:

| The resolver says | Result |
|---|---|
| NXDOMAIN, or no A record | `not_found` (not listed), a real answer, stored |
| one or more `127.x.y.z` | listed: `listed=true;zone=<zone>;codes=127.0.0.2:sbl,...` (sorted, at most eight, labels from `return_codes`), stored |
| any code in `127.255.255.0/24` (`127.255.255.252` to `.255` are how Spamhaus-style lists refuse a public or open resolver or an excessive query volume), or a code in `error_codes` | **failure**, and the zone is not asked again in that run |
| an address outside `127.0.0.0/8` (a resolver rewriting NXDOMAIN into an ad server), or a mix | failure |
| SERVFAIL, REFUSED, timeout, unreachable resolver, cancelled run, cap reached | failure |

A refusal says nothing about the address, so it is neither "listed" nor "not listed". If your resolver is a public one that the zone refuses, every lookup fails and the run is `INCOMPLETE`: point `resolver` at a recursive resolver the operator allows. Known gap: if a resolver answered NXDOMAIN to everything without saying so, jb cannot tell that from a clean address; test the zone with its documented test address (usually `127.0.0.2`) before relying on a run of "not listed" answers.

IPv6: with `ipv6: true` an address is asked as 32 reversed nibbles under the zone. With the default `false`, an IPv6 indicator is a failure ("not asked"), because a zone that publishes no IPv6 data answers NXDOMAIN for every address, which would read as "not listed". An IPv4-mapped IPv6 address is asked as its IPv4 address. Questions are fully qualified (trailing dot) so the system resolver's search list cannot append a domain and send a second question.

## `intel`

| Key | Default | Rules |
|---|---|---|
| `ip_fields` | `[client_ip]` | Event fields to read addresses from in the latest hunt. 1 to 8 names, each 1 to 128 characters of letters, digits and `_ @ . -`. |
| `max_indicators` | `10` | `1` to `1000` distinct addresses per run. The rest are reported as failures (the run is `INCOMPLETE`), never dropped. |

[Back to the configuration index](../CONFIG.md)
