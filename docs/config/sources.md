# Sources

This page covers the `kibana` source: its keys, the filter, ad-hoc search and past windows.

## `type: kibana`

Reads Elasticsearch through the Kibana search proxy (`POST /internal/search/es`).

| Key | Default | Rules |
|---|---|---|
| `url` | none, required | Absolute `https` URL. `http` is accepted for loopback only (`localhost`, `127.0.0.0/8`, `::1`). No credentials in the URL. |
| `api_key_env` | none, required | The *name* of an environment variable holding the API key. Must match `^[A-Z][A-Z0-9_]{0,63}$`. |
| `index` | none, required | Index or pattern, for example `logs-auth-*`. Also gives the source its default name, `kibana:<index>`. |
| `name` | `kibana:<index>` | Optional name of the source, `^[a-z][a-z0-9_.:-]{0,63}$` (no slash: it is part of the run id `<run>/<name>`). It is the stored `source` column and what `jb hunt`, `jb activity` and the dashboard show. Names must be unique in one config. Two sources on the same index need a `name` each; see [Two sources on one index](#two-sources-on-one-index). |
| `time_field` | `@timestamp` | Field used for the window filter and sort. |
| `page_size` | `1000` | `0` to `10000`. `0` takes the default. |
| `search_field` | `message` | The field `jb hunt --search TERM` matches a term against (see [Ad-hoc search](#ad-hoc-search)). Same character rules as a filter `field`. |
| `mapper` | `default` | Name of the mapper that turns a document into an event, or `plugin:<name>` for an allowlisted plugin; see [Mappers](mappers.md#mappers). An unknown name, or a plugin that is not in your allowlist, is an error at load. |
| `mapper_config` | none | Only with `mapper: plugin:<name>`. A YAML map (at most 64 KiB as JSON) passed to the plugin as data on every request. It can never name a path or a command. |
| `key_match` | none | `{field, mode}`. Which raw field of this index holds a key, and how to match it. Needed only by a `newkey` detector with a `history` block (see [`type: newkey`](detectors-account-abuse.md#type-newkey)). `field` has the character rules of a filter `field`. `mode` is required and has no default: `term` is an exact value in a keyword field; `phrase` is the key as a phrase in an analysed field (for example the `message` text). A wrong mode returns zero for every key (a `term` on an analysed field) or over-counts (a `phrase`). `key_match` does not need a `filter`. |

Caveat from the code: every built-in mapper reads the event time from the document's `@timestamp` (RFC 3339), whatever `time_field` is. `time_field` changes the query, not the mapping. A document without a parsable `@timestamp` stops the fetch with an error.

### What leaves the machine: `jb doctor` and the history probe

`jb doctor` lists, per source, what leaves the machine (the "Leaves" text): the search query and the API key, to the Kibana host. A source with `key_match` adds a line: when a `newkey` detector uses `history`, its candidate keys (the values of `key_field`, such as client addresses) are sent to this index, in the body of a count request, never in the URL. The index is one the detector already reads.

### Filter

Without a filter the source downloads every document in the window. On a busy ingress index that is tens of thousands of documents per ten minutes, and a day is millions. `filter` narrows the query on the server. Every clause must match (AND). It is a source key:

```yaml
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
    filter:
      - match_phrase: {field: message, value: "ExampleBrowser/9.1"}
```

| Clause | Meaning |
|---|---|
| `match_phrase: {field, value}` | The analysed text field contains the phrase. Use it for a raw log line. |
| `term: {field, value}` | The keyword field equals the value exactly. It does not match analysed text. |
| `any_of: [member, ...]` | At least one member matches (OR). Each member is a plain `match_phrase` or `term`; `any_of` does not nest. |

`any_of` is how "match any of these paths" is written. It is compiled to `{"bool": {"should": [members], "minimum_should_match": 1}}` and sits inside the same AND as the other clauses, so `jb hunt --search` still narrows every alternative:

```yaml
    filter:
      - term: {field: status, value: "200"}
      - any_of:
          - match_phrase: {field: path, value: /oauth/device/code}
          - match_phrase: {field: path, value: /oauth/token}
```

Rules, checked at load: exactly one of `match_phrase`, `term` or `any_of` per clause; `any_of` has 2 to 16 members, each exactly one of `match_phrase` or `term` (a member that is an `any_of` is an error); `field` is 1 to 128 characters of letters, digits and `_ @ . -`; `value` is 1 to 512 characters with no control or format character (newline, NUL, escape, bidirectional override, zero-width space); an empty list is an error. The bound on clauses counts entries of the `filter` list: at most 8, and an `any_of` is one entry however many members it has. `jb hunt --search` terms count against the same 8. Separately, a filter holds at most 64 match clauses in all (plain clauses and `any_of` members together), so eight `any_of` of 16 members cannot send a 128-clause query. Nothing else can be written here, deliberately: a case carries this file around, and it is data, not a query language. Every value is a JSON string in the request body and is never spliced into query text.

A filter makes an empty result ordinary (an `any_of` changes nothing about this: the probe is the window alone, with no filter): on a quiet day nothing matches. So that this cannot hide a dead source, a filtered fetch that matched nothing makes one more request, a count of the same window without the filter. If that count is above zero the index is alive and the empty result is clean (`Stats.IndexTotal` holds the count, and `jb hunt` prints it: `no match; index alive`). If it is zero too, the index is silent or the source points at the wrong index, and the fetch fails with `no records` as before. A filter is a prefilter, not a judgement: keep it a superset of what the detector matches (a phrase such as `Chrome/126.0.0.0`) and let the detector apply the exact rule.

### Two sources on one index

Two sources may read the same index with different filters, for example one for token paths and one for a user agent, if each has its own `name`:

```yaml
sources:
  - {type: kibana, name: device-paths, url: https://kibana.example.com, api_key_env: JB_KIBANA_API_KEY, index: logs-http-*, filter: [...]}
  - {type: kibana, name: curl-clients, url: https://kibana.example.com, api_key_env: JB_KIBANA_API_KEY, index: logs-http-*, filter: [...]}
```

Two sources that report the same name (two without `name` on one index, or an explicit name equal to another's) are an error at load: `sources[0] (kibana) and sources[1] (kibana) both report the name "kibana:logs-http-*"; give one a distinct name`. The names are not relaxed silently: the name is part of the run id, and a duplicate would make the second source replace the first's events.

Overlapping filters can return the same document to both sources. A run counts a document once. Each Kibana event carries the document's concrete index and `_id`; when two or more sources of one run read the same cluster URL, `jb hunt` and `jb activity` keep the first copy of each document and drop the others before they are saved. The drop is shown, not hidden: the source's `Duplicates` count (`duplicates` in the JSON, and `matched (N already returned by another source)` in the outcome column), and `events` counts kept documents only. Which of two overlapping sources keeps a shared document depends on which read it first, so its stored `source` can differ between runs; the number of distinct documents does not. A run with one source per cluster keeps no per-document memory. The same document fetched again by a later run is collapsed by the store as before (same source, time, kind and digest); two differently named sources on one index in different runs are two sources to the store.

### Ad-hoc search

`jb hunt --search TERM` adds one more clause to every source's filter for a single run, so an analyst can look for an address, a user agent, a username or a path without editing the config:

    jb hunt --case DIR --config config/hunt.yaml --search 198.51.100.7 --window 6h

The term becomes `{"match_phrase": {"<search_field>": "<TERM>"}}` ANDed with the configured filter (and with further `--search` terms). It is a JSON string in the request body and is never spliced into query text. `match_phrase` on an analysed text field matches the tokens in order, not a raw substring. `--search-field` overrides the field for the run; otherwise the source's `search_field`, otherwise `message`.

Rules, checked before any request is made (a violation is a usage error, exit 2, and the error does not echo the term): 1 to 4 terms; each 1 to 256 bytes of valid UTF-8; no control or format character (newline, NUL, escape, bidirectional override, zero-width space); not blank; no leading or trailing whitespace; and the configured filter plus the terms at most 8 clauses. Every source of the config must support a search, or the run is refused rather than searched in part.

A search that matches nothing runs the liveness probe above, so the two zeros differ: `no match; index alive` (the probe counted documents without the term: the term is absent, exit 0) and `index empty or nothing readable` or `unreachable` (the index gave no documents or could not be asked: nothing can be said about the term, exit 1). The count printed is the probe's own answer, never a total minus anything. The detectors read the stored evidence for the window, which includes events saved by earlier runs, so their findings are not about the matches alone.

From Go, set `Search` and `SearchField` in `jb.HuntOptions` (so also `CaseHuntOptions`). The same rules apply and a refusal is a `jb.UsageError` returned before any request is sent. `Result.Search` holds the terms, and `Result.SearchAbsent()` is true for the "term is absent" answer; `Result.Complete()` is false then, because the detectors had nothing to judge, so test `SearchAbsent` first.

### Past windows

`jb hunt --until TIME` and `jb activity --until TIME` hunt `[TIME - window, TIME)` and the same-length window before it, through the same sources, filters, scopes and detectors. The source gets the past bounds as `gte` and `lt` on the time field and pages by timestamp cursor as for any window; nothing in the request is relative to the present. Put a `filter` on the source before a backfill: without one a day is every document of the index (see [Filter](#filter)). The rules and the day-by-day loop are in [BACKFILL.md](../BACKFILL.md). `jb watch` has no `--until`.

[Back to the configuration index](../CONFIG.md)
