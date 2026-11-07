# RFC 0014: History probe for the newkey detector
Status: accepted
Scope: add an optional `history` block to the `newkey` detector that asks the sources, once per run, how many events carried each candidate key over a lookback before the window; add the optional source port that answers it.
Accepted: 2026-11-06 by the maintainer

## Build gate

Accepted with one condition: the cost measurement in open question 6 comes before any code. The measurement was taken on 2026-11-06 and is cheap (open question 6); the gate is lifted.

## Summary

`newkey` calls a key new when it has no event in the preceding window of the same length. On a one hour watcher window that flags every customer who was idle for the previous hour. A downstream rule needs "new" to mean "fewer than N events of any kind in the 7 days before", and a filtered source cannot supply that history: the store holds only what the filter matched.

This RFC adds `history: {lookback, min_events, max_candidates}` to `newkey`. For the keys that already meet `min_hits` on the sensitive paths (the candidates), jb sends each distinct index one request that counts every candidate over `[window.From - lookback, window.From)`, with the source's own filter removed. A key is *known* when its count reaches `min_events`. A candidate that is not known is a finding. A probe that fails, a candidate that was not probed, or an index that cannot show history makes the detector incomplete. It is never quiet.

How the key is matched is the source's setting, not the detector's: a Kibana source says which index field holds the key and how to match it.

## Motivation

A gateway rule set watches four attack paths (phone verification, profile switching, consent creation, IBAN resolution). Its third reason is "an address with 3 or more hits on those paths and fewer than 50 hits of any kind in the previous 7 days". The old, hand-written detector ran one count query per candidate and, on error, stayed quiet. In jb the nearest rule is `newkey`, and it cannot express this:

- The baseline is the preceding window. On a 1 h window, an address that was idle for an hour is "new".
- A 7 day baseline would need about a million events read per cycle (84,913 events for 24 h, measured on the downstream deployment).
- The source is filtered to six endpoint families, so the store cannot answer "hits of any kind". Only the source can count unfiltered.

Measured on seven days of hourly windows: at most 3 candidates per window, 95th percentile 2, median 0. The candidate set is tiny. The cost of an unfiltered query over 7 days of a whole index is not measured; see Open questions.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

An independent read of the first draft against the code found eight problems. Items 2 to 6 below are the changes it forced.

1. **The probe lives in the source, not the store.** A detector reads `core.EventReader`, which is the evidence store. The store holds filtered events and cannot count "any kind". Adding a method to `core.Source` would make every source type implement it, so the port is optional, as `core.Feed.Lookup` is a separate port for reputation. (`core.LivenessReporter` is not the pattern: it reports cached state from the last fetch and does no I/O. This port makes a network call.)
2. **The matching vocabulary stays in the source.** `key_field` is an event field the mapper derived. The field to match in the index is a raw field of that index, and two indices may differ. A Kibana source therefore carries `key_match: {field, mode}` next to its `filter`, and the core port is `CountKeys(ctx, keys, window)` with no Elasticsearch words in it. `mode` is `term` (exact value in a keyword field) or `phrase` (the key as a phrase in an analysed field) and has no default: a wrong mode returns zero for every key (a term on an analysed field) or over-counts (a phrase), so the operator must choose.
3. **One count per index, not per source.** The probe drops each source's filter. Two sources on the same cluster and index with different filters would return the same total, and a sum would double it. jb already groups sources by `core.DocScoped` for hunt's de-duplication. The probe groups by that scope (cluster and index), takes one count per group, and sums across groups. This answers the earlier question of sum or any.
4. **One request per group, all candidates together.** A request with a `filters` aggregation counts up to `max_candidates` keys at once. This removes serial probes, makes the cost one request per index, and removes a trap: with a serial probe cut at N keys in hit order, an attacker who makes N decoy addresses hit more than the real one keeps the real one from ever being probed. With one request, every candidate up to `max_candidates` is counted. If there are more candidates than `max_candidates`, the detector is incomplete and says how many were not judged; the cut is by hits descending then key ascending so the run is repeatable.
5. **History must prove it can see.** A typo in the field, a `term` on an analysed field, or an index that keeps less than `lookback` makes every count zero and every candidate "new" at full severity. Before trusting a zero, the probe asks the same index for the count of all events in the lookback with no key clause. If that is zero, the group cannot show history and the detector is incomplete. The `baseline_empty` severity step that `newkey` applies today is not available once the preceding scan is replaced, so this check stands in for it.
6. **A failed probe is incomplete, not quiet.** The hand-written detector answered "known" on error. That hides an attacker behind a slow Kibana. This is a deliberate difference. The findings already proven are kept (RFC 0012), the error is returned, and the cycle is INCOMPLETE.
7. **History replaces the preceding-window baseline for a candidate.** A key seen once an hour ago but fewer than `min_events` times in 7 days is still new. Keeping both would make the rule depend on two baselines and match neither case.
8. **The detector reaches the sources through one optional entry point.** `core.HistoryDetector` adds `DetectWithHistory(ctx, cur, prev, w, h KeyHistory)`, and `internal/app` prefers it by type assertion. The alternative is a new argument to `Detect` for every detector, which burdens five detectors for one user. Whether to accept the second path is a maintainer decision (Open questions).

## The design

Everything here is proposed.

### Detector configuration

```yaml
detectors:
  - type: newkey
    key_field: client_ip
    path_field: path
    sensitive_paths: ["/verify-phone-and-code", "/customers/switch-profile"]
    min_hits: 3
    history:
      lookback: 168h
      min_events: 50
      max_candidates: 50
```

| Key | Type | Rule |
|---|---|---|
| `lookback` | duration | Required, at most 31 days. It MUST be longer than the window, which is known only at run time, so `Detect` checks it and returns a usage error. |
| `min_events` | integer | Required, 1 or more. A key with this many events in the lookback is known. |
| `max_candidates` | integer | Default 50, at most 100. |

An unknown key, a missing required key or a value out of range is an error at load. `jb case check` validates the block and builds the detector with no network and no environment. The lookback interval is `[window.From - lookback, window.From)`. The window's own events never count toward being known. The previous cycle's attack events do count, so a persistent attacker becomes known after enough cycles. `watch` suppresses repeat alerts by tag, which hides this, but `hunt --until` replays can differ from live behaviour. The docs say so.

### Source configuration

`history` is accepted only when every source the detector reads (its `scopes`, or all sources) is a Kibana source with `key_match`:

```yaml
sources:
  - type: kibana
    # ...
    key_match:
      field: message
      mode: phrase     # term | phrase; required
```

The config check is its own, by concrete source type, in the way `checkQuietNeedsFilters` is. It does not require a filter. Mode `term` REQUIRES a keyword field; `phrase` MAY over-count (see Drawbacks). A source type without the port (plugin or other) is refused at load.

### Core ports (`internal/core`)

```go
// KeyCounter is an optional port of a Source.
type KeyCounter interface {
    CountKeys(ctx context.Context, keys []string, w Window) (map[string]int64, error)
    // CountAll reports how many events of any kind the source's index holds in w.
    CountAll(ctx context.Context, w Window) (int64, error)
}

// KeyHistory counts keys across the distinct indices a detector reads.
type KeyHistory interface {
    Counts(ctx context.Context, keys []string, w Window) (map[string]int64, error)
}

// HistoryDetector is a Detector that can use a KeyHistory.
type HistoryDetector interface {
    Detector
    DetectWithHistory(ctx context.Context, cur, prev EventReader, w Window, h KeyHistory) ([]Finding, error)
}
```

`Detect` on a `newkey` detector configured with `history`, called without a history, returns an error that names the missing history. It never falls back to the preceding window.

### Kibana source

`CountKeys` sends one search request with `size: 0`, a range filter on the time field, and a `filters` aggregation with one named bucket per key (`match_phrase` or `term` on `key_match.field`). The source's own `filter` is not applied. The key is a JSON string value in the request body, never part of a query string, so it cannot add query syntax. `CountAll` sends the same range with no key clause. Keys outside a strict character set (letters, digits and `.:-_@`, at most 256 bytes) are refused before any request. The client does not echo bodies in errors; the new paths MUST NOT include a key in any error or log. A non-200 answer, a malformed answer or a timeout is an error. `describe` (the "Leaves" text that says what leaves the machine) gains a line: with `history`, candidate keys are sent to this index.

### Detector behaviour

1. Count the window as today. A key is a *candidate* when it meets `min_hits` on the sensitive paths and is not in `ignore_keys`. When `user_agent_matches` is set, candidates count only matching hits, while history counts every agent. That is intended: "hits of any kind".
2. Sort candidates by hits descending then key ascending. Take the first `max_candidates`. If more existed, the rest are not judged.
3. For each distinct index, `CountAll` over the lookback. Zero means that index cannot show history: the detector is incomplete.
4. `h.Counts` over the lookback. The key is known when the count is at least `min_events`.
5. A candidate that is not known is a finding with the severity `newkey` already gives. Findings stay sorted by key, as today. `Baseline` is the lookback interval. `Detail` gains `history_lookback`, `history_count`, `history_min_events`, and `history_mode`.
6. If any step fails, the detector keeps the findings already proven (RFC 0012) and returns an error that names the number of candidates not judged and the first cause.
7. With `hash_keys`, the finding shows the hash. The probe uses the plain key in memory. The plain key never appears in a finding, a log line or an error.

### Application

`internal/app` builds the `KeyHistory` for each detector from the sources that detector reads (its scopes), skipping none: a source that failed to build or was disabled is not in the set, and a detector whose scope has no source with the port is refused at load. The same code path serves `hunt`, `activity` and `watch`, which share the detector run. Detectors run concurrently in hunt; a `KeyHistory` is safe for concurrent use and each detector gets its own.

## Non-goals

- A severity setting on `newkey`. The downstream rule used `critical`; `newkey` severities are unchanged here.
- History for other detectors.
- A history that reads the evidence store.
- Caching counts across cycles.
- A probe for sources other than Kibana. The port allows it; none is built.
- Per-component accounting of an incomplete cycle.

## Drawbacks

- Detectors gain a second optional entry point, and a source gains a second optional port.
- `phrase` can over-count and hide a new key: an IPv6 address splits into several tokens, and an address can appear as a hop in a forwarded-for chain or in the body of the text. Over-counting is the quiet direction. The finding records the mode, and `term` is available on a keyword field.
- The probe sends candidate keys to the source. For a personal field that is personal data, sent to an index the detector already reads, in a request body.
- An unfiltered range over a long lookback can be expensive on a large index. The cost is one request per distinct index per run, plus the liveness count.
- History replaces the preceding-window baseline. A user who wants both runs two detectors.
- An attacker who makes a key look known (sends `min_events` harmless requests from the address first) avoids the finding. This is inherent in a count rule.

## Alternatives and prior art

- **Read 7 days into the store each cycle.** Rejected by the measurement above, and the store cannot count unfiltered hits in a filtered source.
- **Widen the watcher window to 7 days.** The hunt would read 7 days every cycle and the sensitive-path counts would blur.
- **A `history-newkey` detector type.** The judgement is the same; only the baseline differs. A second type would duplicate every key the first has.
- **Put the count on `core.Source`.** Every source would implement a method only one can answer.
- **Match field and mode on the detector.** Rejected: they are index vocabulary and differ by index.
- **A serial probe per key.** Rejected: a decoy can push the real key out of the first N, and the latency is `N` round trips.
- **Prior art:** Elasticsearch's search with `size: 0` and a `filters` aggregation, one bucket per key; the same request shape as the liveness probe in `internal/adapters/kibana/source.go`, which also counts without the source filter. The hand-written detector's stay-quiet-on-error behaviour is replaced on purpose.

## Compatibility

`history`, `key_match` and the ports are new. A config without them behaves as before. There is no stored-data change: findings gain `Detail` keys. Nothing is promised to older readers (RFC 0004 is withdrawn; this is pre-1.0).

## Security considerations

- The key goes only to the index the detector already reads, inside a JSON body, never a URL. It is not logged and not echoed in an error. A test forces each error path and checks the key is absent.
- A key from untrusted traffic is the query input. It is a value in a `term` or `match_phrase` clause or a bucket name, never query-string syntax, and a strict character set and length cap are applied first. An attacker cannot change the query shape.
- The probe is read-only and uses the credential of the source from the environment. `docs/POLICY.md` (passive-only recon of third parties) is not affected: this is the operator's own index, and the policy text gets one line saying so.
- The request count is bounded: one search per distinct index plus one liveness count, regardless of how many addresses an attacker uses. The aggregation is bounded by `max_candidates`.
- The decoy attack is handled by design 4: candidates up to `max_candidates` are all counted, and exceeding it is incomplete, never quiet.

## Open questions

Decided on 2026-11-06 by the maintainer, in a grilling session:

1. **Worth owning in jb.** Yes. A filtered source cannot count what its filter dropped, so "new against long history" is not expressible today for any deployment of this kind. The cost is one optional port, one Kibana implementation and an opt-in block.
2. **Severity.** `newkey` gains `min_severity` and `note` with the design of RFC 0011, as a separate small change shipped with this one. This RFC adds no severity setting.
3. **The second entry point.** Keep `HistoryDetector` with a type assertion in `internal/app`. A test forces that a `newkey` with `history` never runs through plain `Detect`.
4. **`phrase` matching.** Allowed. `mode` has no default, the finding records it, and the docs state that `phrase` errs toward quiet. An index with a keyword field should use `term`.
5. **Baseline.** History replaces the preceding-window baseline. A user who wants both runs two detectors.

Still open:

6. **Cost.** Answered on 2026-11-06 by the downstream operator, on a production index of about 14.2 million documents a day across 50 shards: one `filters` aggregation of 2, 8 and 10 phrase buckets over 1 day and 7 days took 219 to 659 ms on the cluster (under 0.9 s wall), and 7 days cost between about the same and 1.9 times what 1 day cost. All requests answered from every shard. Caveats: ordinary customer addresses, not a heavy hitter; one run per shape, off peak; the request used `track_total_hits: true` and a `size: 0` search. The build gate is lifted. Remaining check before the default is final: one run with a heavy-hitter address.
7. **Keyword field.** Answered: the index has no separate field for the client address. It is inside the analysed `message` text, and the `.keyword` subfield is not usable (the value exceeds the keyword limit), so only `mode: phrase` on `message` works there. A phrase also matches the same address in other headers and the body, so a count can only be too high, which makes a key look known (quiet) and never creates a false alarm. Accepted for this index; `mode: term` stays for indices with a keyword field.
8. **The caps.** `max_candidates` 50 is chosen from one deployment (median 0, 95th percentile 2, maximum 3 candidates per hourly window). On the measured cost the cap is a result-size and fairness limit, not a cost limit. Decides: the maintainer, after a week on real data.

## Conformance

Tests to write first and see fail:

- `internal/adapters/detectors/newkey`: a fake `KeyHistory`. Known key gives no finding; a count below `min_events` gives a finding with the history `Detail`; a probe error keeps earlier findings and returns an error naming the number not judged; more candidates than `max_candidates` is incomplete and judges the highest-hit keys; decoys: with `max_candidates` decoys that out-hit the real key, the real key is counted when it fits and the run is incomplete when it does not; every count zero with a zero `CountAll` is incomplete; a key seen in the preceding window but under `min_events` is still a finding; `hash_keys` never shows the plain key in a finding or an error; `Detect` without history returns the missing-history error; lookback not longer than the window is a usage error; findings stay sorted by key; `user_agent_matches` candidates versus all-agent history; `ignore_keys`.
- `internal/adapters/kibana`: a fake index checks the request carries the lookback range, a `filters` aggregation with the right clause for `term` and for `phrase`, no source filter, keys as JSON values; keys with query syntax characters are refused; a key over 256 bytes is refused; a non-200, a malformed answer and a timeout are errors; no key in any error; IPv6 and forwarded-for strings follow the documented over-count; a mapper-derived key field differs from the raw field.
- `internal/config`: `history` with a non-Kibana source, or a Kibana source without `key_match`, is refused at load; each out-of-range value is refused; `mode` has no default; `jb case check` builds a config with `history` with no network and no environment.
- `internal/app`: two sources on the same cluster and index are counted once; two indices are summed; a disabled source is absent; the same history path runs for `hunt`, `activity` and `watch`; concurrent detectors each get a history; `hunt --until` and a watch window give the same candidates.
- End to end through `jb.Hunt` against a fake Kibana: synthetic traffic that reproduces the downstream rule (3 or more hits on the sensitive paths, with 49 and with 50 earlier hits of any kind) gives a finding and no finding. The data is synthetic. There is no recorded firing of this reason on real data.
- `internal/archtest` stays green: `core` has no new imports and the detector imports no adapter. A new assertion fails if a detector package imports an adapter.
