# RFC 0014: History probe for the newkey detector
Status: draft
Scope: add an optional `history` block to the `newkey` detector that asks a source, for each candidate key, how many events carried that key over a lookback before the window; add the optional source port that answers it.

## Summary

`newkey` calls a key new when it has no event in the preceding window of the same length. On a one hour watcher window that flags every customer who was idle for the previous hour. A downstream rule needs "new" to mean "fewer than N events of any kind in the 7 days before", and a filtered source cannot supply that history: the store holds only what the filter matched.

This RFC adds `history: {lookback, min_events, max_candidates, match_field, match}` to `newkey`. For each key that already meets `min_hits` on the sensitive paths, jb asks every source the detector reads for a count of events matching that key in `[window.From - lookback, window.From)`. The key is *known* when the summed count reaches `min_events`. A candidate that is not known is a finding. A probe that fails, times out or is skipped makes the detector incomplete. It is never quiet.

## Motivation

A gateway rule set watches four attack paths (phone verification, profile switching, consent creation, IBAN resolution). Its third reason is "an address with 3 or more hits on those paths and fewer than 50 hits of any kind in the previous 7 days". The old, hand-written detector ran one count query per candidate and, on error, stayed quiet. In jb the nearest rule is `newkey`, and it cannot express this:

- The baseline is the preceding window. On a 1 h window, an address that was idle for an hour is "new".
- A 7 day baseline would need about a million events read per cycle (84,913 events for 24 h, measured on the downstream deployment).
- The source is filtered to six endpoint families, so the store cannot answer "hits of any kind". Only the source can count unfiltered.

Measured on seven days of real hourly windows: at most 3 candidates per window, 95th percentile 2, median 0. The probe is cheap because the candidate set is tiny.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

1. **The probe lives in the source, not the store.** A detector reads `core.EventReader`, which is the evidence store. The store holds filtered events, so it cannot count "any kind". Adding a count method to `core.Source` would force every source type (nginx, plugin, kibana, future ones) to implement it. A separate optional port follows the pattern of `core.LivenessReporter`: a source that can answer implements it, the others do not.
2. **The detector does not import an adapter.** `core.Detector.Detect` keeps its signature. A detector that wants history also implements `core.HistoryDetector`, and `internal/app` calls that method with a `core.KeyHistory` built from the sources. `internal/core` stays standard library only; the arch rules hold.
3. **Refuse at load what cannot be answered.** `history` needs every source the detector reads to implement the port. `internal/config` checks this when it parses, as it does for `empty_is_quiet` (`checkQuietNeedsFilters`). A config that could never answer fails `jb case check`, not mid-incident.
4. **History replaces the preceding-window baseline for a candidate.** With `history`, the preceding-window comparison is not used: a key seen once an hour ago but fewer than `min_events` times in 7 days is still new. The docs and the finding say so. Keeping both would make the rule depend on two baselines and match neither of the cases above.
5. **A failed probe is incomplete, not quiet.** The hand-written detector answered "known" on error. That hides an attacker behind a slow Kibana. This is a deliberate difference. The findings already proven are kept (RFC 0012), the error is returned, and the cycle is INCOMPLETE.
6. **Bound the work.** At most `max_candidates` keys are probed per run, in order of hits descending then key ascending, so a run is deterministic. More candidates than that means the rest are *not judged* and the detector is incomplete. Each probe has its own timeout. Probes run one at a time, so the request count is at most `max_candidates` times the number of sources.
7. **Say how the key is matched.** The client address in the downstream index sits in the request text, not in a keyword field. `match_field` names the field to match and `match` is `term` (exact value in a keyword field) or `phrase` (the key as a phrase in an analysed text field). `phrase` can match the key elsewhere in the text and so over-count. Over-counting makes a key look known, which is the quiet direction. The RFC accepts this only for `phrase`, records the mode in the finding, and recommends `term` where the index has such a field.

## The design

Everything here is proposed.

### Configuration

New block on a `newkey` detector:

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
      max_candidates: 10
      match_field: message
      match: phrase
      probe_timeout: 10s
```

| Key | Type | Rule |
|---|---|---|
| `lookback` | duration | Required. More than the window and at most 31 days. |
| `min_events` | integer | Required, 1 or more. A key with this many events (all sources summed) in the lookback is known. |
| `max_candidates` | integer | Default 10, at most 100. |
| `match_field` | string | Required. The field the source matches the key against. |
| `match` | string | `term` or `phrase`. Default `term`. |
| `probe_timeout` | duration | Default 10s, at most 60s. |

An unknown key, a missing required key or a value out of range is an error at load. `history` with `empty_is_quiet` is allowed. The lookback interval is `[window.From - lookback, window.From)`: the time before the window, so the window's own events never count toward being known.

### Core ports (`internal/core`)

```go
// KeyCount is one question to a source: how many events carried Key in Field.
type KeyCount struct {
    Field string
    Mode  string // "term" or "phrase"
    Key   string
}

// KeyCounter is an optional port of a Source.
type KeyCounter interface {
    CountKey(ctx context.Context, q KeyCount, w Window) (int64, error)
}

// KeyHistory counts a key across every source the detector reads.
type KeyHistory interface {
    Count(ctx context.Context, q KeyCount, w Window) (int64, error)
}

// HistoryDetector is a Detector that can use a KeyHistory.
type HistoryDetector interface {
    Detector
    DetectWithHistory(ctx context.Context, cur, prev EventReader, w Window, h KeyHistory) ([]Finding, error)
}
```

`Detect` on a `newkey` detector configured with `history` and called without a history returns an error that names the missing history. It never falls back to the preceding window.

### Kibana source

`CountKey` sends one count request with the window filter, the source's own filter removed, and a `match_phrase` or `term` clause on `Field`. The key is a JSON string value in the request body, never part of a query string, so it cannot add query syntax. A key longer than 256 bytes is refused with an error. The request and the key MUST NOT be logged; the existing redaction rules apply. A non-200 answer, a malformed answer or a timeout is an error.

"Without the source's own filter" is the point of the probe, and it is the only way the probe differs from `Fetch`. The `term`/`phrase` clause uses the same credentials and the same host as `Fetch`.

### Detector behaviour

1. Count the window as today. A key is a *candidate* when it meets `min_hits` on the sensitive paths and is not ignored.
2. Sort candidates by hits descending then key ascending. Take the first `max_candidates`.
3. For each, `h.Count` over the lookback. The key is known when the count is at least `min_events`.
4. A candidate that is not known is a finding, with the severity `newkey` already gives. `Detail` gains `history_lookback`, `history_count`, `history_min_events`, `history_match` and `history_match_field`.
5. If a probe returns an error, the candidate is *not judged*. The detector keeps the findings it already proved and returns an error that names the number not judged and the first error.
6. If there were more candidates than `max_candidates`, the detector returns an error that names how many were not probed.
7. With `hash_keys`, the finding shows the hash. The probe uses the plain key in memory. The plain key never appears in a finding, a log line or an error. An error from a probe is scrubbed with the same function that scrubs other source errors.

### Application

`internal/app` builds a `KeyHistory` over the hunt's sources: it calls `CountKey` on each source that implements it and sums the results. A source in the hunt that does not implement the port is a bug (the config check refused it), so `Count` returns an error naming that source. Sources that overlap (the same document under two labels) double count and make a key look known; this is the quiet direction and `jb db usage` already reports overlapping labels.

## Open questions

1. **Severity.** The downstream rule gave this reason `critical`. `newkey` has no severity setting. Should `history` carry its own severity, or should a general floor like RFC 0011's `min_severity` come to `newkey`? Decides: the maintainer.
2. **Sum or any.** Counts are summed across sources. Is "known when any one source reaches `min_events`" safer when sources overlap? Decides: the author, with a test on overlapping labels.
3. **`phrase` over-count.** Is `phrase` acceptable at all, given it errs toward quiet, or should `match` be `term` only and the downstream index gain a keyword field? Decides: the maintainer, after checking what the real index offers.
4. **The caps.** `max_candidates` 10 and `probe_timeout` 10s are chosen from one deployment (median 0, 95th percentile 2, maximum 3 candidates per hourly window). Decides: the maintainer, after a week on real data.

## Non-goals

- A severity setting on `newkey`. The downstream rule used `critical` for this reason; `newkey` severities are unchanged here. Raising them is a separate change, and RFC 0011's floor is for `behaviour`.
- History for other detectors.
- A history that reads the evidence store. The store cannot count what the filter did not fetch.
- Catch-up or caching of counts across cycles. The candidate set is small and a cache would be a second place for a stale "known".
- A probe for sources other than Kibana. The port allows it; none is built.
- Per-component accounting of an incomplete cycle.

## Drawbacks

- Detectors gain a second optional entry point, and a source gains a second optional port. That is more surface to test.
- `phrase` can over-count and hide a new key. The finding records the mode, and `term` is available, but the risk is real and is on the quiet side.
- The probe sends a candidate key to the source. For `hash_keys` fields that is personal data, sent to a source the detector already reads, but it is still a new request that carries the value.
- A cycle with a slow source takes up to `max_candidates` times `probe_timeout` longer.
- `history` replaces the preceding-window baseline for the candidate. A user who wants both must run two detectors.

## Alternatives and prior art

- **Read 7 days into the store each cycle.** Rejected by the measurement above, and the store cannot count unfiltered hits in a filtered source.
- **Widen the watcher window to 7 days.** The hunt would read 7 days every cycle and the sensitive-path counts would blur.
- **A `history-newkey` detector type.** The judgement is the same (is this key new); only the baseline differs. A second type would duplicate every key the first one has.
- **Put the count on `core.Source`.** Every source would implement a method only one can answer.
- **Ask in the detector through a callback in config.** That is behaviour in configuration, which jb avoids.
- **Prior art:** Elasticsearch's count API with a `bool` filter, which Kibana's source already uses for its liveness probe; the stay-quiet-on-error behaviour of the hand-written detector, which this RFC replaces on purpose.

## Compatibility

`history` is new. A config without it behaves as before. An older jb refuses the unknown key at load. No stored data changes: findings gain `Detail` keys only. The Go package gains `core` ports that are internal; `jb.Hunt` results are unchanged in shape.

## Security considerations

- The key is sent only to the source the detector already reads, inside a JSON body, never in a URL. It is not logged and not echoed in an error.
- A key from untrusted traffic is the query input. It is a value in a `term` or `match_phrase` clause, never query-string syntax, and it is capped at 256 bytes. An attacker cannot change the query shape.
- The probe is read-only (a count request) and uses the credential of the source from the environment. Passive-only policy is not affected: it is the operator's own index.
- The number of requests is bounded by `max_candidates`, `probe_timeout` and the number of sources, so an attacker who sends traffic from many addresses cannot make a cycle issue an unbounded number of probes.
- An attacker who can make a key look known (by sending 50 harmless requests from the address first) avoids the finding. This is inherent in a count rule; `min_events` is the operator's choice, and the finding records the count.

## Conformance

Tests to write first and see fail:

- `internal/adapters/detectors/newkey`: a fake `KeyHistory`. Known key (count at least `min_events`) gives no finding; count below gives a finding with the history `Detail`; a probe error keeps earlier findings and returns an error; more candidates than `max_candidates` returns an error naming the number not probed and probes the highest-hit keys first; a key seen in the preceding window but under `min_events` is still a finding; `hash_keys` never shows the plain key in a finding or an error; `Detect` without history returns the missing-history error.
- `internal/adapters/kibana`: a fake index checks that the probe request carries the lookback range, the field clause for `term` and for `phrase`, no source filter, the key as a JSON value; a key with query syntax characters does not change the clause shape; a key over 256 bytes is refused; a non-200 and a malformed answer are errors; the key does not appear in an error.
- `internal/config`: `history` with a non-Kibana source is refused at load; each out-of-range value is refused; an unknown key is refused; `jb case check` builds a config with `history` without a network call.
- `internal/app`: `KeyHistory` sums sources; a source without the port is an error.
- End to end through `jb.Hunt` against a fake Kibana: synthetic traffic that reproduces the downstream rule (3 or more hits on the sensitive paths, with 49 and with 50 earlier hits of any kind) gives a finding and no finding. The test data is synthetic. There is no recorded firing of this reason on real data.
- `internal/archtest` stays green: `core` has no new imports and the detector imports no adapter.
