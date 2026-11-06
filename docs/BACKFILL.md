# Hunting a past window (backfill)

`jb hunt --until TIME` and `jb activity --until TIME` ask the same question as always, of a window that ended in the past. The window is `[TIME - window, TIME)` and the baseline is the window of the same length immediately before it (`Window.Previous`), exactly as for a live hunt, anchored at TIME instead of now. Use it to fill in days you did not hunt, to re-check a day with a changed detector, and to replay known incident windows as a regression check.

`jb watch` has no `--until`: a watch cycle always ends now, because what it alerts on is what is happening. A past window is a one-off question, so it is a `hunt` or an `activity`.

## The flag

```sh
jb hunt --case DIR --config config/hunt-filtered.yaml --window 24h --until 2026-10-01T00:00:00Z
jb activity --case DIR --until 2026-10-01T02:00:00+02:00      # same instant, written with an offset
```

| Rule | Why |
|---|---|
| TIME is RFC 3339 **with a zone**: `Z` or `+02:00`. | `2026-10-01T00:00:00` means different instants on different machines. A window that silently moves by the zone offset shows the wrong hours as quiet. Refused with exit 2. |
| Whole seconds only. | The window edges are not rounded. |
| TIME after now is refused (exit 2). | There is nothing to fetch there yet. TIME equal to now is accepted. |
| TIME older than the window is fine. | A window ending in 2020 is a window. It may find no records, and then it is INCOMPLETE like any empty window. |
| `--window` is at most 31d with `--until`. | A backfill fetches the window and the baseline in one run. Loop over days instead (below). |
| Not on `watch`. | See above. |

Everything else is unchanged: the INCOMPLETE rule (exit 1, never printed as quiet), the liveness probe (`no match; index alive`), `empty_is_quiet`, `sources:` scopes, filters and `--search`.

## What the detectors read

Detectors judge the **stored** evidence for the two windows (`Events(ctx, Window)`), not what the run just fetched. For a past window that means exactly the stored events whose timestamps fall in `[from, to)` of the window and of the baseline, including events saved by earlier runs, and nothing after the window. No detector, and neither command, reads the clock once the window is chosen: a hunt of the same absolute window gives identical findings whether it was named by `--until` or by running at that moment (`TestUntilSeesExactlyTheWindowWhateverTheStoreHolds`).

Two consequences for reading a backfill:

- If an earlier run stored events after the window, they are in the store and are still not read.
- If the store lacks part of the baseline (a day you never fetched), the source fetch for this run fills it: a hunt always fetches the window **and** its baseline.

## Run ids and what `jb intel` reads

| Command | Live run id | Past run id |
|---|---|---|
| `hunt` | `hunt-<end>` | `hunt-until-<end>-w<window seconds>` |
| `hunt --search` | `search-<end>` | `search-until-<end>-w<window seconds>` |
| `activity` | `activity-<end>` | `activity-until-<end>-w<window seconds>` |

`<end>` is `20061002T150405Z`, the window's end in UTC. The events of each source are stored under `<run>/<source>`.

- A past run cannot collide with a live run started in the same second, and the name says which window it covers.
- The window length is in the name because two windows that end together but differ in length are different evidence and must not replace each other.
- The same window hunted again is the same run id. The store replaces that run, so a repeated backfill does not pile up.
- `watch-` is reserved for retention; a past run never starts with it, so `watch --keep` never deletes a backfill.
- `jb intel` with no addresses, and any other "latest run" lookup, takes the run with the newest **creation** time (`created_at`), as for every run. A backfill you just stored is therefore the latest run, and `jb intel` says which run it read (`latest stored run hunt-until-...`). Saving a run again keeps its creation time, so repeating an *old* backfill does not make it the latest again. If you want `jb intel` to read the live hunt, pass the addresses, or run the live hunt after the backfill. `TestLatestRunIndicatorsOrdersABackfillByWhenItWasStored` pins this.

## No double counting

The store's identity for an event is `(source, ts, kind, doc_sha256)` plus its occurrence number within its run (`internal/adapters/duckdb`, `Events`). The same event fetched by two runs, by a repeated backfill, by a live hunt over the same window or by an overlapping window, is read once; two identical lines inside one fetch are two events. This is the existing rule and it needed no change for `--until`. `TestUntilRepeatedBackfillDoesNotDoubleCount` hunts one window several times, by both names, and checks the findings and the activity counts do not move.

### Name your sources before you backfill

The source **label** is part of the identity above. A source with no `name:` stores under `kibana:<index>`; the same documents stored later under an explicit `name:` are a second set, and a detector that reads both counts each document twice (77 documents read as 154 in the case that found this). So give every source its `name:` **before** the first backfill, and do not rename it afterwards. If it has happened, `jb hunt`, `activity`, `watch` and `doctor` warn and print the fix; `jb db rename-source --case DIR OLD NEW --merge` is a dry run that shows the counts, and `--apply` relabels the stored history (docs/CONFIG.md, [Source labels and double counting](CONFIG.md#source-labels-and-double-counting)). A backfill hunts a past window in a store a live `jb watch` may be writing: the open waits for the writer up to 15 s (`JB_DB_LOCK_WAIT`) instead of failing.

## Day by day

A day of a busy index is millions of documents. Backfill through a config whose source has a server-side `filter` (docs/CONFIG.md, [Filter](CONFIG.md#filter)), narrowed to what the detectors need, and keep it a superset of what they match:

```yaml
# config/hunt-filtered.yaml (example.com, made-up values)
sources:
  - type: kibana
    url: https://kibana.example.com
    api_key_env: JB_KIBANA_API_KEY
    index: logs-http-*
    filter:
      - any_of:
          - match_phrase: {field: path, value: /login}
          - match_phrase: {field: path, value: /token}
```

`empty_is_quiet: true` on a detector reads a day with nothing to judge as quiet, which is only accepted when every source it reads is filtered, and the liveness probe still fails a dead index.

`examples/backfill/backfill-days.sh` loops one UTC day at a time:

```sh
examples/backfill/backfill-days.sh ./my-case config/hunt-filtered.yaml 2026-10-01 2026-10-07
```

Each iteration is `jb hunt --window 24h --until <midnight ending that day> --output json`, and prints one line per day: `complete`, the number of findings and their tags. A day that ends INCOMPLETE (exit 1) is listed at the end and the script exits 1; a usage error (exit 2) stops the loop. Re-running the same range is safe (see above).

Why days: the cost of a hunt is the window plus its baseline, a day is a size the source pages through comfortably (1000 documents a page by default), and a day that fails is a day you re-run, not a week.

## Prune after a backfill

Every backfill hunt stores its window and its baseline under its own run id, and the identity rule collapses repeated documents when the store is **read**, not when it is written. Overlapping windows, a retried day or a replay therefore store the same documents again, and a loop over many days grows the file several times faster than the distinct document count (found live: a 1.7 GB store, mostly `activity-*`, `hunt-*` and `hunt-until-*` runs that nothing ever pruned; only `jb watch` retention prunes, and only its own `watch-` runs). Follow a backfill loop with a prune once you have read what you needed:

```sh
jb db usage --case DIR                                                    # what is big
jb db prune --case DIR --kind hunt-until,activity-until --older-than 1d   # dry run
jb db prune --case DIR --kind hunt-until,activity-until --older-than 1d --apply
```

Findings stay by default (they are the conclusions); the newest run of each kind is always kept. The file only shrinks after `jb db compact` and a swap (docs/CONFIG.md, [Store maintenance](CONFIG.md#store-maintenance)).

## Replaying known windows as a regression check

When a detector changes, replaying the windows of past incidents shows whether it still sees them and still stays quiet on the control days. Record **only** what you expect, never the events:

```json
[
  {"name": "example-spray-week-1", "until": "2026-09-15T00:00:00Z", "window": "24h",
   "tags": ["authspike:203.0.113.7"], "findings": 1},
  {"name": "example-quiet-control", "until": "2026-09-16T00:00:00Z", "window": "24h",
   "tags": [], "findings": 0}
]
```

```sh
examples/backfill/replay-windows.sh ./my-case config/hunt-filtered.yaml expected.json
```

The script fails a window when the tags differ from the recorded ones in either direction, when the count differs, or when the replay was INCOMPLETE (an unread window proves nothing either way). The expected file is a list of names, times, tags and counts: no event, no log line and no address beyond the tag the detector itself names, so it can live in the repo. The events stay in the evidence store, which is outside git (`jb case check` refuses a case whose evidence is not ignored).

A replay needs the source to still hold those days. If retention has dropped them the window is empty, the hunt says `no records`, and the check fails rather than passing a missing window.

## Reading the output

```
run       hunt-until-20261001T000000Z-w86400s
until     2026-10-01T00:00:00Z (historical window; not relative to now)
window    2026-09-30T00:00:00Z to 2026-10-01T00:00:00Z
baseline  2026-09-29T00:00:00Z to 2026-09-30T00:00:00Z
```

- `until` is printed only for a past window. JSON carries `"until"` the same way, beside `window` and `baseline` (absolute times, UTC); a live hunt has no `until` key. A finding's own `window` and `baseline` are absolute as well.
- `activity` ends with its verdict line, which adds `[historical, --until TIME]` after the window. `ACTIVE` here means the actor was active **in that window**, not now.
- The counts printed are the ones fetched and judged. `no match; index alive` on a filtered source means the day had no matching document and the index was alive; `index empty or nothing readable` means nothing can be said, and the hunt is INCOMPLETE.
- A quiet backfilled day is only as good as its baseline: `baseline_empty` in a finding's detail, or a lowered severity, means the day before had nothing to compare with.
