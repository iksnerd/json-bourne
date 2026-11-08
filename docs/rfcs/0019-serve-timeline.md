# RFC 0019: Timeline page for `jb serve`
Status: implemented
Scope: one new read-only page, `/timeline`, that shows findings and watch cycles on one time axis and marks the spans where a watcher left no cycle for longer than three of its intervals.

Accepted: 2026-11-07 by the maintainer

## Summary

`jb serve` gets one new page, `GET /timeline`. It lists, newest first, the findings saved in the evidence store and the cycles that each watcher of the case wrote to its `watch*.log`, on one page. Where a watcher has no cycle line for more than three of its intervals, the page shows a row that says so. The row states an absence of evidence. It does not say the watcher was down, and it does not say it was healthy.

The page needs one new read port (`core.WatchHistoryReader`) and one new store method (`FindingsBetween`). It adds no file, no format and no config key.

## Motivation

The wrapper project that runs several named watchers on one case reads findings and watch cycles from a separate CLI today. The analyst's workflow is: something happened at a time T; what did the watchers see around T, and was every watcher actually cycling then? Today that takes the Findings page (latest 200 rows, no cycle information), the Watch page (see below), and a manual read of `watch.NAME.log` for each watcher.

The requester asks for, on one page:

- Findings: time, detector, severity, subject, run id.
- Watch cycles: time, watcher name, verdict (`QUIET`, `FINDINGS`, `INCOMPLETE`, `FAILED`), the gap span when one was reported, duration.
- A gap marker where no cycle exists for longer than three of the watcher's intervals. In their words: "the one thing we cannot see anywhere is a watcher that did not run at all".

### What `jb serve` already shows

Read from `internal/adapters/web/web.go` (routes) and `views.go` (handlers):

| Page | What it shows | What it does not |
|---|---|---|
| `/` (`overview`) | Store counts, up to 100 run groups with event and finding counts | No time axis, no cycles |
| `/run?id=` (`run`) | One run group: event summary, its findings, 50 recent events | One run only |
| `/findings` (`findings`) | The latest 200 findings by run time (`LatestFindings`), text and severity filter | No cycles, no window, no gaps. The cut is shown, the time order is by run only |
| `/watch` (`watch`) | The last 100 lines of one `watch.log`, the verdict and age of its last `CYCLE` line, the dedupe memory | The unnamed watcher only (see below). No history, no gaps |
| `/estate*`, `/reputation` | Unrelated | |

Verified: `jb/dashboard.go` wires `Log` and `State` to `watch.log` and `watch-state.json` only (`watchrun.LogFile`, `watchrun.StateFile`, with no watcher name). A named watcher writes `watch.NAME.log`, so the Watch page does not show it. This is the largest gap for the requester, who runs named watchers.

What is new in this RFC, and only this:

1. Findings and cycles merged in time order.
2. Cycles of every watcher, named or not.
3. The "no cycle recorded" row.
4. A time window, not "the latest N".

What this RFC does not duplicate: the run page, the finding detail, the dedupe memory, the raw log tail. The timeline links to the run page for every run id.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

"Cycle line" is the line `jb watch` appends to `watch[.NAME].log` at the end of each cycle (`app.cycleLine`, delivered with kind `cycle`). "Interval" is the watcher's `--every`. "Marker" is the row that reports a span with no cycle line.

## How this design was made

**Where the cycles live.** Verified in code, not assumed. A cycle writes to four places:

- `watch[.NAME].log`: one cycle line per cycle, plus one `ALERT` line per alert (`internal/app/watch.go`, `watchCycle`; `internal/adapters/alertlog`). The log is append-only. I found no rotation or truncation in `alertlog` or `app`.
- `watch-status[.NAME].json`: a single record, replaced at the end of each cycle. It holds the last cycle only, plus `everySeconds` and `keepSeconds` (`app.Watch`, `WatchDeps.publish`; `watchstatus.Record`).
- `watch-state[.NAME].json`: dedupe memory. Not history.
- The store: every hunt calls `SaveFindings`, which inserts a `runs` row before it writes any finding (`duckdb.Store.SaveFindings`, `INSERT INTO runs`), so a completed watch hunt with no findings still leaves a `runs` row `watch[-NAME]-<UTC stamp>`. A hunt that fails before it saves leaves none (unverified for every failure path). The row carries no verdict. And retention (`--keep`, default 48 h, `app.DefaultWatchKeep`) deletes watch runs older than that, except each watcher's newest one (`duckdb.PruneRuns`).

So the verdict, the cycle time and the reported gap exist only in the log. The store cannot replace it: it has no verdict, and it forgets after `--keep`. The log is the source of cycles. The store is the source of findings.

**The cycle line, and what it lacks.** `Line` writes `<At> CYCLE <run> [w:NAME] CYCLE <VERDICT>: <text>`. `At` is the time the cycle started (`now` at the top of `watchCycle`, which is also the window end). The line holds no duration. Only the status record gives one, for the last cycle: `Ended` minus `WindowTo` (unverified in a running watcher; derived from `WatchDeps.publish` and `watchCycle`). I do not add the duration to the line, because that changes a log format the other user's code may read. The page shows the duration for the newest cycle of each watcher and `not recorded` for the rest. See Open question 1.

**The gap span.** The cycle line for an `INCOMPLETE` cycle says only `gap=true` or `gap=false`. The span is in a separate `ALERT` line with tag `watch-gap`, written in the same cycle with the same `At`: `<D> of events between <T1> and <T2> were never examined: ...`. The alert line has no run id, so it is joined to its cycle by `At` and by the watcher's file. The span text is human text. The parser lives beside the writer in `internal/adapters/alertlog`, and a test round-trips `Line` through it, so a change to the wording fails a test and does not silently drop the span. If the line is missing or does not parse, the page shows `gap reported, span not read`.

**One reader, in `watchrun`.** `internal/watchrun` already lists the evidence directory for watchers (`Status`, `NameFrom`) and already owns the heartbeat constant (`HeartbeatFactor = 3`, exported as `jb.WatchHeartbeatFactor`). The new reader goes there, so the factor stays defined once. The web adapter sees a `core` port only, as the archtest rule requires.

**Why not the existing `LogTailer` port.** `alertlog.Tailer.Tail` drops lines cut by its 256 KiB read bound without saying so. A timeline must say that it starts mid-history. The new port returns `Cut`.

**Time axis.** A table is the record; an SVG lane per watcher is the picture over it. A CSS bar is not possible: the CSP is `style-src 'self'`, so an inline `style="width:..."` is refused. SVG geometry attributes (`x`, `width`) are not styles and are allowed. Both are server-rendered by templ.

## The design

Proposed, all of it.

### 1. The page

`GET /timeline` returns the full page. With `HX-Request: true` it returns the results fragment only, as `/findings` and `/watch` do (`isHX`).

| Parameter | Values | Rule |
|---|---|---|
| `w` | `1h`, `6h`, `24h`, `7d` | Window ending now. Default `24h`. Any other value is ignored and the default is used. Maximum 7 days. |
| `watcher` | A watcher name, or `_` for the unnamed watcher | Repeatable, as `kind` on the Estate page (`?watcher=a&watcher=_`). None chosen means all. A value that is not a discovered watcher is ignored. `_` cannot be a real name (`app.ValidWatchName` requires a letter first). |
| `sev` | `info`, `check`, `activity`, `high`, `critical` | Repeatable. None chosen means all. Unknown values are ignored. Filters findings only, never cycles. |
| `gaps` | `1` | Only gaps view: the table does not list plain cycles (`QUIET` or `FINDINGS` with no reported gap); markers, findings and every `INCOMPLETE`, `FAILED` or gap-reporting cycle stay. Each watcher gets a summary line with the number of plain cycles not listed. Any other value is ignored (all cycles). A link in the results switches the view and keeps the other parameters. Render only: the data is the same. |

With a `watcher` filter, findings are limited to the runs of those watchers and the cycles to their logs. Without one, findings of hunts (run ids that are not `watch*`) are shown too, with the watcher column `hunt`.

The page has these panels. Each fails on its own, so a failed store does not hide the cycles and the reverse.

1. **Notices.** Every cut, absence and unknown (below), in plain text, before the results.
2. **Lanes.** One SVG per watcher: a tick per cycle, a dot per finding, an outlined span per marker. Shapes carry the meaning (tick height and a letter per verdict, filled dot versus ring per severity band). No colour carries a verdict or a severity. The SVG is `aria-hidden`; the table is the accessible record.
3. **Table.** Findings, cycles and markers merged, newest first. Columns: `time` (UTC, RFC 3339), `kind` (`finding`, `cycle`, `no cycle recorded`), `watcher`, `detail`, `run`.
   - finding: detail is `severity`, `detector`, `tag` (see Privacy: the tag is the subject).
   - cycle: detail is the verdict, the reported gap span if any, and the duration or `not recorded`.
   - marker: see 3.
   - `run` links to `/run?id=` (`runHref`) for a finding and for any cycle whose run id is in the store window.

### 2. Data sources

**Findings** come from the store through the existing per-request read-only open (`Deps.Open`; `duckdb.OpenDashboardContext`, `access_mode=READ_ONLY`). The time of a finding is `runs.created_at`. A finding has no time of its own. For `hunt --until` backfills this is the day of the backfill, not the time of the events. The Findings page already shows the window; the timeline shows it too, in the detail column, when it differs from the run time by more than the window length.

**Cycles** come from `watch[.NAME].log` of every watcher found in the case's evidence directory. Discovery is `watchrun.NameFrom` over the directory, as `jb watch status` does. This is the same kind of file `/watch` already reads. It is a wider reading of the same directory, not a new file kind. `jb serve --config` without `--case` looks beside the store, as the Watch page does.

**Interval, retention** come from `watch-status[.NAME].json` (`watchstatus.Read`, strict). It gives `everySeconds` and `keepSeconds`. No other file is read: not the config, not the lock, not the state file.

**How much history exists.**

- The log is unbounded in code, but one read reads at most the last 256 KiB (`alertlog` `maxTailBytes`). The reader keeps that bound and reports `Cut` when the file is larger. Cycles per 256 KiB depend on line length and on alerts per cycle. I did not measure it, so no number is given here (unverified). The implementer measures it on a synthetic log; the numbers are under Reference implementations.
- Findings of watch runs older than `keepSeconds` are gone from the store. Cycle lines older than that are still in the log. For a cycle older than that horizon the page prints `findings of this watcher older than <keep> are removed by retention`, so an empty finding column there is not read as "none". If the status record is missing, the horizon is unknown and the page says so.
- Findings of hunts are not pruned by `--keep`.

### 3. The marker

**Rule.** For one watcher with interval `E` (from its status record) and cycle times `t1 < t2 < ... < tn` (the `At` of its cycle lines in the read window):

- Between consecutive cycles: a marker when `t(i+1) - t(i) > 3 * E`. Exactly `3 * E` gives no marker. This is the same strict `>` and the same factor as `jb watch status` (`watchrun.HeartbeatFactor`, `inspect`).
- Trailing: a marker when `now - tn > 3 * E`, shown as open (`no cycle recorded since <tn>`).
- Leading: none. The first cycle read has no known predecessor. If the log was cut, the page says the history starts at `t1`.
- A watcher with no cycle line in the log and a known interval: one notice, `no cycle line in the log`. No span is drawn, because the start is unknown.

**Wording.** Fixed sentence, no verdict word:

> No cycle line in watch.NAME.log from T1 to T2 (1h12m). This watcher's interval is 5m, so this is more than 3 intervals. The log shows no cycle in this span. The cause is not known: the watcher may not have run, or its log may not have been written.

**Unknown interval.** If the status record is missing, unreadable or for another name, the page draws no marker for that watcher and prints `interval unknown (no readable watch-status record): no gap is judged for this watcher`. It never guesses a default.

**Limits the page states.**

- The interval is the one in the current record. If the operator changed `--every` during the window, markers are judged with the current value. The record keeps no history of it (verified: one record per watcher, replaced each cycle).
- A restarted watcher leaves a marker for the time it was down, which the existing `gap` report misses: `lastCompleteTo` in `app.Watch` is held in memory only, so the first cycle after a restart reports no gap (code comment in `app.Watch`). That is the case the requester cannot see today.

**Difference from `stale`.** `jb watch status` judges one instant. It needs the lock probe and the status record, and its answer is a process state (`running`, `stale`, `stopped`, `unknown`). The marker needs neither the lock nor the record's last cycle. It judges every past span from log lines, and states only that lines are absent. The two share the factor and the `>`. They differ in the clock they measure from: `stale` uses the end of the last cycle (`Ended`), the marker uses the start of each cycle (`At`, the only time the log has). A watcher can read `stale` and have no marker yet, or the reverse. The page links to no verdict word from either.

### 4. Bounds

| Bound | Value | When hit |
|---|---|---|
| Window | 7 days | Larger `w` is ignored |
| Findings rows | 500 (`timelineFindingsLimit`) | `INCOMPLETE: the newest 500 findings of this window are shown; older ones in the window are not.` |
| Log read | 256 KiB per watcher (existing) | `Log read from <t1> only; earlier cycles are not shown.` |
| Watchers | 16 | The rest are named and not drawn |
| Store time limit | 3 s (`timelineBudget`, a variable for tests, as `overlayBudget`) | The findings panel shows `could not read the store`. Cycles still render. |
| Request | 20 s (existing `requestBudget`) | Existing behaviour |

A cut is never silent and never renders as a complete page. The notice sits before the table and the table header repeats `INCOMPLETE` while any notice about a cut is active. An empty result is one of four distinct texts: `no findings in this window`, `store not available`, `could not read the store`, `findings older than the retention horizon are removed`.

### 5. Store port

In `internal/core/dashboard.go`:

```go
// FindingsQuery selects findings by the time their run was saved: [From, To).
type FindingsQuery struct {
	From, To    time.Time
	Severities  []Severity // none means all
	RunPrefixes []string   // each "watch-", "watch-NAME-"; none means all runs
	Limit       int        // must be positive
}

// TimelineFinding is a stored finding with the time its run was saved.
type TimelineFinding struct {
	Created time.Time
	StoredFinding
}

// FindingsPage is the rows and whether more matched than Limit.
type FindingsPage struct {
	Rows []TimelineFinding
	More bool
}
```

and one method on `DashboardStore`:

```go
FindingsBetween(ctx context.Context, q FindingsQuery) (FindingsPage, error)
```

SQL shape in `internal/adapters/duckdb/dashboard.go`. The text is fixed. Only the count of placeholders varies (as `Reputation` does). Every value is bound:

```sql
SELECT r.created_at, f.run_id, f.detector, f.tag, f.severity,
       f.window_from, f.window_to, f.summary
FROM findings f JOIN runs r ON r.run_id = f.run_id
WHERE r.created_at >= CAST(? AS TIMESTAMPTZ) AND r.created_at < CAST(? AS TIMESTAMPTZ)
  [AND f.severity IN (?, ...)]
  [AND ( (starts_with(f.run_id, ?) AND regexp_full_match(split_part(f.run_id, '/', 1), ?)) OR ... )]
ORDER BY r.created_at DESC, f.run_id, f.severity DESC, f.seq
LIMIT ?   -- Limit + 1
```

- `detail` is not selected. The Findings page does not show it either.
- The prefix terms use the delimiter-safe shape `prefix + \d{8}T\d{6}Z` that `PruneRuns` uses, so `watch-a-` does not reach `watch-ab-`. Prefixes come from `app.WatchRunPrefixFor` over names that `NameFrom` accepted, never from request text.
- The handle is read-only, so the engine refuses a write whatever the SQL. The existing `readonly_test.go` pattern applies.
- The `JOIN` is inner. Findings without a `runs` row are not listed (unverified whether any can exist: `SaveFindings` writes both in one transaction).
- Adding a method to `DashboardStore` breaks its fakes in tests. They get the method.

New port in `core`, implemented in `internal/watchrun/history.go`, wired in `jb/dashboard.go` as `Deps.History` (nil means "not available", like `Log`):

```go
type WatchHistoryReader interface {
	// Watchers lists the watchers found, "" for the unnamed one, in name order.
	Watchers(ctx context.Context) ([]string, error)
	// Read returns one watcher's cycles and its judged gaps at the instant now.
	Read(ctx context.Context, name string, now time.Time) (WatchHistory, error)
}

type WatchHistory struct {
	Cycles   []WatchCycleLine // oldest first
	Gaps     []WatchNoCycle   // spans judged by the 3-interval rule
	Every    time.Duration    // zero: unknown
	Keep     time.Duration    // zero: unknown
	Last     *WatchCycleSummary // from the status record; the only source of a duration
	Cut      bool             // the log is larger than the read bound
	Unparsed int              // lines that were read and not understood
}

type WatchCycleLine struct {
	At                time.Time
	Run, Verdict      string
	GapReported       bool
	GapFrom, GapTo    time.Time // zero when the span was not read
}

type WatchNoCycle struct {
	From, To time.Time // To is zero for an open span
}
```

`core.ErrAbsent` is returned when there is no log, as `LogTailer` does.

### 6. Rendering and escaping

- templ components in `internal/adapters/web/timeline.templ`; generated file and `static/tailwind.css` are committed (`make ui`). No `templ.Raw`, no inline script, no inline style. No new script and no new static file. The page works without script; htmx only refreshes the results fragment, as on `/findings`.
- Every stored string passes `c()` (`clip`, 300 characters, control characters replaced) and then templ escapes it for its place (text, attribute, URL). This covers detector, tag, summary, run id, watcher name, verdict, and the gap text. SVG `<title>` text goes through the same path.
- `subject` is the finding's `tag`, clipped to 120 characters in the table. The full tag is on the run page.
- A verdict is matched to the closed set `QUIET`, `FINDINGS`, `INCOMPLETE`, `FAILED` by an anchored parser. Anything else is `unparsed` and counted. Verdict text is never taken from a free-text position in a line: a `FAILED` cycle carries error text, and an alert carries finding text, which can hold attacker-influenced strings, including the words `CYCLE QUIET`. When this was drafted, the Watch page used an unanchored `cycleRE` (`views.go`). Open question 4 fixed that: no `cycleRE` remains, and the Watch page uses `core.ParseWatchLogLine`.
- The watcher name in a row is the file's name (validated by `NameFrom`), not the `[w:...]` text inside the line.
- Order is total: rows sort by time descending, then kind, then watcher, then run id, then sequence. Two loads over unchanged files and an unchanged store with the same `Deps.Now` give byte-identical output. `Now` is rounded down to the minute for the window end and the trailing marker.
- Severity: the name in text (`high`), and a shape in the SVG. The Findings page colours its severity badge (`sevVariant`: `destructive`, `warning`). The timeline does not reuse that badge. See Open question 3.
- Verdict: text and letter only. `INCOMPLETE` and `FAILED` are written with the words `not a quiet result`, the phrase the cycle line already uses.

### 7. Privacy

A finding's `tag`, `summary` and `Detail` can hold a subject such as an address or a username. For `username`, `email` and `user_id` keys, the detectors refuse to run without `hash_keys`, so the stored tag and summary carry `h:` plus 12 hex digits of SHA-256, not the plain value (`hash_keys` is documented in `docs/config/mappers.md` and `docs/config/detectors-markers-and-actors.md`; the guard is `internal/piiguard`). The hash is applied by the detector before the finding is stored, so any reader of the store sees the hashed form. The existing Findings page shows `tag` and `summary` as stored. The timeline shows `detector`, `severity`, `tag` and the run id only. It never selects `detail`, and never reads events. It therefore shows no more than `/findings` already shows. A plain address as a key (`client_ip`) is not hashed unless the config says so; that is the same on every page. Cycle lines hold names, counts and the failure text of components. The Watch page already prints these lines whole. The timeline prints the verdict, the gap span and component names only.

## Non-goals

- No port-state overlay and no reading of any estate file.
- No reading of `watch-state.json`, the lock file or the config beyond what section 2 lists.
- No alert, notification or sound. The page is read when a person opens it.
- No write path: GET and HEAD only, as everywhere.
- No change to `watch.log`, the cycle line, the status record, the store schema or any config key.
- No duration for old cycles (Open question 1).
- No JSON endpoint and no export.
- No change to the Watch page or the Findings page.

## Drawbacks

- The gap rule rests on one number, the current interval. A changed `--every` makes some old markers wrong in either direction. The page says which interval it used.
- The log is the only source of verdicts and the parser reads human text. The round-trip test keeps it honest, but a future wording change must touch the parser.
- A missing line has more than one cause (no run, log not written, log deleted). The wording says so. A reader who wants a yes or no gets neither.
- Findings of watch runs older than `--keep` are gone, so the timeline looks emptier in the past than the log says. The notice explains it. It cannot fix it.
- One more route, one more store method and one more port are to maintain.
- Duration is shown for the newest cycle only.

## Alternatives and prior art

**Extend the Watch page.** Rejected. It has one watcher wired in `jb/dashboard.go`, no time window and a different job: the live state of one watcher. Merging findings into it mixes "now" with "history". The timeline could replace its log tail later (Open question 5).

**A JSON API only.** Rejected. The requester reads in a browser and the dashboard has no JSON API except `/estate/graph.json`, which exists for the graph script. A new JSON surface is a new contract, and RFC 0018 lists the dashboard pages as unsupported surface, so a JSON API would be a new contract with no gain here.

**Client-side rendering (d3, as the Estate graph).** Rejected. It needs a new script file, a JSON route and escaping done in the browser. The Estate page needs the graph layout; a timeline needs only rows and ticks, which templ can write. The static fallback would still be required, so it is more code, not less.

**Cycles from the store `runs` table.** Rejected as the source, kept as an idea for duration. It has no verdict, no gap and no watcher interval, and it forgets after `--keep`.

**Read the cycle history from a new file the watcher writes.** Rejected. It adds a file format, and the freeze allows none. The log already holds every cycle.

**Marker from `jb watch status` state.** Rejected. It judges one instant and needs the lock.

Prior art is the split `jb watch status` already uses (RFC 0006): the lock proves a process, the timestamp proves progress. The marker is the log-only half of that, applied to the past.

## Compatibility

The dashboard is pre-1.0 and its pages are unsupported surface (RFC 0018), so adding a route and adding a method to `core.DashboardStore` break nothing that is promised; tests' fakes get the new method.

## Security considerations

- Routes: one new GET route behind the existing wrapper, so the Host check, the CSP, `Cache-Control: no-store`, `nosniff` and the GET and HEAD limit apply with no new code (`web.New`). RFC 0003 rules hold.
- Input: `w`, `watcher` and `sev` select among closed sets. A free value is never put in SQL, a path or a file name. A watcher name reaches a file path only if `NameFrom` found it in the directory, and a run prefix only from that name.
- Store: read-only by engine, fixed SQL, bound values, 3 s limit. Output is bounded by the row cap.
- Files: the reader opens regular files in the evidence directory by names it built. Reading is bounded (256 KiB per log, one small record per watcher). A symlink in that directory is followed as the Watch page's reads already do (unverified for `watchstatus.Read`; the implementer checks it and refuses a non-regular file).
- Untrusted text: log lines carry detector output and error text. The writer escapes control characters, so one alert cannot forge a second line (`alertlog.clean`). The parser is anchored at the line start and at fixed positions, and reads the verdict, the gap alert and the watcher only from those. A forged `watch-gap` or `CYCLE QUIET` in free text is not read.
- Denial: 16 watchers, 256 KiB each, 500 findings, one store query. A hostile case cannot make the page larger than that.
- Disclosure: no field is shown that the Findings or Watch page does not show (section 7).
- Wording: a marker is a statement that lines are absent. It is not an alert and carries no colour.

## Conformance

The implementation is checked by the tests below. Status on 2026-11-09.

Shipped:

- `internal/adapters/duckdb/findings_between_test.go`: `FindingsBetween` (bounds, order, `More`, filters, prefix matching, read-only handle).
- `internal/core/watchlog_test.go`: the anchored parser `core.ParseWatchLogLine` (`internal/core/watchlog.go`). The parser moved from `alertlog` to `core` (see Changes), so these tests replace the `internal/adapters/alertlog` parser tests the draft listed.
- `internal/watchrun/history_test.go` and `internal/watchrun/gaps_test.go`: the gap rule, the trailing marker, the unknown interval, a cut log, a missing log. `TestReadRoundTripsWhatTheWatchLoopWrites` in `history_test.go` runs the real watch loop into the real alert log and reads it back.
- `internal/adapters/web/timeline_test.go` and `timeline_gaps_test.go`: escaping, bounds, determinism, wording, filters and the existing secure-header checks, with store and history fakes.
- `cmd/jb/serve_timeline_test.go`: an end-to-end test through `jb hunt`, `jb watch --once` and `jb serve`. `/timeline` shows the finding and the cycle with no marker, then draws a marker after 3 intervals. It rewrites the cycle time in the log by hand to move it near the real clock.
- `internal/archtest`: `TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch` covers the new `.templ` and `.go` files with no change.
- Browser smoke test: run once with Playwright on 2026-11-07 (see Reference implementations).
- Docs: `docs/config/serve.md` (`## Timeline`) describes the page.

Not done:

- A root end-to-end test in `jb/dashboard_test.go` with `seedDash` and a real `jb watch --once` against the fake source. `grep -i timeline jb/dashboard_test.go` finds nothing. `cmd/jb/serve_timeline_test.go` and `TestReadRoundTripsWhatTheWatchLoopWrites` cover the same ground.
- A new archtest rule that `internal/watchrun` history imports no `net/http`. The existing rule that confines `net/http` to the remote adapters and the dashboard already fails for that package (see Changes).
- A doc-parity test that `docs/config/serve.md` names the route: not checked.

## Reference implementations

Shipped (2026-11-07, unreleased):

- `internal/core/dashboard.go`: `FindingsQuery`, `TimelineFinding`, `FindingsPage`, `DashboardStore.FindingsBetween`, `WatchHistoryReader` and its types. `WatchHistory` also carries `GapFactor`, so the page prints the factor the reader judged with and does not copy it.
- `internal/core/watchlog.go`: the anchored parser for cycle and watch-gap lines (`ParseWatchLogLine`). It is in `core`, not in `alertlog` as drafted, because the web adapter may import `core` only, and the Watch page now uses the same parser.
- `internal/adapters/alertlog/tail.go`: `ReadTail`, a bounded tail read that reports a cut and refuses a file that is not regular.
- `internal/adapters/duckdb/dashboard.go`: `FindingsBetween`.
- `internal/watchrun/history.go`: `History` (`Watchers`, `Read`), `Gaps`; `internal/watchrun/status.go`: `Overdue`, the one strict comparison that `jb watch status` and the marker share.
- `internal/adapters/web/timeline.go`, `timeline.templ`, `web.go` (route, `Deps.History`), `layout.templ` (nav).
- `jb/dashboard.go`: wiring. No exported identifier of package `jb` is added.
- `docs/config/serve.md`: the page (`## Timeline`).

Measured 2026-11-07 (not re-run) on a synthetic log written by the real watch loop (6000 quiet cycles, `alertlog.Sink`, one read of the 262144 byte bound with no alert lines between the cycle lines):

| Watcher | Bytes per cycle line | Cycles in one read |
|---|---|---|
| unnamed | 137 | 1913 |
| `a` | 145 | 1807 |
| `retrieval-watch` | 173 | 1515 |

At an interval of 5 minutes, 1807 cycles are about 6.3 days. At 1 minute they are about 30 hours, so a 7 day window on a 1 minute watcher is always cut and says so. Each `ALERT` line adds about as many bytes as a cycle line, so a watcher that alerts every cycle shows about half as many. The page keeps at most 500 cycle rows per watcher (`timelineCycleRows`), so the log bound is not the tighter one at an interval of 5 minutes or more over a window of 24 hours.

Browser smoke test (Playwright, 2026-11-07): `jb serve --case` on a temporary copy of `examples/case` with a hand-written log for one named and one unnamed watcher, a status record for the named one and findings in the store. `/timeline` rendered with the lanes, a marker for an 11 cycle silence and the unknown-interval notice for the unnamed watcher. Ticking a severity box (the htmx fragment) produced no console warning or error and no CSP violation. Not covered: the filter result was not inspected, only that it raised no error; Firefox and Safari.

## Open questions

Decided on 2026-11-07 by the maintainer, in a grilling session, with the draft's own recommendations:

1. **Duration for every cycle.** Show it for the newest cycle only; older cycles read "not recorded". No log format change. Revisit after use.
2. **Is "3 intervals" right for a marker?** Yes: one constant, no flag, the same factor as `jb watch status`.
3. **Severity badge colour.** The timeline uses text and shape, no colour. The Findings page is not changed here.
4. **The Watch page's unanchored `cycleRE`.** A bug, so the freeze allows it: fixed in a separate commit that reuses the new parser, with a test that feeds an `ALERT` line containing `CYCLE QUIET` (red first).
5. **Retire the Watch page's log tail?** No. Leave `/watch` as is and revisit after the timeline is used.
6. **Finding time for backfills.** `runs.created_at`, with the window shown, as drafted.
7. **Retention horizon in the page.** Printed per watcher, as drafted.
8. **Fixture size for the 256 KiB measure.** The implementer measures cycles per read bound on a synthetic log and records the number under "Reference implementations"; the maintainer decides only if it is small enough to matter.

## Changes

- 2026-11-07: draft.
- 2026-11-07: accepted; open questions decided by the maintainer.
- 2026-11-07: built. Deviations from the draft, each from the code:
  - The line parser is `core.ParseWatchLogLine`, not `alertlog/parse.go`. The web adapter may not import an adapter, and the Watch page (Open question 4) needs the same parser. The round trip is tested in `internal/watchrun` against the real watch loop and the real `alertlog.Sink`.
  - The page caps cycle rows at 500 per watcher and says so. The draft bounded the log read only; at a 1 minute interval one read holds about 1800 cycles.
  - `WatchHistory.GapFactor` is added so the page prints the factor the reader used.
  - A cycle row links to `/run` only if its run is among the 100 newest run groups or has a finding in the window; a quiet cycle older than that has no link, because the page does not query the store per cycle.
  - The cycle line parser reads `gap=true` or `gap=false` only from the fixed text of an `INCOMPLETE` line. A first version looked for the text after a leading space and read no gap; the round-trip test caught it.
  - No archtest rule was added for `internal/watchrun` and `net/http`: the existing rule that confines `net/http` to the remote adapters and the dashboard already fails for that package (checked by planting an import).
  - The draft says the unnamed watcher and hunts are told apart by the run id. The page labels them `(unnamed)` and `(hunt)`; the parentheses cannot occur in a watcher name.
- 2026-11-07: added the `gaps=1` only-gaps view (render only; no new query or route; the notices and the retention section are shown in both views).
- 2026-11-09: straightened against the code. Status set to `implemented`; the four deviations above stay. Conformance rewritten: it lists the tests that exist, and lists the root `jb/dashboard_test.go` end-to-end test and the archtest rule as not done. Paths updated (`jb/dashboard.go`, `docs/config/serve.md`, `core.ParseWatchLogLine`). The `cycleRE` and `hash_keys` references corrected. The byte table is marked as measured 2026-11-07 and not re-run.
