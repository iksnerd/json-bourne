# RFC 0012: Keep the findings of a detector that did not finish
Status: accepted
Scope: say that `Hunt` keeps the findings a detector returns beside an error, state the contract a detector follows when it cannot finish, and say how the verdict reads.
Accepted: 2026-11-06 by the maintainer

## Summary

`core.Detector.Detect` returns `([]Finding, error)`, so a detector can return both. `Hunt` today throws the findings away whenever the error is non-nil. A detector with several independent rules therefore loses a real finding from one rule because another rule could not be judged.

This RFC changes the host and writes the contract down. `Hunt` keeps, counts, stores and alerts the findings returned beside an error. The detector stays `error` or `no_records`, so the run is incomplete and never reads as clean. A detector that cannot finish returns the findings it can prove from the evidence it read, and never a finding it could not support.

## Motivation

RFC 0011 adds a truncation rule to the `behaviour` detector. When keys were dropped at `max_keys` and no stored key reached `min_events_per_key`, that one action cannot be judged, and `Detect` returns an error. The detector's other actions are judged normally, and `Detect` returns their findings next to the error. `Hunt` ignores them (`internal/app/hunt.go`: `if err == nil { ... found[i] = fs }`). A flood of distinct keys on one action hides a hit on a different action in the same detector.

That is the opposite of evidence-first. A failure must make the run incomplete. It must not hide what was found. The cause is that the host reads the error and the findings as exclusive, while the interface allows both. Patching the behaviour detector to avoid the error would leave every future multi-rule detector with the same hole.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

The cause is the host's reading of the return value, so the fix is in `Hunt` and in the written contract, not in one detector. One rule at the host covers every present and future detector. The alternative was a new result type with a "partial" flag. It was declined: `error` already means "did not finish", and a second channel for the same fact can disagree with the first.

A finding beside an error is kept whatever the error is: `error`, `no_records`, `unavailable` or `canceled`. The status tells the reader why the detector stopped. The findings tell the reader what it proved before it stopped. The two do not conflict.

The cost of trusting a detector is a rule that a finding returned beside an error must rest only on evidence the detector read. This RFC states the rule and checks it for every built-in detector (see Conformance). A host cannot check it, because it cannot tell which rule produced which finding.

For `activity`, a kept finding is a genuine event: `Detect` applies the same noise and infrastructure rules as `Activity`. The verdict is therefore `ACTIVE`, and the output says the check is also incomplete. This follows the existing rule that `ACTIVE` stands despite gaps.

## The design

Proposed, in `internal/app/hunt.go`: `Hunt` stores the findings a detector returns whatever the error. `DetectorResult.Findings` counts them. `DetectorResult.Status` and `Err` still come from `classify(err)`, so `Result.Complete()` is false and `Result.Failures()` lists the detector.

Proposed, in `internal/core/core.go`, the contract on `Detector`:

- A detector that cannot finish MUST return the findings it can prove from the evidence it read, together with the error.
- It MUST NOT return a finding that depends on the part it failed to read, or that it could not support.
- A detector with nothing to prove returns no findings and the error, as today.
- The host treats an error with findings as incomplete-with-findings.

How each caller reads it:

| Caller | Findings with an error |
|---|---|
| `Hunt` | Listed in `Result.Findings`, stored under the run, counted in `DetectorResult.Findings`. The detector row keeps its status and error. `Complete()` is false. |
| `jb hunt` | The table shows the detector as `error` with its finding count, and the findings table lists them. The `INCOMPLETE` line stays. Exit 1, as for any incomplete hunt. JSON has the finding in `findings`, `detectors[].findings` greater than zero and `complete` false. |
| `Activity` | `ActivityDetector.Findings` carries the count. The verdict is `ACTIVE` and `Complete()` is false, with the reason `detector X did not finish`. With no finding the verdict stays `INCOMPLETE`. `jb activity` exits 0 for `ACTIVE`, as it does today for `ACTIVE` with another gap, and 1 for `INCOMPLETE`. JSON has `findings_before_stop` on the detector. |
| `watch` | The finding alerts through the normal path: deduped by tag, held back inside `--ttl`. The `watch-incomplete` alert for the detector is raised as well. The two alerts are different kinds with different tags, so neither suppresses the other and neither repeats the other. The cycle status is `incomplete`. |

`Hunt` is the only caller of `Detect` outside tests (`grep -rn 'Detect(' --include='*.go'`). `Activity` and `watch` reach it through `Hunt`. The search path (`jb hunt --search`) is `Hunt`, and its summary reads `Result.Findings`.

## Non-goals

- A new status for "partial". `error` and `no_records` stay the only ways to not finish.
- A change to how `classify` maps errors.
- A way for the host to check which rule produced a finding.
- Changing the exit code of `jb hunt` or `jb watch --once`. Both already exit 1 when any component did not finish.
- Making `jb activity` exit 1 for `ACTIVE` with an incomplete detector.

## Drawbacks

A reader sees findings and an `INCOMPLETE` line together and must read both. That is the intended state, but a script that treated "incomplete" as "no usable findings" now reads findings it ignored before.

The rule that a finding beside an error rests on read evidence is a convention. A future detector can break it, and only its own tests catch that.

`jb activity` exits 0 for `ACTIVE` with an incomplete detector. A script that wants to know the check was incomplete must read `complete` in JSON or the `NOTE` line, as it must today for `ACTIVE` with an incomplete source.

## Alternatives and prior art

- **Make the behaviour detector return no findings on a truncated action.** Declined. It fixes one detector and keeps the hole for the next.
- **Split the detector into one detector per action.** Declined. It makes the config longer and does not help a detector whose rules share one read of the evidence.
- **A `Partial` field on `DetectorResult` and a new status.** Declined. See "How this design was made".
- **Return a joined error per rule and let the host aggregate.** Declined. The host would need to know the rules.

Prior art: Go's own `io.Reader` contract says a caller must process the `n > 0` bytes returned before it considers the error. This RFC applies the same rule to findings.

## Compatibility

Nothing is promised stable, and there is no shim. What changes for a script or program that reads `jb hunt`, `jb watch` or `jb activity` output:

- `jb hunt` JSON and table: `findings` can be non-empty when a detector's `status` is not `ok`. Before, a failed detector contributed none. The exit code is unchanged (1 when anything did not finish).
- `DetectorResult.Findings` is non-zero for a failed detector. Before, it was always zero.
- `jb activity` JSON: the verdict can be `ACTIVE` with `complete` false where it was `INCOMPLETE` (exit 1) before. The exit code in that case moves from 1 to 0. The detector entry gains an optional `findings_before_stop`.
- `jb watch`: a cycle with an incomplete detector can now alert findings it did not alert before. The cycle status is still `incomplete`.
- The stored findings of a run can include findings from a detector whose status is `error`. The evidence store has no schema change.

Migration: a script that decided "no findings, so ignore" from an incomplete hunt reads `complete` first and `findings` second. A script that relied on `INCOMPLETE` from `jb activity` reading `complete` false instead of the verdict reads `complete`.

## Security considerations

Dropping findings hid attacker activity whenever a flood of distinct keys made one rule unjudgeable. This RFC removes that hiding. It adds no input and no output channel. The risk is a detector that returns a finding it did not support beside an error. The contract forbids it, and the Conformance section lists the check for each built-in detector. A finding still carries only what the detector counted from the events it read, and the key rules (`hash_keys`) are unchanged.

## Conformance

Host behaviour, in `internal/app/partial_test.go`: `TestHuntKeepsFindingsReturnedBesideAnError` (finding kept, status `error`, `Complete()` false, finding stored), `TestHuntKeepsFindingsBesideNoRecordsToo`, `TestHuntErrorWithoutFindingsStaysEmpty` (a plain error still produces no findings), `TestWatchAlertsAPartialFindingOnceAndRaisesIncomplete` (one finding alert, one incomplete alert, no repeat on the next cycle), `TestActivityOfAnIncompleteDetectorWithAFindingIsActiveAndIncomplete`.

End to end with the real `behaviour` detector, in `cmd/jb/partial_e2e_test.go`: `TestHuntReportsTheFindingOfAnIncompleteDetector` (one action fires, one is truncated per RFC 0011; the finding is in the output, the run exits 1) and `TestActivityIsActiveAndIncompleteForAnIncompleteDetectorWithAFinding`. The detector side is `TestTruncatedActionDoesNotHideAnotherActionsFinding` in `internal/adapters/detectors/behaviour/floor_test.go`.

Review of the built-in detectors (read in the code, not by a test): `authspike`, `fingerprint`, `newkey`, `signature` and `signup` return `nil` findings on every error path, and `out, nil` only at the end. Only `behaviour` returns findings with an error, and its incomplete action never sets a finding (`outcome.incomplete` is set only where `finding` stays nil). No file under `plugins/` implements `Detect`.

## Reference implementations

Proposed: the `Hunt` change in `internal/app/hunt.go`, `ActivityDetector.Findings` and the `ACTIVE` rule in `internal/app/activity.go`, the contract text on `core.Detector`, the activity table and JSON in `cmd/jb/activity.go`, the `--help` text of `jb hunt` and `jb activity`, and the text in `docs/ARCHITECTURE.md` and `docs/CONFIG.md`, all in the commit that adds this file.

Shipped: none.

## Open questions

- Should `jb activity` exit 1 for `ACTIVE` with an incomplete detector? It exits 0 today for `ACTIVE` with an incomplete source. The maintainer decides.
- Should a future conformance helper run every detector against a failing reader and check the contract? It would turn the review above into a test. The maintainer decides.
- 2026-11-06: accepted by the maintainer; the code is merged.
