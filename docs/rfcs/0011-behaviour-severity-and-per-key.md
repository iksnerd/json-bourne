# RFC 0011: Behaviour severity floor and per-key threshold
Status: implemented
Scope: add `min_severity`, `note` and `min_events_per_key` to a `rare` action of the `behaviour` detector, and say what happens when keys are truncated.
Accepted: 2026-11-06 by the maintainer

## Summary

A `rare` action of the `behaviour` detector always reports at severity `activity`, or `check` when the preceding window is empty. Its threshold counts events across all keys. Two rules of a downstream user need more.

First, an action such as an admin console login must never rank below `critical`. This RFC adds `min_severity`, a floor: the finding severity becomes the greater of the computed one and the floor. Second, "three attempts from one client" differs from "three clients, one attempt each". This RFC adds `min_events_per_key`: the action fires only when at least one key has that many events. When keys were dropped at `max_keys` and no stored key reached the threshold, the action is reported as incomplete, not quiet.

## Motivation

A rule set for a private admin console wants any login attempt to be `critical`, with a sentence saying why. Today the only severity control is the empty-baseline drop in `rare` (`internal/adapters/detectors/behaviour/behaviour.go`). A second rule wants repeated attempts from one client and ignores a scan that touches many clients once. `min_events` cannot say that, because it counts the total.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

1. **A floor, not an override.** `min_severity` can only raise. The reader of a config sees that no key can quiet a finding. The names are those of `core.SeverityName`: `info`, `check`, `activity`, `high`, `critical`.
2. **Refuse a floor that cannot raise.** A `rare` finding is `activity` or `check`, so `info` and `check` never raise anything. They are errors at load, as is any unknown name.
3. **Critical needs a reason.** `min_severity: critical` requires a non-empty `note`. The note is plain text carried in the finding, so the person who reads the alert sees why.
4. **The floor applies after the empty-baseline drop.** The existing drop stays. `baseline_empty` stays in `Detail`. `min_severity` appears in `Detail` only when the floor raised the result.
5. **The tag does not change.** It stays `detector:action`. `watchCycle` in `internal/app/watch.go` suppresses a finding only when its severity is at or below the stored one for the same tag. A raised severity alerts again and a lower one does not. The test `TestWatchRaisedSeverityUnderUnchangedTagAlertsAndLowerDoesNot` covers both directions.
6. **Per-key counts live in the existing key map.** The detector already stores at most `max_keys` distinct keys per action for the current window. The set becomes a map from key to count. Memory stays `O(actions * max_keys)`.
7. **Truncation is incomplete, not quiet.** If keys were dropped, a dropped key might have reached the threshold. Reporting nothing would look clean. The action is therefore reported as not judged.

## The design

Everything here is proposed. It is implemented in the same change as this draft.

New keys on an action (`Action` in `behaviour.go`):

| Key | Type | Rule |
|---|---|---|
| `min_events_per_key` | integer | `rare` only. `0` is off. Negative is an error. The action needs `cur_events >= min_events` and some key with `>= min_events_per_key`. |
| `min_severity` | string | `rare` only. One of `activity`, `high`, `critical`. |
| `note` | string | `rare` only. Carried as `Detail["note"]`. Required, non-empty, with `critical`. |

A `common` action that sets any of the three is refused at load, with an error that names the action.

With `min_events_per_key` the finding adds `hot_key` (the key with the most events, the smallest on a tie), `hot_key_events` and `min_events_per_key` to `Detail`. `hot_key` goes through `piiguard.Shown` exactly as `sole_key` does, so `hash_keys` hashes it. A personal `key_field` without `hash_keys` is already refused.

Truncation. When `keys_truncated` would be true, the action sets `min_events_per_key`, and no stored key reached it, `Detect` and `Activity` return an error. It is not `core.ErrNoRecords`. It names the action, says `max_keys` was reached and says to raise it. `classify` in `internal/app/hunt.go` maps it to status `error`, `Hunt` keeps the findings of the other actions beside the error (RFC 0012), `Activity` reports `INCOMPLETE` (`ACTIVE` and incomplete when another action fired), and `watchCycle` raises the `watch-incomplete` alert. When a stored key reached the threshold, the action fires normally.

Example (not run here):

```yaml
- name: admin-console-login
  class: rare
  path: /admin/login
  methods: [POST]
  min_events_per_key: 3
  min_severity: critical
  note: the admin console is not reachable from outside the office network
```

## Non-goals

- Per-key severity, or a threshold on a `common` action.
- A tag per hot key.
- Any new field in the finding other than `hot_key`, `hot_key_events`, `min_events_per_key`, `min_severity` and `note`.

## Drawbacks

An incomplete action marks the whole detector incomplete for that run, so the hunt is incomplete. The findings of the other actions are kept (RFC 0012).

A floor of `activity` on an action with an empty baseline restores the severity the empty-baseline drop removed. That is what the floor means, and a reader must know it.

## Alternatives and prior art

- **A plain `severity` key.** Declined. It reads as an override and could lower a finding.
- **Remove the empty-baseline drop for rare actions.** Declined. It would change every existing `rare` action.
- **A tag per hot key.** Declined. Tags would be unbounded, and the dedupe state would grow with the attackers.
- **Report quiet but flag the truncation.** Declined. A quiet result with a flag is read as clean. The rule in `CLAUDE.md` is that a detector that cannot judge never prints a clean-looking negative.
- **Do the per-key rule in `authspike`.** Not chosen. `authspike` is per-key already but for logins by status. `behaviour` actions match by path, method and fields.

## Compatibility

Nothing breaks. Three new optional keys are added. A config that sets none behaves as before. A config file with the keys is read only by a build that has them; the config loader already rejects unknown keys. The two users change nothing unless they want the new rules.

## Security considerations

`hot_key` is a key and so personal data when the key field is. It goes through `piiguard.Shown`, and a personal key field without `hash_keys` is refused at load. A `note` is the operator's text and is printed as is: it MUST NOT hold a secret. A floor can only raise severity, so no setting hides a finding. The incomplete outcome prevents a flood of distinct keys from turning a per-key rule into silence.

## Conformance

All in `internal/adapters/detectors/behaviour/floor_test.go`: `TestMinSeverityRaisesRareFinding`, `TestMinSeverityIsAFloorAppliedAfterBaselineDrop`, `TestMinSeverityAndNoteRefusals`, `TestMinEventsPerKeyRefusals`, `TestMinEventsPerKeyBoundary` (N-1 from one key quiet, N fires, N over N keys quiet), `TestMinEventsPerKeyCombinesWithMinEvents`, `TestHotKeyIsHashedWithHashKeys`, `TestTruncatedWithoutHotKeyIsIncompleteNotQuiet`, `TestTruncatedWithHotKeyStillFires`. The dedupe test is in `internal/app/watch_test.go`. The format test is `TestRFCsAreWellFormed` in `internal/archtest`.

## Amendment: the floor on newkey

Proposed and accepted on 2026-11-06 by the maintainer. The rest of this RFC is merged; this section is not built yet.

A downstream rule ported to `newkey` (RFC 0014) needs `critical`. `newkey` reports `high`, or `activity` (one step lower) when the preceding window is empty (every key is new then, so the severity drops one step). It has no setting that raises that.

`newkey` gains `min_severity` and `note` with the rules above:

- `min_severity` is one of `high` or `critical`. `info`, `check` and `activity` are refused at load: a floor at or below `high` can raise only the empty-baseline case, and `activity` would lower nothing and mislead. Any unknown name is an error.
- It is a floor: the finding severity becomes the greater of the computed one and the floor, applied after the empty-baseline drop. It can only raise.
- `critical` requires a non-empty `note`, carried as `Detail["note"]`. `Detail["min_severity"]` is present only when the floor raised the result.
- The tag does not change. `watchCycle` already alerts again on a raised severity under an unchanged tag (decision 5 above).

The check and the field live in one helper shared by `behaviour` and `newkey`, so the two detectors cannot drift. Tests, in `internal/adapters/detectors/newkey`: the floor raises; the floor is applied after the empty-baseline drop; refusals (below `high`, unknown name, `critical` without a note); the floor never lowers a finding. Non-goals are unchanged: no per-key severity and no plain `severity` key.

## Reference implementations

Implemented in: the code, tests and `docs/CONFIG.md` text in the commit that adds this file.

Shipped: yes. The list below is where it lives.

## Open questions

- Should a `note` be allowed on a floor below `critical`? The code allows it. The maintainer decides.
- 2026-11-06: accepted by the maintainer; the code is merged.
