#!/usr/bin/env bash
# Replay known windows as a regression check (docs/BACKFILL.md).
#
#   examples/backfill/replay-windows.sh CASE_DIR CONFIG EXPECTED.json
#
# EXPECTED.json records, per window, only the finding tags and their count that the
# detectors are expected to raise. It holds no event, address or log line:
#
#   [{"name": "example-spray", "until": "2026-09-15T00:00:00Z", "window": "24h",
#     "tags": ["fingerprint:actor-a"], "findings": 1}]
#
# Exit 0 when every window raised exactly the recorded tags (and no others) and
# completed; 1 when one differs or did not complete; 2 on bad input. A window that is
# INCOMPLETE fails the check: an unread window proves nothing either way.
# JB overrides the binary. Needs jq.
set -u

case_dir=${1:?usage: replay-windows.sh CASE_DIR CONFIG EXPECTED.json}
config=${2:?config}
expected=${3:?expected}
jb=${JB:-jb}

jq -e 'type == "array" and all(.[]; has("name") and has("until") and has("window") and (.tags | type == "array"))' "$expected" >/dev/null \
  || { echo "$expected: not a list of {name, until, window, tags}" >&2; exit 2; }

fail=0
n=$(jq length "$expected")
for i in $(seq 0 $((n - 1))); do
  name=$(jq -r ".[$i].name" "$expected")
  until_time=$(jq -r ".[$i].until" "$expected")
  window=$(jq -r ".[$i].window" "$expected")
  want=$(jq -c ".[$i].tags | sort" "$expected")
  want_n=$(jq -r ".[$i].findings // (.[$i].tags | length)" "$expected")

  out=$("$jb" hunt --case "$case_dir" --config "$config" --window "$window" --until "$until_time" --output json)
  code=$?
  if [ "$code" -ge 2 ]; then echo "FAIL $name: jb exited $code" >&2; exit "$code"; fi
  got=$(printf '%s' "$out" | jq -c '[.findings[].tag] | sort')
  got_n=$(printf '%s' "$out" | jq -r '.findings | length')
  complete=$(printf '%s' "$out" | jq -r '.complete')

  if [ "$complete" != "true" ]; then
    echo "FAIL $name: the replay was INCOMPLETE (exit $code), which says nothing about the tags"; fail=1
  elif [ "$got" != "$want" ] || [ "$got_n" != "$want_n" ]; then
    echo "FAIL $name: expected $want_n finding(s) $want, got $got_n $got"; fail=1
  else
    echo "ok   $name: $got"
  fi
done
exit $fail
