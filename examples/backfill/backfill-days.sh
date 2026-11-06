#!/usr/bin/env bash
# Backfill a case one UTC day at a time with `jb hunt --until` (docs/BACKFILL.md).
#
#   examples/backfill/backfill-days.sh CASE_DIR CONFIG FIRST_DAY LAST_DAY
#   examples/backfill/backfill-days.sh ./my-case config/hunt-filtered.yaml 2026-10-01 2026-10-07
#
# Each day D is hunted as the window [D 00:00Z, D+1 00:00Z) and its baseline, the day
# before. CONFIG should name a source with a `filter`: without one every day downloads
# every document of the index.
#
# A day that ends INCOMPLETE (exit 1) is NOT quiet. The loop keeps going, lists those days
# at the end and exits 1. A usage error (exit 2) stops the loop at once. JB overrides the
# binary, JB_FLAGS adds flags to every hunt. Needs date, jq.
set -u

case_dir=${1:?usage: backfill-days.sh CASE_DIR CONFIG FIRST_DAY LAST_DAY (days as YYYY-MM-DD, UTC)}
config=${2:?config}
first=${3:?first day}
last=${4:?last day}
jb=${JB:-jb}

to_epoch() { # YYYY-MM-DD (UTC) -> epoch seconds, GNU or BSD date
  date -u -d "$1 00:00:00" +%s 2>/dev/null || date -ju -f '%Y-%m-%d %H:%M:%S' "$1 00:00:00" +%s
}
from_epoch() { # epoch seconds -> RFC 3339 UTC
  date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -ju -r "$1" +%Y-%m-%dT%H:%M:%SZ
}

start=$(to_epoch "$first") || { echo "bad first day: $first" >&2; exit 2; }
stop=$(to_epoch "$last") || { echo "bad last day: $last" >&2; exit 2; }
[ "$start" -le "$stop" ] || { echo "first day is after last day" >&2; exit 2; }

incomplete=()
day=$start
while [ "$day" -le "$stop" ]; do
  until_time=$(from_epoch $((day + 86400)))   # the day ends where the next one starts
  echo "== window ending $until_time (24h)"
  # shellcheck disable=SC2086  # JB_FLAGS is meant to split
  out=$("$jb" hunt --case "$case_dir" --config "$config" --window 24h --until "$until_time" --output json ${JB_FLAGS:-})
  code=$?
  case $code in
    0) ;;
    1) incomplete+=("$until_time") ;;
    *) echo "jb exited $code for $until_time; stopping" >&2; exit "$code" ;;
  esac
  # One line per day: complete or not, and the finding tags only (never the events).
  printf '%s' "$out" | jq -r '"   complete=\(.complete) findings=\(.findings | length) tags=\([.findings[].tag] | sort | join(","))"'
  day=$((day + 86400))
done

if [ "${#incomplete[@]}" -gt 0 ]; then
  echo "INCOMPLETE, not quiet, re-run these windows: ${incomplete[*]}" >&2
  exit 1
fi
