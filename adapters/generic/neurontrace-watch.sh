#!/usr/bin/env bash
# Generic adapter: tail NeuronTrace feedback and print violations to stderr
# Works with any agent that reads stderr or can be wrapped with this script
#
# Usage:
#   ./neurontrace-watch.sh &              # background watcher
#   ./neurontrace-watch.sh --once         # print last violation and exit

set -euo pipefail

FEEDBACK="${NEURONTRACE_FEEDBACK:-/run/neurontrace/feedback.jsonl}"

if [ "${1:-}" = "--once" ]; then
  [ -f "$FEEDBACK" ] || exit 0
  tail -1 "$FEEDBACK" 2>/dev/null | jq -r '
    select(.kind == "violation") |
    "neurontrace: \(.hook) \(.target) → \(.effect)"
  ' 2>/dev/null || true
  exit 0
fi

# Stream mode: watch for new violations
[ -f "$FEEDBACK" ] || { echo "Waiting for $FEEDBACK..." >&2; while [ ! -f "$FEEDBACK" ]; do sleep 1; done; }

tail -f "$FEEDBACK" 2>/dev/null | jq --unbuffered -r '
  select(.kind == "violation") |
  "[\(.severity)] \(.hook) \(.target) → \(.effect) | \(.message)"
' 2>/dev/null
