#!/usr/bin/env sh
set -eu

INTERVAL="${RUN_INTERVAL_SECONDS:-10}"

echo "[engine] Running detection loop every ${INTERVAL}s"

while true; do
  python /engine/detector.py || true
  python /engine/report.py || true
  sleep "$INTERVAL"
done