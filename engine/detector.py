from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone

from rules import detect_bruteforce, detect_credential_stuffing, detect_suspicious_success


LOG_FILE = os.getenv("AUTH_LOG_PATH", "/data/auth.log")
ALERTS_PATH = os.getenv("ALERTS_PATH", "/output/sample_output.json")


def _parse_timestamp(ts_raw: str) -> datetime | None:
    """
    Accepts timestamps like:
      - 2026-02-20T10:00:01+00:00
      - 2026-02-20T10:00:01.123456+00:00
      - 2026-02-20T10:00:01Z
    Returns tz-aware datetime (UTC if naive).
    """
    ts_raw = ts_raw.strip()
    if ts_raw.endswith("Z"):
        ts_raw = ts_raw[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(ts_raw)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_logs():
    """
    Expected log line format:
      <timestamp>, IP=<ip>, user=<username>, status=<SUCCESS|FAIL>
    """
    events = []

    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found at {LOG_FILE} (no events yet).")
        return events

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            parts = line.split(", ")
            if len(parts) != 4:
                continue

            ts_raw, ip_part, user_part, status_part = parts

            if not ip_part.startswith("IP=") or not user_part.startswith("user=") or not status_part.startswith("status="):
                continue

            ip = ip_part.split("=", 1)[1].strip()
            user = user_part.split("=", 1)[1].strip()
            status = status_part.split("=", 1)[1].strip().upper()

            if status not in {"SUCCESS", "FAIL"}:
                continue

            ts = _parse_timestamp(ts_raw)
            if ts is None:
                continue

            events.append({"timestamp": ts, "ip": ip, "user": user, "status": status})

    events.sort(key=lambda e: e["timestamp"])
    return events


def main():
    events = parse_logs()

    alerts = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_credential_stuffing(events))
    alerts.extend(detect_suspicious_success(events))

    out_dir = os.path.dirname(ALERTS_PATH) or "."
    os.makedirs(out_dir, exist_ok=True)

    with open(ALERTS_PATH, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4, default=str)

    print(f"[+] Parsed events: {len(events)} from {LOG_FILE}")
    print(f"[+] Alerts written: {len(alerts)} -> {ALERTS_PATH}")

    if alerts:
        counts = Counter(a.get("type", "Unknown") for a in alerts)
        for k, v in counts.most_common():
            print(f"    - {k}: {v}")


if __name__ == "__main__":
    main()