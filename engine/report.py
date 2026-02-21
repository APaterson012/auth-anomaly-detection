from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


LOG_FILE = Path(os.getenv("AUTH_LOG_PATH", "/data/auth.log"))
ALERTS_FILE = Path(os.getenv("ALERTS_PATH", "/output/sample_output.json"))

REPORT_MD = Path(os.getenv("REPORT_MD", "/output/report.md"))
REPORT_JSON = Path(os.getenv("REPORT_JSON", "/output/report.json"))


def _parse_timestamp(ts_raw: str) -> datetime | None:
    ts_raw = ts_raw.strip()
    if ts_raw.endswith("Z"):
        ts_raw = ts_raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts_raw)
    except ValueError:
        return None


def parse_logs(log_path: Path):
    events = []
    if not log_path.exists():
        return events

    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(", ")
            if len(parts) != 4:
                continue

            ts_raw, ip_part, user_part, status_part = parts
            if not ip_part.startswith("IP=") or not user_part.startswith("user=") or not status_part.startswith("status="):
                continue

            ts = _parse_timestamp(ts_raw)
            if ts is None:
                continue

            ip = ip_part.split("=", 1)[1].strip()
            user = user_part.split("=", 1)[1].strip()
            status = status_part.split("=", 1)[1].strip().upper()
            if status not in {"SUCCESS", "FAIL"}:
                continue

            events.append({"timestamp": ts, "ip": ip, "user": user, "status": status})

    events.sort(key=lambda e: e["timestamp"])
    return events


def load_alerts(alerts_path: Path):
    if not alerts_path.exists():
        return []
    with alerts_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def mitigations_for(alert_counts: dict):
    mitigations = []

    if alert_counts.get("Brute Force", 0) > 0:
        mitigations += [
            "Enable MFA for all accounts, prioritising privileged users.",
            "Rate-limit login attempts per IP and per account.",
            "Temporary lockout after repeated failures (e.g., 5 attempts / 5 minutes).",
            "Add CAPTCHA after abnormal failure patterns.",
        ]

    if alert_counts.get("Credential Stuffing", 0) > 0:
        mitigations += [
            "Add bot protection / WAF rules for high-velocity login attempts.",
            "Use breached-password screening and force resets for compromised accounts.",
            "Risk-based authentication (device + IP reputation + velocity checks).",
        ]

    if alert_counts.get("Suspicious Success", 0) > 0:
        mitigations += [
            "Invalidate active sessions and force password reset for impacted accounts.",
            "Increase monitoring for accounts showing repeated failures then success.",
        ]

    mitigations += [
        "Centralise authentication logs into a SIEM (ELK/Splunk/Sentinel) for correlation.",
        "Create an incident response playbook for credential attacks (triage → contain → recover).",
        "Tune thresholds based on baseline traffic patterns to reduce false positives.",
    ]

    # Deduplicate while preserving order
    out, seen = [], set()
    for m in mitigations:
        if m not in seen:
            out.append(m)
            seen.add(m)
    return out


def render_md(summary: dict):
    md = []
    md.append("# Authentication Anomaly Detection Report\n\n")

    md.append("## Executive Summary\n")
    md.append(f"- **Time range analysed:** `{summary['time_range']['start']}` → `{summary['time_range']['end']}`\n")
    md.append(f"- **Total events:** `{summary['event_counts']['total']}` (SUCCESS `{summary['event_counts']['success']}`, FAIL `{summary['event_counts']['fail']}`)\n")
    md.append(f"- **Total alerts:** `{summary['alerts_total']}`\n\n")

    md.append("### Alerts by Type\n")
    if summary["alerts_by_type"]:
        for k, v in sorted(summary["alerts_by_type"].items(), key=lambda x: (-x[1], x[0])):
            md.append(f"- **{k}:** {v}\n")
    else:
        md.append("- None\n")

    md.append("\n## Key Indicators\n")
    md.append("\n### Top Failed IPs\n")
    for ip, c in summary["top_failed_ips"]:
        md.append(f"- `{ip}` - {c} failures\n")

    md.append("\n### Top Failed Users\n")
    for u, c in summary["top_failed_users"]:
        md.append(f"- `{u}` - {c} failures\n")

    md.append("\n### Activity Totals\n")
    md.append(f"- Unique IPs: `{summary['unique_ips']}`\n")
    md.append(f"- Unique users: `{summary['unique_users']}`\n")

    md.append("\n## Findings (Alert Details)\n")
    if summary["alerts_total"] == 0:
        md.append("- No suspicious patterns detected.\n")
    else:
        for i, a in enumerate(summary["alerts"], start=1):
            md.append(f"\n### Finding {i}: {a.get('type','Unknown')}\n")
            # Keep a predictable ordering for readability
            for k in sorted(a.keys()):
                md.append(f"- **{k}**: `{a[k]}`\n")

    md.append("\n## Recommended Mitigations\n")
    for m in mitigations_for(summary["alerts_by_type"]):
        md.append(f"- {m}\n")

    md.append("\n## Notes\n")
    md.append("- This report is auto-generated from authentication logs and rule-based detections.\n")
    md.append("- Thresholds are configurable in `engine/rules.py`.\n")

    return "".join(md)


def main():
    events = parse_logs(LOG_FILE)
    alerts = load_alerts(ALERTS_FILE)

    if events:
        start = events[0]["timestamp"].isoformat()
        end = events[-1]["timestamp"].isoformat()
    else:
        start, end = "N/A", "N/A"

    status_counts = Counter(e["status"] for e in events)
    fail_by_ip = Counter(e["ip"] for e in events if e["status"] == "FAIL")
    fail_by_user = Counter(e["user"] for e in events if e["status"] == "FAIL")

    alerts_by_type = defaultdict(int)
    for a in alerts:
        alerts_by_type[a.get("type", "Unknown")] += 1

    unique_ips = len({e["ip"] for e in events})
    unique_users = len({e["user"] for e in events})

    summary = {
        "time_range": {"start": start, "end": end},
        "event_counts": {
            "total": len(events),
            "success": status_counts.get("SUCCESS", 0),
            "fail": status_counts.get("FAIL", 0),
        },
        "unique_ips": unique_ips,
        "unique_users": unique_users,
        "top_failed_ips": fail_by_ip.most_common(5),
        "top_failed_users": fail_by_user.most_common(5),
        "alerts_total": len(alerts),
        "alerts_by_type": dict(alerts_by_type),
        "alerts": alerts,
    }

    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_JSON.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)

    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_MD.open("w", encoding="utf-8") as f:
        f.write(render_md(summary))

    print(f"[+] Wrote {REPORT_MD}")
    print(f"[+] Wrote {REPORT_JSON}")


if __name__ == "__main__":
    main()