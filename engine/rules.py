from __future__ import annotations

from collections import defaultdict, Counter
from datetime import timedelta


# -------- Tunable thresholds (portfolio-friendly defaults) --------
BRUTE_FORCE_FAILS = 5
BRUTE_FORCE_WINDOW = timedelta(seconds=60)

CRED_STUFF_USERS = 5
CRED_STUFF_WINDOW = timedelta(seconds=60)

SUSPICIOUS_SUCCESS_FAILS = 3


def _within_window(sorted_events, window: timedelta):
    """
    Sliding window helper for already time-sorted events.
    Returns list of (start_index, end_index) windows inclusive.
    """
    windows = []
    j = 0
    for i in range(len(sorted_events)):
        while j < len(sorted_events) and sorted_events[j]["timestamp"] <= sorted_events[i]["timestamp"] + window:
            j += 1
        windows.append((i, j))  # [i, j)
    return windows


def detect_bruteforce(events):
    """
    Brute force: >= BRUTE_FORCE_FAILS FAILs from same IP against same user within BRUTE_FORCE_WINDOW.
    """
    alerts = []
    groups = defaultdict(list)

    for e in events:
        # group by (ip, user)
        groups[(e["ip"], e["user"])].append(e)

    for (ip, user), logs in groups.items():
        # Only failures matter for brute force
        fails = [e for e in logs if e["status"] == "FAIL"]
        fails.sort(key=lambda x: x["timestamp"])

        if len(fails) < BRUTE_FORCE_FAILS:
            continue

        for i, j in _within_window(fails, BRUTE_FORCE_WINDOW):
            count = j - i
            if count >= BRUTE_FORCE_FAILS:
                start_ts = fails[i]["timestamp"]
                end_ts = fails[j - 1]["timestamp"]
                alerts.append({
                    "type": "Brute Force",
                    "severity": "HIGH",
                    "ip": ip,
                    "user": user,
                    "fail_count": count,
                    "window_seconds": int(BRUTE_FORCE_WINDOW.total_seconds()),
                    "window_start": start_ts.isoformat(),
                    "window_end": end_ts.isoformat(),
                    "rule": f"{BRUTE_FORCE_FAILS}+ FAILs / {int(BRUTE_FORCE_WINDOW.total_seconds())}s (same IP+user)"
                })
                break

    return alerts


def detect_credential_stuffing(events):
    """
    Credential stuffing: same IP targets >= CRED_STUFF_USERS distinct users within CRED_STUFF_WINDOW,
    with mostly FAIL outcomes.
    """
    alerts = []
    ip_groups = defaultdict(list)

    for e in events:
        ip_groups[e["ip"]].append(e)

    for ip, logs in ip_groups.items():
        logs.sort(key=lambda x: x["timestamp"])

        if len(logs) < CRED_STUFF_USERS:
            continue

        windows = _within_window(logs, CRED_STUFF_WINDOW)
        for i, j in windows:
            chunk = logs[i:j]
            if len(chunk) < CRED_STUFF_USERS:
                continue

            users = {e["user"] for e in chunk}
            fails = sum(1 for e in chunk if e["status"] == "FAIL")
            success = sum(1 for e in chunk if e["status"] == "SUCCESS")

            if len(users) >= CRED_STUFF_USERS and fails >= CRED_STUFF_USERS and fails >= success:
                start_ts = chunk[0]["timestamp"]
                end_ts = chunk[-1]["timestamp"]
                top_users = [u for u, _ in Counter(e["user"] for e in chunk).most_common(5)]

                alerts.append({
                    "type": "Credential Stuffing",
                    "severity": "HIGH",
                    "ip": ip,
                    "users_targeted": len(users),
                    "fail_count": fails,
                    "success_count": success,
                    "window_seconds": int(CRED_STUFF_WINDOW.total_seconds()),
                    "window_start": start_ts.isoformat(),
                    "window_end": end_ts.isoformat(),
                    "top_users": top_users,
                    "rule": f"{CRED_STUFF_USERS}+ users / {int(CRED_STUFF_WINDOW.total_seconds())}s (same IP)"
                })
                break

    return alerts


def detect_suspicious_success(events):
    """
    Suspicious success: SUCCESS after >= SUSPICIOUS_SUCCESS_FAILS consecutive FAILs for the same user.
    """
    alerts = []
    user_groups = defaultdict(list)

    for e in events:
        user_groups[e["user"]].append(e)

    for user, logs in user_groups.items():
        logs.sort(key=lambda x: x["timestamp"])

        consecutive_fails = 0
        last_fail_ip = None
        last_fail_ts = None

        for e in logs:
            if e["status"] == "FAIL":
                consecutive_fails += 1
                last_fail_ip = e["ip"]
                last_fail_ts = e["timestamp"]
                continue

            # SUCCESS
            if consecutive_fails >= SUSPICIOUS_SUCCESS_FAILS:
                alerts.append({
                    "type": "Suspicious Success",
                    "severity": "MEDIUM",
                    "user": user,
                    "ip": e["ip"],
                    "previous_failures": consecutive_fails,
                    "last_fail_ip": last_fail_ip,
                    "last_fail_time": last_fail_ts.isoformat() if last_fail_ts else None,
                    "success_time": e["timestamp"].isoformat(),
                    "rule": f"{SUSPICIOUS_SUCCESS_FAILS}+ consecutive FAILs then SUCCESS (same user)"
                })

            # reset after any success
            consecutive_fails = 0
            last_fail_ip = None
            last_fail_ts = None

    return alerts