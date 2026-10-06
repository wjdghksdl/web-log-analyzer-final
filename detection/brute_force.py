from collections import defaultdict
from datetime import datetime


FAILED_STATUS_CODES = {401, 403}
LOGIN_PATHS = {"/login", "/signin", "/auth/login"}
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def detect_brute_force(logs, threshold=5, time_window=60):
    attempts_by_ip = defaultdict(list)

    for log in logs:
        if log.get("path") not in LOGIN_PATHS:
            continue

        if log.get("status") not in FAILED_STATUS_CODES:
            continue

        try:
            timestamp = datetime.strptime(log["timestamp"], TIME_FORMAT)
        except (KeyError, ValueError):
            continue

        attempts_by_ip[log["ip"]].append(timestamp)

    alerts = []

    for ip, attempts in attempts_by_ip.items():
        attempts.sort()

        for i in range(len(attempts)):
            start = attempts[i]
            count = sum(
                1 for attempt in attempts[i:]
                if (attempt - start).total_seconds() <= time_window
            )

            if count >= threshold:
                alerts.append({
                    "timestamp": start.strftime(TIME_FORMAT),
                    "ip": ip,
                    "attack_type": "Brute Force",
                    "severity": "HIGH",
                    "rule_id": "BRUTE-001",
                    "failed_attempts": count,
                    "time_window": f"{time_window} seconds",
                    "target": "/login",
                })
                break

    return alerts
