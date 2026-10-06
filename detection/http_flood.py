from collections import defaultdict
from datetime import datetime


TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def detect_http_flood(logs, threshold=20, time_window=5):
    requests_by_ip = defaultdict(list)

    for log in logs:
        try:
            timestamp = datetime.strptime(log["timestamp"], TIME_FORMAT)
        except (KeyError, ValueError):
            continue

        requests_by_ip[log["ip"]].append(timestamp)

    alerts = []

    for ip, requests in requests_by_ip.items():
        requests.sort()

        for i in range(len(requests)):
            start = requests[i]

            count = sum(
                1 for request in requests[i:]
                if (request - start).total_seconds() <= time_window
            )

            if count >= threshold:
                alerts.append({
                    "timestamp": start.strftime(TIME_FORMAT),
                    "ip": ip,
                    "attack_type": "HTTP Flood",
                    "severity": "HIGH",
                    "rule_id": "FLOOD-001",
                    "request_count": count,
                    "time_window": f"{time_window} seconds",
                })
                break

    return alerts
