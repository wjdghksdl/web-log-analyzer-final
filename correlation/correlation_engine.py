from collections import defaultdict


def group_alerts_by_ip(alerts):
    grouped = defaultdict(list)

    for alert in alerts:
        ip = alert.get("ip")
        if ip:
            grouped[ip].append(alert)

    return dict(grouped)


def analyze_attack_types(alerts):
    grouped = group_alerts_by_ip(alerts)
    results = []

    for ip, ip_alerts in grouped.items():
        attack_types = []

        for alert in ip_alerts:
            attack_type = alert.get("attack_type")

            if attack_type and attack_type not in attack_types:
                attack_types.append(attack_type)

        results.append({
            "ip": ip,
            "alert_count": len(ip_alerts),
            "attack_types": attack_types,
        })

    return results


def detect_attack_chain(alerts):
    grouped = group_alerts_by_ip(alerts)
    chains = []

    for ip, ip_alerts in grouped.items():
        attack_types = {
            alert.get("attack_type")
            for alert in ip_alerts
        }

        stages = []

        if "Web Scanner" in attack_types:
            stages.append("Reconnaissance")

        if "Path Traversal" in attack_types:
            stages.append("Exploitation")

        if "SQL Injection" in attack_types:
            stages.append("Exploitation")

        if "Brute Force" in attack_types:
            stages.append("Credential Attack")

        if "HTTP Flood" in attack_types:
            stages.append("Availability Attack")

        # 중복 단계 제거
        stages = list(dict.fromkeys(stages))

        if len(stages) >= 2:
            chains.append({
                "ip": ip,
                "attack_types": sorted(attack_types),
                "stages": stages,
                "correlated": True,
            })

    return chains
