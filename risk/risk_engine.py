from collections import defaultdict


SEVERITY_SCORE = {
    "LOW": 10,
    "MEDIUM": 20,
    "HIGH": 30,
    "CRITICAL": 50,
}


def calculate_ip_risk(alerts):
    ip_alerts = defaultdict(list)

    for alert in alerts:
        ip = alert.get("ip")

        if ip:
            ip_alerts[ip].append(alert)

    results = []

    for ip, alerts_for_ip in ip_alerts.items():
        score = sum(
            SEVERITY_SCORE.get(
                alert.get("severity", "LOW"),
                0,
            )
            for alert in alerts_for_ip
        )

        score = min(score, 100)

        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        results.append({
            "ip": ip,
            "risk_score": score,
            "risk_level": level,
            "alert_count": len(alerts_for_ip),
            "attack_types": sorted({
                alert.get("attack_type")
                for alert in alerts_for_ip
                if alert.get("attack_type")
            }),
        })

    return results
