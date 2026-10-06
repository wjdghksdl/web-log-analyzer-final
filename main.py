import json

from parser.log_parser import parse_log_file

from detection.sql_injection import detect_sql_injection
from detection.path_traversal import detect_path_traversal
from detection.scanner import detect_web_scanner
from detection.brute_force import detect_brute_force
from detection.http_flood import detect_http_flood

from correlation.correlation_engine import (
    analyze_attack_types,
    detect_attack_chain,
)

from risk.risk_engine import calculate_ip_risk


LOG_FILE = "data/access.log"
OUTPUT_FILE = "data/alerts.json"


def run_detection(logs):
    alerts = []

    per_log_detectors = [
        detect_sql_injection,
        detect_path_traversal,
        detect_web_scanner,
    ]

    for log in logs:
        for detector in per_log_detectors:
            result = detector(log)
            if result:
                alerts.append(result)

    alerts.extend(detect_brute_force(logs))
    alerts.extend(detect_http_flood(logs))

    return alerts


def build_result(logs):
    alerts = run_detection(logs)
    risk_results = calculate_ip_risk(alerts)
    correlation_results = analyze_attack_types(alerts)
    attack_chains = detect_attack_chain(alerts)

    return {
        "summary": {
            "total_logs": len(logs),
            "total_alerts": len(alerts),
            "total_ips": len(risk_results),
            "correlated_chains": len(attack_chains),
        },
        "alerts": alerts,
        "risk_results": risk_results,
        "correlation_results": correlation_results,
        "attack_chains": attack_chains,
    }


def main():
    print("=" * 70)
    print("Web Security Log Analyzer")
    print("=" * 70)

    logs = parse_log_file(LOG_FILE)
    result = build_result(logs)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False, indent=4)

    print(f"분석 로그 수 : {result['summary']['total_logs']}")
    print(f"탐지 이벤트  : {result['summary']['total_alerts']}")
    print(f"의심 IP      : {result['summary']['total_ips']}")
    print(f"공격 흐름    : {result['summary']['correlated_chains']}")
    print()

    print("[IP별 위험도]")
    print("-" * 70)

    for item in sorted(
        result["risk_results"],
        key=lambda x: x["risk_score"],
        reverse=True,
    ):
        print(
            f"{item['ip']} | "
            f"Score: {item['risk_score']:>3} | "
            f"{item['risk_level']:<8} | "
            f"Alerts: {item['alert_count']}"
        )

    print()
    print(f"결과 저장 완료: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
