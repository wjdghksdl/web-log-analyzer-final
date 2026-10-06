SCANNER_PATHS = {
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git/config",
    "/config",
    "/backup",
    "/backup.zip",
    "/robots.txt",
}


def detect_web_scanner(log):
    path = log.get("path", "").lower()

    if path in SCANNER_PATHS:
        return {
            "timestamp": log.get("timestamp"),
            "ip": log.get("ip"),
            "attack_type": "Web Scanner",
            "severity": "MEDIUM",
            "rule_id": "SCAN-001",
            "url": log.get("url"),
        }

    return None
