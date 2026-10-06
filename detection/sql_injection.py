import re
from urllib.parse import unquote


SQL_PATTERNS = [
    re.compile(r"""(?:'|")\s*or\s+(?:'|")?\d+(?:'|")?\s*=\s*(?:'|")?\d+""", re.I),
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I),
    re.compile(r"\bselect\s+.+\s+from\b", re.I),
    re.compile(r"\bsleep\s*\(", re.I),
    re.compile(r"\bbenchmark\s*\(", re.I),
]


def detect_sql_injection(log):
    url = unquote(log.get("url", ""))

    for pattern in SQL_PATTERNS:
        if pattern.search(url):
            return {
                "timestamp": log.get("timestamp"),
                "ip": log.get("ip"),
                "attack_type": "SQL Injection",
                "severity": "CRITICAL",
                "rule_id": "SQLI-001",
                "url": log.get("url"),
            }

    return None
