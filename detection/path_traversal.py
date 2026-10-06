import re
from urllib.parse import unquote


PATH_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"/etc/passwd", re.I),
    re.compile(r"/etc/shadow", re.I),
]


def detect_path_traversal(log):
    url = unquote(log.get("url", ""))

    for pattern in PATH_PATTERNS:
        if pattern.search(url):
            return {
                "timestamp": log.get("timestamp"),
                "ip": log.get("ip"),
                "attack_type": "Path Traversal",
                "severity": "HIGH",
                "rule_id": "PATH-001",
                "url": log.get("url"),
            }

    return None
