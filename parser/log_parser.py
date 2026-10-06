import re
from urllib.parse import urlsplit


APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


def parse_line(line):
    line = line.strip()

    if not line:
        return None

    match = APACHE_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        status = int(data["status"])
    except ValueError:
        status = 0

    try:
        size = int(data["size"]) if data["size"] != "-" else 0
    except ValueError:
        size = 0

    parsed = {
        "ip": data["ip"],
        "timestamp": data["timestamp"],
        "method": data["method"],
        "url": data["url"],
        "path": urlsplit(data["url"]).path,
        "protocol": data["protocol"],
        "status": status,
        "size": size,
        "raw": line,
    }

    return parsed


def parse_log_file(file_path):
    logs = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            parsed = parse_line(line)

            if parsed:
                logs.append(parsed)

    return logs
