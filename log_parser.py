
import re
import ipaddress
from datetime import datetime


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"\s*(?:\|\s*|\s+)"
    r"(?P<severity>INFO|WARNING|ERROR)"
    r"\s*(?:\|\s*|\s+)"
    r"user=(?P<username>\S+)"
    r"\s*(?:\|\s*|\s+)"
    r"ip=(?P<ip_address>\d{1,3}(?:\.\d{1,3}){3})"
    r"\s*(?:\|\s*|\s+)"
    r"event=(?P<event_type>[a-zA-Z_]+)"
    r"(?:\s*\|\s*.*)?$"
)


def parse_log_line(line):
    """Parse one log line into a structured dictionary."""
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    match = LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        datetime.strptime(
            data["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        ipaddress.IPv4Address(data["ip_address"])

    except ValueError:
        return None

    return data


def parse_log_file(file_path):
    """Read a log file and return valid events and invalid line numbers."""
    events = []
    invalid_lines = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip() or line.strip().startswith("#"):
                continue

            event = parse_log_line(line)

            if event is None:
                invalid_lines.append(line_number)
                continue

            events.append(event)

    return events, invalid_lines
