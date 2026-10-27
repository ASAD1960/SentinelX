
from collections import Counter, defaultdict


def analyze_events(events, failed_login_threshold=4):
    """
    Analyze security events and flag IP addresses with repeated
    failed login attempts.

    Raises:
        ValueError: If the threshold is invalid or an event is
                    missing required fields.
    """

    # Validate the failed-login threshold.
    if (
        isinstance(failed_login_threshold, bool)
        or not isinstance(failed_login_threshold, int)
        or failed_login_threshold <= 0
    ):
        raise ValueError(
            "failed_login_threshold must be a positive integer."
        )

    failed_logins = Counter()
    failed_users_by_ip = defaultdict(set)
    ip_events = defaultdict(list)
    alerts = []

    required_fields = {"ip_address", "event_type", "username"}

    for event in events:
        # Ensure each event is a dictionary with all required fields.
        if not isinstance(event, dict):
            raise ValueError("Each event must be a dictionary.")

        missing_fields = required_fields - event.keys()

        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(
                f"Event is missing required fields: {missing}"
            )

        ip_address = event["ip_address"]
        event_type = event["event_type"]
        username = event["username"]

        # Ensure required values are not empty.
        if not all(
            isinstance(value, str) and value.strip()
            for value in (ip_address, event_type, username)
        ):
            raise ValueError(
                "Event IP address, event type, and username "
                "must be non-empty strings."
            )

        ip_events[ip_address].append(event)

        if event_type == "login_failed":
            failed_logins[ip_address] += 1
            failed_users_by_ip[ip_address].add(username)

    for ip_address, count in failed_logins.items():
        if count >= failed_login_threshold:
            alerts.append({
                "ip_address": ip_address,
                "failed_attempts": count,
                "severity": "HIGH",
                "description": (
                    f"{count} failed login attempts detected "
                    f"from {ip_address}"
                ),
                "targeted_users": sorted(
                    failed_users_by_ip[ip_address]
                ),
            })

    return {
        "total_events": len(events),
        "failed_logins": sum(failed_logins.values()),
        "unique_ips": len(ip_events),
        "flagged_ips": len(alerts),
        "alerts": alerts,
    }
