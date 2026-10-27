"""Reusable, testable helpers for Sentinel Security Log Analyzer."""
from collections import defaultdict
from datetime import datetime


def filter_events_by_date(events, start_date="", end_date=""):
    """Filter event dictionaries by inclusive YYYY-MM-DD date boundaries."""
    if start_date:
        datetime.strptime(start_date, "%Y-%m-%d")
    if end_date:
        datetime.strptime(end_date, "%Y-%m-%d")
    if start_date and end_date and start_date > end_date:
        raise ValueError("start_date must not be after end_date")
    result = []
    for event in events:
        date = str(event.get("timestamp", ""))[:10]
        if start_date and date < start_date:
            continue
        if end_date and date > end_date:
            continue
        result.append(event)
    return result


def calculate_ip_risk(events):
    """Return heuristic per-IP risk rows; scores are triage hints, not verdicts."""
    per_ip = defaultdict(lambda: {"failed": 0, "errors": 0, "users": set()})
    for event in events:
        ip = event.get("ip_address", "Unknown")
        record = per_ip[ip]
        if str(event.get("event_type", "")).lower() == "login_failed":
            record["failed"] += 1
        if str(event.get("severity", "")).upper() == "ERROR":
            record["errors"] += 1
        record["users"].add(event.get("username", "Unknown"))
    rows = []
    for ip, record in per_ip.items():
        score = min(100, record["failed"] * 4 + record["errors"] * 8 + max(0, len(record["users"]) - 1) * 3)
        level = "High" if score >= 70 else "Medium" if score >= 35 else "Low"
        rows.append({"ip_address": ip, "score": score, "risk": level,
                     "failed_logins": record["failed"], "error_events": record["errors"],
                     "unique_users": len(record["users"])})
    return sorted(rows, key=lambda row: row["score"], reverse=True)


def find_failed_login_bursts(events, attempts=5, window_minutes=10):
    """Find IPs with at least `attempts` failed logins inside a sliding time window."""
    if attempts < 2 or window_minutes < 1:
        raise ValueError("attempts must be >= 2 and window_minutes must be >= 1")
    times_by_ip = defaultdict(list)
    for event in events:
        if str(event.get("event_type", "")).lower() != "login_failed":
            continue
        try:
            timestamp = datetime.strptime(str(event.get("timestamp", "")), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        times_by_ip[event.get("ip_address", "Unknown")].append(timestamp)
    found = []
    window_seconds = window_minutes * 60
    for ip, timestamps in times_by_ip.items():
        timestamps.sort()
        left = 0
        for right, current in enumerate(timestamps):
            while left <= right and (current - timestamps[left]).total_seconds() > window_seconds:
                left += 1
            if right - left + 1 >= attempts:
                found.append({"ip_address": ip, "attempts_in_window": right - left + 1,
                              "window_minutes": window_minutes,
                              "first_seen": timestamps[left].strftime("%Y-%m-%d %H:%M:%S"),
                              "last_seen": current.strftime("%Y-%m-%d %H:%M:%S")})
                break
    return found
