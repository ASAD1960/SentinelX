
import csv
from datetime import datetime
from pathlib import Path


REPORTS_DIR = Path(__file__).parent / "reports"


def _ensure_reports_dir():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def export_events_csv(events, output_path=None):
    """Export security events to a CSV file."""
    _ensure_reports_dir()

    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"security_events_{timestamp}.csv"

    output_path = Path(output_path)

    fieldnames = [
        "timestamp",
        "severity",
        "username",
        "ip_address",
        "event_type",
    ]

    with output_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            writer.writerow({
                field: event.get(field, "")
                for field in fieldnames
            })

    return output_path


def export_analysis_report(results, output_path=None):
    """Export an analysis summary and security alerts as a text file."""
    _ensure_reports_dir()

    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORTS_DIR / f"security_report_{timestamp}.txt"

    output_path = Path(output_path)

    lines = [
        "SECURITY LOG ANALYSIS REPORT",
        "=" * 45,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Total events: {results['total_events']}",
        f"Failed logins: {results['failed_logins']}",
        f"Unique IP addresses: {results['unique_ips']}",
        f"Flagged IP addresses: {results['flagged_ips']}",
        "",
        "SECURITY ALERTS",
        "-" * 45,
    ]

    alerts = results.get("alerts", [])

    if not alerts:
        lines.append("No alerts detected.")
    else:
        for alert in alerts:
            lines.extend([
                f"Severity: {alert['severity']}",
                f"IP address: {alert['ip_address']}",
                f"Failed attempts: {alert['failed_attempts']}",
                f"Description: {alert['description']}",
                f"Targeted users: {', '.join(alert['targeted_users'])}",
                "",
            ])

    output_path.write_text("\n".join(lines), encoding="utf-8")

    return output_path
