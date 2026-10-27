
import statistics
import time
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

from log_parser import parse_log_file
from detection_engine import analyze_events

SAMPLE_LOG = Path(__file__).parent / "sample_logs" / "sample_auth.log"


def benchmark_dashboard(events, threshold=5, burst_attempts=5, burst_window=10):
    """Benchmark dashboard analysis without using the GUI or database."""
    start = time.perf_counter()

    results = analyze_events(events)

    failed_by_ip = Counter()
    users_by_ip = defaultdict(set)

    for event in events:
        if event.get("event_type", "").lower() == "login_failed":
            ip = event.get("ip_address", "Unknown")
            failed_by_ip[ip] += 1
            users_by_ip[ip].add(event.get("username", "Unknown"))

    brute_force_alerts = sum(
        1 for count in failed_by_ip.values() if count >= threshold
    )

    failed_times_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type", "").lower() != "login_failed":
            continue

        try:
            event_time = datetime.strptime(
                str(event.get("timestamp", "")),
                "%Y-%m-%d %H:%M:%S",
            )
        except ValueError:
            continue

        failed_times_by_ip[event.get("ip_address", "Unknown")].append(event_time)

    burst_alerts = 0

    for times in failed_times_by_ip.values():
        times.sort()
        left = 0

        for right, current_time in enumerate(times):
            while (
                current_time - times[left]
            ).total_seconds() > burst_window * 60:
                left += 1

            if right - left + 1 >= burst_attempts:
                burst_alerts += 1
                break

    elapsed = time.perf_counter() - start

    return {
        "events": len(events),
        "failed_logins": results["failed_logins"],
        "unique_ips": results["unique_ips"],
        "base_flagged_ips": results["flagged_ips"],
        "brute_force_alerts": brute_force_alerts,
        "burst_alerts": burst_alerts,
        "elapsed": elapsed,
    }


def main():
    if not SAMPLE_LOG.exists():
        print(f"Sample log not found: {SAMPLE_LOG}")
        return

    print("Loading sample log...")
    events, invalid_lines = parse_log_file(SAMPLE_LOG)

    if not events:
        print("No valid events found.")
        return

    print(f"Valid events: {len(events):,}")
    print(f"Invalid lines: {len(invalid_lines):,}")
    print("Running one warm-up and five measured runs...")

    benchmark_dashboard(events)  # Warm-up
    timings = []
    last_result = None

    for run_number in range(1, 6):
        last_result = benchmark_dashboard(events)
        timings.append(last_result["elapsed"])
        print(f"Run {run_number}: {last_result['elapsed']:.4f} seconds")

    average = statistics.mean(timings)
    median = statistics.median(timings)
    throughput = len(events) / median if median else 0

    print("\n--- SentinelX Dashboard Benchmark ---")
    print(f"Events analyzed: {last_result['events']:,}")
    print(f"Failed logins: {last_result['failed_logins']:,}")
    print(f"Unique IPs: {last_result['unique_ips']:,}")
    print(f"Base flagged IPs: {last_result['base_flagged_ips']:,}")
    print(f"Brute-force alerts: {last_result['brute_force_alerts']:,}")
    print(f"Burst alerts: {last_result['burst_alerts']:,}")
    print(f"Average time: {average:.4f} seconds")
    print(f"Median time: {median:.4f} seconds")
    print(f"Median throughput: {throughput:,.0f} events/second")


if __name__ == "__main__":
    main()
