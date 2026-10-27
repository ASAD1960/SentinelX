
import time
from pathlib import Path

from log_parser import parse_log_file
from detection_engine import analyze_events


LOG_FILE = Path("sample_logs") / "sample_auth.log"


def main():
    if not LOG_FILE.exists():
        print(f"ERROR: Log file not found: {LOG_FILE}")
        return

    print("=" * 52)
    print("SentinelX - Detection Engine Benchmark")
    print("=" * 52)

    print("\nLoading security events...")
    events, invalid_lines = parse_log_file(LOG_FILE)

    if invalid_lines:
        print(f"Warning: {len(invalid_lines)} invalid lines found.")

    print(f"Events loaded: {len(events):,}")
    print("\nRunning detection benchmark...")

    start = time.perf_counter()
    results = analyze_events(events)
    elapsed = time.perf_counter() - start

    speed = (
        results["total_events"] / elapsed
        if elapsed > 0 else 0
    )

    print("\nRESULTS")
    print("-" * 52)
    print(f"Total events analyzed: {results['total_events']:,}")
    print(f"Failed login events:   {results['failed_logins']:,}")
    print(f"Unique IP addresses:   {results['unique_ips']:,}")
    print(f"Flagged IP addresses:  {results['flagged_ips']:,}")
    print(f"Detection time:        {elapsed:.4f} seconds")
    print(f"Analysis speed:        {speed:,.0f} events/second")

    print("\nBenchmark complete.")
    print("No database or original log files were modified.")


if __name__ == "__main__":
    main()
