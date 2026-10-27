
import os
import time
from pathlib import Path

from log_parser import parse_log_file

LOG_FILE = Path("sample_logs") / "sample_auth.log"


def main():
    if not LOG_FILE.exists():
        print(f"ERROR: Log file not found: {LOG_FILE}")
        return

    file_size_mb = os.path.getsize(LOG_FILE) / (1024 * 1024)

    print("=" * 50)
    print("SentinelX - Log Parser Benchmark")
    print("=" * 50)
    print(f"Log file: {LOG_FILE}")
    print(f"File size: {file_size_mb:.2f} MB")
    print("Running benchmark...\n")

    start = time.perf_counter()
    events, invalid_lines = parse_log_file(LOG_FILE)
    elapsed = time.perf_counter() - start

    total = len(events) + len(invalid_lines)
    speed = len(events) / elapsed if elapsed > 0 else 0

    print("RESULTS")
    print("-" * 50)
    print(f"Valid events parsed: {len(events):,}")
    print(f"Invalid log lines:   {len(invalid_lines):,}")
    print(f"Total processing time: {elapsed:.3f} seconds")
    print(f"Parsing speed: {speed:,.0f} events/second")

    if total:
        print(f"Valid event rate: {len(events) / total * 100:.2f}%")

    print("\nBenchmark complete.")
    print("Your original log file and database were not modified.")


if __name__ == "__main__":
    main()
