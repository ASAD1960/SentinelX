
import time
from pathlib import Path

from log_parser import parse_log_file
from database import SecurityDatabase

LOG_FILE = Path("sample_logs") / "sample_auth.log"
BENCHMARK_DB = Path("data") / "benchmark_security_logs.db"


def main():
    if not LOG_FILE.exists():
        print(f"ERROR: Log file not found: {LOG_FILE}")
        return

    # Remove only our dedicated benchmark database and its SQLite
    # journal files before starting, never the production database.
    for suffix in ("", "-journal", "-wal", "-shm"):
        path = Path(str(BENCHMARK_DB) + suffix)
        if path.exists():
            try:
                path.unlink()
            except PermissionError:
                print(f"ERROR: Close anything using {path} and retry.")
                return

    events, invalid_lines = parse_log_file(LOG_FILE)

    print("=" * 54)
    print("SentinelX - SQLite Database Benchmark")
    print("=" * 54)
    print(f"Valid events: {len(events):,}")
    print(f"Invalid lines: {len(invalid_lines):,}")

    db = SecurityDatabase(db_path=BENCHMARK_DB)

    start = time.perf_counter()
    saved = db.save_events(events)
    insert_time = time.perf_counter() - start

    start = time.perf_counter()
    count = db.count_events()
    count_time = time.perf_counter() - start

    start = time.perf_counter()
    retrieved = db.get_events()
    retrieval_time = time.perf_counter() - start

    start = time.perf_counter()
    duplicate_saved = db.save_events(events[:100])
    duplicate_time = time.perf_counter() - start

    print("\nRESULTS")
    print("-" * 54)
    print(f"New events inserted:  {saved:,}")
    print(f"Events counted:       {count:,}")
    print(f"Events retrieved:     {len(retrieved):,}")
    print(f"Duplicate rows added: {duplicate_saved:,}")
    print(f"Bulk insertion:       {insert_time:.4f} seconds")
    print(f"Count query:          {count_time:.4f} seconds")
    print(f"Full retrieval:       {retrieval_time:.4f} seconds")
    print(f"Duplicate check:      {duplicate_time:.4f} seconds")

    passed = (
        count == len(events)
        and len(retrieved) == len(events)
        and duplicate_saved == 0
    )

    print("\nPASS: Database checks succeeded." if passed
          else "\nCHECK: Review the results.")

    print(f"\nBenchmark database: {BENCHMARK_DB}")
    print("Your original security_logs.db was not modified.")
    print("The benchmark database is kept for inspection.")


if __name__ == "__main__":
    main()
