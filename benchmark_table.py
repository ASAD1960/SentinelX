
import statistics
import time
import tkinter as tk
from tkinter import ttk


ROW_COUNTS = (1000, 2500, 5000)
REPEATS = 3


def make_event(index):
    return (
        f"2026-10-25 {index % 24:02d}:{index % 60:02d}:00",
        ("INFO", "WARNING", "ERROR")[index % 3],
        f"user_{index % 100:03d}",
        f"192.168.{(index // 250) % 255}.{index % 250 + 1}",
        ("login_success", "login_failed", "file_access")[index % 3],
    )


def benchmark_table(root, tree, row_count):
    rows = [make_event(i) for i in range(row_count)]

    # Remove any rows from the previous test.
    for item in tree.get_children():
        tree.delete(item)

    # Measure the time to insert the requested number of rows.
    start = time.perf_counter()

    for row in rows:
        tree.insert("", "end", values=row)

    # Process pending GUI updates before stopping the timer.
    root.update_idletasks()

    return time.perf_counter() - start


def main():
    root = tk.Tk()
    root.title("SentinelX Table Benchmark")
    root.geometry("900x450")

    ttk.Label(
        root,
        text="SentinelX — Security Event Table Benchmark",
        font=("Segoe UI", 14, "bold"),
    ).pack(pady=12)

    columns = ("timestamp", "severity", "username", "ip_address", "event_type")
    tree = ttk.Treeview(root, columns=columns, show="headings")

    for column, heading in zip(
        columns,
        ("TIMESTAMP", "SEVERITY", "USERNAME", "SOURCE IP", "EVENT TYPE"),
    ):
        tree.heading(column, text=heading)
        tree.column(column, width=165)

    tree.pack(fill="both", expand=True, padx=12, pady=8)

    root.update()

    print("\nSentinelX table-rendering benchmark")
    print("Times include Treeview insertions and pending idle GUI updates.")
    print("First run is a warm-up; three runs are measured per size.\n")

    try:
        for row_count in ROW_COUNTS:
            # Warm-up run
            benchmark_table(root, tree, row_count)

            timings = []

            for run_number in range(1, REPEATS + 1):
                elapsed = benchmark_table(root, tree, row_count)
                timings.append(elapsed)
                print(
                    f"{row_count:>5,} rows | "
                    f"Run {run_number}: {elapsed:.4f} seconds"
                )

            print(
                f"       Median: "
                f"{statistics.median(timings):.4f} seconds\n"
            )

    finally:
        root.destroy()

    print("Benchmark complete.")


if __name__ == "__main__":
    main()
