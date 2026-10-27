import tkinter as tk
import re
import sqlite3
import hashlib
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from collections import Counter
from datetime import datetime

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from log_parser import parse_log_file, parse_log_line
from detection_engine import analyze_events
from database import SecurityDatabase
from report_exporter import export_events_csv, export_analysis_report


APP_DIR = Path(__file__).parent
SAMPLE_LOG = APP_DIR / "sample_logs" / "sample_auth.log"


class SecurityLogAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("SentinelX | Security Event Intelligence")
        self.root.geometry("1400x900")
        self.root.minsize(1120, 720)

        self.database = SecurityDatabase()
        self.events = []
        self.results = None

        self.search_var = tk.StringVar()
        self.severity_var = tk.StringVar(value="All")
        self.start_date_var = tk.StringVar()
        self.end_date_var = tk.StringVar()
        self.threshold_var = tk.StringVar(value="5")
        self.burst_attempts_var = tk.StringVar(value="5")
        self.burst_window_var = tk.StringVar(value="10")
        self.status_var = tk.StringVar(value="Ready")

        self.monitor_path = None
        self.monitor_offset = 0
        self.monitor_active = False
        self.monitor_job = None

        self.feature_db_path = APP_DIR / "data" / "security_logs.db"
        self.feature_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_feature_storage()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.setup_style()
        self.build_interface()
        self.load_sample()

    # ---------------------------------------------------------
    # STYLING
    # ---------------------------------------------------------

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        self.root.configure(bg="#eef2f7")

        style.configure(
            "TFrame",
            background="#eef2f7",
        )
        style.configure(
            "Card.TFrame",
            background="#ffffff",
        )
        style.configure(
            "TLabel",
            background="#eef2f7",
            foreground="#334155",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Muted.TLabel",
            background="#eef2f7",
            foreground="#64748b",
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardTitle.TLabel",
            background="#ffffff",
            foreground="#64748b",
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "CardValue.TLabel",
            background="#ffffff",
            foreground="#0f172a",
            font=("Segoe UI", 23, "bold"),
        )
        style.configure(
            "Section.TLabel",
            background="#ffffff",
            foreground="#0f172a",
            font=("Segoe UI", 11, "bold"),
        )

        style.configure(
            "TButton",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 8),
            background="#e2e8f0",
            foreground="#0f172a",
            borderwidth=0,
        )
        style.map(
            "TButton",
            background=[("active", "#cbd5e1")],
        )

        style.configure(
            "Primary.TButton",
            background="#2563eb",
            foreground="#ffffff",
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#1d4ed8")],
            foreground=[("active", "#ffffff")],
        )

        style.configure(
            "Dark.TButton",
            background="#1e293b",
            foreground="#ffffff",
        )
        style.map(
            "Dark.TButton",
            background=[("active", "#334155")],
        )

        style.configure(
            "TEntry",
            padding=7,
            fieldbackground="#ffffff",
            foreground="#0f172a",
        )
        style.configure(
            "TCombobox",
            padding=6,
            fieldbackground="#ffffff",
            foreground="#0f172a",
        )
        style.configure(
            "TSpinbox",
            padding=5,
            fieldbackground="#ffffff",
        )

        style.configure(
            "Treeview",
            background="#ffffff",
            fieldbackground="#ffffff",
            foreground="#334155",
            rowheight=32,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#f1f5f9",
            foreground="#475569",
            font=("Segoe UI", 9, "bold"),
            padding=(9, 10),
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#dbeafe")],
            foreground=[("selected", "#1e3a8a")],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#e2e8f0",
            troughcolor="#f8fafc",
            borderwidth=0,
            arrowsize=12,
        )

    # ---------------------------------------------------------
    # MAIN DASHBOARD
    # ---------------------------------------------------------

    def build_interface(self):
        shell = tk.Frame(self.root, bg="#eef2f7")
        shell.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(shell, bg="#0f172a", width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = tk.Frame(
            sidebar,
            bg="#0f172a",
            padx=18,
            pady=24,
        )
        brand.pack(fill="x")

        tk.Label(
            brand,
            text="◈  SENTINELX",
            bg="#0f172a",
            fg="#f8fafc",
            font=("Segoe UI", 17, "bold"),
        ).pack(anchor="w")

        tk.Label(
            brand,
            text="SECURITY OPERATIONS",
            bg="#0f172a",
            fg="#94a3b8",
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(6, 0))

        tk.Frame(
            sidebar,
            bg="#334155",
            height=1,
        ).pack(fill="x", padx=16, pady=(2, 16))

        tk.Label(
            sidebar,
            text="WORKSPACE",
            bg="#0f172a",
            fg="#64748b",
            font=("Segoe UI", 8, "bold"),
            padx=18,
        ).pack(anchor="w", pady=(0, 8))

        self._nav_button(sidebar, "▦   Overview", lambda: None, active=True)
        self._nav_button(sidebar, "⇧   Load log file", self.load_file)
        self._nav_button(sidebar, "⌁   Analyze events", self.analyze)
        self._nav_button(sidebar, "▥   Analytics", self.show_analytics)
        self._nav_button(sidebar, "◉   Real-time monitor", self.start_realtime_monitor)
        self._nav_button(sidebar, "⚑   Manage alerts", self.show_alert_management)
        self._nav_button(sidebar, "⌁   IP risk scores", self.show_ip_risk_scores)

        tk.Label(
            sidebar,
            text="REPORTS",
            bg="#0f172a",
            fg="#64748b",
            font=("Segoe UI", 8, "bold"),
            padx=18,
        ).pack(anchor="w", pady=(24, 8))

        self._nav_button(sidebar, "⇩   Export CSV", self.export_csv)
        self._nav_button(sidebar, "▤   Export report", self.export_report)
        self._nav_button(sidebar, "▧   Export PDF report", self.export_pdf_report)

        sidebar_bottom = tk.Frame(
            sidebar,
            bg="#0f172a",
            padx=18,
            pady=18,
        )
        sidebar_bottom.pack(side="bottom", fill="x")

        tk.Label(
            sidebar_bottom,
            text="●  LOCAL ANALYSIS",
            bg="#0f172a",
            fg="#86efac",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")

        tk.Label(
            sidebar_bottom,
            text="Logs stay on this machine",
            bg="#0f172a",
            fg="#94a3b8",
            font=("Segoe UI", 8),
            wraplength=175,
            justify="left",
        ).pack(anchor="w", pady=(6, 0))

        # Main content
        content = tk.Frame(
            shell,
            bg="#eef2f7",
            padx=24,
            pady=22,
        )
        content.pack(side="left", fill="both", expand=True)

        # Header
        top = tk.Frame(content, bg="#eef2f7")
        top.pack(fill="x", pady=(0, 18))

        title_area = tk.Frame(top, bg="#eef2f7")
        title_area.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_area,
            text="Security overview",
            bg="#eef2f7",
            fg="#0f172a",
            font=("Segoe UI", 23, "bold"),
        ).pack(anchor="w")

        tk.Label(
            title_area,
            text=(
                "Monitor authentication activity, identify suspicious "
                "patterns, and export findings."
            ),
            bg="#eef2f7",
            fg="#64748b",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 0))

        ttk.Button(
            top,
            text="＋  Load log file",
            style="Primary.TButton",
            command=self.load_file,
        ).pack(side="right", padx=(8, 0))

        ttk.Button(
            top,
            text="↻  Analyze",
            command=self.analyze,
        ).pack(side="right")

        # Metric cards
        self.metrics_frame = tk.Frame(content, bg="#eef2f7")
        self.metrics_frame.pack(fill="x", pady=(0, 16))

        self.metric_values = {}

        metrics = [
            ("TOTAL EVENTS", "total", "#2563eb", "▤"),
            ("FAILED LOGINS", "failed", "#d97706", "!"),
            ("UNIQUE IP ADDRESSES", "ips", "#0891b2", "⌁"),
            ("FLAGGED IP ADDRESSES", "flagged", "#dc2626", "⚑"),
        ]

        for index, (label, key, accent, symbol) in enumerate(metrics):
            card = tk.Frame(
                self.metrics_frame,
                bg="#ffffff",
                highlightbackground="#e2e8f0",
                highlightthickness=1,
                padx=17,
                pady=15,
            )
            card.grid(
                row=0,
                column=index,
                sticky="nsew",
                padx=(0 if index == 0 else 10, 0),
            )

            self.metrics_frame.columnconfigure(index, weight=1)

            line = tk.Frame(card, bg="#ffffff")
            line.pack(fill="x")

            tk.Label(
                line,
                text=label,
                bg="#ffffff",
                fg="#64748b",
                font=("Segoe UI", 8, "bold"),
            ).pack(side="left", anchor="w")

            tk.Label(
                line,
                text=symbol,
                bg="#eff6ff",
                fg=accent,
                font=("Segoe UI", 12, "bold"),
                width=3,
                pady=3,
            ).pack(side="right")

            value = tk.Label(
                card,
                text="0",
                bg="#ffffff",
                fg="#0f172a",
                font=("Segoe UI", 25, "bold"),
            )
            value.pack(anchor="w", pady=(9, 0))

            self.metric_values[key] = value

        # Filters
        filter_card = tk.Frame(
            content,
            bg="#ffffff",
            highlightbackground="#e2e8f0",
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        filter_card.pack(fill="x", pady=(0, 14))

        tk.Label(
            filter_card,
            text="EVENT FILTERS",
            bg="#ffffff",
            fg="#0f172a",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        row1 = tk.Frame(filter_card, bg="#ffffff")
        row1.pack(fill="x")

        tk.Label(
            row1,
            text="Search",
            bg="#ffffff",
            fg="#475569",
            font=("Segoe UI", 9),
        ).pack(side="left")

        search_entry = ttk.Entry(
            row1,
            textvariable=self.search_var,
            width=24,
        )
        search_entry.pack(side="left", padx=(8, 14))

        self.search_var.trace_add("write", self.refresh_table)

        ttk.Label(
            row1,
            text="Severity",
            background="#ffffff",
        ).pack(side="left")

        severity_filter = ttk.Combobox(
            row1,
            textvariable=self.severity_var,
            values=("All", "INFO", "WARNING", "ERROR"),
            state="readonly",
            width=11,
        )
        severity_filter.pack(side="left", padx=(8, 16))
        severity_filter.bind("<<ComboboxSelected>>", self.refresh_table)

        ttk.Label(row1, text="From", background="#ffffff").pack(side="left")

        ttk.Entry(
            row1,
            textvariable=self.start_date_var,
            width=12,
        ).pack(side="left", padx=(6, 10))

        ttk.Label(row1, text="To", background="#ffffff").pack(side="left")

        ttk.Entry(
            row1,
            textvariable=self.end_date_var,
            width=12,
        ).pack(side="left", padx=(6, 10))

        ttk.Button(
            row1,
            text="Apply dates",
            style="Primary.TButton",
            command=self.apply_date_filter,
        ).pack(side="left", padx=(0, 6))

        ttk.Button(
            row1,
            text="Reset",
            command=self.clear_date_filter,
        ).pack(side="left")

        # Detection settings
        row2 = tk.Frame(filter_card, bg="#ffffff")
        row2.pack(fill="x", pady=(13, 0))

        tk.Label(
            row2,
            text="DETECTION RULES",
            bg="#ffffff",
            fg="#64748b",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(0, 12))

        ttk.Label(
            row2,
            text="Failed logins / IP",
            background="#ffffff",
        ).pack(side="left")

        ttk.Spinbox(
            row2,
            from_=2,
            to=100,
            width=5,
            textvariable=self.threshold_var,
        ).pack(side="left", padx=(6, 14))

        ttk.Label(
            row2,
            text="Burst attempts",
            background="#ffffff",
        ).pack(side="left")

        ttk.Spinbox(
            row2,
            from_=2,
            to=100,
            width=5,
            textvariable=self.burst_attempts_var,
        ).pack(side="left", padx=(6, 10))

        ttk.Label(row2, text="within", background="#ffffff").pack(side="left")

        ttk.Spinbox(
            row2,
            from_=1,
            to=1440,
            width=6,
            textvariable=self.burst_window_var,
        ).pack(side="left", padx=6)

        ttk.Label(
            row2,
            text="minutes",
            background="#ffffff",
        ).pack(side="left")

        ttk.Button(
            row2,
            text="Apply rules",
            command=self.apply_threshold,
        ).pack(side="left", padx=(14, 0))

        tk.Label(
            row2,
            text="Dates: YYYY-MM-DD",
            bg="#ffffff",
            fg="#94a3b8",
            font=("Segoe UI", 8),
        ).pack(side="right")

        # Event table
        table_card = tk.Frame(
            content,
            bg="#ffffff",
            highlightbackground="#e2e8f0",
            highlightthickness=1,
        )
        table_card.pack(fill="both", expand=True)

        table_header = tk.Frame(
            table_card,
            bg="#ffffff",
            padx=16,
            pady=12,
        )
        table_header.pack(fill="x")

        tk.Label(
            table_header,
            text="Security events",
            bg="#ffffff",
            fg="#0f172a",
            font=("Segoe UI", 12, "bold"),
        ).pack(side="left")

        tk.Label(
            table_header,
            text="Live view of loaded log entries",
            bg="#ffffff",
            fg="#64748b",
            font=("Segoe UI", 9),
        ).pack(side="left", padx=12)

        # New matching-event count
        self.table_count_label = tk.Label(
            table_header,
            text="0 matching events",
            bg="#eff6ff",
            fg="#1d4ed8",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=5,
        )
        self.table_count_label.pack(side="right")

        tk.Frame(
            table_card,
            bg="#e2e8f0",
            height=1,
        ).pack(fill="x")

        table_frame = tk.Frame(
            table_card,
            bg="#ffffff",
            padx=12,
            pady=10,
        )
        table_frame.pack(fill="both", expand=True)

        columns = (
            "timestamp",
            "severity",
            "username",
            "ip_address",
            "event_type",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
        )

        headings = {
            "timestamp": ("TIMESTAMP", 180),
            "severity": ("SEVERITY", 105),
            "username": ("USERNAME", 140),
            "ip_address": ("SOURCE IP", 160),
            "event_type": ("EVENT TYPE", 200),
        }

        for column, (heading, width) in headings.items():
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview,
        )

        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Severity colors and alternating rows
        self.tree.tag_configure(
            "INFO",
            background="#ffffff",
            foreground="#334155",
        )
        self.tree.tag_configure(
            "WARNING",
            background="#fff7ed",
            foreground="#9a3412",
        )
        self.tree.tag_configure(
            "ERROR",
            background="#fef2f2",
            foreground="#b91c1c",
        )
        self.tree.tag_configure(
            "INFO_ALT",
            background="#f8fafc",
            foreground="#334155",
        )
        self.tree.tag_configure(
            "WARNING_ALT",
            background="#ffedd5",
            foreground="#9a3412",
        )
        self.tree.tag_configure(
            "ERROR_ALT",
            background="#fee2e2",
            foreground="#b91c1c",
        )

        # Bottom status and alerts
        bottom = tk.Frame(content, bg="#eef2f7")
        bottom.pack(fill="x", pady=(12, 0))

        self.status_label = tk.Label(
            bottom,
            textvariable=self.status_var,
            bg="#eef2f7",
            fg="#334155",
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=430,
        )
        self.status_label.pack(side="left", fill="x", expand=True)

        alert_card = tk.Frame(
            bottom,
            bg="#fff7ed",
            highlightbackground="#fed7aa",
            highlightthickness=1,
            padx=12,
            pady=9,
        )
        alert_card.pack(
            side="right",
            fill="x",
            expand=True,
            padx=(18, 0),
        )

        tk.Label(
            alert_card,
            text="⚑  SECURITY ALERTS",
            bg="#fff7ed",
            fg="#9a3412",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")

        self.alert_text = tk.Text(
            alert_card,
            height=3,
            wrap="word",
            font=("Segoe UI", 9),
            bg="#fff7ed",
            fg="#7c2d12",
            relief="flat",
            state="disabled",
            borderwidth=0,
        )
        self.alert_text.pack(fill="x", pady=(5, 0))

        ttk.Button(
            alert_card,
            text="Investigate alerts  →",
            style="Primary.TButton",
            command=self.show_alert_investigation,
        ).pack(anchor="e", pady=(7, 0))

    def _nav_button(self, parent, label, command, active=False):
        normal_bg = "#1d4ed8" if active else "#0f172a"
        hover_bg = "#1e40af" if active else "#1e293b"
        normal_fg = "#ffffff" if active else "#cbd5e1"

        button = tk.Button(
            parent,
            text=label,
            command=command,
            anchor="w",
            relief="flat",
            bd=0,
            bg=normal_bg,
            fg=normal_fg,
            activebackground=hover_bg,
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            padx=18,
            pady=11,
            cursor="hand2",
            takefocus=True,
        )

        button.pack(fill="x", padx=10, pady=2)

        button.bind(
            "<Enter>",
            lambda _event: button.configure(bg=hover_bg),
        )
        button.bind(
            "<Leave>",
            lambda _event: button.configure(bg=normal_bg),
        )

    # ---------------------------------------------------------
    # FILE LOADING
    # ---------------------------------------------------------

    def on_close(self):
        self.monitor_active = False

        if self.monitor_job:
            try:
                self.root.after_cancel(self.monitor_job)
            except tk.TclError:
                pass

        self.root.destroy()

    def load_sample(self):
        if SAMPLE_LOG.exists():
            self.process_file(SAMPLE_LOG)

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a security log file",
            filetypes=[
                ("Log files", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )

        if file_path:
            self.process_file(Path(file_path))

    def process_file(self, file_path):
        try:
            events, invalid_lines = parse_log_file(file_path)
        except (OSError, UnicodeError, ValueError) as error:
            messagebox.showerror(
                "File Error",
                f"Could not read the selected file:\n{error}",
            )
            return

        if not events:
            messagebox.showwarning(
                "No Valid Events",
                "No valid log entries were found in this file.",
            )
            return

        self.events = events

        try:
            self.database.save_events(self.events)
            saved_count = self.database.save_events([])
        except Exception as error:
            messagebox.showerror(
                "Database Error",
                f"Events were analyzed but could not be saved:\n{error}",
            )
            saved_count = 0

        # Recalculate the dashboard using the active filters.
        self.update_date_filtered_dashboard()
        self.refresh_table()

        status = (
            f"Loaded {len(events):,} events from {file_path.name}. "
        )

        if invalid_lines:
            status += f"Skipped {len(invalid_lines)} invalid lines. "

        status += f"Database save operation completed."

        self.status_var.set(status)

    # ---------------------------------------------------------
    # ANALYSIS AND METRICS
    # ---------------------------------------------------------

    def analyze(self):
        if not self.events:
            messagebox.showinfo(
                "No Events",
                "Load a log file before analyzing.",
            )
            return

        self.update_date_filtered_dashboard()
        self.refresh_table()

        self.status_var.set(
            "Analysis completed for the selected date range."
        )

    def get_date_filtered_events(self):
        start_date = self.start_date_var.get().strip()
        end_date = self.end_date_var.get().strip()

        filtered = []

        for event in self.events:
            event_date = str(event.get("timestamp", ""))[:10]

            if start_date and event_date < start_date:
                continue

            if end_date and event_date > end_date:
                continue

            filtered.append(event)

        return filtered

    def update_date_filtered_dashboard(self):
        filtered_events = self.get_date_filtered_events()

        self.results = (
            analyze_events(filtered_events)
            if filtered_events
            else {
                "total_events": 0,
                "failed_logins": 0,
                "unique_ips": 0,
                "flagged_ips": 0,
                "alerts": [],
            }
        )

        try:
            threshold = int(self.threshold_var.get())
        except (ValueError, AttributeError):
            threshold = 5

        failed_by_ip = Counter()
        users_by_ip = {}

        for event in filtered_events:
            if event.get("event_type", "").lower() == "login_failed":
                ip = event.get("ip_address", "Unknown")
                failed_by_ip[ip] += 1
                users_by_ip.setdefault(ip, set()).add(
                    event.get("username", "Unknown")
                )

        custom_alerts = []

        for ip, count in failed_by_ip.items():
            if count >= threshold:
                custom_alerts.append({
                    "severity": "HIGH",
                    "ip_address": ip,
                    "description": (
                        f"Brute-force suspicion: {count} failed login "
                        f"attempts from {ip} in the selected date range "
                        f"(threshold: {threshold})."
                    ),
                    "targeted_users": sorted(users_by_ip.get(ip, set())),
                })

        try:
            burst_attempts = int(self.burst_attempts_var.get())
            burst_window = int(self.burst_window_var.get())
        except (ValueError, AttributeError):
            burst_attempts, burst_window = 5, 10

        failed_times_by_ip = {}

        for event in filtered_events:
            if event.get("event_type", "").lower() != "login_failed":
                continue

            ip = event.get("ip_address", "Unknown")

            try:
                event_time = datetime.strptime(
                    str(event.get("timestamp", "")),
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError:
                continue

            failed_times_by_ip.setdefault(ip, []).append(event_time)

        for ip, times in failed_times_by_ip.items():
            times.sort()
            left = 0
            burst_found = False

            for right, current_time in enumerate(times):
                while (
                    left <= right
                    and (current_time - times[left]).total_seconds()
                    > burst_window * 60
                ):
                    left += 1

                if right - left + 1 >= burst_attempts:
                    burst_found = True
                    break

            if burst_found:
                custom_alerts.append({
                    "severity": "HIGH",
                    "ip_address": ip,
                    "description": (
                        f"Rapid failed-login burst: at least "
                        f"{burst_attempts} failed attempts from {ip} "
                        f"within {burst_window} minutes."
                    ),
                    "targeted_users": sorted(users_by_ip.get(ip, set())),
                })

        self.results.setdefault("alerts", []).extend(custom_alerts)

        self.results["flagged_ips"] = max(
            self.results.get("flagged_ips", 0),
            len({
                ip
                for ip, count in failed_by_ip.items()
                if count >= threshold
            }),
        )

        self.update_metrics()
        self.update_alerts()

    def update_metrics(self):
        if not self.results:
            return

        values = {
            "total": self.results["total_events"],
            "failed": self.results["failed_logins"],
            "ips": self.results["unique_ips"],
            "flagged": self.results["flagged_ips"],
        }

        for key, value in values.items():
            self.metric_values[key].configure(text=f"{value:,}")

        if self.results["flagged_ips"]:
            self.metric_values["flagged"].configure(fg="#dc2626")
        else:
            self.metric_values["flagged"].configure(fg="#15803d")

    def apply_threshold(self):
        try:
            threshold = int(self.threshold_var.get())
            if not 2 <= threshold <= 100:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Invalid Threshold",
                "Enter a whole number from 2 to 100.",
            )
            return

        try:
            burst_attempts = int(self.burst_attempts_var.get())
            burst_window = int(self.burst_window_var.get())

            if (
                not 2 <= burst_attempts <= 100
                or not 1 <= burst_window <= 1440
            ):
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Invalid Burst Settings",
                "Burst attempts must be 2–100 and the time window "
                "must be 1–1440 minutes.",
            )
            return

        self.update_date_filtered_dashboard()
        self.status_var.set(
            f"Rules applied: {threshold} failed logins per IP; "
            f"{burst_attempts} attempts within {burst_window} minutes."
        )

    # ---------------------------------------------------------
    # FILTERS AND TABLE
    # ---------------------------------------------------------

    def apply_date_filter(self):
        start_date = self.start_date_var.get().strip()
        end_date = self.end_date_var.get().strip()

        try:
            if start_date:
                datetime.strptime(start_date, "%Y-%m-%d")

            if end_date:
                datetime.strptime(end_date, "%Y-%m-%d")

        except ValueError:
            messagebox.showerror(
                "Invalid Date",
                "Enter dates in YYYY-MM-DD format, for example 2026-10-26.",
            )
            return

        if start_date and end_date and start_date > end_date:
            messagebox.showerror(
                "Invalid Date Range",
                "The From date cannot be later than the To date.",
            )
            return

        self.update_date_filtered_dashboard()
        self.refresh_table()

        self.status_var.set("Date filters applied to the dashboard.")

    def clear_date_filter(self):
        self.start_date_var.set("")
        self.end_date_var.set("")

        self.update_date_filtered_dashboard()
        self.refresh_table()

        self.status_var.set("Date filters cleared; showing all events.")

    def refresh_table(self, *_):
        if not hasattr(self, "tree"):
            return

        query = self.search_var.get().strip().lower()
        selected_severity = self.severity_var.get()
        start_date = self.start_date_var.get().strip()
        end_date = self.end_date_var.get().strip()

        self.tree.delete(*self.tree.get_children())

        shown_count = 0
        matched_count = 0
        max_rows = 5000

        for event in self.events:
            searchable = " ".join(
                str(value) for value in event.values()
            )

            if query and query not in searchable.lower():
                continue

            if (
                selected_severity != "All"
                and event.get("severity") != selected_severity
            ):
                continue

            event_date = str(event.get("timestamp", ""))[:10]

            if start_date and event_date < start_date:
                continue

            if end_date and event_date > end_date:
                continue

            matched_count += 1

            if shown_count >= max_rows:
                continue

            severity = str(event.get("severity", "INFO")).upper()

            if severity not in {"INFO", "WARNING", "ERROR"}:
                severity = "INFO"

            tag = severity if shown_count % 2 == 0 else f"{severity}_ALT"

            self.tree.insert(
                "",
                "end",
                values=(
                    event.get("timestamp", ""),
                    event.get("severity", ""),
                    event.get("username", ""),
                    event.get("ip_address", ""),
                    event.get("event_type", ""),
                ),
                tags=(tag,),
            )

            shown_count += 1

        if hasattr(self, "table_count_label"):
            label = (
                "1 matching event"
                if matched_count == 1
                else f"{matched_count:,} matching events"
            )
            self.table_count_label.configure(text=label)

        if matched_count > max_rows:
            self.status_var.set(
                f"Showing {max_rows:,} of {matched_count:,} matching events. "
                "Narrow your filters to view fewer rows."
            )

    # ---------------------------------------------------------
    # ANALYTICS
    # ---------------------------------------------------------

    def show_analytics(self):
        if not self.events:
            messagebox.showinfo(
                "No Events",
                "Load a log file before viewing analytics.",
            )
            return

        filtered_events = self.get_date_filtered_events()

        if not filtered_events:
            messagebox.showinfo(
                "No Events in Date Range",
                "There are no events within the selected date range.",
            )
            return

        event_counts = Counter(
            event["event_type"] for event in filtered_events
        )
        severity_counts = Counter(
            event["severity"] for event in filtered_events
        )
        failed_ip_counts = Counter(
            event["ip_address"]
            for event in filtered_events
            if event["event_type"] == "login_failed"
        )

        chart_window = tk.Toplevel(self.root)
        chart_window.title("SentinelX | Security Analytics")
        chart_window.geometry("1100x750")
        chart_window.configure(bg="white")

        figure = Figure(figsize=(11, 7), dpi=100)
        figure.suptitle(
            "SentinelX Security Event Analytics",
            fontsize=16,
            fontweight="bold",
        )

        event_ax = figure.add_subplot(221)
        severity_ax = figure.add_subplot(222)
        ip_ax = figure.add_subplot(223)
        heat_ax = figure.add_subplot(224)

        if event_counts:
            event_ax.pie(
                list(event_counts.values()),
                labels=list(event_counts.keys()),
                autopct="%1.1f%%",
                startangle=90,
            )
            event_ax.set_title("Event Distribution")

        if severity_counts:
            severity_ax.bar(
                list(severity_counts.keys()),
                list(severity_counts.values()),
            )
            severity_ax.set_title("Severity Distribution")
            severity_ax.set_ylabel("Number of Events")

        top_ips = failed_ip_counts.most_common(5)

        if top_ips:
            ip_ax.barh(
                [ip for ip, _count in reversed(top_ips)],
                [count for _ip, count in reversed(top_ips)],
            )
            ip_ax.set_title("Top IPs by Failed Login Attempts")
            ip_ax.set_xlabel("Failed Login Attempts")
        else:
            ip_ax.text(
                0.5,
                0.5,
                "No failed login attempts",
                ha="center",
                va="center",
                transform=ip_ax.transAxes,
            )
            ip_ax.set_title("Failed Login Attempts")

        heat = [[0 for _ in range(24)] for _ in range(7)]

        for event in filtered_events:
            try:
                stamp = datetime.strptime(
                    str(event.get("timestamp", "")),
                    "%Y-%m-%d %H:%M:%S",
                )
                heat[stamp.weekday()][stamp.hour] += 1
            except ValueError:
                continue

        heat_ax.imshow(heat, aspect="auto", interpolation="nearest")
        heat_ax.set_title("Activity Heatmap (weekday × hour)")
        heat_ax.set_xlabel("Hour of day")
        heat_ax.set_ylabel("Weekday")
        heat_ax.set_xticks(range(0, 24, 3))
        heat_ax.set_yticks(range(7))
        heat_ax.set_yticklabels(
            ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        )

        figure.tight_layout(rect=[0, 0, 1, 0.95])

        canvas = FigureCanvasTkAgg(figure, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10,
        )

    # ---------------------------------------------------------
    # ALERT STORAGE AND MANAGEMENT
    # ---------------------------------------------------------

    def init_feature_storage(self):
        with sqlite3.connect(self.feature_db_path) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS alert_workflow (
                    alert_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'New',
                    notes TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                )
            """)

    @staticmethod
    def _alert_id(alert):
        key = "|".join([
            str(alert.get("ip_address", "")),
            str(alert.get("severity", "")),
            str(alert.get("description", "")),
        ])

        return hashlib.sha256(
            key.encode("utf-8")
        ).hexdigest()[:24]

    def _get_workflow(self, alert):
        alert_id = self._alert_id(alert)

        with sqlite3.connect(self.feature_db_path) as connection:
            row = connection.execute(
                "SELECT status, notes FROM alert_workflow WHERE alert_id=?",
                (alert_id,),
            ).fetchone()

        return row if row else ("New", "")

    def _save_workflow(self, alert, status, notes):
        alert_id = self._alert_id(alert)

        with sqlite3.connect(self.feature_db_path) as connection:
            connection.execute("""
                INSERT INTO alert_workflow(
                    alert_id, status, notes, updated_at
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    status=excluded.status,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
            """, (
                alert_id,
                status,
                notes,
                datetime.now().isoformat(timespec="seconds"),
            ))

    def show_alert_management(self):
        alerts = list(self.results.get("alerts", [])) if self.results else []

        window = tk.Toplevel(self.root)
        window.title("SentinelX | Alert Management")
        window.geometry("1050x650")
        window.configure(bg="#eef2f7")

        header = tk.Frame(
            window,
            bg="#0f172a",
            padx=20,
            pady=16,
        )
        header.pack(fill="x")

        tk.Label(
            header,
            text="Alert management",
            bg="#0f172a",
            fg="#f8fafc",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Track alert status and save investigation notes. "
                 "Changes persist in SQLite.",
            bg="#0f172a",
            fg="#cbd5e1",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 0))

        body = tk.Frame(
            window,
            bg="#eef2f7",
            padx=16,
            pady=16,
        )
        body.pack(fill="both", expand=True)

        columns = ("severity", "status", "ip", "description")
        tree = ttk.Treeview(
            body,
            columns=columns,
            show="headings",
            height=11,
        )

        for col, title, width in [
            ("severity", "SEVERITY", 90),
            ("status", "STATUS", 120),
            ("ip", "SOURCE IP", 130),
            ("description", "ALERT", 580),
        ]:
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w")

        tree.pack(fill="both", expand=True)

        edit = tk.Frame(
            body,
            bg="#ffffff",
            padx=12,
            pady=12,
        )
        edit.pack(fill="x", pady=(12, 0))

        tk.Label(edit, text="Status", bg="#ffffff").grid(
            row=0, column=0, sticky="w"
        )

        status_var = tk.StringVar(value="New")

        ttk.Combobox(
            edit,
            textvariable=status_var,
            values=("New", "Investigating", "Resolved", "False Positive"),
            state="readonly",
            width=18,
        ).grid(row=0, column=1, padx=8, sticky="w")

        tk.Label(
            edit,
            text="Investigation notes",
            bg="#ffffff",
        ).grid(row=1, column=0, sticky="nw", pady=(10, 0))

        notes = tk.Text(
            edit,
            height=4,
            wrap="word",
            font=("Segoe UI", 9),
        )
        notes.grid(
            row=1,
            column=1,
            columnspan=2,
            sticky="ew",
            padx=8,
            pady=(10, 0),
        )

        edit.columnconfigure(1, weight=1)

        alert_by_iid = {}

        def refresh_rows():
            tree.delete(*tree.get_children())
            alert_by_iid.clear()

            for i, alert in enumerate(alerts):
                status, _note = self._get_workflow(alert)
                iid = str(i)
                alert_by_iid[iid] = alert

                tree.insert(
                    "",
                    "end",
                    iid=iid,
                    values=(
                        alert.get("severity", "UNKNOWN"),
                        status,
                        alert.get("ip_address", "Unknown"),
                        alert.get("description", "Security alert"),
                    ),
                )

        def load_selected(_event=None):
            selection = tree.selection()

            if not selection:
                return

            alert = alert_by_iid[selection[0]]
            status, note = self._get_workflow(alert)

            status_var.set(status)
            notes.delete("1.0", "end")
            notes.insert("1.0", note)

        def save_selected():
            selection = tree.selection()

            if not selection:
                messagebox.showinfo(
                    "Select Alert",
                    "Select an alert before saving.",
                    parent=window,
                )
                return

            alert = alert_by_iid[selection[0]]

            self._save_workflow(
                alert,
                status_var.get(),
                notes.get("1.0", "end").strip(),
            )

            selected_iid = selection[0]
            refresh_rows()
            tree.selection_set(selected_iid)

            messagebox.showinfo(
                "Saved",
                "Alert status and notes saved.",
                parent=window,
            )

        tree.bind("<<TreeviewSelect>>", load_selected)

        ttk.Button(
            edit,
            text="Save status and notes",
            style="Primary.TButton",
            command=save_selected,
        ).grid(row=0, column=2, padx=8, sticky="e")

        refresh_rows()

        if alerts:
            tree.selection_set("0")
            load_selected()
        else:
            tk.Label(
                body,
                text="No current alerts. Load and analyze a log file first.",
                bg="#eef2f7",
                fg="#64748b",
            ).pack(pady=8)

    def show_ip_risk_scores(self):
        events = self.get_date_filtered_events()

        if not events:
            messagebox.showinfo(
                "No Events",
                "Load events or clear the date filter first.",
            )
            return

        per_ip = {}

        for event in events:
            ip = event.get("ip_address", "Unknown")

            record = per_ip.setdefault(
                ip,
                {
                    "failed": 0,
                    "errors": 0,
                    "users": set(),
                    "times": [],
                },
            )

            if event.get("event_type", "").lower() == "login_failed":
                record["failed"] += 1
                record["times"].append(
                    str(event.get("timestamp", ""))
                )

            if event.get("severity", "").upper() == "ERROR":
                record["errors"] += 1

            record["users"].add(event.get("username", "Unknown"))

        rows = []

        for ip, rec in per_ip.items():
            score = min(
                100,
                rec["failed"] * 4
                + rec["errors"] * 8
                + max(0, len(rec["users"]) - 1) * 3,
            )

            level = (
                "High" if score >= 70
                else "Medium" if score >= 35
                else "Low"
            )

            rows.append((
                score,
                ip,
                level,
                rec["failed"],
                rec["errors"],
                len(rec["users"]),
            ))

        rows.sort(reverse=True)

        window = tk.Toplevel(self.root)
        window.title("SentinelX | IP Risk Scores")
        window.geometry("850x520")
        window.configure(bg="#eef2f7")

        tk.Label(
            window,
            text="IP risk ranking",
            bg="#0f172a",
            fg="white",
            font=("Segoe UI", 17, "bold"),
            padx=18,
            pady=16,
        ).pack(fill="x")

        tk.Label(
            window,
            text="Heuristic score based on failed logins, ERROR events, "
                 "and distinct usernames. This is a triage aid, not "
                 "proof of malicious activity.",
            bg="#eef2f7",
            fg="#475569",
            wraplength=800,
            justify="left",
            padx=16,
            pady=12,
        ).pack(fill="x")

        tree = ttk.Treeview(
            window,
            columns=("score", "ip", "risk", "failed", "errors", "users"),
            show="headings",
        )

        for col, title, width in [
            ("score", "SCORE", 80),
            ("ip", "IP ADDRESS", 170),
            ("risk", "RISK", 100),
            ("failed", "FAILED LOGINS", 130),
            ("errors", "ERROR EVENTS", 120),
            ("users", "USERNAMES", 110),
        ]:
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w")

        tree.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        for row in rows:
            tree.insert("", "end", values=row)

    # ---------------------------------------------------------
    # REAL-TIME MONITOR
    # ---------------------------------------------------------

    def start_realtime_monitor(self):
        if self.monitor_active:
            self.monitor_active = False

            if self.monitor_job:
                try:
                    self.root.after_cancel(self.monitor_job)
                except tk.TclError:
                    pass

            self.monitor_job = None
            self.status_var.set("Real-time monitoring stopped.")

            messagebox.showinfo(
                "Monitoring stopped",
                "Real-time log monitoring has stopped.",
            )
            return

        chosen = filedialog.askopenfilename(
            title="Choose a log file to monitor",
            filetypes=[
                ("Log files", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )

        if not chosen:
            return

        self.monitor_path = Path(chosen)

        try:
            self.monitor_offset = self.monitor_path.stat().st_size
        except OSError as error:
            messagebox.showerror("Monitor Error", str(error))
            return

        self.monitor_active = True

        self.status_var.set(
            f"Monitoring appended entries in {self.monitor_path.name}. "
            "Click Real-time monitor again to stop."
        )

        self._poll_monitored_file()

    def _poll_monitored_file(self):
        if not self.monitor_active or not self.monitor_path:
            return

        try:
            size = self.monitor_path.stat().st_size

            if size < self.monitor_offset:
                self.monitor_offset = 0

            if size > self.monitor_offset:
                with self.monitor_path.open(
                    "r",
                    encoding="utf-8",
                ) as stream:
                    stream.seek(self.monitor_offset)
                    chunk = stream.read()
                    self.monitor_offset = stream.tell()

                new_events = []

                for line in chunk.splitlines():
                    event = parse_log_line(line)

                    if event:
                        new_events.append(event)

                if new_events:
                    self.events.extend(new_events)

                    try:
                        self.database.save_events(new_events)
                    except Exception:
                        pass

                    self.update_date_filtered_dashboard()
                    self.refresh_table()

                    self.status_var.set(
                        f"Real-time monitor: received {len(new_events)} "
                        f"new event(s). Total loaded: {len(self.events):,}."
                    )

        except (OSError, UnicodeError) as error:
            self.status_var.set(f"Monitor read error: {error}")

        self.monitor_job = self.root.after(
            1500,
            self._poll_monitored_file,
        )

    # ---------------------------------------------------------
    # ALERT INVESTIGATION
    # ---------------------------------------------------------

    def show_alert_investigation(self):
        alerts = self.results.get("alerts", []) if self.results else []

        window = tk.Toplevel(self.root)
        window.title("SentinelX | Alert Investigation")
        window.geometry("1050x680")
        window.minsize(850, 520)
        window.configure(bg="#eef2f7")

        header = tk.Frame(
            window,
            bg="#0f172a",
            padx=22,
            pady=18,
        )
        header.pack(fill="x")

        tk.Label(
            header,
            text="Alert investigation",
            bg="#0f172a",
            fg="#f8fafc",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Select an alert to review its source IP, targeted accounts, "
                 "and related log events.",
            bg="#0f172a",
            fg="#cbd5e1",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 0))

        body = tk.Frame(
            window,
            bg="#eef2f7",
            padx=18,
            pady=16,
        )
        body.pack(fill="both", expand=True)

        left = tk.Frame(
            body,
            bg="#ffffff",
            highlightbackground="#e2e8f0",
            highlightthickness=1,
        )
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))

        right = tk.Frame(
            body,
            bg="#ffffff",
            highlightbackground="#e2e8f0",
            highlightthickness=1,
        )
        right.pack(side="left", fill="both", expand=True)

        tk.Label(
            left,
            text="DETECTED ALERTS",
            bg="#ffffff",
            fg="#0f172a",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=12,
        ).pack(anchor="w")

        alert_tree = ttk.Treeview(
            left,
            columns=("severity", "description"),
            show="headings",
            height=12,
        )

        alert_tree.heading("severity", text="SEVERITY")
        alert_tree.heading("description", text="ALERT")
        alert_tree.column("severity", width=90, stretch=False)
        alert_tree.column("description", width=340, anchor="w")
        alert_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        alert_tree.tag_configure("HIGH", background="#fef2f2")
        alert_tree.tag_configure("MEDIUM", background="#fffbeb")

        tk.Label(
            right,
            text="INVESTIGATION DETAILS",
            bg="#ffffff",
            fg="#0f172a",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=12,
        ).pack(anchor="w")

        details = tk.Text(
            right,
            wrap="word",
            font=("Consolas", 10),
            bg="#ffffff",
            fg="#334155",
            relief="flat",
            padx=12,
            pady=8,
            state="disabled",
        )
        details.pack(fill="both", expand=True, padx=4, pady=(0, 8))

        current_alerts = list(alerts)

        for index, alert in enumerate(current_alerts):
            alert_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    alert.get("severity", "UNKNOWN"),
                    alert.get("description", "Security alert"),
                ),
                tags=(alert.get("severity", ""),),
            )

        def show_details(_event=None):
            selected = alert_tree.selection()

            if not selected:
                return

            alert = current_alerts[int(selected[0])]
            description = str(alert.get("description", "Security alert"))
            severity = str(alert.get("severity", "UNKNOWN"))
            targeted_users = alert.get("targeted_users", []) or []

            ip_address = alert.get("ip_address")

            if not ip_address:
                match = re.search(
                    r"(?:from|IP[: ]+)\s*(\d{1,3}(?:\.\d{1,3}){3})",
                    description,
                    re.IGNORECASE,
                )
                ip_address = (
                    match.group(1)
                    if match
                    else "Not specified in alert"
                )

            relevant_events = []

            for event in self.get_date_filtered_events():
                if (
                    ip_address != "Not specified in alert"
                    and event.get("ip_address") != ip_address
                ):
                    continue

                if (
                    event.get("event_type", "").lower() == "login_failed"
                    or ip_address == "Not specified in alert"
                ):
                    relevant_events.append(event)

            failed_events = [
                event
                for event in relevant_events
                if event.get("event_type", "").lower() == "login_failed"
            ]

            user_names = sorted({
                event.get("username", "Unknown")
                for event in relevant_events
            })

            if not user_names:
                user_names = sorted(set(targeted_users))

            lines = [
                f"Severity: {severity}",
                f"Alert: {description}",
                f"Source IP: {ip_address}",
                "Targeted usernames: "
                + (
                    ", ".join(user_names)
                    if user_names
                    else "Not available"
                ),
                f"Related failed-login events: {len(failed_events)}",
                "",
                "RELATED EVENTS (within the currently selected date range)",
                "-" * 58,
            ]

            for event in sorted(
                relevant_events,
                key=lambda item: str(item.get("timestamp", "")),
            )[:100]:
                lines.append(
                    f"{event.get('timestamp', 'Unknown time')} | "
                    f"{event.get('severity', 'UNKNOWN')} | "
                    f"user={event.get('username', 'Unknown')} | "
                    f"ip={event.get('ip_address', 'Unknown')} | "
                    f"event={event.get('event_type', 'Unknown')}"
                )

            if not relevant_events:
                lines.append(
                    "No related events found for this alert "
                    "in the selected date range."
                )

            if len(relevant_events) > 100:
                lines.extend([
                    "",
                    f"Showing first 100 of {len(relevant_events)} related events.",
                ])

            details.configure(state="normal")
            details.delete("1.0", "end")
            details.insert("1.0", "\n".join(lines))
            details.configure(state="disabled")

        alert_tree.bind("<<TreeviewSelect>>", show_details)
        alert_tree.bind("<Double-1>", show_details)

        if not current_alerts:
            details.configure(state="normal")
            details.insert(
                "1.0",
                "No alerts are currently detected. Try loading logs "
                "or adjusting the detection rules.",
            )
            details.configure(state="disabled")
        else:
            first = alert_tree.get_children()[0]
            alert_tree.selection_set(first)
            show_details()

    def update_alerts(self):
        self.alert_text.configure(state="normal")
        self.alert_text.delete("1.0", "end")

        alerts = self.results.get("alerts", []) if self.results else []

        if not alerts:
            self.alert_text.insert(
                "end",
                "No suspicious patterns detected.",
            )
        else:
            for alert in alerts:
                self.alert_text.insert(
                    "end",
                    f"[{alert['severity']}] {alert['description']}\n"
                    f"Targeted users: "
                    f"{', '.join(alert.get('targeted_users', []))}\n\n",
                )

        self.alert_text.configure(state="disabled")

    # ---------------------------------------------------------
    # REPORT EXPORTS
    # ---------------------------------------------------------

    def export_csv(self):
        if not self.events:
            messagebox.showwarning(
                "No Events",
                "Load a log file before exporting.",
            )
            return

        try:
            filtered_events = self.get_date_filtered_events()

            if not filtered_events:
                messagebox.showinfo(
                    "No Events to Export",
                    "No events match the selected date range.",
                )
                return

            path = export_events_csv(filtered_events)

            messagebox.showinfo(
                "CSV Exported",
                f"CSV report for {len(filtered_events):,} events saved to:\n"
                f"{path}",
            )

        except (OSError, ValueError) as error:
            messagebox.showerror("Export Error", str(error))

    def export_report(self):
        if not self.events:
            messagebox.showwarning(
                "No Events",
                "Load a log file before exporting.",
            )
            return

        filtered_events = self.get_date_filtered_events()

        if not filtered_events:
            messagebox.showinfo(
                "No Events to Export",
                "No events match the selected date range.",
            )
            return

        filtered_results = analyze_events(filtered_events)

        try:
            path = export_analysis_report(filtered_results)

            messagebox.showinfo(
                "Report Exported",
                f"Analysis report saved to:\n{path}",
            )

        except (OSError, ValueError, KeyError) as error:
            messagebox.showerror("Export Error", str(error))

    def export_pdf_report(self):
        events = self.get_date_filtered_events()

        if not events:
            messagebox.showinfo(
                "No Events",
                "No events match the current date range.",
            )
            return

        path = filedialog.asksaveasfilename(
            title="Save PDF incident report",
            defaultextension=".pdf",
            filetypes=[("PDF report", "*.pdf")],
            initialfile="security_incident_report.pdf",
        )

        if not path:
            return

        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, landscape
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
            )
            from reportlab.lib.units import inch

        except ImportError:
            messagebox.showerror(
                "Missing Dependency",
                "PDF export requires ReportLab. Install it with:\n"
                "py -m pip install reportlab",
            )
            return

        try:
            results = analyze_events(events)

            doc = SimpleDocTemplate(
                path,
                pagesize=landscape(letter),
                rightMargin=0.4 * inch,
                leftMargin=0.4 * inch,
                topMargin=0.45 * inch,
                bottomMargin=0.45 * inch,
            )

            styles = getSampleStyleSheet()

            story = [
                Paragraph(
                    "SentinelX Security Incident Report",
                    styles["Title"],
                ),
                Spacer(1, 8),
                Paragraph(
                    f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
                    styles["Normal"],
                ),
                Paragraph(
                    f"Events analyzed: {len(events):,} | "
                    f"Failed logins: {results.get('failed_logins', 0):,} | "
                    f"Unique IPs: {results.get('unique_ips', 0):,} | "
                    f"Alerts: {len(results.get('alerts', []))}",
                    styles["Normal"],
                ),
                Spacer(1, 12),
            ]

            alert_data = [["Severity", "Source IP", "Description"]]

            for alert in results.get("alerts", [])[:80]:
                alert_data.append([
                    str(alert.get("severity", "")),
                    str(alert.get("ip_address", "")),
                    str(alert.get("description", ""))[:180],
                ])

            if len(alert_data) == 1:
                alert_data.append([
                    "—",
                    "—",
                    "No alerts returned by the base analysis rule.",
                ])

            table = Table(
                alert_data,
                colWidths=[
                    0.9 * inch,
                    1.25 * inch,
                    8.0 * inch,
                ],
                repeatRows=1,
            )

            table.setStyle(TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#0f172a"),
                ),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor("#cbd5e1"),
                ),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f1f5f9")],
                ),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))

            story.extend([
                Paragraph("Detected Alerts", styles["Heading2"]),
                table,
                Spacer(1, 12),
                Paragraph(
                    "Note: alerts are rule-based indicators and require "
                    "human review; they do not independently prove "
                    "malicious activity.",
                    styles["Italic"],
                ),
            ])

            doc.build(story)

            messagebox.showinfo(
                "PDF Exported",
                f"PDF report saved to:\n{path}",
            )

        except Exception as error:
            messagebox.showerror("PDF Export Error", str(error))


def main():
    root = tk.Tk()
    SecurityLogAnalyzer(root)
    root.mainloop()


if __name__ == "__main__":
    main()