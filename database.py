
import sqlite3
from pathlib import Path
from contextlib import closing


DEFAULT_DB_PATH = Path(__file__).parent / "data" / "security_logs.db"


class SecurityDatabase:
    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._create_tables()

    def _connect(self):
        """Create a SQLite connection with a reasonable timeout."""
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _create_tables(self):
        """Create the events table and attempt to add a unique index."""
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        username TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        event_type TEXT NOT NULL
                    )
                """)

                try:
                    connection.execute("""
                        CREATE UNIQUE INDEX IF NOT EXISTS
                        idx_unique_security_events
                        ON events (
                            timestamp,
                            severity,
                            username,
                            ip_address,
                            event_type
                        )
                    """)
                except sqlite3.IntegrityError:
                    # Preserve existing records if duplicates prevent
                    # creation of the unique index.
                    pass

    def save_events(self, events):
        """Save new events and skip duplicates."""
        if not events:
            return 0

        rows = [
            (
                event["timestamp"],
                event["severity"],
                event["username"],
                event["ip_address"],
                event["event_type"],
            )
            for event in events
        ]

        saved_count = 0

        with closing(self._connect()) as connection:
            with connection:
                for row in rows:
                    cursor = connection.execute("""
                        INSERT INTO events (
                            timestamp,
                            severity,
                            username,
                            ip_address,
                            event_type
                        )
                        SELECT ?, ?, ?, ?, ?
                        WHERE NOT EXISTS (
                            SELECT 1 FROM events
                            WHERE timestamp = ?
                              AND severity = ?
                              AND username = ?
                              AND ip_address = ?
                              AND event_type = ?
                        )
                    """, row + row)

                    saved_count += cursor.rowcount

        return saved_count

    def get_events(self, search_text=""):
        """Return stored events, optionally filtered by text."""
        with closing(self._connect()) as connection:
            if search_text:
                pattern = f"%{search_text}%"

                rows = connection.execute("""
                    SELECT * FROM events
                    WHERE timestamp LIKE ?
                       OR severity LIKE ?
                       OR username LIKE ?
                       OR ip_address LIKE ?
                       OR event_type LIKE ?
                    ORDER BY timestamp DESC, id DESC
                """, (pattern,) * 5).fetchall()
            else:
                rows = connection.execute("""
                    SELECT * FROM events
                    ORDER BY timestamp DESC, id DESC
                """).fetchall()

        return [dict(row) for row in rows]

    def count_events(self):
        """Return the total number of stored events."""
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]
