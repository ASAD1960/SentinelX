
import tempfile
from pathlib import Path

from database import SecurityDatabase


def run_tests():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_db_path = Path(temp_dir) / "test_security_logs.db"

        db = SecurityDatabase(db_path=test_db_path)

        # Test 1: Save a new event.
        event = {
            "timestamp": "2026-10-20 09:00:00",
            "severity": "WARNING",
            "username": "test_user",
            "ip_address": "203.0.113.25",
            "event_type": "login_failed",
        }

        saved = db.save_events([event])
        assert saved == 1, f"Expected 1, got {saved}"
        assert db.count_events() == 1
        print("PASS: New event saved successfully.")

        # Test 2: The same event must not be saved twice.
        saved_again = db.save_events([event])
        assert saved_again == 0, f"Expected 0, got {saved_again}"
        assert db.count_events() == 1
        print("PASS: Duplicate event was skipped.")

        # Test 3: Reconnect and check persistence.
        db_after_restart = SecurityDatabase(db_path=test_db_path)
        events = db_after_restart.get_events()

        assert len(events) == 1
        assert events[0]["username"] == "test_user"
        assert events[0]["ip_address"] == "203.0.113.25"
        assert events[0]["event_type"] == "login_failed"
        print("PASS: Event persisted across database reconnection.")

        print("\nAll 3 database safety tests passed.")


if __name__ == "__main__":
    run_tests()
