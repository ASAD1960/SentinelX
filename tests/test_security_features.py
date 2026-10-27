
import unittest

from security_features import (
    filter_events_by_date,
    calculate_ip_risk,
    find_failed_login_bursts,
)


class TestDateFiltering(unittest.TestCase):

    def setUp(self):
        self.events = [
            {"timestamp": "2026-01-01 10:00:00", "username": "ali"},
            {"timestamp": "2026-01-02 12:00:00", "username": "sara"},
            {"timestamp": "2026-01-03 14:00:00", "username": "ahmed"},
        ]

    def test_filter_start_date(self):
        result = filter_events_by_date(
            self.events, start_date="2026-01-02"
        )
        self.assertEqual(len(result), 2)

    def test_filter_end_date(self):
        result = filter_events_by_date(
            self.events, end_date="2026-01-02"
        )
        self.assertEqual(len(result), 2)

    def test_filter_date_range(self):
        result = filter_events_by_date(
            self.events, "2026-01-02", "2026-01-02"
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["username"], "sara")

    def test_invalid_date_range(self):
        with self.assertRaises(ValueError):
            filter_events_by_date(
                self.events, "2026-01-03", "2026-01-01"
            )


class TestIPRiskScoring(unittest.TestCase):

    def test_failed_logins_increase_risk(self):
        events = [
            {
                "ip_address": "192.0.2.10",
                "event_type": "login_failed",
                "severity": "WARNING",
                "username": "ali",
            }
            for _ in range(10)
        ]

        result = calculate_ip_risk(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["score"], 40)
        self.assertEqual(result[0]["risk"], "Medium")
        self.assertEqual(result[0]["failed_logins"], 10)

    def test_high_risk_ip_is_ranked_first(self):
        events = [
            {
                "ip_address": "192.0.2.20",
                "event_type": "login_failed",
                "severity": "ERROR",
                "username": "ali",
            }
            for _ in range(20)
        ] + [
            {
                "ip_address": "192.0.2.30",
                "event_type": "login_success",
                "severity": "INFO",
                "username": "sara",
            }
        ]

        result = calculate_ip_risk(events)

        self.assertEqual(result[0]["ip_address"], "192.0.2.20")
        self.assertEqual(result[0]["score"], 100)
        self.assertEqual(result[0]["risk"], "High")


class TestFailedLoginBursts(unittest.TestCase):

    def test_detects_five_failed_logins_within_ten_minutes(self):
        events = [
            {
                "timestamp": f"2026-01-01 10:0{i}:00",
                "ip_address": "192.0.2.50",
                "event_type": "login_failed",
            }
            for i in range(5)
        ]

        result = find_failed_login_bursts(
            events, attempts=5, window_minutes=10
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip_address"], "192.0.2.50")
        self.assertGreaterEqual(result[0]["attempts_in_window"], 5)

    def test_ignores_successful_logins(self):
        events = [
            {
                "timestamp": f"2026-01-01 10:0{i}:00",
                "ip_address": "192.0.2.60",
                "event_type": "login_success",
            }
            for i in range(5)
        ]

        result = find_failed_login_bursts(events)

        self.assertEqual(result, [])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            find_failed_login_bursts([], attempts=1)

    def test_ignores_attempts_outside_time_window(self):
        events = [
            {
                "timestamp": f"2026-01-01 10:{minute:02d}:00",
                "ip_address": "192.0.2.70",
                "event_type": "login_failed",
            }
            for minute in (0, 2, 4, 20, 22)
        ]

        result = find_failed_login_bursts(
            events, attempts=5, window_minutes=10
        )

        self.assertEqual(result, [])

    def test_detects_failed_logins_among_successful_logins(self):
        events = [
            {
                "timestamp": f"2026-01-01 10:0{i}:00",
                "ip_address": "192.0.2.80",
                "event_type": (
                    "login_failed"
                    if i in (0, 1, 2, 3, 4)
                    else "login_success"
                ),
            }
            for i in range(6)
        ]

        result = find_failed_login_bursts(
            events, attempts=5, window_minutes=10
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip_address"], "192.0.2.80")

    def test_different_ips_are_detected_separately(self):
        events = []

        for ip in ("192.0.2.90", "192.0.2.91"):
            for minute in range(5):
                events.append({
                    "timestamp": f"2026-01-01 10:0{minute}:00",
                    "ip_address": ip,
                    "event_type": "login_failed",
                })

        result = find_failed_login_bursts(
            events, attempts=5, window_minutes=10
        )

        detected_ips = {alert["ip_address"] for alert in result}

        self.assertEqual(
            detected_ips,
            {"192.0.2.90", "192.0.2.91"},
        )


if __name__ == "__main__":
    unittest.main()
