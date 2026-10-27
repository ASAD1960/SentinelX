
import unittest

from detection_engine import analyze_events


class TestAnalyzeEvents(unittest.TestCase):

    def test_empty_event_list(self):
        result = analyze_events([])

        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["failed_logins"], 0)
        self.assertEqual(result["unique_ips"], 0)
        self.assertEqual(result["flagged_ips"], 0)
        self.assertEqual(result["alerts"], [])

    def test_counts_total_events_and_unique_ips(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_success",
                "username": "asad",
            },
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_failed",
                "username": "asad",
            },
            {
                "ip_address": "192.168.1.20",
                "event_type": "login_success",
                "username": "ali",
            },
        ]

        result = analyze_events(events)

        self.assertEqual(result["total_events"], 3)
        self.assertEqual(result["unique_ips"], 2)
        self.assertEqual(result["failed_logins"], 1)
        self.assertEqual(result["flagged_ips"], 0)

    def test_alert_created_at_default_threshold(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_failed",
                "username": "asad",
            }
            for _ in range(4)
        ]

        result = analyze_events(events)

        self.assertEqual(result["flagged_ips"], 1)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(
            result["alerts"][0]["ip_address"],
            "192.168.1.10",
        )
        self.assertEqual(
            result["alerts"][0]["failed_attempts"],
            4,
        )
        self.assertEqual(result["alerts"][0]["severity"], "HIGH")
        self.assertEqual(
            result["alerts"][0]["targeted_users"],
            ["asad"],
        )

    def test_below_threshold_does_not_create_alert(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_failed",
                "username": "asad",
            }
            for _ in range(3)
        ]

        result = analyze_events(events)

        self.assertEqual(result["failed_logins"], 3)
        self.assertEqual(result["flagged_ips"], 0)
        self.assertEqual(result["alerts"], [])

    def test_successful_logins_do_not_count_as_failures(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_success",
                "username": "asad",
            }
            for _ in range(5)
        ]

        result = analyze_events(events)

        self.assertEqual(result["failed_logins"], 0)
        self.assertEqual(result["flagged_ips"], 0)

    def test_ips_are_analyzed_separately(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_failed",
                "username": "asad",
            }
            for _ in range(3)
        ] + [
            {
                "ip_address": "192.168.1.20",
                "event_type": "login_failed",
                "username": "ali",
            }
            for _ in range(3)
        ]

        result = analyze_events(events)

        self.assertEqual(result["failed_logins"], 6)
        self.assertEqual(result["unique_ips"], 2)
        self.assertEqual(result["flagged_ips"], 0)

    def test_alert_lists_all_targeted_users(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_failed",
                "username": username,
            }
            for username in ["zara", "asad", "ali", "asad"]
        ]

        result = analyze_events(events)

        self.assertEqual(
            result["alerts"][0]["targeted_users"],
            ["ali", "asad", "zara"],
        )

    def test_zero_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_events([], failed_login_threshold=0)

    def test_negative_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_events([], failed_login_threshold=-1)

    def test_float_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_events([], failed_login_threshold=2.5)

    def test_string_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_events([], failed_login_threshold="4")

    def test_missing_ip_address_is_rejected(self):
        events = [
            {
                "event_type": "login_failed",
                "username": "asad",
            }
        ]

        with self.assertRaises(ValueError):
            analyze_events(events)

    def test_missing_event_type_is_rejected(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "username": "asad",
            }
        ]

        with self.assertRaises(ValueError):
            analyze_events(events)

    def test_missing_username_is_rejected(self):
        events = [
            {
                "ip_address": "192.168.1.10",
                "event_type": "login_failed",
            }
        ]

        with self.assertRaises(ValueError):
            analyze_events(events)

    def test_boolean_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_events([], failed_login_threshold=True)


if __name__ == "__main__":
    unittest.main()
