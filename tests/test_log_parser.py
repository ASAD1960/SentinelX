
import os
import tempfile
import unittest

from log_parser import parse_log_line, parse_log_file


class TestParseLogLine(unittest.TestCase):

    def test_valid_log_line(self):
        line = (
            "2026-10-25 12:30:00 | WARNING | "
            "user=asad | ip=192.168.1.10 | event=login_failed"
        )

        result = parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["timestamp"], "2026-10-25 12:30:00")
        self.assertEqual(result["severity"], "WARNING")
        self.assertEqual(result["username"], "asad")
        self.assertEqual(result["ip_address"], "192.168.1.10")
        self.assertEqual(result["event_type"], "login_failed")

    def test_blank_line_is_ignored(self):
        self.assertIsNone(parse_log_line("   "))

    def test_comment_line_is_ignored(self):
        self.assertIsNone(parse_log_line("# This is a comment"))

    def test_invalid_date_is_rejected(self):
        line = (
            "2026-13-25 12:30:00 | INFO | "
            "user=asad | ip=192.168.1.10 | event=login_success"
        )

        self.assertIsNone(parse_log_line(line))

    def test_invalid_time_is_rejected(self):
        line = (
            "2026-10-25 25:30:00 | INFO | "
            "user=asad | ip=192.168.1.10 | event=login_success"
        )

        self.assertIsNone(parse_log_line(line))

    def test_malformed_line_is_rejected(self):
        self.assertIsNone(parse_log_line("This is not a valid security log"))

    def test_missing_username_is_rejected(self):
        line = (
            "2026-10-25 12:30:00 | INFO | "
            "ip=192.168.1.10 | event=login_success"
        )

        self.assertIsNone(parse_log_line(line))

    def test_invalid_severity_is_rejected(self):
        line = (
            "2026-10-25 12:30:00 | CRITICAL | "
            "user=asad | ip=192.168.1.10 | event=login_success"
        )

        self.assertIsNone(parse_log_line(line))

    def test_invalid_event_type_is_rejected(self):
        line = (
            "2026-10-25 12:30:00 | INFO | "
            "user=asad | ip=192.168.1.10 | event=login-success"
        )

        self.assertIsNone(parse_log_line(line))

    def test_invalid_ipv4_address_is_rejected(self):
        line = (
            "2026-10-25 12:30:00 | INFO | "
            "user=asad | ip=999.999.999.999 | event=login_success"
        )

        self.assertIsNone(parse_log_line(line))

    def test_valid_ipv4_boundary_address_is_accepted(self):
        line = (
            "2026-10-25 12:30:00 | INFO | "
            "user=asad | ip=255.255.255.255 | event=login_success"
        )

        result = parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["ip_address"], "255.255.255.255")


class TestParseLogFile(unittest.TestCase):

    def test_invalid_line_numbers_are_reported(self):
        content = (
            "2026-10-25 12:30:00 | INFO | "
            "user=asad | ip=192.168.1.10 | event=login_success\n"
            "not a valid log\n"
            "\n"
            "# ignored comment\n"
            "2026-13-25 12:30:00 | INFO | "
            "user=asad | ip=192.168.1.10 | event=login_success\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".log",
            delete=False
        ) as file:
            file.write(content)
            file_path = file.name

        try:
            events, invalid_lines = parse_log_file(file_path)

            self.assertEqual(len(events), 1)
            self.assertEqual(invalid_lines, [2, 5])
        finally:
            os.remove(file_path)


if __name__ == "__main__":
    unittest.main()
