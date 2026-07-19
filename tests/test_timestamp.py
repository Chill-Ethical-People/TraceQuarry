from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from uac_parser.timeline.timestamp import (
    parse_any,
    parse_apache,
    parse_epoch,
    parse_iso,
    parse_last_style,
    parse_syslog,
    to_utc_iso,
)


class TimestampTests(unittest.TestCase):
    def test_utc_normalization_handles_naive_and_offset_values(self) -> None:
        self.assertEqual(
            to_utc_iso(datetime(2026, 1, 2, 3, 4, 5)), "2026-01-02T03:04:05Z"
        )
        self.assertEqual(
            to_utc_iso(
                datetime(2026, 1, 2, 11, 4, 5, tzinfo=timezone(timedelta(hours=8)))
            ),
            "2026-01-02T03:04:05Z",
        )

    def test_epoch_rejects_invalid_values_and_normalizes_valid_value(self) -> None:
        self.assertIsNone(parse_epoch("not-an-epoch"))
        self.assertIsNone(parse_epoch(0))
        self.assertEqual(parse_epoch("1"), "1970-01-01T00:00:01Z")

    def test_iso_and_rfc_dates_are_supported(self) -> None:
        self.assertIsNone(parse_iso(""))
        self.assertIsNone(parse_iso("not-a-date"))
        self.assertEqual(parse_iso("2026-05-16T19:17:08Z"), "2026-05-16T19:17:08Z")
        self.assertEqual(
            parse_iso("Sat, 16 May 2026 19:17:08 GMT"),
            "2026-05-16T19:17:08Z",
        )

    def test_syslog_uses_host_timezone_and_falls_back_to_utc(self) -> None:
        self.assertIsNone(parse_syslog("malformed", year=2026))
        self.assertEqual(
            parse_syslog("Jun 16 10:00:01 host sshd: message", 2026, "Asia/Hong_Kong"),
            "2026-06-16T02:00:01Z",
        )
        self.assertEqual(
            parse_syslog("Jun 16 10:00:01 host sshd: message", 2026, "Invalid/Zone"),
            "2026-06-16T10:00:01Z",
        )

    def test_apache_and_last_style_formats(self) -> None:
        self.assertIsNone(parse_apache("16/Jun/2026:10:00:01"))
        self.assertEqual(
            parse_apache("16/Jun/2026:10:00:01 +0800"),
            "2026-06-16T02:00:01Z",
        )
        self.assertIsNone(parse_last_style("Bad", "16", "10:00", 2026))
        self.assertEqual(
            parse_last_style("Jun", "16", "10:00", 2026, "Asia/Hong_Kong"),
            "2026-06-16T02:00:00Z",
        )

    def test_parse_any_tries_all_supported_formats(self) -> None:
        self.assertEqual(parse_any("2026-06-16T10:00:01Z"), "2026-06-16T10:00:01Z")
        self.assertEqual(
            parse_any("16/Jun/2026:10:00:01 +0800"),
            "2026-06-16T02:00:01Z",
        )
        self.assertEqual(
            parse_any("Jun 16 10:00:01 host app: started", 2026, "UTC"),
            "2026-06-16T10:00:01Z",
        )
        self.assertIsNone(parse_any("not a timestamp", 2026))


if __name__ == "__main__":
    unittest.main()
