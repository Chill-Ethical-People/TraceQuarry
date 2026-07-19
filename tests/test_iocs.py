from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from uac_parser.enrich.iocs import (
    Ioc,
    ioc_finding,
    load_iocs,
    match_iocs,
    parse_ioc_text,
    write_ioc_hits,
)
from uac_parser.timeline.event import TimelineEvent


class IocTests(unittest.TestCase):
    def test_text_parser_guesses_types_labels_and_deduplicates(self) -> None:
        iocs = parse_ioc_text(
            """
            # responder indicators
            198.51.100.50
            198.51.100.50,ip,scanner
            example.invalid
            /dev/shm/payload
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            rclone,literal,exfil tool
            """
        )

        self.assertEqual(
            [ioc.kind for ioc in iocs], ["ip", "domain", "path", "hash", "literal"]
        )
        self.assertEqual(iocs[-1].label, "exfil tool")
        self.assertEqual(parse_ioc_text(None), [])

    def test_load_iocs_reads_replacement_safe_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "iocs.csv"
            path.write_text("alice,literal,account\n", encoding="utf-8")
            self.assertEqual(load_iocs(path), [Ioc("alice", "literal", "account")])
        self.assertEqual(load_iocs(None), [])

    def test_matching_covers_typed_fields_and_preserves_raw_context(self) -> None:
        event = TimelineEvent(
            event_id="evt-1",
            timestamp="2026-06-16T10:00:00Z",
            source_path="var/log/auth.log",
            source_type="auth_log",
            event_action="ssh_login_success",
            user="alice",
            src_ip="198.51.100.50",
            command="rclone copy /srv data:case",
            file_path="/dev/shm/payload",
            raw="connected to c2.example.invalid with sha256 " + "a" * 64,
        )
        iocs = [
            Ioc("198.51.100.50", "ip"),
            Ioc("c2.example.invalid", "domain"),
            Ioc("/dev/shm/payload", "path"),
            Ioc("a" * 64, "hash"),
            Ioc("rclone", "literal"),
        ]

        hits = match_iocs([event], iocs)

        self.assertEqual(len(hits), 5)
        self.assertTrue(all(hit["event_id"] == "evt-1" for hit in hits))
        self.assertTrue(all(hit["raw"] == event.raw for hit in hits))

    def test_literal_matching_uses_boundaries_and_empty_sets_are_safe(self) -> None:
        event = TimelineEvent(event_id="evt", command="rclone-copy helper")
        self.assertEqual(match_iocs([event], [Ioc("rclone")]), [])
        self.assertEqual(match_iocs([event], []), [])
        self.assertEqual(match_iocs([event], [Ioc(" ")]), [])

    def test_writers_create_restricted_csv_and_json(self) -> None:
        hits = [{"ioc": "rclone", "event_id": "evt", "summary": "tool observed"}]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_ioc_hits(output, hits)
            json_hits = json.loads((output / "ioc_hits.json").read_text())
            csv_text = (output / "ioc_hits.csv").read_text()

            self.assertEqual(json_hits[0]["ioc"], "rclone")
            self.assertIn("event_id", csv_text)
            self.assertEqual(
                stat.S_IMODE((output / "ioc_hits.json").stat().st_mode), 0o600
            )
            self.assertEqual(
                stat.S_IMODE((output / "ioc_hits.csv").stat().st_mode), 0o600
            )

    def test_finding_deduplicates_and_limits_event_references(self) -> None:
        self.assertIsNone(ioc_finding([]))
        hits = [
            {"ioc": "rclone", "event_id": f"evt-{index}"} for index in range(12)
        ] + [{"ioc": "rclone", "event_id": "evt-0"}]

        finding = ioc_finding(hits)

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(len(finding["event_ids"]), 10)
        self.assertEqual(finding["iocs"], ["rclone"])
        self.assertEqual(finding["severity"], "high")


if __name__ == "__main__":
    unittest.main()
