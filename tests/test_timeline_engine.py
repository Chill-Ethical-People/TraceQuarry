import unittest

from uac_parser.timeline.engine import assign_event_ids, dedupe_events
from uac_parser.timeline.event import TimelineEvent


class TimelineEngineTests(unittest.TestCase):
    def test_dedupe_preserves_distinct_raw_records(self) -> None:
        common = {
            "timestamp": "2026-06-16T10:00:00Z",
            "source_path": "var/log/auth.log",
            "event_action": "ssh_login_failure",
        }
        events = [
            TimelineEvent(
                **common, user="root", src_ip="10.0.0.8", raw="failure port 41001"
            ),
            TimelineEvent(
                **common, user="root", src_ip="10.0.0.8", raw="failure port 41002"
            ),
        ]

        self.assertEqual(len(dedupe_events(events)), 2)

    def test_dedupe_removes_exact_normalized_duplicate(self) -> None:
        event = TimelineEvent(
            timestamp="2026-06-16T10:00:00Z",
            source_path="var/log/auth.log",
            event_action="ssh_login_failure",
            raw="same record",
        )

        self.assertEqual(len(dedupe_events([event, event])), 1)

    def test_event_ids_include_identity_and_parser_evidence(self) -> None:
        common = {
            "timestamp": "2026-06-16T10:00:00Z",
            "source_path": "etc/shadow",
            "event_action": "shadow_account_observed",
            "raw": "same normalized evidence",
        }
        root, evilroot = assign_event_ids(
            [
                TimelineEvent(**common, user="root", extra={"uid": "0"}),
                TimelineEvent(**common, user="evilroot", extra={"uid": "0"}),
            ]
        )

        self.assertNotEqual(root.event_id, evilroot.event_id)
