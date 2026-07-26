import tempfile
import unittest
from pathlib import Path

from uac_parser.output.writers import (
    write_csv,
    write_jsonl,
    write_summary,
    write_timeline,
)
from uac_parser.timeline.event import TimelineEvent


class TimelineWriterTests(unittest.TestCase):
    def test_combined_writer_matches_individual_writers(self) -> None:
        events = [
            TimelineEvent(
                event_id="evt_test",
                timestamp="2026-07-23T12:00:00Z",
                mitre=["T1059.004"],
                attack_phases=["execution"],
                tags=["execution", "shell"],
                raw="synthetic evidence",
                extra={"nested": {"value": 1}},
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected_jsonl = root / "expected.jsonl"
            expected_csv = root / "expected.csv"
            actual_jsonl = root / "actual.jsonl"
            actual_csv = root / "actual.csv"

            write_jsonl(expected_jsonl, events)
            write_csv(expected_csv, events)
            write_timeline(actual_jsonl, actual_csv, events)

            self.assertEqual(actual_jsonl.read_bytes(), expected_jsonl.read_bytes())
            self.assertEqual(actual_csv.read_bytes(), expected_csv.read_bytes())

    def test_event_dictionary_does_not_alias_mutable_evidence(self) -> None:
        event = TimelineEvent(
            tags=["one"],
            attack_phases=["execution"],
            extra={"nested": ["value"]},
        )

        payload = event.to_dict()
        payload["tags"].append("two")
        payload["attack_phases"].append("persistence")
        payload["extra"]["nested"].append("changed")

        self.assertEqual(event.tags, ["one"])
        self.assertEqual(event.attack_phases, ["execution"])
        self.assertEqual(event.extra, {"nested": ["value"]})

    def test_summary_deduplicates_accounts_and_does_not_count_created_groups(
        self,
    ) -> None:
        events = [
            TimelineEvent(
                source_type="account_diff",
                event_action="account_created_since_backup",
                user="svc-backup",
            ),
            TimelineEvent(
                source_type="account_diff",
                event_action="account_created_since_backup",
                user="svc-backup",
            ),
            TimelineEvent(
                source_type="account_diff",
                event_action="group_created_since_backup",
                summary="Group created since backup: backup-operators",
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.md"
            write_summary(path, events, [], [])
            summary = path.read_text(encoding="utf-8")

        self.assertIn("Accounts created: svc-backup", summary)
        self.assertNotIn("Accounts created: svc-backup, svc-backup", summary)
        self.assertNotIn("Accounts created: ?", summary)

    def test_summary_reports_confirmed_and_candidate_attack_phases(self) -> None:
        events = [
            TimelineEvent(attack_phases=["execution"]),
            TimelineEvent(attack_phase_candidates=["persistence"]),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.md"
            write_summary(path, events, [], [])
            summary = path.read_text(encoding="utf-8")

        self.assertIn("MITRE ATT&CK Phase Breakdown", summary)
        self.assertIn("Execution (TA0002)", summary)
        self.assertIn("1 confirmed event(s), 0 candidate event(s)", summary)
        self.assertIn("Persistence (TA0003)", summary)
        self.assertIn("0 confirmed event(s), 1 candidate event(s)", summary)
