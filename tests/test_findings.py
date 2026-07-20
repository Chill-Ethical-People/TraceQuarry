import unittest
from datetime import UTC, datetime, timedelta

from uac_parser.enrich.ttp_rules import derive_findings, enrich_events
from uac_parser.parsers.auth import parse as parse_auth
from uac_parser.timeline.event import TimelineEvent


def _ssh(action: str, when: datetime) -> TimelineEvent:
    return TimelineEvent(
        event_id=f"evt-{when.timestamp()}",
        timestamp=when.isoformat().replace("+00:00", "Z"),
        source_type="auth_log",
        event_category="authentication",
        event_action=action,
        user="root",
        src_ip="198.51.100.50",
    )


class FindingTests(unittest.TestCase):
    def test_state_inventory_does_not_claim_credential_access_behavior(self) -> None:
        state = TimelineEvent(
            source_type="shadow",
            file_path="/etc/shadow",
            event_action="password_state_observed",
            evidence_role="state_observation",
        )
        behavior = TimelineEvent(
            source_type="shell_history",
            command="cat /etc/shadow",
            event_action="shell_command",
            event_category="execution",
            evidence_role="behavior",
        )

        enrich_events([state, behavior])

        self.assertNotIn("credential_material_access", state.detection_names)
        self.assertIn("credential_material_access", behavior.detection_names)

    def test_auth_user_creation_preserves_full_username(self) -> None:
        import tempfile
        from pathlib import Path

        raw = (
            "Jul 12 03:08:00 host useradd[4120]: new user: name=svc-backup, "
            "UID=1107, GID=1107, home=/home/svc-backup, shell=/bin/bash\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(raw, encoding="utf-8")
            events = parse_auth(path, "var/log/auth.log", year=2026)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].user, "svc-backup")
        self.assertEqual(events[0].uid, "1107")
        self.assertEqual(events[0].extra["shell"], "/bin/bash")

    def test_success_after_failures_uses_bounded_window(self) -> None:
        success = datetime(2026, 6, 16, 10, 0, tzinfo=UTC)
        old_failures = [
            _ssh("ssh_login_failure", success - timedelta(hours=2, minutes=index))
            for index in range(6)
        ]
        recent_failures = [
            _ssh("ssh_login_failure", success - timedelta(minutes=index + 1))
            for index in range(5)
        ]

        findings = derive_findings(
            old_failures + recent_failures + [_ssh("ssh_login_success", success)]
        )
        finding = next(
            item
            for item in findings
            if item["title"] == "Successful SSH login after repeated failures"
        )

        self.assertIn("after 5 failed attempts", finding["summary"])
        self.assertEqual(finding["evidence_window_seconds"], 1800)

    def test_lateral_negative_is_inconclusive_when_sources_missing(self) -> None:
        findings = derive_findings([], available_source_types={"auth_log"})
        finding = next(item for item in findings if "Lateral Movement" in item["title"])

        self.assertIn("coverage_gap", finding["tags"])
        self.assertEqual(finding["confidence"], "low")

    def test_lateral_negative_requires_relevant_coverage(self) -> None:
        findings = derive_findings(
            [],
            available_source_types={"shell_history", "ss_output", "known_hosts"},
        )
        finding = next(item for item in findings if "Lateral Movement" in item["title"])

        self.assertIn("coverage_sufficient", finding["tags"])

    def test_known_hosts_is_context_not_lateral_movement_evidence(self) -> None:
        event = TimelineEvent(
            event_id="evt-known-host",
            event_action="known_host_observed",
            source_type="known_hosts",
            dst_ip="10.0.0.12",
        )
        findings = derive_findings(
            [event],
            available_source_types={"shell_history", "ss_output", "known_hosts"},
        )

        self.assertTrue(
            any(item["title"] == "Known SSH Destination Observed" for item in findings)
        )
        self.assertFalse(
            any(
                item["title"] == "Outbound Lateral Movement Evidence"
                for item in findings
            )
        )

    def test_suid_inventory_is_medium_severity(self) -> None:
        event = TimelineEvent(
            event_id="evt-suid",
            event_action="suid_file_observed",
            source_type="bodyfile_privilege",
            file_path="/usr/bin/passwd",
        )

        finding = next(
            item
            for item in derive_findings([event])
            if item["title"] == "Suid File Observed"
        )
        self.assertEqual(finding["severity"], "medium")
