import tempfile
from pathlib import Path
import unittest

from uac_parser.assist import (
    InvestigationProfileError,
    build_assisted_investigation,
    profile_choices,
    validate_profile,
    write_assisted_investigation,
)
from uac_parser.timeline.event import TimelineEvent


class AssistedInvestigationTests(unittest.TestCase):
    def test_profiles_are_available_and_unknown_profile_is_rejected(self) -> None:
        profile_ids = {profile["id"] for profile in profile_choices()}

        self.assertIn("ransomware_extortion", profile_ids)
        self.assertIn("public_facing_exploitation", profile_ids)
        self.assertIn("apt_like_intrusion", profile_ids)
        with self.assertRaises(InvestigationProfileError):
            validate_profile("unsupported")

    def test_ransomware_profile_prioritizes_exfiltration_finding(self) -> None:
        event = TimelineEvent(
            event_id="evt-1",
            event_action="shell_command",
            event_category="execution",
            command="rclone copy /tmp/data remote:case",
            summary="rclone exfiltration command",
            severity="high",
            tags=["exfil_tool_usage", "archive"],
            detection_names=["exfil_tool_usage"],
            mitre=["T1567"],
        )
        findings = [{
            "title": "Exfil Tool Usage",
            "severity": "high",
            "confidence": "high",
            "summary": "Observed rclone execution.",
            "event_ids": ["evt-1"],
            "tags": ["exfil_tool_usage"],
        }]

        report = build_assisted_investigation(
            "ransomware_extortion", [event], findings, {"shell_history", "ss_output"}
        )

        self.assertEqual(report["profile_id"], "ransomware_extortion")
        self.assertEqual(report["prioritized_findings"][0]["relevance"], "primary")
        self.assertTrue(any(item["status"] == "observed" for item in report["checklist"]))
        with tempfile.TemporaryDirectory() as directory:
            write_assisted_investigation(Path(directory), report)
            self.assertTrue((Path(directory) / "assisted_investigation.md").exists())
            self.assertTrue((Path(directory) / "assisted_investigation.json").exists())
