import copy
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from uac_parser.enrich.rule_registry import (
    RegistryError,
    actor_similarity_rules,
    load_registry,
    load_registry_file,
    tool_rules,
    ttp_rules,
    validate_registry,
)
from uac_parser.enrich.ttp_rules import derive_findings, enrich_events
from uac_parser.rules_cli import main as rules_main
from uac_parser.timeline.event import TimelineEvent


class RuleRegistryTests(unittest.TestCase):
    def test_registry_loads_runtime_tool_rules(self) -> None:
        self.assertEqual(load_registry()["metadata"]["schema_version"], "1.1")
        self.assertIn("rclone", tool_rules())
        self.assertIn("download_execute_chain", ttp_rules())
        self.assertIn("teamtnt_like", actor_similarity_rules())

    def test_registry_tool_match_tags_event(self) -> None:
        event = TimelineEvent(
            source_type="shell_history",
            event_category="execution",
            event_action="shell_command",
            command="rclone copy /srv/data remote:case",
            raw="rclone copy /srv/data remote:case",
        )

        enriched = enrich_events([event])[0]

        self.assertIn("tool.rclone", enriched.tags)
        self.assertIn("ttp.exfil_tool_usage", enriched.tags)
        self.assertIn("ttp.cloud_storage_exfiltration", enriched.tags)
        self.assertIn("tool_rclone_executed", enriched.detection_names)
        self.assertIn("T1567.002", enriched.mitre)

    def test_actor_profile_is_yaml_driven_and_non_attributive(self) -> None:
        events = [
            TimelineEvent(event_id="evt-miner", tags=["ttp.miner_execution"]),
            TimelineEvent(event_id="evt-docker", tags=["ttp.docker_socket_access"]),
            TimelineEvent(event_id="evt-cloud", tags=["ttp.cloud_metadata_access"]),
            TimelineEvent(event_id="evt-cron", tags=["ttp.cron_persistence"]),
        ]

        finding = next(
            item
            for item in derive_findings(events)
            if item.get("profile_id") == "teamtnt_like"
        )

        self.assertEqual(finding["confidence"], "medium")
        self.assertIn("not_attribution", finding["tags"])
        self.assertIn("This is not attribution", finding["summary"])

    def test_actor_profile_requires_multiple_source_events(self) -> None:
        event = TimelineEvent(
            event_id="evt-one-line",
            tags=[
                "ttp.miner_execution",
                "ttp.docker_socket_access",
                "ttp.cloud_metadata_access",
                "ttp.cron_persistence",
            ],
        )

        findings = derive_findings([event])

        self.assertFalse(
            any(item.get("profile_id") == "teamtnt_like" for item in findings)
        )

    def test_duplicate_yaml_keys_are_rejected(self) -> None:
        content = """\
metadata:
  schema_version: '1.1'
  schema_version: '1.2'
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.yml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(RegistryError, "duplicate key"):
                load_registry_file(path)

    def test_actor_profiles_cannot_claim_high_confidence(self) -> None:
        registry = copy.deepcopy(load_registry())
        registry["actor_similarity_profiles"]["teamtnt_like"]["confidence_cap"] = "high"

        with self.assertRaisesRegex(RegistryError, "cannot produce high-confidence"):
            validate_registry(registry)

    def test_rules_cli_reports_valid_pack_summary(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            result = rules_main([])

        self.assertEqual(result, 0)
        self.assertIn("Valid TraceQuarry detection pack", output.getvalue())
        self.assertIn("actor_similarity_profiles: 15", output.getvalue())

    def test_rules_cli_returns_failure_for_invalid_pack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yml"
            path.write_text("metadata: []\n", encoding="utf-8")
            output = io.StringIO()

            with redirect_stdout(output):
                result = rules_main([str(path)])

        self.assertEqual(result, 1)
        self.assertIn("Invalid TraceQuarry detection pack", output.getvalue())
