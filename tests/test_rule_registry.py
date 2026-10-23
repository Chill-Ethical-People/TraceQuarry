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

    def test_candidate_technique_ids_are_validated(self) -> None:
        registry = copy.deepcopy(load_registry())
        registry["ttp_tags"]["exfil_tool_usage"]["mitre_candidates"] = ["invalid"]
        with self.assertRaises(RegistryError):
            validate_registry(registry)

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
        # A remote name alone does not establish a cloud provider or exfiltration.
        self.assertNotIn("ttp.cloud_storage_exfiltration", enriched.tags)
        self.assertIn("T1048", enriched.mitre_candidates)
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

    def test_actor_profile_tags_are_reached_from_command_enrichment(self) -> None:
        commands = [
            "xmrig --config /tmp/miner.json",
            "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
            "curl http://169.254.169.254/latest/meta-data/",
            "crontab /tmp/jobs",
        ]
        events = [
            TimelineEvent(
                event_id=f"event-{index}",
                command=command,
                raw=command,
                event_category="execution",
                event_action="shell_command",
                source_type="shell_history",
            )
            for index, command in enumerate(commands)
        ]
        findings = derive_findings(enrich_events(events))
        self.assertTrue(
            any(finding.get("profile_id") == "teamtnt_like" for finding in findings)
        )
        self.assertTrue(
            all("actor_similarity.teamtnt_like" in event.tags for event in events)
        )

    def test_every_existing_actor_profile_tags_only_supporting_events(self) -> None:
        for profile_id, profile in actor_similarity_rules().items():
            with self.subTest(profile=profile_id):
                signals = sorted(
                    set(
                        profile["strong_indicators"]
                        + profile.get("supporting_indicators", [])
                        + profile.get("required_any_indicators", [])
                    )
                )
                events = [
                    TimelineEvent(event_id=f"evt-{index}", tags=[signal])
                    for index, signal in enumerate(signals)
                ]
                unrelated = TimelineEvent(
                    event_id="unrelated", tags=["routine_maintenance"]
                )
                findings = derive_findings([*events, unrelated])
                finding = next(
                    item for item in findings if item.get("profile_id") == profile_id
                )
                label = f"actor_similarity.{profile_id}"
                self.assertIn(label, finding["tags"])
                self.assertIn("This is not attribution", finding["summary"])
                relevant = set(
                    profile["strong_indicators"]
                    + profile.get("supporting_indicators", [])
                )
                for event, signal in zip(events, signals, strict=True):
                    self.assertEqual(label in event.tags, signal in relevant)
                self.assertNotIn(label, unrelated.tags)

    def test_actor_tags_are_not_limited_to_finding_preview_ids(self) -> None:
        events = [
            TimelineEvent(event_id=f"evt-{i}", tags=["ttp.miner_execution"])
            for i in range(20)
        ]
        events += [
            TimelineEvent(event_id="docker", tags=["ttp.docker_socket_access"]),
            TimelineEvent(event_id="cloud", tags=["ttp.cloud_metadata_access"]),
            TimelineEvent(event_id="cron", tags=["ttp.cron_persistence"]),
        ]
        derive_findings(events)
        self.assertTrue(
            all("actor_similarity.teamtnt_like" in event.tags for event in events)
        )

    def test_actor_profile_does_not_tag_a_single_multi_signal_record(self) -> None:
        for profile_id, profile in actor_similarity_rules().items():
            event = TimelineEvent(
                event_id="only-one",
                tags=profile["strong_indicators"]
                + profile.get("supporting_indicators", []),
            )
            findings = derive_findings([event])
            self.assertFalse(
                any(item.get("profile_id") == profile_id for item in findings)
            )
            self.assertNotIn(f"actor_similarity.{profile_id}", event.tags)

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
