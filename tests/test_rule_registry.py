import unittest

from uac_parser.enrich.rule_registry import load_registry, tool_rules
from uac_parser.enrich.ttp_rules import enrich_events
from uac_parser.timeline.event import TimelineEvent


class RuleRegistryTests(unittest.TestCase):
    def test_registry_loads_runtime_tool_rules(self) -> None:
        self.assertEqual(load_registry()["metadata"]["schema_version"], "1.0")
        self.assertIn("rclone", tool_rules())

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
        self.assertIn("tool_rclone_executed", enriched.detection_names)
        self.assertIn("T1567.002", enriched.mitre)
