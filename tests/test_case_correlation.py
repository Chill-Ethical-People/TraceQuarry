import unittest

from uac_parser.pipeline import build_case_correlations
from uac_parser.timeline.event import TimelineEvent


class CaseCorrelationTests(unittest.TestCase):
    def test_multiple_shared_tools_are_indexed_in_one_event_pass(self) -> None:
        events = [
            TimelineEvent(
                event_id=f"evt-{collection}",
                collection_id=collection,
                command="rclone copy /srv remote:case && chisel client example.invalid",
            )
            for collection in ("collection-a", "collection-b")
        ]

        correlations = build_case_correlations(events)
        shared_tools = {
            item["value"]: item
            for item in correlations
            if item["type"] == "shared_tooling"
        }

        self.assertEqual(set(shared_tools), {"rclone", "chisel"})
        self.assertEqual(
            shared_tools["rclone"]["collections"],
            ["collection-a", "collection-b"],
        )
        self.assertEqual(
            shared_tools["rclone"]["event_ids"],
            ["evt-collection-a", "evt-collection-b"],
        )
