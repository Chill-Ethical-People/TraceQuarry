import json
import stat
import tempfile
import unittest
from pathlib import Path

from uac_parser.pipeline import run_case_pipeline, run_pipeline


class PipelineTests(unittest.TestCase):
    def test_fixture_pipeline_writes_defensible_manifest(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"

            result = run_pipeline(
                fixture,
                output,
                incident_start="2026-06-16T01:58:00Z",
                incident_end="2026-06-16T10:01:40Z",
                year=2026,
                timezone_name="Asia/Hong_Kong",
            )

            self.assertGreater(result.events, 0)
            self.assertEqual(result.errors, 0)
            manifest = json.loads((output / "run_manifest.json").read_text())
            self.assertEqual(manifest["tracequarry_version"], "0.4.0b1")
            self.assertGreater(manifest["coverage"]["sources_discovered"], 0)
            self.assertEqual(manifest["coverage"]["sources_failed"], 0)
            self.assertTrue(all(source["sha256"] for source in manifest["sources"]))
            self.assertTrue((output / "timeline_full.csv").exists())
            self.assertTrue((output / "source_index.json").exists())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((output / "timeline_full.jsonl").stat().st_mode), 0o600
            )
            event_ids = [
                json.loads(line)["event_id"]
                for line in (output / "timeline_full.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(event_ids), len(set(event_ids)))

    def test_assisted_profile_writes_reports_without_filtering_events(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            baseline_output = Path(directory) / "baseline"
            assisted_output = Path(directory) / "assisted"
            baseline = run_pipeline(fixture, baseline_output, year=2026)
            assisted = run_pipeline(
                fixture,
                assisted_output,
                year=2026,
                threat_type="persistence_backdoor",
            )

            self.assertEqual(assisted.events, baseline.events)
            self.assertTrue((assisted_output / "assisted_investigation.md").exists())
            report = json.loads(
                (assisted_output / "assisted_investigation.json").read_text()
            )
            self.assertEqual(report["profile_id"], "persistence_backdoor")
            manifest = json.loads((assisted_output / "run_manifest.json").read_text())
            self.assertEqual(
                manifest["settings"]["threat_type"], "persistence_backdoor"
            )
            self.assertIn(
                "## Assisted Investigation",
                (assisted_output / "summary.md").read_text(),
            )

            run_pipeline(fixture, assisted_output, year=2026)
            self.assertFalse((assisted_output / "assisted_investigation.md").exists())
            self.assertFalse((assisted_output / "assisted_investigation.json").exists())

    def test_case_pipeline_preserves_collection_provenance(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "case"
            result = run_case_pipeline(
                [fixture, fixture], output, year=2026, case_name="Regression Case"
            )

            self.assertEqual(result.collections, 2)
            self.assertEqual(result.duplicate_collections, 1)
            manifest = json.loads((output / "case_manifest.json").read_text())
            collection_ids = [item["collection_id"] for item in manifest["collections"]]
            self.assertEqual(len(set(collection_ids)), 2)
            first_event = json.loads(
                (output / "case_timeline_full.jsonl").read_text().splitlines()[0]
            )
            self.assertTrue(first_event["collection_id"])
            case_events = [
                json.loads(line)
                for line in (output / "case_timeline_full.jsonl")
                .read_text()
                .splitlines()
            ]
            case_event_ids = {event["event_id"] for event in case_events}
            self.assertTrue(
                all(
                    related_id in case_event_ids
                    for event in case_events
                    for related_id in event["related_event_ids"]
                )
            )
            self.assertTrue((output / "case_correlation.json").exists())
            self.assertEqual(len(manifest["duplicate_collection_groups"]), 1)
            correlations = json.loads((output / "case_correlation.json").read_text())
            self.assertEqual(correlations["correlations"], [])
            findings = json.loads((output / "case_findings.json").read_text())[
                "findings"
            ]
            self.assertTrue(
                any(
                    item["title"] == "Duplicate Collection Evidence Detected"
                    for item in findings
                )
            )
