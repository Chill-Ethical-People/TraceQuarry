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
            self.assertEqual(manifest["tracequarry_version"], "0.4.0b2")
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

    def test_parallel_case_pipeline_is_deterministic_and_reports_each_collection(
        self,
    ) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            serial_output = Path(directory) / "serial"
            parallel_output = Path(directory) / "parallel"
            serial = run_case_pipeline(
                [fixture, fixture], serial_output, year=2026, max_workers=1
            )
            progress: list[dict[str, object]] = []
            parallel = run_case_pipeline(
                [fixture, fixture],
                parallel_output,
                year=2026,
                max_workers=2,
                progress_callback=progress.append,
            )

            self.assertEqual(parallel.events, serial.events)
            self.assertEqual(parallel.findings, serial.findings)
            self.assertEqual(parallel.duplicate_collections, 1)
            self.assertEqual(len(list((parallel_output / "hosts").iterdir())), 2)
            completed = {
                int(item["collection_index"])
                for item in progress
                if item.get("stage") == "collection_complete"
            }
            self.assertEqual(completed, {1, 2})
            serial_lines = (serial_output / "case_timeline_full.jsonl").read_text()
            parallel_lines = (parallel_output / "case_timeline_full.jsonl").read_text()
            self.assertEqual(parallel_lines, serial_lines)

    def test_case_pipeline_rejects_zero_workers(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "workers"),
        ):
            run_case_pipeline([fixture], directory, max_workers=0)
