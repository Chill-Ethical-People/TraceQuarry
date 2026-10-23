import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from uac_parser.output.workbook import write_investigation_workbook


class WorkbookTests(unittest.TestCase):
    def test_review_columns_and_complete_selected_export(self) -> None:
        event = {
            "timestamp": "2022-05-20T11:15:57.540000Z",
            "host": "lab",
            "summary": "Script invocation recorded",
            "raw": "2022-05-20T11:15:57.540Z. shell: python enc.py /vmfs/volumes/lab",
            "mitre_candidates": ["T1486"],
            "tags": ["payload_candidate.esxi_python_encryptor_candidate"],
            "event_id": "evt-lab",
        }
        with tempfile.TemporaryDirectory() as directory:
            for streamed in (False, True):
                with self.subTest(streamed=streamed):
                    target = Path(directory) / "review.xlsx"
                    result = write_investigation_workbook(
                        target,
                        case_name="Synthetic review",
                        briefing={"selected_events": [event]},
                        timeline_rows=[event],
                        timeline_fields=list(event),
                        findings=[],
                        selected_rows=(
                            dict(event, event_id=f"evt-{i}") for i in range(502)
                        )
                        if streamed
                        else None,
                    )
                    self.assertEqual(result["selected_rows"], 502 if streamed else 1)
                    with zipfile.ZipFile(target) as archive:
                        namespace = {
                            "s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                        }
                        for sheet in (2, 3):
                            root = ET.fromstring(
                                archive.read(f"xl/worksheets/sheet{sheet}.xml")
                            )
                            rows = root.findall("s:sheetData/s:row", namespace)
                            headers = [
                                "".join(c.itertext())
                                for c in rows[0].findall("s:c", namespace)
                            ]
                            values = {
                                c.get("r"): "".join(c.itertext())
                                for c in rows[1].findall("s:c", namespace)
                            }
                            raw_index = headers.index("summary") + 1
                            self.assertIn(headers[raw_index], ("raw", "raw_evidence"))
                            self.assertIn(event["raw"], values.values())
                            self.assertIn(
                                "2022-05-20 11:15:57.540 (UTC)", values.values()
                            )
                            self.assertIsNotNone(root.find("s:autoFilter", namespace))
                            if sheet == 2:
                                self.assertEqual(len(rows) - 1, result["selected_rows"])
                        self.assertIn(
                            b"payload_candidate.esxi_python_encryptor_candidate",
                            archive.read("xl/worksheets/sheet3.xml"),
                        )

    def test_workbook_contains_briefing_and_disables_formula_interpretation(
        self,
    ) -> None:
        briefing = {
            "scope": "full",
            "metrics": {
                "timeline_events": 1,
                "selected_events": 1,
                "hosts": 1,
                "findings": 1,
                "ioc_hits": 1,
            },
            "narrative": "One analyst-selected event requires validation.",
            "executive": {
                "summary": "Evidence-backed review summary.",
                "incident_timeline": [
                    {"timestamp": "2026-07-10T01:25:00Z", "summary": "Access"}
                ],
                "key_metrics": [
                    {"label": "Timeline events", "value": 1},
                    {"label": "Selected milestones", "value": 1},
                ],
                "threat_actions": [{"summary": "Observed access"}],
                "data_exfiltration": ["No selected exfiltration milestone."],
                "impact": ["No selected impact milestone."],
                "accounts": ["root"],
                "legal_note": "Requires incident owner and legal review.",
            },
            "phase_breakdown": [
                {
                    "label": "Initial Access",
                    "tactic_id": "TA0001",
                    "confirmed_events": 1,
                    "candidate_events": 0,
                    "selected_events": 1,
                    "first_observed": "2026-07-10T01:25:00Z",
                }
            ],
            "selected_events": [
                {
                    "timestamp": "2026-07-10T01:25:00Z",
                    "host": "host01",
                    "attack_phases": ["initial_access"],
                    "severity": "high",
                    "summary": "Successful login",
                    "analyst_disposition": "suspicious",
                    "analyst_tags": ["initial_access"],
                    "analyst_note": "Validate source ownership.",
                    "event_id": "evt_1",
                    "source_type": "auth_log",
                    "source_path": "var/log/auth.log",
                    "source_sha256": "a" * 64,
                    "raw": "Accepted publickey for root",
                }
            ],
        }
        fields = ["timestamp", "summary", "raw", "event_id"]
        rows = [
            {
                "timestamp": "2026-07-10T01:25:00Z",
                "summary": '=HYPERLINK("https://invalid.example","open")',
                "raw": "+cmd",
                "event_id": "evt_1",
            }
        ]
        findings = [
            {
                "severity": "high",
                "confidence": "medium",
                "title": "Successful login",
                "summary": "Review source.",
                "tags": ["valid_account"],
                "event_ids": ["evt_1"],
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "investigation.xlsx"
            result = write_investigation_workbook(
                target,
                case_name="Workbook test",
                briefing=briefing,
                timeline_rows=rows,
                timeline_fields=fields,
                findings=findings,
            )

            self.assertEqual(result["timeline_rows"], 1)
            self.assertEqual(result["selected_rows"], 1)
            with zipfile.ZipFile(target) as archive:
                workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
                styles_xml = archive.read("xl/styles.xml").decode("utf-8")
                executive_sheet_xml = archive.read("xl/worksheets/sheet1.xml").decode(
                    "utf-8"
                )
                sheet_xml = "".join(
                    archive.read(name).decode("utf-8")
                    for name in archive.namelist()
                    if name.startswith("xl/worksheets/sheet")
                )
            self.assertIn("Executive Briefing", workbook_xml)
            self.assertIn("Selected Timeline", workbook_xml)
            self.assertIn("Findings", workbook_xml)
            self.assertNotIn("<f>", sheet_xml)
            for brand_color in (
                "FF0E1626",
                "FF16213A",
                "FF9DBE8D",
                "FFE5A84B",
                "FFD96A5B",
                "FFFCFBF8",
            ):
                self.assertIn(brand_color, styles_xml)
            self.assertNotIn("FF275B87", styles_xml)
            self.assertNotIn("FF347DB8", styles_xml)
            self.assertNotIn("FFB91C1C", styles_xml)
            self.assertIn('tabColor rgb="FFE5A84B"', executive_sheet_xml)


if __name__ == "__main__":
    unittest.main()
