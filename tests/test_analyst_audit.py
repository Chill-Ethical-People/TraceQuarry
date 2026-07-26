import json
import stat
import tempfile
import unittest
from pathlib import Path

from uac_parser.analyst_audit import (
    append_annotation_audit,
    audit_status,
    read_and_verify,
)


class AnalystAuditTests(unittest.TestCase):
    def test_annotation_audit_is_private_ordered_and_hash_chained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "analyst_audit.jsonl"
            first = append_annotation_audit(
                path,
                event_id="evt_one",
                before={},
                after={"disposition": "suspicious"},
            )
            second = append_annotation_audit(
                path,
                event_id="evt_one",
                before={"disposition": "suspicious"},
                after={"disposition": "malicious"},
            )

            records = read_and_verify(path)
            mode = stat.S_IMODE(path.stat().st_mode)

        self.assertEqual([record["sequence"] for record in records], [1, 2])
        self.assertEqual(second["previous_hash"], first["record_hash"])
        self.assertEqual(mode, 0o600)

    def test_tampered_audit_record_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "analyst_audit.jsonl"
            append_annotation_audit(
                path,
                event_id="evt_one",
                before={},
                after={"disposition": "suspicious"},
            )
            record = json.loads(path.read_text(encoding="utf-8"))
            record["after"]["disposition"] = "benign"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")

            status = audit_status(path)

            self.assertFalse(status["valid"])
            with self.assertRaisesRegex(ValueError, "integrity verification"):
                read_and_verify(path)


if __name__ == "__main__":
    unittest.main()
