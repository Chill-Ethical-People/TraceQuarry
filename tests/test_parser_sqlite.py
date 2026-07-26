from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from uac_parser.loaders.uac_layout import discover_sources
from uac_parser.parsers.sqlite_log import parse
from uac_parser.pipeline import run_pipeline


class SqliteLogParserTests(unittest.TestCase):
    def test_extensionless_synology_database_is_discovered_and_parsed_read_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / ".SYNOSYSLOGDB"
            self._create_synology_log_database(database)
            before = self._sha256(database)

            sources = discover_sources(root)
            self.assertEqual(
                [(source.relative, source.source_type) for source in sources],
                [(".SYNOSYSLOGDB", "sqlite_log")],
            )
            events = parse(database, database.name, timezone_name="UTC")

            records = [
                event for event in events if event.event_action == "sqlite_log_record"
            ]
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].timestamp, "2026-01-01T00:00:00Z")
            self.assertEqual(records[0].host, "nas01")
            self.assertEqual(records[0].process, "sshd")
            self.assertEqual(records[0].src_ip, "192.0.2.10")
            self.assertIn("Failed password", records[0].summary)
            self.assertIn("synology_nas", records[0].tags)
            self.assertEqual(before, self._sha256(database))

            output = root / "pipeline-output"
            result = run_pipeline(database, output, year=2026, timezone_name="UTC")
            source_index = json.loads((output / "source_index.json").read_text())
            self.assertGreaterEqual(result.events, 2)
            self.assertEqual(source_index["input"]["kind"], "file")
            self.assertEqual(source_index["sources"][0]["source_type"], "sqlite_log")
            self.assertEqual(source_index["sources"][0]["parser_status"], "parsed")
            self.assertEqual(before, self._sha256(database))

    def test_pipeline_accepts_direct_var_log_directory_and_loose_log_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            var_log = root / "var" / "log"
            var_log.mkdir(parents=True)
            auth_log = var_log / "auth.log"
            auth_log.write_text(
                "Jul 21 10:15:30 host01 sshd[123]: Failed password for root "
                "from 192.0.2.30 port 2222 ssh2\n",
                encoding="utf-8",
            )

            directory_result = run_pipeline(
                var_log,
                root / "directory-output",
                year=2026,
                timezone_name="UTC",
            )
            file_result = run_pipeline(
                auth_log,
                root / "file-output",
                year=2026,
                timezone_name="UTC",
            )

            self.assertEqual(directory_result.events, 1)
            self.assertEqual(file_result.events, 1)
            self.assertTrue((root / "directory-output" / "timeline_full.csv").is_file())
            self.assertTrue((root / "file-output" / "timeline_full.csv").is_file())

    @staticmethod
    def _create_synology_log_database(path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.executescript(
                """
                CREATE TABLE hosts(host_id INTEGER PRIMARY KEY, host_name TEXT);
                CREATE TABLE progs(prog_id INTEGER PRIMARY KEY, prog_name TEXT);
                CREATE TABLE tags(tag_id INTEGER PRIMARY KEY, tag_name TEXT);
                CREATE TABLE logs(
                    id INTEGER PRIMARY KEY,
                    host INTEGER,
                    ip INTEGER,
                    tag INTEGER,
                    utcsec INTEGER,
                    prog INTEGER,
                    msg TEXT
                );
                INSERT INTO hosts VALUES(1, 'nas01');
                INSERT INTO progs VALUES(1, 'sshd');
                INSERT INTO tags VALUES(1, 'auth');
                INSERT INTO logs VALUES(
                    1, 1, 3221225994, 1, 1767225600, 1,
                    'Failed password for root from 192.0.2.10'
                );
                INSERT INTO logs VALUES(
                    2, 1, 3221225994, 1, 1767225660, 1,
                    'Accepted publickey for analyst from 192.0.2.10'
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
