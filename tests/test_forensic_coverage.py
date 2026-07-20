from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from pathlib import Path

from uac_parser.loaders.uac_layout import discover_sources
from uac_parser.output.writers import write_summary
from uac_parser.parsers.auth import parse as parse_auth
from uac_parser.parsers.journal import parse as parse_journal
from uac_parser.parsers.network import parse_netstat
from uac_parser.pipeline import run_case_pipeline, run_pipeline
from uac_parser.timeline.event import TimelineEvent


class ForensicCoverageTests(unittest.TestCase):
    def test_compressed_auth_rotation_is_parsed_transparently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log.1.gz"
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                handle.write(
                    "Jun 16 10:00:01 host sshd[7]: Accepted publickey for root "
                    "from 198.51.100.8 port 4242 ssh2\n"
                )

            events = parse_auth(path, "var/log/auth.log.1.gz", year=2026)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_action, "ssh_login_success")

    def test_large_recognized_sources_are_not_silently_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log.large"
            with path.open("wb") as handle:
                handle.seek(201 * 1024 * 1024)
                handle.write(b"\0")

            sources = discover_sources(Path(directory))

        self.assertTrue(any(source.relative == "auth.log.large" for source in sources))

    def test_native_binary_logs_are_accounted_for_as_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "collection"
            (root / "var/log/journal/id").mkdir(parents=True)
            (root / "var/log/journal/id/system.journal").write_bytes(b"LPKSHHRH")
            output = Path(directory) / "out"

            result = run_pipeline(root, output, year=2026)
            source_index = json.loads((output / "source_index.json").read_text())

        journal = next(
            source
            for source in source_index["sources"]
            if source["source_type"] == "journal_binary"
        )
        inventory = next(
            item
            for item in source_index["evidence_inventory"]
            if item["relative"].endswith("system.journal")
        )
        self.assertEqual(result.errors, 0)
        self.assertEqual(journal["parser_status"], "unsupported")
        self.assertEqual(inventory["coverage_status"], "unsupported")

    def test_optional_compression_is_reported_as_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "collection"
            (root / "var/log").mkdir(parents=True)
            (root / "var/log/auth.log.1.zst").write_bytes(
                b"\x28\xb5\x2f\xfdnot-a-complete-zstd-frame"
            )
            output = Path(directory) / "out"

            result = run_pipeline(root, output, year=2026)
            source_index = json.loads((output / "source_index.json").read_text())

        source = next(
            item
            for item in source_index["sources"]
            if item["relative"].endswith("auth.log.1.zst")
        )
        self.assertEqual(result.errors, 0)
        self.assertEqual(source["parser_status"], "unsupported")
        self.assertIn("zstd decoder", source["parser_error"])

    def test_case_fingerprint_includes_unmatched_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collections = []
            for name, note in (("one", "alpha"), ("two", "beta")):
                collection = root / name
                (collection / "var/log").mkdir(parents=True)
                (collection / "var/log/auth.log").write_text(
                    "Jun 16 10:00:01 host sshd[7]: Failed password for root "
                    "from 198.51.100.8 port 4242 ssh2\n",
                    encoding="utf-8",
                )
                (collection / "unparsed-evidence.bin").write_text(
                    note, encoding="utf-8"
                )
                collections.append(collection)

            result = run_case_pipeline(collections, root / "case", year=2026)

        self.assertEqual(result.duplicate_collections, 0)

    def test_syslog_rollover_assigns_preceding_december_to_prior_year(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(
                "Dec 31 23:59:59 host sshd[7]: Failed password for root "
                "from 198.51.100.8 port 4242 ssh2\n"
                "Jan  1 00:00:01 host sshd[7]: Accepted publickey for root "
                "from 198.51.100.8 port 4242 ssh2\n",
                encoding="utf-8",
            )

            events = parse_auth(path, "var/log/auth.log", year=2026)

        self.assertTrue(events[0].timestamp.startswith("2025-12-31"))
        self.assertTrue(events[1].timestamp.startswith("2026-01-01"))

    def test_network_direction_requires_listener_or_role_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "netstat.txt"
            path.write_text(
                "tcp 0 0 10.0.0.5:2222 198.51.100.30:55000 "
                "ESTABLISHED 60/sshd\n"
                "tcp 0 0 10.0.0.5:25000 198.51.100.40:25001 "
                "ESTABLISHED 61/custom\n",
                encoding="utf-8",
            )

            events = parse_netstat(path, "netstat.txt")

        inbound, unknown = events
        self.assertEqual(inbound.event_action, "inbound_connection")
        self.assertEqual(
            inbound.extra["direction_reason"], "sshd is acting as a server process"
        )
        self.assertEqual(unknown.event_action, "connection_observed")
        self.assertEqual(unknown.extra["direction"], "unknown")
        self.assertNotIn("outbound_ssh_connection", unknown.detection_names)

    def test_windowed_summary_keeps_untimed_network_snapshot_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            network = TimelineEvent(
                source_type="network_state",
                event_action="listening_port",
                evidence_role="state_observation",
                summary="Listening on 0.0.0.0:22",
            )

            write_summary(summary, [], [], [], context_events=[network])
            text = summary.read_text(encoding="utf-8")

        self.assertIn("1 listening port(s)", text)
        self.assertIn("no point-in-time timestamp", text)

    def test_journalctl_text_is_parsed_as_log_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journalctl.txt"
            path.write_text(
                "2026-06-16T10:00:01+00:00 host sshd[7]: Accepted publickey "
                "for root from 198.51.100.8 port 4242 ssh2\n",
                encoding="utf-8",
            )

            events = parse_journal(path, "journalctl.txt", year=2026)

        self.assertEqual(events[0].event_action, "ssh_login_success")
        self.assertEqual(events[0].timestamp, "2026-06-16T10:00:01Z")


if __name__ == "__main__":
    unittest.main()
