import tempfile
import unittest
from pathlib import Path

from uac_parser.enrich.storylines import build_storylines
from uac_parser.parsers import auditd
from uac_parser.parsers.auditd import parse as parse_auditd
from uac_parser.parsers.journal import parse as parse_journal
from uac_parser.timeline.event import TimelineEvent


class JournalParserRiskTests(unittest.TestCase):
    def test_journal_classifies_security_and_availability_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journalctl.txt"
            path.write_text(
                "\n".join(
                    [
                        "not a journal line",
                        "Jun 16 10:00:00 host sshd[7]: Failed password for invalid user admin from 198.51.100.8 port 4242 ssh2",
                        "2026-06-16T10:00:01+00:00 host sudo[8]: root : USER=root ; COMMAND=/usr/bin/id",
                        "2026-06-16T10:00:02+00:00 host systemd[1]: Started Suspicious Service",
                        "2026-06-16T10:00:03+00:00 host systemd[1]: Stopped Suspicious Service",
                        "2026-06-16T10:00:04+00:00 host CRON[9]: (root) CMD (/tmp/task)",
                        "2026-06-16T10:00:05+00:00 host kernel[1]: Out of memory: Kill process 22",
                        "2026-06-16T10:00:06+00:00 host kernel[1]: worker segfault at 0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            events = parse_journal(
                path,
                "journalctl.txt",
                year=2026,
                timezone_name="UTC",
            )

        actions = [event.event_action for event in events]
        self.assertEqual(
            actions,
            [
                "ssh_login_failure",
                "sudo_command",
                "service_started",
                "service_stopped",
                "cron_execution",
                "out_of_memory",
                "process_crash",
            ],
        )
        self.assertEqual(events[0].user, "admin")
        self.assertEqual(events[0].src_ip, "198.51.100.8")
        self.assertEqual(events[1].command, "/usr/bin/id")
        self.assertEqual(events[4].mitre, ["T1053.003"])


class AuditParserRiskTests(unittest.TestCase):
    def test_audit_records_are_grouped_decoded_and_key_enriched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.log"
            path.write_text(
                "\n".join(
                    [
                        'node=host01 type=SYSCALL msg=audit(1718532000.100:42): pid=55 uid=0 auid=1000 comm="sh" exe="/bin/sh" success=yes key="exec_from_tmp"',
                        'node=host01 type=EXECVE msg=audit(1718532000.100:42): argc=2 a0="2f62696e2f7368" a1="2d63"',
                        'node=host01 type=PATH msg=audit(1718532000.100:42): name="/tmp/payload"',
                        "node=host01 type=EOE msg=audit(1718532000.100:42):",
                        'node=host01 type=ADD_USER msg=audit(1718532001.100:43): acct="backdoor" res=success',
                        "node=host01 type=EOE msg=audit(1718532001.100:43):",
                        'node=host01 type=USER_AUTH msg=audit(1718532002.100:44): acct="root" addr=198.51.100.9 res=failed',
                        "node=host01 type=EOE msg=audit(1718532002.100:44):",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            events = parse_auditd(path, "var/log/audit/audit.log")

        self.assertEqual(len(events), 3)
        execution, account, authentication = events
        self.assertEqual(execution.command, "/bin/sh -c")
        self.assertEqual(execution.file_path, "/tmp/payload")
        self.assertIn("audit_exec_from_tmp", execution.detection_names)
        self.assertEqual(execution.host, "host01")
        self.assertEqual(account.event_action, "user_account_change")
        self.assertIn("audit_user_account_change", account.detection_names)
        self.assertEqual(authentication.event_action, "user_auth")
        self.assertIn("audit_authentication_failure", authentication.detection_names)

    def test_pending_audit_groups_are_bounded_and_flushed(self) -> None:
        original_limit = auditd.MAX_PENDING_AUDIT_EVENTS
        auditd.MAX_PENDING_AUDIT_EVENTS = 1
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "audit.log"
                path.write_text(
                    "\n".join(
                        [
                            'type=USER_CMD msg=audit(1718532000.100:1): cmd="id"',
                            'type=USER_CMD msg=audit(1718532001.100:2): cmd="whoami"',
                        ]
                    )
                    + "\n",
                    encoding="utf-8",
                )

                events = parse_auditd(path, "audit.log", host="host01")
        finally:
            auditd.MAX_PENDING_AUDIT_EVENTS = original_limit

        self.assertEqual(len(events), 2)
        self.assertEqual([event.command for event in events], ["id", "whoami"])


class StorylineRiskTests(unittest.TestCase):
    def test_bruteforce_success_and_post_access_activity_are_correlated(self) -> None:
        failures = [
            TimelineEvent(
                event_id=f"evt_fail_{index}",
                timestamp=f"2026-07-10T00:{index:02d}:00Z",
                event_action="ssh_login_failure",
                src_ip="198.51.100.50",
                user="root",
            )
            for index in range(10)
        ]
        success = TimelineEvent(
            event_id="evt_success",
            timestamp="2026-07-10T00:10:00Z",
            event_action="ssh_login_success",
            src_ip="198.51.100.50",
            user="root",
            severity="medium",
        )
        sudo = TimelineEvent(
            event_id="evt_sudo",
            timestamp="2026-07-10T00:11:00Z",
            event_action="sudo_command",
            user="root",
            severity="medium",
        )

        storylines = build_storylines([*failures, success, sudo])

        brute_force = next(
            item for item in storylines if str(item["title"]).startswith("Brute-force")
        )
        self.assertEqual(brute_force["confidence"], "high")
        self.assertIn("10 failed attempts", brute_force["summary"])
        self.assertIn("evt_success", brute_force["event_ids"])
        self.assertIn("evt_sudo", brute_force["event_ids"])

    def test_initial_access_execution_and_credential_changes_form_storylines(
        self,
    ) -> None:
        events = [
            TimelineEvent(
                event_id="evt_access",
                timestamp="2026-07-10T00:00:00Z",
                event_action="http_request",
                severity="medium",
            ),
            TimelineEvent(
                event_id="evt_download",
                timestamp="2026-07-10T00:01:00Z",
                event_action="shell_command",
                detection_names=["download_execute_chain"],
                severity="high",
            ),
            TimelineEvent(
                event_id="evt_password",
                timestamp="2026-07-10T00:02:00Z",
                event_action="password_changed",
                user="svc-backup",
                severity="medium",
            ),
        ]

        storylines = build_storylines(events)
        titles = {str(item["title"]) for item in storylines}

        self.assertIn(
            "Initial access followed by suspicious execution or persistence", titles
        )
        self.assertIn("Credential modification activity", titles)


if __name__ == "__main__":
    unittest.main()
