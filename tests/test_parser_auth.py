from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from uac_parser.parsers.auth import parse


class AuthParserTests(unittest.TestCase):
    def test_authentication_privilege_and_account_actions(self) -> None:
        records = [
            "Jun 16 10:00:01 host sshd[1]: Accepted publickey for root from 198.51.100.50 port 50001 ssh2",
            "Jun 16 10:00:02 host sshd[2]: Failed password for invalid user admin from 198.51.100.50 port 50002 ssh2",
            "Jun 16 10:00:03 host sudo[3]: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            "Jun 16 10:00:04 host su[4]: session opened for user root by alice(uid=1000)",
            "Jun 16 10:00:05 host passwd[5]: password changed for root",
            "Jun 16 10:00:06 host useradd[6]: new user: name=svc-backup, UID=1107, GID=1107, home=/home/svc-backup, shell=/bin/bash",
            "Jun 16 10:00:07 host groupadd[7]: new group: name=ops, GID=1200",
            "Jun 16 10:00:08 host userdel[8]: delete user 'stale'",
            "Jun 16 10:00:09 host usermod[9]: change user 'alice' shell from '/bin/sh' to '/bin/bash'",
            "Jun 16 10:00:10 host usermod[10]: user alice account unlocked",
            "Jun 16 10:00:11 host sshd[11]: Invalid user oracle from 198.51.100.60 port 50003",
            "not a timestamp and should be ignored",
            "Jun 16 10:00:12 host app[12]: ordinary informational message",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("\n".join(records), encoding="utf-8")
            events = parse(path, "var/log/auth.log", host="override", year=2026)

        by_action = {event.event_action: event for event in events}
        self.assertEqual(
            set(by_action),
            {
                "ssh_login_success",
                "ssh_login_failure",
                "sudo_command",
                "su_session_opened",
                "password_changed",
                "user_created",
                "group_created",
                "user_deleted",
                "user_modified",
                "account_unlocked",
                "ssh_invalid_user",
            },
        )
        self.assertEqual(by_action["ssh_login_success"].src_ip, "198.51.100.50")
        self.assertEqual(
            by_action["sudo_command"].extra, {"pwd": "/tmp", "runas": "root"}
        )
        self.assertIn(
            "root_password_changed", by_action["password_changed"].detection_names
        )
        self.assertEqual(by_action["user_created"].extra["shell"], "/bin/bash")
        self.assertEqual(by_action["ssh_invalid_user"].mitre, ["T1110"])
        self.assertTrue(all(event.host == "override" for event in events))

    def test_malformed_candidate_messages_do_not_create_events(self) -> None:
        records = [
            "Jun 16 10:00:01 host sshd[1]: Accepted password without an address",
            "Jun 16 10:00:02 host sudo[2]: malformed sudo message",
            "Jun 16 10:00:03 host useradd[3]: new user: malformed",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("\n".join(records), encoding="utf-8")
            self.assertEqual(parse(path, "auth.log", year=2026), [])


if __name__ == "__main__":
    unittest.main()
