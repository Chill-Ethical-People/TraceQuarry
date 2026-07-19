from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from uac_parser.parsers.account_diff import diff_accounts
from uac_parser.parsers.accounts import parse_group, parse_passwd, parse_shadow


class AccountParserTests(unittest.TestCase):
    def test_account_files_classify_privilege_and_password_risks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            passwd = root / "passwd"
            passwd.write_text(
                "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/tmp:/bin/bash\ndaemonx:x:50:50::/srv:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nmalformed\n",
                encoding="utf-8",
            )
            shadow = root / "shadow"
            shadow.write_text(
                "root:$6$hash:20616::::::\nlegacy:$1$hash:20615::::::\nlocked:!!:0::::::\n",
                encoding="utf-8",
            )
            group = root / "group"
            group.write_text(
                "sudo:x:27:alice\ndocker:x:999:bob\nusers:x:100:\n", encoding="utf-8"
            )

            passwd_events = parse_passwd(passwd, "etc/passwd")
            shadow_events = parse_shadow(shadow, "etc/shadow")
            group_events = parse_group(group, "etc/group")

        backdoor = next(event for event in passwd_events if event.user == "backdoor")
        daemon = next(event for event in passwd_events if event.user == "daemonx")
        legacy = next(event for event in shadow_events if event.user == "legacy")
        locked = next(event for event in shadow_events if event.user == "locked")
        docker = next(
            event for event in group_events if event.extra["group"] == "docker"
        )
        self.assertIn("uid0_non_root_account", backdoor.detection_names)
        self.assertIn("interactive_shell_for_system_account", daemon.detection_names)
        self.assertEqual(legacy.extra["hash_type"], "MD5")
        self.assertEqual(legacy.raw, "[shadow hash redacted]")
        self.assertEqual(locked.extra["hash_type"], "locked_or_disabled")
        self.assertEqual(docker.severity, "high")

    def test_backup_diffs_cover_account_password_and_group_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc = root / "etc"
            etc.mkdir()
            (etc / "passwd-").write_text(
                "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\nstale:x:1002:1002::/home/stale:/bin/bash\n",
                encoding="utf-8",
            )
            (etc / "passwd").write_text(
                "root:x:0:0:root:/root:/bin/bash\nalice:x:0:1000::/srv/alice:/bin/bash\nnewsvc:x:1100:1100::/home/newsvc:/bin/bash\n",
                encoding="utf-8",
            )
            (etc / "shadow-").write_text(
                "root:$6$old:20600::::::\nalice:!!:20600::::::\nlockme:$6$old:20600::::::\n",
                encoding="utf-8",
            )
            (etc / "shadow").write_text(
                "root:$6$new:20616::::::\nalice:$6$new:20616::::::\nlockme:!:20616::::::\nnewsvc:$6$new:20616::::::\n",
                encoding="utf-8",
            )
            (etc / "group-").write_text(
                "sudo:x:27:alice\nops:x:1200:alice,bob\nremoved:x:1300:old\n",
                encoding="utf-8",
            )
            (etc / "group").write_text(
                "sudo:x:27:alice,bob\nops:x:1200:alice\nnewgroup:x:1400:newsvc\n",
                encoding="utf-8",
            )

            events = diff_accounts(root, host="host01")

        actions = {event.event_action for event in events}
        self.assertTrue(
            {
                "account_created_since_backup",
                "account_modified_since_backup",
                "account_deleted_since_backup",
                "password_set_new_account",
                "password_changed",
                "account_unlocked",
                "account_locked",
                "group_created_since_backup",
                "group_member_added",
                "group_member_removed",
                "group_deleted_since_backup",
            }.issubset(actions)
        )
        root_password = next(
            event
            for event in events
            if event.user == "root" and event.event_action == "password_changed"
        )
        sudo_add = next(
            event for event in events if event.event_action == "group_member_added"
        )
        self.assertIn("root_password_changed", root_password.detection_names)
        self.assertEqual(root_password.raw, "[shadow hash redacted]")
        self.assertIn("privileged_group_member_added", sudo_add.detection_names)
        self.assertTrue(all(event.host == "host01" for event in events))

    def test_missing_backups_produce_no_diff_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
            self.assertEqual(diff_accounts(root), [])


if __name__ == "__main__":
    unittest.main()
