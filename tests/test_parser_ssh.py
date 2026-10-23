import gzip
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from uac_parser.parsers.ssh import parse_authorized_keys


class AuthorizedKeysTests(unittest.TestCase):
    def test_key_fields_and_evidence_are_preserved(self) -> None:
        cases = [
            ("ssh-rsa AAAA", "ssh-rsa", None),
            ("ssh-dss AAAA legacy", "ssh-dss", "legacy"),
            ("ssh-ed25519\tAAAA\tcomment", "ssh-ed25519", "comment"),
            ("ecdsa-sha2-nistp256 AAAA curve", "ecdsa-sha2-nistp256", "curve"),
            ('from="host1,host2",no-pty ssh-rsa AAAA note', "ssh-rsa", "note"),
            ('command="id",no-pty\tssh-ed25519 AAAA # note', "ssh-ed25519", "# note"),
            ("ssh-ed25519 AAAA text,with\ttabs", "ssh-ed25519", "text,with\ttabs"),
            ("malformed !,!,", "", ""),
            ('command="echo hello" ssh-rsa AAAA', "ssh-rsa", None),
            (
                'command="echo\thello" ssh-ed25519 AAAA operator',
                "ssh-ed25519",
                "operator",
            ),
            ('command="echo \\"hello\\"",no-pty ssh-rsa AAAA note', "ssh-rsa", "note"),
            ('command="unterminated ssh-ed25519 AAAA tail', "", ""),
            ("sk-ssh-ed25519@openssh.com AAAA", "", ""),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorized_keys"
            path.write_text("# comment\n\n" + "\n".join(row[0] for row in cases) + "\n")
            events = parse_authorized_keys(path, "root/.ssh/authorized_keys", "lab")
        self.assertEqual(len(events), len(cases))
        for line, (event, (raw, key_type, comment)) in enumerate(
            zip(events, cases, strict=True), start=3
        ):
            self.assertEqual(event.raw, raw)
            self.assertEqual(event.extra["line"], line)
            self.assertEqual(event.extra["key_type"], key_type)
            self.assertEqual(event.extra["comment"], comment)
            self.assertEqual(event.host, "lab")
            self.assertEqual(event.source_path, "root/.ssh/authorized_keys")
            self.assertEqual(event.evidence_role, "state_observation")

    def test_key_looking_comment_does_not_replace_the_key_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorized_keys"
            path.write_text("ssh-ed25519\tAAAA\tssh-rsa\tBBBB\tcomment\n")
            event = parse_authorized_keys(path, "root/.ssh/authorized_keys")[0]
        self.assertEqual(event.extra["key_type"], "ssh-ed25519")
        self.assertEqual(event.extra["comment"], "ssh-rsa\tBBBB\tcomment")

    def test_adversarial_lines_complete_and_retain_raw_evidence(self) -> None:
        raw_lines = [
            "!," * 100_000 + "!",
            "x" + "\t" * 100_000 + "!",
            "!,\t" * 100_000 + "!",
            "no-pty " + "ssh-" + "a" * 100_000 + " ! !",
            "ssh-ed25519 AAAA valid-after-malformed",
        ]
        code = """
import sys
from pathlib import Path
from uac_parser.parsers.common import read_text_lines
from uac_parser.parsers.ssh import parse_authorized_keys
path = Path(sys.argv[1])
expected = list(read_text_lines(path))
events = parse_authorized_keys(path, 'root/.ssh/authorized_keys')
assert [event.raw for event in events] == expected
assert events[-1].extra['key_type'] == 'ssh-ed25519'
assert events[-1].extra['comment'] == 'valid-after-malformed'
"""
        with tempfile.TemporaryDirectory() as directory:
            for compressed in (False, True):
                with self.subTest(compressed=compressed):
                    path = Path(directory) / "authorized_keys"
                    data = ("\n".join(raw_lines) + "\n").encode()
                    path.write_bytes(gzip.compress(data) if compressed else data)
                    subprocess.run(
                        [sys.executable, "-c", code, str(path)],
                        check=True,
                        capture_output=True,
                        timeout=10,
                    )


if __name__ == "__main__":
    unittest.main()
