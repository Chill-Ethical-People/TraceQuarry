import tempfile
import unittest
from pathlib import Path

from uac_parser.enrich.esxi_profiles import esxi_profile_findings, profile_assessment
from uac_parser.enrich.ttp_rules import enrich_events
from uac_parser.parsers.esxi import parse


class EsxiProfileTests(unittest.TestCase):
    def commands(self, commands: list[str]):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shell.log"
            path.write_text(
                "\n".join(
                    f"2026-01-02T01:{index:02d}:00Z shell[42]: [root]: {command}"
                    for index, command in enumerate(commands)
                )
            )
            events = parse(path, "var/run/log/shell.log", host="esx-lab")
        for index, event in enumerate(events):
            event.event_id = f"evt-{index}"
            event.collection_id = "collection-lab"
        return enrich_events(events)

    def test_payload_invocation_is_candidate_not_attribution(self) -> None:
        event = self.commands(["python enc.py /vmfs/volumes/lab"])[0]
        self.assertIn("payload_candidate.esxi_python_encryptor_candidate", event.tags)
        self.assertIn("T1486", event.mitre_candidates)
        self.assertNotIn("T1486", event.mitre)
        self.assertFalse(any(tag.startswith("actor_similarity.") for tag in event.tags))
        self.assertEqual(event.extra["payload_candidates"][0]["confidence"], "low")

    def test_read_only_and_literals_do_not_become_payloads(self) -> None:
        for command in (
            "grep enc.py /vmfs/volumes/lab/log",
            "echo python enc.py /vmfs/volumes/lab",
            "cat /vmfs/volumes/lab/enc.py",
            "python benign.py enc.py /vmfs/volumes/lab",
            "python -c 'enc.py /vmfs/volumes/lab'",
            "python enc.py /tmp/lab",
            "cp enc.py /vmfs/volumes/lab/enc.py",
        ):
            with self.subTest(command=command):
                events = self.commands([command])
                self.assertFalse(
                    any(event.extra.get("payload_candidates") for event in events)
                )

    def test_vmkatz_records_invocation_not_credential_recovery(self) -> None:
        event = self.commands(
            [
                "python vmkatz_loader.py --vmfs-device /dev/disks/lab /vmfs/volumes/lab/disk.vmdk"
            ]
        )[0]
        self.assertIn("tool.vmkatz", event.tags)
        self.assertIn("T1003", event.mitre)
        self.assertEqual(
            event.extra["outcome"], "invocation_recorded_credential_recovery_unproven"
        )

    def test_same_host_profile_and_cross_host_rejection(self) -> None:
        commands = [
            "./vmkatz /vmfs/volumes/lab/disk.vmdk",
            "vim-cmd hostsvc/disable_lockdown_mode",
            "python enc.py /vmfs/volumes/lab",
        ]
        events = self.commands(commands)
        findings = esxi_profile_findings(events)
        self.assertTrue(
            any(f.get("profile_kind") == "actor_neutral_tradecraft" for f in findings)
        )
        for boundary in ("host", "collection_id", "timestamp"):
            with self.subTest(boundary=boundary):
                events = self.commands(commands)
                setattr(
                    events[-1],
                    boundary,
                    "2026-01-05T01:02:00Z" if boundary == "timestamp" else "different",
                )
                findings = esxi_profile_findings(events)
                self.assertFalse(
                    any(
                        f.get("profile_kind") == "actor_neutral_tradecraft"
                        for f in findings
                    )
                )

    def test_profile_report_explains_no_actor_match(self) -> None:
        events = self.commands(["python enc.py /vmfs/volumes/lab"])
        report = profile_assessment(events, esxi_profile_findings(events))
        self.assertEqual(report["actor_profiles_evaluated"], 15)
        self.assertEqual(report["qualified_actor_similarities"], [])
        self.assertEqual(report["attribution"], "not_assessed")
        self.assertTrue(report["payload_candidates"])
