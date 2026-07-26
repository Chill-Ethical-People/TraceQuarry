import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from uac_parser.integrations.caseweave import default_case_reference
from uac_parser.pipeline import run_case_pipeline, run_pipeline


def _jsonl(content: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in content.decode().splitlines() if line]


class CaseWeaveIntegrationTests(unittest.TestCase):
    def test_single_collection_bundle_is_self_consistent_and_candidate_only(
        self,
    ) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            run_pipeline(
                fixture,
                output,
                year=2026,
                case_reference="IR-2026-0711",
            )

            bundle = output / "caseweave_import_bundle.zip"
            self.assertTrue(bundle.is_file())
            with zipfile.ZipFile(bundle) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {
                        "manifest.json",
                        "events.jsonl",
                        "timeline-candidates.jsonl",
                        "finding-candidates.jsonl",
                        "omissions.jsonl",
                    },
                )
                manifest = json.loads(archive.read("manifest.json"))
                events = _jsonl(archive.read("events.jsonl"))
                timeline = _jsonl(archive.read("timeline-candidates.jsonl"))
                findings = _jsonl(archive.read("finding-candidates.jsonl"))
                omissions = _jsonl(archive.read("omissions.jsonl"))

                self.assertEqual(
                    manifest["schema_name"],
                    "caseweave.tracequarry-import-bundle",
                )
                self.assertEqual(manifest["schema_version"], "1.0.0")
                self.assertEqual(manifest["case"]["case_reference"], "IR-2026-0711")
                self.assertTrue(manifest["collection"]["collection_id"])
                self.assertIsNone(manifest["collection"]["acquired_from_utc"])
                self.assertIsNone(manifest["collection"]["acquired_to_utc"])
                self.assertEqual(
                    manifest["collection"]["acquisition_time_confidence"],
                    "unknown",
                )
                self.assertFalse(manifest["extensions"]["analyst_decisions_included"])
                self.assertEqual(
                    manifest["extensions"]["omission_count"], len(omissions)
                )
                self.assertEqual(manifest["counts"]["events"], len(events))
                self.assertEqual(
                    manifest["counts"]["timeline_candidates"], len(timeline)
                )
                self.assertEqual(
                    manifest["counts"]["finding_candidates"], len(findings)
                )
                for dataset in manifest["datasets"].values():
                    content = archive.read(dataset["path"])
                    self.assertEqual(dataset["byte_size"], len(content))
                    self.assertEqual(
                        dataset["sha256"], hashlib.sha256(content).hexdigest()
                    )
                omission_dataset = manifest["extensions"]["omissions_dataset"]
                omission_content = archive.read(omission_dataset["path"])
                self.assertEqual(omission_dataset["record_count"], len(omissions))
                self.assertEqual(
                    omission_dataset["sha256"],
                    hashlib.sha256(omission_content).hexdigest(),
                )

            member_ids = {
                member["member_id"] for member in manifest["package"]["members"]
            }
            self.assertTrue(member_ids)
            collection_id = manifest["collection"]["collection_id"]
            self.assertTrue(
                all(event["collection_id"] == collection_id for event in events)
            )
            self.assertTrue(
                all(event.get("raw") or event.get("source_locator") for event in events)
            )
            self.assertTrue(
                all(
                    event.get("timestamp")
                    or (event.get("time_start") and event.get("time_end"))
                    for event in events
                )
            )
            self.assertTrue(
                all(
                    event.get("source_locator", {}).get("member_id") in member_ids
                    for event in events
                    if event.get("source_locator")
                )
            )
            self.assertTrue(
                all(item["producer_assessment"] != "malicious" for item in timeline)
            )
            self.assertTrue(
                all(item["producer_assessment"] != "malicious" for item in findings)
            )
            self.assertTrue(all(item["related_event_ids"] for item in findings))
            source_package = manifest["package"]["source_package"]
            self.assertEqual(source_package["schema_name"], "caseweave.source-package")
            self.assertEqual(source_package["schema_version"], "1.0.0")
            self.assertTrue(source_package["sha256"])
            source_package_path = output / "caseweave_source_package.tar"
            self.assertTrue(source_package_path.is_file())
            self.assertEqual(
                source_package["byte_size"], source_package_path.stat().st_size
            )
            self.assertEqual(
                source_package["sha256"],
                hashlib.sha256(source_package_path.read_bytes()).hexdigest(),
            )
            with tarfile.open(source_package_path) as source_archive:
                archived_members = {
                    member.name
                    for member in source_archive.getmembers()
                    if member.isfile()
                }
            self.assertTrue(
                all(
                    member["external_ref"]["source_package_id"]
                    == source_package["source_package_id"]
                    and member["external_ref"]["schema_name"]
                    == "caseweave.external-evidence-ref"
                    and member["external_ref"]["source_package_sha256"]
                    == source_package["sha256"]
                    and member["external_ref"]["member_path"] == member["relative_path"]
                    and member["external_ref"]["member_path"] in archived_members
                    for member in manifest["package"]["members"]
                )
            )
            serialized = json.dumps({"timeline": timeline, "findings": findings})
            self.assertNotIn("created_by", serialized)
            self.assertNotIn("last_edited_by", serialized)

    def test_multi_collection_index_uses_one_case_reference(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "case"
            run_case_pipeline(
                [fixture, fixture],
                output,
                year=2026,
                case_name="CaseWeave Contract Test",
                case_reference="IR-2026-0712",
            )

            index = json.loads((output / "caseweave_exports.json").read_text())
            self.assertEqual(index["case_reference"], "IR-2026-0712")
            self.assertEqual(len(index["exports"]), 2)
            self.assertEqual(
                {item["case_reference"] for item in index["exports"]},
                {"IR-2026-0712"},
            )
            self.assertEqual(
                len({item["collection_id"] for item in index["exports"]}),
                2,
            )
            self.assertTrue(
                all(
                    not Path(item["path"]).is_absolute()
                    and (output / item["path"]).is_file()
                    and not Path(item["source_package_path"]).is_absolute()
                    and (output / item["source_package_path"]).is_file()
                    for item in index["exports"]
                )
            )

            package_ids = []
            for item in index["exports"]:
                with zipfile.ZipFile(output / item["path"]) as archive:
                    manifest = json.loads(archive.read("manifest.json"))
                    package_ids.append(manifest["package"]["package_id"])
            self.assertEqual(len(set(package_ids)), 1)

    def test_exchange_identity_is_stable_when_evidence_moves(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            moved = root / "renamed-evidence"
            shutil.copytree(fixture, moved)
            output = root / "case"
            run_pipeline(fixture, output, year=2026)
            with zipfile.ZipFile(
                output / "caseweave_import_bundle.zip"
            ) as first_archive:
                first_manifest = json.loads(first_archive.read("manifest.json"))
                first_events = _jsonl(first_archive.read("events.jsonl"))
            run_pipeline(moved, output, year=2026)
            with zipfile.ZipFile(
                output / "caseweave_import_bundle.zip"
            ) as second_archive:
                second_manifest = json.loads(second_archive.read("manifest.json"))
                second_events = _jsonl(second_archive.read("events.jsonl"))

            self.assertEqual(
                first_manifest["collection"]["collection_id"],
                second_manifest["collection"]["collection_id"],
            )
            self.assertEqual(
                [event["event_id"] for event in first_events],
                [event["event_id"] for event in second_events],
            )
            self.assertEqual(
                first_manifest["case"]["case_reference"],
                second_manifest["case"]["case_reference"],
            )

    def test_wrapped_archive_external_refs_use_source_member_paths(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "wrapped-uac.tar"
            with tarfile.open(source, "w") as archive:
                archive.add(fixture, arcname="uac-wrapper")
            output = root / "out"
            run_pipeline(source, output, year=2026)

            with zipfile.ZipFile(output / "caseweave_import_bundle.zip") as archive:
                manifest = json.loads(archive.read("manifest.json"))

            self.assertTrue(
                all(
                    member["external_ref"]["member_path"]
                    == f"uac-wrapper/{member['relative_path']}"
                    for member in manifest["package"]["members"]
                )
            )

    def test_custody_registry_survives_duplicate_collection_rename(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alpha = root / "alpha"
            beta = root / "beta"
            renamed = root / "renamed-beta"
            shutil.copytree(fixture, alpha)
            shutil.copytree(fixture, beta)
            output = root / "case"

            run_case_pipeline([alpha, beta], output, year=2026)
            first = _collection_ids_by_name(output)
            beta.rename(renamed)
            run_case_pipeline([alpha, renamed], output, year=2026)
            second = _collection_ids_by_name(output)

            self.assertEqual(first["alpha"], second["alpha"])
            self.assertEqual(first["beta"], second["renamed-beta"])
            registry = json.loads((output / "caseweave_custody.json").read_text())
            self.assertEqual(registry["schema_version"], "1.0.0")
            self.assertEqual(len(registry["collections"]), 2)

    def test_package_inventory_accounts_for_metadata_and_symlinks(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plain = root / "plain"
            with_metadata = root / "with-metadata"
            shutil.copytree(fixture, plain)
            shutil.copytree(fixture, with_metadata)
            (with_metadata / ".DS_Store").write_bytes(b"forensic metadata")
            (with_metadata / "evidence-link").symlink_to("/etc/passwd")
            os.mkfifo(with_metadata / "capture-pipe")
            run_pipeline(plain, root / "plain-out", year=2026)
            run_pipeline(with_metadata, root / "metadata-out", year=2026)
            plain_manifest = _bundle_manifest(root / "plain-out")
            metadata_manifest = _bundle_manifest(root / "metadata-out")

            self.assertNotEqual(
                plain_manifest["package"]["package_id"],
                metadata_manifest["package"]["package_id"],
            )
            self.assertIn(
                ".DS_Store",
                {
                    member["relative_path"]
                    for member in metadata_manifest["package"]["members"]
                },
            )
            directory_link = next(
                member
                for member in metadata_manifest["package"]["members"]
                if member["relative_path"] == "evidence-link"
            )
            self.assertEqual(directory_link["member_type"], "symlink")
            special_member = next(
                member
                for member in metadata_manifest["package"]["members"]
                if member["relative_path"] == "capture-pipe"
            )
            self.assertEqual(special_member["member_type"], "special")
            self.assertTrue(
                all(
                    isinstance(item["byte_size"], int)
                    for item in metadata_manifest["extensions"][
                        "source_package_exclusions"
                    ]
                )
            )
            self.assertEqual(
                metadata_manifest["package"]["inventory_fingerprint"],
                _contract_inventory_fingerprint(
                    metadata_manifest["package"]["members"]
                ),
            )
            with tarfile.open(
                root / "metadata-out" / "caseweave_source_package.tar"
            ) as package:
                self.assertTrue(package.getmember("evidence-link").issym())
                self.assertTrue(package.getmember("capture-pipe").isfifo())

            source = root / "symlink-uac.tar"
            with tarfile.open(source, "w") as archive:
                payload = b"Jul 26 01:00:00 host sshd[1]: listening\n"
                regular = tarfile.TarInfo("wrapper/var/log/auth.log")
                regular.size = len(payload)
                archive.addfile(regular, io.BytesIO(payload))
                link = tarfile.TarInfo("wrapper/evidence-link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                archive.addfile(link)
            run_pipeline(source, root / "symlink-out", year=2026)
            symlink_manifest = _bundle_manifest(root / "symlink-out")
            symlink_member = next(
                member
                for member in symlink_manifest["package"]["members"]
                if member["relative_path"] == "evidence-link"
            )
            self.assertEqual(symlink_member["member_type"], "symlink")
            self.assertEqual(
                symlink_member["external_ref"]["member_path"],
                "wrapper/evidence-link",
            )

    def test_custody_identity_changes_when_symlink_target_changes(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            output = root / "out"
            shutil.copytree(fixture, evidence)
            link = evidence / "evidence-link"
            link.symlink_to("/etc/passwd")

            run_pipeline(evidence, output, year=2026)
            first_manifest = _bundle_manifest(output)
            link.unlink()
            link.symlink_to("/etc/shadow")
            run_pipeline(evidence, output, year=2026)
            second_manifest = _bundle_manifest(output)

            self.assertNotEqual(
                first_manifest["collection"]["collection_id"],
                second_manifest["collection"]["collection_id"],
            )
            self.assertNotEqual(
                first_manifest["package"]["inventory_fingerprint"],
                second_manifest["package"]["inventory_fingerprint"],
            )

    def test_default_case_reference_is_stable(self) -> None:
        first = default_case_reference("Example IR Case", "collection-01")
        second = default_case_reference("Example IR Case", "collection-01")

        self.assertEqual(first, second)
        self.assertRegex(first, r"^TQ-EXAMPLE-IR-CASE-[A-F0-9]{10}$")


def _collection_ids_by_name(output: Path) -> dict[str, str]:
    index = json.loads((output / "caseweave_exports.json").read_text())
    result = {}
    for item in index["exports"]:
        with zipfile.ZipFile(output / item["path"]) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        result[manifest["collection"]["collection_name"]] = manifest["collection"][
            "collection_id"
        ]
    return result


def _bundle_manifest(output: Path) -> dict[str, object]:
    with zipfile.ZipFile(output / "caseweave_import_bundle.zip") as archive:
        return json.loads(archive.read("manifest.json"))


def _contract_inventory_fingerprint(members: list[dict[str, object]]) -> str:
    lines = ["caseweave-inventory-v1"]
    for member in sorted(
        members,
        key=lambda item: (
            str(item["relative_path"]),
            str(item.get("member_type") or ""),
        ),
    ):
        fields = [
            str(member["relative_path"]),
            str(member["byte_size"]),
            str(member["sha256"]),
            str(member["role"]),
        ]
        if member.get("member_type"):
            fields.append(str(member["member_type"]))
        lines.append("\t".join(fields))
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


if __name__ == "__main__":
    unittest.main()
