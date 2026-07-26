import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from uac_parser.loaders.archive import load_input
from uac_parser.loaders.uac_layout import discover_exclusions, discover_sources


class ArchiveTests(unittest.TestCase):
    def test_loose_evidence_file_is_copied_into_isolated_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "auth.log.1.gz"
            source.write_bytes(b"not-compressed-test-evidence\n")

            loaded = load_input(str(source))
            try:
                copied = loaded.root / source.name
                self.assertTrue(copied.is_file())
                self.assertEqual(copied.read_bytes(), source.read_bytes())
                self.assertNotEqual(copied.parent, source.parent)
            finally:
                loaded.cleanup()

    def test_invalid_named_archive_is_not_treated_as_a_loose_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "collection.tar.gz"
            source.write_text("not an archive")

            with self.assertRaisesRegex(ValueError, "archive name but is not valid"):
                load_input(str(source))

    def test_tar_regular_file_is_streamed_into_canonical_root(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "valid.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("collection/var/log/auth.log")
                payload = b"synthetic auth event\n"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            loaded = load_input(str(archive))
            try:
                extracted = loaded.root / "var/log/auth.log"
                self.assertEqual(extracted.read_bytes(), payload)
                self.assertTrue(
                    extracted.resolve().is_relative_to(loaded.root.resolve())
                )
            finally:
                loaded.cleanup()

    def test_mixed_root_archive_keeps_every_top_level_member_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "mixed-root.tar"
            with tarfile.open(archive, "w") as handle:
                for name, payload in (
                    ("collection/var/log/auth.log", b"nested event\n"),
                    ("collection-manifest.txt", b"manifest\n"),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    handle.addfile(member, io.BytesIO(payload))

            loaded = load_input(str(archive))
            try:
                self.assertEqual(loaded.member_prefix, "")
                self.assertTrue((loaded.root / "collection/var/log/auth.log").is_file())
                self.assertTrue((loaded.root / "collection-manifest.txt").is_file())
            finally:
                loaded.cleanup()

    def test_archive_uses_configured_scratch_volume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "valid.tar.gz"
            scratch = root / "scratch"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("collection/var/log/auth.log")
                payload = b"synthetic auth event\n"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            loaded = load_input(str(archive), temp_parent=scratch)
            try:
                self.assertTrue(loaded.root.resolve().is_relative_to(scratch.resolve()))
            finally:
                loaded.cleanup()

    def test_archive_rejects_insufficient_expansion_space(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "valid.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("collection/var/log/auth.log")
                payload = b"synthetic auth event\n"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            with (
                patch(
                    "uac_parser.loaders.archive.shutil.disk_usage",
                    return_value=SimpleNamespace(free=0),
                ),
                self.assertRaisesRegex(ValueError, "Insufficient free disk space"),
            ):
                load_input(str(archive))

    def test_tar_path_traversal_is_rejected(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("../outside.txt")
                payload = b"unsafe"
                member.size = len(payload)
                handle.addfile(member, io.BytesIO(payload))

            with self.assertRaisesRegex(ValueError, "escapes extraction root"):
                load_input(str(archive))

    def test_tar_links_are_not_materialized(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "links.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                member = tarfile.TarInfo("evidence-link")
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                handle.addfile(member)

            loaded = load_input(str(archive))
            try:
                self.assertFalse((loaded.root / "evidence-link").exists())
                exclusion = (loaded.archive_exclusions or [])[0]
                self.assertEqual(exclusion["relative"], "evidence-link")
                self.assertEqual(exclusion["member_type"], "symlink")
                self.assertEqual(exclusion["link_target"], "/etc/passwd")
                self.assertEqual(exclusion["byte_size"], len("/etc/passwd"))
                self.assertEqual(len(exclusion["sha256"]), 64)
            finally:
                loaded.cleanup()

    def test_zip_path_traversal_is_rejected(self) -> None:
        with self.subTest("zip traversal"):
            import tempfile

            with tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "unsafe.zip"
                with zipfile.ZipFile(archive, "w") as handle:
                    handle.writestr("../outside.txt", "unsafe")

                with self.assertRaisesRegex(ValueError, "escapes extraction root"):
                    load_input(str(archive))

    def test_zip_symlink_is_not_materialized(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "links.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                member = zipfile.ZipInfo("evidence-link")
                member.create_system = 3
                member.external_attr = 0o120777 << 16
                handle.writestr(member, "/etc/passwd")

            loaded = load_input(str(archive))
            try:
                self.assertFalse((loaded.root / "evidence-link").exists())
                exclusion = (loaded.archive_exclusions or [])[0]
                self.assertEqual(exclusion["relative"], "evidence-link")
                self.assertEqual(exclusion["member_type"], "symlink")
                self.assertEqual(exclusion["link_target"], "/etc/passwd")
                self.assertEqual(exclusion["byte_size"], len("/etc/passwd"))
                self.assertEqual(len(exclusion["sha256"]), 64)
            finally:
                loaded.cleanup()

    def test_missing_input_has_clear_error(self) -> None:
        import tempfile

        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "Input does not exist"),
        ):
            load_input(str(Path(directory) / "missing.tar.gz"))

    def test_macos_metadata_is_excluded_and_audited(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bodyfile.txt").write_text("0|/tmp/a|1|0|0|0|0|1|1|1|1\n")
            (root / "._bodyfile.txt").write_text("AppleDouble metadata")
            (root / "__MACOSX").mkdir()
            (root / "__MACOSX" / "bodyfile.txt").write_text("metadata copy")

            sources = discover_sources(root)
            exclusions = discover_exclusions(root)

            self.assertTrue(sources)
            self.assertTrue(
                all(
                    "._" not in source.relative and "__MACOSX" not in source.relative
                    for source in sources
                )
            )
            self.assertEqual(
                {item["relative"] for item in exclusions},
                {"._bodyfile.txt", "__MACOSX/bodyfile.txt"},
            )
