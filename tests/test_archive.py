from pathlib import Path
import unittest
import zipfile

from uac_parser.loaders.archive import load_input
from uac_parser.loaders.uac_layout import discover_exclusions, discover_sources


class ArchiveTests(unittest.TestCase):
    def test_zip_path_traversal_is_rejected(self) -> None:
        with self.subTest("zip traversal"):
            import tempfile
            with tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "unsafe.zip"
                with zipfile.ZipFile(archive, "w") as handle:
                    handle.writestr("../outside.txt", "unsafe")

                with self.assertRaisesRegex(ValueError, "escapes extraction root"):
                    load_input(str(archive))


    def test_missing_input_has_clear_error(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Input does not exist"):
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
            self.assertTrue(all("._" not in source.relative and "__MACOSX" not in source.relative for source in sources))
            self.assertEqual({item["relative"] for item in exclusions}, {"._bodyfile.txt", "__MACOSX/bodyfile.txt"})
