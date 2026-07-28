import argparse
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import install_tracequarry as installer


class InstallerTests(unittest.TestCase):
    def test_secure_directory_tightens_existing_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case-data"
            path.mkdir(mode=0o755)

            installer._secure_directory(path)

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_platform_defaults_keep_application_and_case_data_together(self) -> None:
        home = Path("/home/analyst")

        linux = installer.default_install_root("linux", home, {})
        macos = installer.default_install_root("macos", home, {})
        windows = installer.default_install_root(
            "windows", home, {"LOCALAPPDATA": "C:/TraceQuarryTest/AppData/Local"}
        )

        self.assertEqual(linux, home / ".local/share/tracequarry")
        self.assertEqual(macos, home / "Library/Application Support/TraceQuarry")
        self.assertEqual(
            windows, Path("C:/TraceQuarryTest/AppData/Local") / "TraceQuarry"
        )

    def test_launchers_quote_paths_and_preserve_user_arguments(self) -> None:
        executable = Path("/opt/Trace Quarry/bin/tracequarry-web")
        data_dir = Path("/cases/Trace Quarry")

        unix = installer.render_unix_launcher(executable, work_dir=data_dir)
        windows = installer.render_windows_launcher(executable, work_dir=data_dir)

        self.assertIn(installer.MANAGED_MARKER, unix)
        self.assertIn("'/opt/Trace Quarry/bin/tracequarry-web'", unix)
        self.assertIn("--work-dir '/cases/Trace Quarry/web_runs'", unix)
        self.assertTrue(unix.rstrip().endswith('"$@"'))
        self.assertIn('"/opt/Trace Quarry/bin/tracequarry-web"', windows)
        self.assertIn('"/cases/Trace Quarry/web_runs"', windows)
        self.assertIn("%*", windows)

    def test_uninstall_preserves_case_data_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "install"
            layout = installer.InstallLayout(
                platform="linux",
                install_root=root,
                venv_dir=root / "venv",
                bin_dir=root / "bin",
                data_dir=root / "data",
            )
            layout.venv_dir.mkdir(parents=True)
            layout.data_dir.mkdir()
            evidence = layout.data_dir / "web_runs/outputs/case/summary.md"
            evidence.parent.mkdir(parents=True)
            evidence.write_text("preserve me", encoding="utf-8")
            for path in installer.launcher_paths(layout).values():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    f"#!/bin/sh\n# {installer.MANAGED_MARKER}\n", encoding="utf-8"
                )
            (root / "install.json").write_text("{}", encoding="utf-8")

            installer.uninstall(layout, purge_data=False)

            self.assertTrue(evidence.is_file())
            self.assertFalse(layout.venv_dir.exists())
            self.assertFalse((root / "install.json").exists())
            self.assertTrue(
                all(
                    not path.exists()
                    for path in installer.launcher_paths(layout).values()
                )
            )

    def test_purge_data_requires_uninstall(self) -> None:
        args = argparse.Namespace(
            platform="linux",
            source=".",
            install_root=None,
            bin_dir=None,
            data_dir=None,
            uninstall=False,
            purge_data=True,
            dry_run=False,
        )
        with mock.patch.object(installer, "build_parser") as parser:
            parser.return_value.parse_args.return_value = args
            with self.assertRaisesRegex(SystemExit, "only be used with --uninstall"):
                installer.main([])
