from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from uac_parser import cli


class CliTests(unittest.TestCase):
    def _result(self) -> Mock:
        result = Mock()
        result.to_dict.return_value = {"events": 7, "output_dir": "out"}
        return result

    def test_single_collection_routes_settings_and_iocs(self) -> None:
        result = self._result()
        with (
            patch.object(cli, "run_pipeline", return_value=result) as run,
            patch("builtins.print") as output,
        ):
            status = cli.main(
                [
                    "collection.tar.gz",
                    "--out",
                    "out",
                    "--year",
                    "2026",
                    "--timezone",
                    "Asia/Hong_Kong",
                    "--host",
                    "host01",
                    "--ioc",
                    "198.51.100.50",
                    "--threat-type",
                    "comprehensive",
                ]
            )

        self.assertEqual(status, 0)
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["year"], 2026)
        self.assertEqual(kwargs["timezone_name"], "Asia/Hong_Kong")
        self.assertEqual(kwargs["iocs"][0].kind, "ip")
        self.assertEqual(kwargs["threat_type"], "comprehensive")
        self.assertEqual(json.loads(output.call_args.args[0])["events"], 7)

    def test_case_mode_combines_positional_repeated_and_manifest_inputs(self) -> None:
        result = self._result()
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "inputs.txt"
            manifest.write_text("# case inputs\nthird.tar.gz\n\n", encoding="utf-8")
            with (
                patch.object(cli, "run_case_pipeline", return_value=result) as run,
                patch("builtins.print"),
            ):
                status = cli.main(
                    [
                        "first.tar.gz",
                        "--input",
                        "second.tar.gz",
                        "--input-manifest",
                        str(manifest),
                        "--case-out",
                        "case-out",
                        "--case-name",
                        "Case 42",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(
            run.call_args.args[:2],
            (["first.tar.gz", "second.tar.gz", "third.tar.gz"], "case-out"),
        )
        self.assertEqual(run.call_args.kwargs["case_name"], "Case 42")

    def test_required_arguments_have_clear_errors(self) -> None:
        with self.assertRaisesRegex(SystemExit, "requires an input path"):
            cli.main([])
        with self.assertRaisesRegex(SystemExit, "requires --out"):
            cli.main(["collection.tar.gz"])
        with self.assertRaisesRegex(SystemExit, "Case mode requires"):
            cli.main(["--case-out", "case"])

    def test_pipeline_value_errors_become_cli_errors(self) -> None:
        with (
            patch.object(
                cli, "run_pipeline", side_effect=ValueError("invalid incident window")
            ),
            self.assertRaisesRegex(SystemExit, "invalid incident window"),
        ):
            cli.main(["collection", "--out", "out"])

    def test_manifest_loader_ignores_comments_and_blank_lines(self) -> None:
        self.assertEqual(cli._load_manifest(None), [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.txt"
            path.write_text("# comment\nfirst\n\n second \n", encoding="utf-8")
            self.assertEqual(cli._load_manifest(str(path)), ["first", "second"])


if __name__ == "__main__":
    unittest.main()
