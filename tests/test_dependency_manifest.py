from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]


class DependencyManifestTests(unittest.TestCase):
    def test_snyk_manifest_matches_runtime_dependencies(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        runtime = {
            requirement.name.lower(): requirement
            for value in project["project"]["dependencies"]
            if (requirement := Requirement(value))
        }
        scan = {
            requirement.name.lower(): requirement
            for line in (ROOT / "requirements.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if (value := line.strip()) and not value.startswith("#")
            if (requirement := Requirement(value))
        }

        self.assertEqual(scan.keys(), runtime.keys())
        for name, scan_requirement in scan.items():
            exact_pins = [
                specifier.version
                for specifier in scan_requirement.specifier
                if specifier.operator == "==" and "*" not in specifier.version
            ]
            self.assertEqual(
                len(exact_pins),
                1,
                f"{name} must have one exact version in requirements.txt",
            )
            self.assertIn(Version(exact_pins[0]), runtime[name].specifier)


if __name__ == "__main__":
    unittest.main()
