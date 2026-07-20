from __future__ import annotations

import re
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

from tools.package_agent_skill import PACKAGE_FILES, build_package

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = ROOT / "skills" / "tracequarry"
SKILL_PATH = SKILL_ROOT / "SKILL.md"


class AgentSkillContractTests(unittest.TestCase):
    def test_skill_frontmatter_is_minimal_and_valid(self) -> None:
        content = SKILL_PATH.read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
        self.assertIsNotNone(match)
        metadata = yaml.safe_load(match.group(1))  # type: ignore[union-attr]

        self.assertEqual(set(metadata), {"name", "description"})
        self.assertEqual(metadata["name"], "tracequarry")
        self.assertRegex(metadata["name"], r"^[a-z0-9-]{1,64}$")
        self.assertLessEqual(len(metadata["description"]), 1024)
        self.assertIn("Use when", metadata["description"])

    def test_skill_metadata_and_references_are_present(self) -> None:
        metadata = yaml.safe_load(
            (SKILL_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )
        interface = metadata["interface"]

        self.assertIn("$tracequarry", interface["default_prompt"])
        self.assertTrue((SKILL_ROOT / interface["icon_small"]).is_file())
        self.assertTrue((SKILL_ROOT / interface["icon_large"]).is_file())
        self.assertTrue(
            (SKILL_ROOT / "references" / "evidence-and-output-guide.md").is_file()
        )
        self.assertTrue(
            (SKILL_ROOT / "references" / "investigation-pivots.md").is_file()
        )

    def test_skill_tracks_current_cli_and_schema_contract(self) -> None:
        content = SKILL_PATH.read_text(encoding="utf-8")
        event_model = (ROOT / "uac_parser" / "timeline" / "event.py").read_text(
            encoding="utf-8"
        )

        for term in (
            "tracequarry",
            "--case-out",
            "--input-manifest",
            "--threat-type",
            "case_manifest.json",
            "mitre_candidates",
            "evidence_role",
        ):
            self.assertIn(term, content)
        self.assertIn('schema_version: str = "1.1"', event_model)

    def test_uploadable_skill_package_is_complete(self) -> None:
        source_files = {
            path.relative_to(SKILL_ROOT).as_posix()
            for path in SKILL_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(source_files, set(PACKAGE_FILES))
        self.assertFalse((ROOT / "SKILL.md").exists())

        with tempfile.TemporaryDirectory() as directory:
            output = build_package(Path(directory) / "tracequarry-skill.zip")
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {f"tracequarry/{relative}" for relative in PACKAGE_FILES},
                )
                self.assertTrue(
                    archive.read("tracequarry/SKILL.md").startswith(b"---\n")
                )


if __name__ == "__main__":
    unittest.main()
