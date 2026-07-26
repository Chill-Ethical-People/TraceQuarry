#!/usr/bin/env python3
"""Build a deterministic, uploadable TraceQuarry Agent Skill archive."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = "tracequarry"
SKILL_SOURCE = ROOT / "skills" / SKILL_ROOT
PACKAGE_FILES = (
    "SKILL.md",
    "LICENSE",
    "NOTICE",
    "agents/openai.yaml",
    "assets/tracequarry-platform-icon.svg",
    "assets/tracequarry-lockup.svg",
    "references/evidence-and-output-guide.md",
    "references/investigation-pivots.md",
)


def build_package(output: Path) -> Path:
    missing = [
        relative
        for relative in PACKAGE_FILES
        if not (SKILL_SOURCE / relative).is_file()
    ]
    if missing:
        raise FileNotFoundError(f"Missing Agent Skill files: {', '.join(missing)}")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        for relative in PACKAGE_FILES:
            info = zipfile.ZipInfo(f"{SKILL_ROOT}/{relative}")
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                info, (SKILL_SOURCE / relative).read_bytes(), compresslevel=9
            )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Package the TraceQuarry Agent Skill for upload or distribution."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "tracequarry-skill.zip",
        help="Destination zip file",
    )
    args = parser.parse_args()
    output = build_package(args.output)
    print(f"Created {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
