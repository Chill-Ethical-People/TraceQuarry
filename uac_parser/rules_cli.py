from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from uac_parser.enrich.rule_registry import (
    RULE_SECTIONS,
    RegistryError,
    load_registry_file,
    registry_path,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracequarry-rules",
        description="Validate a TraceQuarry YAML detection pack.",
    )
    parser.add_argument(
        "registry",
        nargs="?",
        type=Path,
        default=registry_path(),
        help="Registry YAML to validate (default: packaged tagging_registry.yml)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        registry = load_registry_file(args.registry)
    except RegistryError as exc:
        print(f"Invalid TraceQuarry detection pack: {exc}")
        return 1

    metadata = registry["metadata"]
    print(
        f"Valid TraceQuarry detection pack: {args.registry}\n"
        f"Schema: {metadata['schema_version']}\n"
        + "\n".join(f"{section}: {len(registry[section])}" for section in RULE_SECTIONS)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
