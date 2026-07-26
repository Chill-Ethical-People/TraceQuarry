from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from uac_parser.enrich.attack_phases import (
    AttackPhaseRegistryError,
    attack_phase_registry_path,
    load_attack_phase_registry,
    load_attack_phase_registry_file,
)
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
    parser.add_argument(
        "--attack-phases",
        type=Path,
        default=attack_phase_registry_path(),
        help="ATT&CK phase YAML to validate (default: packaged attack_phases.yml)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        registry = load_registry_file(args.registry)
        if args.attack_phases == attack_phase_registry_path():
            phase_registry = load_attack_phase_registry()
        else:
            phase_registry = load_attack_phase_registry_file(args.attack_phases)
    except (RegistryError, AttackPhaseRegistryError) as exc:
        print(f"Invalid TraceQuarry detection pack or phase registry: {exc}")
        return 1

    metadata = registry["metadata"]
    print(
        f"Valid TraceQuarry detection pack: {args.registry}\n"
        f"Schema: {metadata['schema_version']}\n"
        + "\n".join(f"{section}: {len(registry[section])}" for section in RULE_SECTIONS)
        + f"\nattack_phases: {len(phase_registry['phases'])}"
        + f"\ntechnique_phase_mappings: {len(phase_registry['techniques'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
