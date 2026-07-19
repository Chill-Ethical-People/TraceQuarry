from __future__ import annotations

import argparse
import json
import os
import sys

from uac_parser.assist import profile_choices
from uac_parser.enrich.iocs import load_iocs, parse_ioc_text
from uac_parser.pipeline import (
    CasePipelineResult,
    PipelineResult,
    run_case_pipeline,
    run_pipeline,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uac-timeline",
        description="TraceQuarry: parse UAC collections into normalized Linux forensic timelines with TTP enrichment.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="UAC archive (.tar, .tar.gz, .tgz, .zip) or extracted directory",
    )
    parser.add_argument("--out", help="Output directory for single-collection mode")
    parser.add_argument(
        "--input",
        action="append",
        dest="case_inputs",
        default=[],
        help="UAC input for case mode. Repeat for multiple collections.",
    )
    parser.add_argument(
        "--input-manifest",
        help="Text file of UAC inputs for case mode. One archive or directory per line.",
    )
    parser.add_argument(
        "--case-out", help="Output directory for multi-collection case workspace"
    )
    parser.add_argument(
        "--case-name",
        default="TraceQuarry Case",
        help="Case name for multi-collection summaries",
    )
    parser.add_argument(
        "--incident-start",
        help="Mini-timeline start timestamp, e.g. 2026-06-16T08:00:00Z",
    )
    parser.add_argument(
        "--incident-end", help="Mini-timeline end timestamp, e.g. 2026-06-16T12:00:00Z"
    )
    parser.add_argument(
        "--year",
        type=int,
        help="Year to apply to syslog-style timestamps that omit a year",
    )
    parser.add_argument(
        "--timezone",
        default="UTC",
        help="Timezone for syslog-style local timestamps, e.g. UTC or Asia/Hong_Kong",
    )
    parser.add_argument(
        "--host", default="", help="Host override when UAC layout does not reveal it"
    )
    parser.add_argument(
        "--ioc",
        action="append",
        default=[],
        help="Known IoC to match. Repeatable. Values may be IPs, domains, hashes, paths, users, or literals.",
    )
    parser.add_argument(
        "--ioc-file",
        help="Text/CSV file of IoCs. One IoC per line, or value,kind,label.",
    )
    parser.add_argument(
        "--threat-type",
        choices=[profile["id"] for profile in profile_choices()],
        default="",
        help="Assisted-investigation profile. Prioritizes evidence without filtering the complete timeline.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = build_arg_parser().parse_args(argv)
    iocs = []
    iocs.extend(load_iocs(args.ioc_file))
    iocs.extend(parse_ioc_text("\n".join(args.ioc)))
    try:
        result: CasePipelineResult | PipelineResult
        if args.case_out:
            inputs = []
            if args.input:
                inputs.append(args.input)
            inputs.extend(args.case_inputs)
            inputs.extend(_load_manifest(args.input_manifest))
            if not inputs:
                raise SystemExit(
                    "Case mode requires a positional input, --input, or --input-manifest."
                )
            result = run_case_pipeline(
                inputs,
                args.case_out,
                incident_start=args.incident_start,
                incident_end=args.incident_end,
                year=args.year,
                timezone_name=args.timezone,
                host=args.host,
                iocs=iocs,
                case_name=args.case_name,
                threat_type=args.threat_type,
            )
        else:
            if not args.input:
                raise SystemExit("Single-collection mode requires an input path.")
            if not args.out:
                raise SystemExit("Single-collection mode requires --out.")
            result = run_pipeline(
                args.input,
                args.out,
                incident_start=args.incident_start,
                incident_end=args.incident_end,
                year=args.year,
                timezone_name=args.timezone,
                host=args.host,
                iocs=iocs,
                threat_type=args.threat_type,
            )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def _load_manifest(path: str | None) -> list[str]:
    if not path:
        return []
    output = []
    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if line and not line.startswith("#"):
                output.append(line)
    return output


if __name__ == "__main__":
    sys.exit(main())
