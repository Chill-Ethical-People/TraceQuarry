#!/usr/bin/env python3
"""Run bounded, synthetic TraceQuarry capacity benchmarks.

The harness keeps fixture generation outside the measured interval, runs each
scenario in a fresh process, and stops a scenario if it exceeds the configured
wall-time or resident-memory ceiling. Evidence is synthetic and uses only
documentation address ranges.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import subprocess
import sys
import tarfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Scenario:
    name: str
    axis: str
    mode: str
    collections: int
    lines_per_collection: int
    files_per_collection: int = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded synthetic TraceQuarry capacity benchmarks."
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("/tmp") / f"tracequarry-load-{int(time.time())}",
        help="New directory for generated fixtures, outputs, and results.",
    )
    parser.add_argument(
        "--profile",
        choices=("quick", "full"),
        default="quick",
        help="Quick smoke profile or progressive full capacity profile.",
    )
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-rss-mib", type=int, default=4096)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    return parser


def scenarios(profile: str) -> list[Scenario]:
    if profile == "quick":
        return [
            Scenario("uac-single-10k", "uac_events", "single_uac", 1, 10_000),
            Scenario("uac-case-10x100", "uac_collections", "uac_case", 10, 100),
            Scenario("esxi-10x1k", "esxi_inventory", "esxi", 1, 1_000, 10),
        ]
    return [
        Scenario("uac-single-10k", "uac_events", "single_uac", 1, 10_000),
        Scenario("uac-single-50k", "uac_events", "single_uac", 1, 50_000),
        Scenario("uac-single-100k", "uac_events", "single_uac", 1, 100_000),
        Scenario("uac-single-200k", "uac_events", "single_uac", 1, 200_000),
        Scenario("uac-single-400k", "uac_events", "single_uac", 1, 400_000),
        Scenario("uac-case-10x200", "uac_collections", "uac_case", 10, 200),
        Scenario("uac-case-50x200", "uac_collections", "uac_case", 50, 200),
        Scenario("uac-case-100x200", "uac_collections", "uac_case", 100, 200),
        Scenario("uac-case-250x200", "uac_collections", "uac_case", 250, 200),
        Scenario("uac-case-500x100", "uac_collections", "uac_case", 500, 100),
        Scenario("esxi-10x1k", "esxi_inventory", "esxi", 1, 1_000, 10),
        Scenario("esxi-100x1k", "esxi_inventory", "esxi", 1, 1_000, 100),
        Scenario("esxi-500x1k", "esxi_inventory", "esxi", 1, 1_000, 500),
        Scenario("esxi-1000x1k", "esxi_inventory", "esxi", 1, 1_000, 1_000),
    ]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.worker:
        return run_worker(args.worker)
    work_dir = args.work_dir.expanduser().resolve()
    if work_dir.exists():
        raise SystemExit(f"Refusing existing benchmark directory: {work_dir}")
    work_dir.mkdir(parents=True, mode=0o700)
    results: list[dict[str, Any]] = []
    stopped_axes: set[str] = set()
    for scenario in scenarios(args.profile):
        if scenario.axis in stopped_axes:
            results.append(
                {
                    **asdict(scenario),
                    "status": "skipped_after_axis_limit",
                }
            )
            continue
        print(f"Preparing {scenario.name}...", flush=True)
        spec = prepare_scenario(work_dir, scenario)
        result = execute_scenario(
            spec,
            timeout_seconds=args.timeout,
            max_rss_mib=args.max_rss_mib,
        )
        results.append(result)
        print(json.dumps(result, sort_keys=True), flush=True)
        if result["status"] in {"timeout", "rss_limit", "failed"}:
            stopped_axes.add(scenario.axis)
    payload = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "profile": args.profile,
        "host": host_context(),
        "safety": {
            "timeout_seconds": args.timeout,
            "max_rss_mib": args.max_rss_mib,
            "synthetic_evidence_only": True,
        },
        "results": results,
    }
    result_path = work_dir / "load_test_results.json"
    result_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"Results: {result_path}")
    return 1 if any(item["status"] == "failed" for item in results) else 0


def prepare_scenario(work_dir: Path, scenario: Scenario) -> Path:
    scenario_dir = work_dir / scenario.name
    inputs_dir = scenario_dir / "inputs"
    outputs_dir = scenario_dir / "outputs"
    inputs_dir.mkdir(parents=True)
    outputs_dir.mkdir()
    inputs: list[str] = []
    if scenario.mode == "single_uac":
        inputs.append(
            str(
                create_uac_archive(
                    inputs_dir,
                    scenario.name,
                    scenario.lines_per_collection,
                    collection_index=1,
                )
            )
        )
    elif scenario.mode == "uac_case":
        for index in range(1, scenario.collections + 1):
            inputs.append(
                str(
                    create_uac_archive(
                        inputs_dir,
                        f"host-{index:04d}",
                        scenario.lines_per_collection,
                        collection_index=index,
                    )
                )
            )
    elif scenario.mode == "esxi":
        inputs.append(
            str(
                create_esxi_archive(
                    inputs_dir,
                    scenario.name,
                    files=scenario.files_per_collection,
                    lines_per_file=scenario.lines_per_collection,
                )
            )
        )
    else:
        raise ValueError(f"Unknown scenario mode: {scenario.mode}")
    spec = {
        **asdict(scenario),
        "inputs": inputs,
        "output": str(outputs_dir),
        "input_bytes": sum(Path(path).stat().st_size for path in inputs),
    }
    spec_path = scenario_dir / "scenario.json"
    spec_path.write_text(json.dumps(spec, indent=2), encoding="utf-8")
    return spec_path


def create_uac_archive(
    inputs_dir: Path,
    name: str,
    line_count: int,
    *,
    collection_index: int,
) -> Path:
    staging = inputs_dir / f".{name}-staging"
    auth_log = staging / "var" / "log" / "auth.log"
    auth_log.parent.mkdir(parents=True)
    host = f"synthetic-linux-{collection_index:04d}"
    start = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=collection_index % 28)
    with auth_log.open("w", encoding="utf-8") as handle:
        for index in range(line_count):
            observed = start + timedelta(seconds=index)
            ip_octet = (index % 250) + 1
            handle.write(
                f"{observed:%b %e %H:%M:%S} {host} sshd[{2000 + index % 50000}]: "
                f"Failed password for invalid user loaduser{index % 64} from "
                f"198.51.100.{ip_octet} port {40000 + index % 20000} ssh2\n"
            )
    archive = inputs_dir / f"uac-synthetic-{name}-20260101000000.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=6) as handle:
        handle.add(staging, arcname=f"uac-synthetic-{name}")
    shutil.rmtree(staging)
    return archive


def create_esxi_archive(
    inputs_dir: Path,
    name: str,
    *,
    files: int,
    lines_per_file: int,
) -> Path:
    staging = inputs_dir / f".{name}-staging"
    log_dir = staging / "var" / "run" / "log"
    log_dir.mkdir(parents=True)
    names = ("vmkernel", "hostd", "vpxa", "vobd", "fdm")
    start = datetime(2026, 2, 1, tzinfo=UTC)
    for file_index in range(files):
        path = log_dir / f"{names[file_index % len(names)]}-{file_index:04d}.log"
        with path.open("w", encoding="utf-8") as handle:
            for line_index in range(lines_per_file):
                observed = start + timedelta(seconds=line_index)
                handle.write(
                    f"{observed:%Y-%m-%dT%H:%M:%S}.000Z cpu{line_index % 8}:"
                    f"{1000 + line_index})WARNING: synthetic ESXi load event "
                    f"file={file_index} sequence={line_index}\n"
                )
    archive = inputs_dir / f"uac-synthetic-{name}-20260201000000.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=6) as handle:
        handle.add(staging, arcname=f"uac-synthetic-{name}")
    shutil.rmtree(staging)
    return archive


def execute_scenario(
    spec_path: Path, *, timeout_seconds: int, max_rss_mib: int
) -> dict[str, Any]:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        str(spec_path),
    ]
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    peak_rss_kib = 0
    status = "success"
    while process.poll() is None:
        elapsed = time.perf_counter() - started
        peak_rss_kib = max(peak_rss_kib, process_rss_kib(process.pid))
        if elapsed > timeout_seconds:
            status = "timeout"
            process.terminate()
            break
        if peak_rss_kib > max_rss_mib * 1024:
            status = "rss_limit"
            process.terminate()
            break
        time.sleep(0.1)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    elapsed = time.perf_counter() - started
    peak_rss_kib = max(peak_rss_kib, process_rss_kib(process.pid))
    worker_result: dict[str, Any] = {}
    if stdout.strip():
        try:
            worker_result = json.loads(stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            status = "failed"
    if status == "success" and process.returncode != 0:
        status = "failed"
    return {
        **{key: spec[key] for key in asdict(Scenario("", "", "", 0, 0))},
        "status": status,
        "input_bytes": spec["input_bytes"],
        "wall_seconds": round(elapsed, 3),
        "peak_rss_mib": round(peak_rss_kib / 1024, 1),
        "return_code": process.returncode,
        "stderr_tail": stderr.strip()[-1000:],
        **worker_result,
    }


def process_rss_kib(pid: int) -> int:
    try:
        result = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return 0
    try:
        return int(result.stdout.strip() or 0)
    except ValueError:
        return 0


def run_worker(spec_path: Path) -> int:
    from uac_parser.pipeline import (
        CasePipelineResult,
        PipelineResult,
        run_case_pipeline,
        run_pipeline,
    )

    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    output = Path(spec["output"])
    result: CasePipelineResult | PipelineResult
    if spec["mode"] == "uac_case":
        result = run_case_pipeline(
            spec["inputs"],
            output,
            incident_start="2026-01-01T00:00:00Z",
            incident_end="2026-12-31T23:59:59Z",
            year=2026,
            timezone_name="UTC",
            case_name=f"Synthetic load test: {spec['name']}",
        )
    else:
        result = run_pipeline(
            spec["inputs"][0],
            output,
            incident_start="2026-01-01T00:00:00Z",
            incident_end="2026-12-31T23:59:59Z",
            year=2026,
            timezone_name="UTC",
            host="synthetic-esxi" if spec["mode"] == "esxi" else "",
        )
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    max_rss_bytes = usage if sys.platform == "darwin" else usage * 1024
    source_index_name = (
        "case_source_index.json" if spec["mode"] == "uac_case" else "source_index.json"
    )
    source_index = json.loads((output / source_index_name).read_text(encoding="utf-8"))
    if spec["mode"] == "uac_case":
        evidence_files = sum(
            len(collection.get("evidence_inventory", []))
            for collection in source_index.get("collections", [])
        )
        unmatched_files = sum(
            sum(
                item.get("coverage_status") == "unmatched"
                for item in collection.get("evidence_inventory", [])
            )
            for collection in source_index.get("collections", [])
        )
    else:
        evidence_files = len(source_index.get("evidence_inventory", []))
        unmatched_files = sum(
            item.get("coverage_status") == "unmatched"
            for item in source_index.get("evidence_inventory", [])
        )
    payload = {
        "parsed_events": result.events,
        "parser_errors": result.errors,
        "output_bytes": directory_size(output),
        "evidence_files": evidence_files,
        "unmatched_files": unmatched_files,
        "worker_max_rss_mib": round(max_rss_bytes / 1024**2, 1),
    }
    print(json.dumps(payload, sort_keys=True))
    return 0


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def host_context() -> dict[str, Any]:
    return {
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "available_disk_bytes": shutil.disk_usage("/tmp").free,
    }


if __name__ == "__main__":
    raise SystemExit(main())
