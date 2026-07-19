#!/usr/bin/env python3
"""Reject evidence material and workstation metadata from tracked files."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".zip",
    ".7z",
    ".rar",
    ".raw",
    ".dd",
    ".e01",
    ".aff4",
    ".pcap",
    ".pcapng",
    ".mem",
    ".vmem",
    ".lime",
    ".dmp",
    ".evtx",
    ".journal",
)
GENERATED_PREFIXES = (
    "tests/synthetic_uac/generated/",
    "tests/synthetic_uac/archives/",
    "tests/synthetic_uac/analysis/",
    "web_runs/",
    "uat_results/",
)
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".csv",
    ".html",
    ".ini",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".py",
    ".service",
    ".sh",
    ".svg",
    ".txt",
    ".yml",
    ".yaml",
}
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
LOCAL_HOME_RE = re.compile(
    r"(?:/" + "Users/" + r"|[A-Za-z]:\\" + "Users" + r"\\)[^/\\\s]+[/\\]"
)
DUPLICATE_SIDECAR_RE = re.compile(r"(?:^|/)[^/]+ \d+$")
ALLOWED_PUBLIC_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def tracked_files() -> list[str]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, text=False)
    return [item.decode("utf-8") for item in output.split(b"\0") if item]


def allowed_ip(address: ipaddress.IPv4Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or any(address in network for network in ALLOWED_PUBLIC_NETWORKS)
    )


def main() -> int:
    failures: list[str] = []
    for relative in tracked_files():
        lower = relative.lower()
        if DUPLICATE_SIDECAR_RE.search(relative):
            failures.append(f"cloud-sync duplicate sidecar is tracked: {relative}")
        if lower.startswith(GENERATED_PREFIXES):
            failures.append(f"generated case material is tracked: {relative}")
        if lower.endswith(EVIDENCE_SUFFIXES):
            failures.append(f"archive or forensic evidence file is tracked: {relative}")

        path = ROOT / relative
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if LOCAL_HOME_RE.search(content):
            failures.append(f"workstation-specific home path is tracked: {relative}")
        for match in IP_RE.finditer(content):
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv4Address) and not allowed_ip(address):
                failures.append(
                    f"non-reserved public IP {address} is tracked in {relative}"
                )

    if failures:
        print("Repository hygiene check failed:", file=sys.stderr)
        for failure in sorted(set(failures)):
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        "Repository hygiene check passed: no tracked evidence archives or unsafe indicators."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
