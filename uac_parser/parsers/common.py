from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


def read_text_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line.rstrip("\n")


def basename_host_from_source(relative: str) -> str:
    parts = [p for p in relative.split("/") if p]
    for idx, part in enumerate(parts):
        if part in {"hostname", "uname"} and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""
