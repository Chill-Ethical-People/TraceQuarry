from __future__ import annotations

import bz2
import gzip
import lzma
from collections.abc import Iterable
from contextlib import AbstractContextManager
from io import TextIOWrapper
from pathlib import Path
from typing import TextIO

from uac_parser.timeline.timestamp import MONTHS, SYSLOG_RE

GZIP_MAGIC = b"\x1f\x8b"
BZ2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
LZ4_MAGIC = b"\x04\x22\x4d\x18"


class UnsupportedCompressionError(ValueError):
    pass


def open_text(path: Path) -> AbstractContextManager[TextIO]:
    """Open plain or commonly compressed text evidence without loading it in memory."""
    with path.open("rb") as probe:
        magic = probe.read(6)
    if magic.startswith(GZIP_MAGIC):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if magic.startswith(BZ2_MAGIC):
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if magic.startswith(XZ_MAGIC):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    if magic.startswith(ZSTD_MAGIC):
        raise UnsupportedCompressionError(
            "Zstandard-compressed evidence requires an optional zstd decoder."
        )
    if magic.startswith(LZ4_MAGIC):
        raise UnsupportedCompressionError(
            "LZ4-compressed evidence requires an optional lz4 decoder."
        )
    return TextIOWrapper(path.open("rb"), encoding="utf-8", errors="replace")


def read_text_lines(path: Path) -> Iterable[str]:
    with open_text(path) as handle:
        for line in handle:
            yield line.rstrip("\r\n")


def read_syslog_lines(
    path: Path, anchor_year: int | None
) -> Iterable[tuple[str, int | None]]:
    """Yield syslog lines with rollover-aware years for chronological log files."""
    start_year = anchor_year
    if anchor_year is not None and _contains_year_rollover(path):
        start_year = anchor_year - 1
    current_year = start_year
    previous_month: int | None = None
    for line in read_text_lines(path):
        match = SYSLOG_RE.match(line)
        month = MONTHS.get(match.group("mon")) if match else None
        if (
            current_year is not None
            and previous_month is not None
            and month is not None
            and previous_month - month >= 6
        ):
            current_year += 1
        if month is not None:
            previous_month = month
        yield line, current_year


def _contains_year_rollover(path: Path) -> bool:
    previous_month: int | None = None
    for line in read_text_lines(path):
        match = SYSLOG_RE.match(line)
        if not match:
            continue
        month = MONTHS[match.group("mon")]
        if previous_month is not None and previous_month - month >= 6:
            return True
        previous_month = month
    return False


def basename_host_from_source(relative: str) -> str:
    parts = [p for p in relative.split("/") if p]
    for idx, part in enumerate(parts):
        if part in {"hostname", "uname"} and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""
