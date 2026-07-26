from __future__ import annotations

import shutil
import stat
import tarfile
import tempfile
import threading
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

MAX_ARCHIVE_MEMBERS = 100_000
MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_SINGLE_MEMBER_BYTES = 1024 * 1024 * 1024
MIN_EXTRACTION_FREE_BYTES = 512 * 1024 * 1024
_EXTRACTION_CONDITION = threading.Condition()
_EXTRACTION_RESERVATIONS: dict[int, int] = {}


@dataclass
class LoadedCase:
    root: Path
    tempdir: tempfile.TemporaryDirectory[str] | None = None
    extraction_reservation: tuple[int, int] | None = None
    member_prefix: str = ""
    archive_exclusions: list[dict[str, Any]] | None = None

    def cleanup(self) -> None:
        try:
            if self.tempdir:
                self.tempdir.cleanup()
        finally:
            if self.extraction_reservation:
                _release_extraction(self.extraction_reservation)
                self.extraction_reservation = None


def load_input(path: str, *, temp_parent: str | Path | None = None) -> LoadedCase:
    source = Path(path).expanduser().resolve()
    if not source.exists():
        raise ValueError(f"Input does not exist: {source}")
    if source.is_dir():
        return LoadedCase(root=source)
    parent = None
    if temp_parent is not None:
        scratch_root = Path(temp_parent).expanduser().resolve()
        scratch_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = str(scratch_root)
    temp = tempfile.TemporaryDirectory(prefix=".uac_parser_", dir=parent)
    dest = Path(temp.name).resolve()
    reservation: tuple[int, int] | None = None
    archive_exclusions: list[dict[str, Any]] = []
    try:
        if tarfile.is_tarfile(source):
            with tarfile.open(source) as archive:
                tar_members = archive.getmembers()
                expanded = _validate_members(tar_members)
                archive_exclusions = _tar_exclusions(tar_members)
                reservation = _reserve_extraction(dest, expanded)
                _extract_tar(archive, tar_members, dest)
        elif zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                zip_members = archive.infolist()
                expanded = _validate_members(zip_members)
                archive_exclusions = _zip_exclusions(archive, zip_members)
                reservation = _reserve_extraction(dest, expanded)
                _extract_zip(archive, zip_members, dest)
        else:
            if _has_archive_name(source):
                raise ValueError(
                    f"Input has an archive name but is not valid: {source}"
                )
            reservation = _reserve_extraction(dest, source.stat().st_size)
            target = dest / source.name
            shutil.copyfile(source, target)
            target.chmod(0o600)
    except Exception:
        temp.cleanup()
        if reservation:
            _release_extraction(reservation)
        raise
    top_level = list(dest.iterdir())
    root = top_level[0] if len(top_level) == 1 and top_level[0].is_dir() else dest
    member_prefix = root.relative_to(dest).as_posix() if root != dest else ""
    return LoadedCase(
        root=root,
        tempdir=temp,
        extraction_reservation=reservation,
        member_prefix=member_prefix,
        archive_exclusions=archive_exclusions,
    )


def _tar_exclusions(
    members: Sequence[tarfile.TarInfo],
) -> list[dict[str, Any]]:
    exclusions = []
    for member in members:
        if member.isdir() or member.isfile():
            continue
        member_type = (
            "symlink" if member.issym() else "hardlink" if member.islnk() else "special"
        )
        value = (
            member.linkname
            if member_type in {"symlink", "hardlink"}
            else f"{member.type!r}:{member.devmajor}:{member.devminor}"
        )
        encoded = value.encode("utf-8", "surrogateescape")
        exclusion = {
            "relative": member.name.replace("\\", "/"),
            "reason": "non_regular_archive_member_not_materialized",
            "member_type": member_type,
            "byte_size": len(encoded),
            "sha256": _bytes_sha256(encoded),
            "link_target": value if member_type != "special" else "",
        }
        if member_type == "special":
            exclusion.update(
                {
                    "type_flag": member.type.decode("ascii", "replace"),
                    "device_major": str(member.devmajor),
                    "device_minor": str(member.devminor),
                }
            )
        exclusions.append(exclusion)
    return exclusions


def _zip_exclusions(
    archive: zipfile.ZipFile,
    members: Sequence[zipfile.ZipInfo],
) -> list[dict[str, Any]]:
    exclusions = []
    for member in members:
        if member.is_dir() or not stat.S_ISLNK(member.external_attr >> 16):
            continue
        value = archive.read(member)
        exclusions.append(
            {
                "relative": member.filename.replace("\\", "/"),
                "reason": "non_regular_archive_member_not_materialized",
                "member_type": "symlink",
                "byte_size": len(value),
                "sha256": _bytes_sha256(value),
                "link_target": value.decode("utf-8", "replace"),
            }
        )
    return exclusions


def _bytes_sha256(value: bytes) -> str:
    return sha256(value).hexdigest()


def _has_archive_name(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".zip"))


def _target_path(dest: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError(f"Archive member escapes extraction root: {member_name}")
    target = (dest / normalized).resolve()
    if not target.is_relative_to(dest):
        raise ValueError(f"Archive member escapes extraction root: {member_name}")
    return target


def _extract_tar(
    archive: tarfile.TarFile, members: Sequence[tarfile.TarInfo], dest: Path
) -> None:
    for member in members:
        target = _target_path(dest, member.name)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            continue
        source = archive.extractfile(member)
        if source is None:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with source, target.open("wb") as handle:
            shutil.copyfileobj(source, handle)


def _extract_zip(
    archive: zipfile.ZipFile, members: Sequence[zipfile.ZipInfo], dest: Path
) -> None:
    for member in members:
        target = _target_path(dest, member.filename)
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        unix_mode = member.external_attr >> 16
        if stat.S_ISLNK(unix_mode):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("wb") as handle:
            shutil.copyfileobj(source, handle)


def _validate_members(members: Sequence[object]) -> int:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"Archive contains too many members ({len(members):,}).")
    expanded = 0
    for member in members:
        size = int(getattr(member, "size", getattr(member, "file_size", 0)) or 0)
        name = str(getattr(member, "name", getattr(member, "filename", "")))
        if size < 0:
            raise ValueError(f"Archive member has an invalid size: {name}")
        if size > MAX_SINGLE_MEMBER_BYTES:
            raise ValueError(f"Archive member exceeds size limit: {name}")
        expanded += size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("Archive expanded size exceeds the 8 GiB safety limit.")
    return expanded


def _reserve_extraction(dest: Path, expected_bytes: int) -> tuple[int, int] | None:
    if expected_bytes <= 0:
        return None
    device = dest.stat().st_dev
    with _EXTRACTION_CONDITION:
        while True:
            reserved = _EXTRACTION_RESERVATIONS.get(device, 0)
            required = reserved + expected_bytes + MIN_EXTRACTION_FREE_BYTES
            if shutil.disk_usage(dest).free >= required:
                _EXTRACTION_RESERVATIONS[device] = reserved + expected_bytes
                break
            if not reserved:
                raise ValueError(
                    "Insufficient free disk space for archive expansion and the "
                    "evidence safety reserve."
                )
            _EXTRACTION_CONDITION.wait()
    return device, expected_bytes


def _release_extraction(reservation: tuple[int, int]) -> None:
    device, reserved_bytes = reservation
    with _EXTRACTION_CONDITION:
        remaining = max(0, _EXTRACTION_RESERVATIONS.get(device, 0) - reserved_bytes)
        if remaining:
            _EXTRACTION_RESERVATIONS[device] = remaining
        else:
            _EXTRACTION_RESERVATIONS.pop(device, None)
        _EXTRACTION_CONDITION.notify_all()
