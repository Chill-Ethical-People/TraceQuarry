from __future__ import annotations

import shutil
import stat
import tarfile
import tempfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MAX_ARCHIVE_MEMBERS = 100_000
MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_SINGLE_MEMBER_BYTES = 1024 * 1024 * 1024


@dataclass
class LoadedCase:
    root: Path
    tempdir: tempfile.TemporaryDirectory[str] | None = None

    def cleanup(self) -> None:
        if self.tempdir:
            self.tempdir.cleanup()


def load_input(path: str) -> LoadedCase:
    source = Path(path).expanduser().resolve()
    if not source.exists():
        raise ValueError(f"Input does not exist: {source}")
    if source.is_dir():
        return LoadedCase(root=source)
    temp = tempfile.TemporaryDirectory(prefix="uac_parser_")
    dest = Path(temp.name).resolve()
    try:
        if tarfile.is_tarfile(source):
            with tarfile.open(source) as archive:
                tar_members = archive.getmembers()
                _validate_members(tar_members)
                _extract_tar(archive, tar_members, dest)
        elif zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                zip_members = archive.infolist()
                _validate_members(zip_members)
                _extract_zip(archive, zip_members, dest)
        else:
            raise ValueError(f"Unsupported input: {source}")
    except Exception:
        temp.cleanup()
        raise
    roots = [p for p in dest.iterdir() if p.is_dir()]
    root = roots[0] if len(roots) == 1 else dest
    return LoadedCase(root=root, tempdir=temp)


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


def _validate_members(members: Sequence[object]) -> None:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"Archive contains too many members ({len(members):,}).")
    expanded = 0
    for member in members:
        size = int(getattr(member, "size", getattr(member, "file_size", 0)) or 0)
        name = str(getattr(member, "name", getattr(member, "filename", "")))
        if size > MAX_SINGLE_MEMBER_BYTES:
            raise ValueError(f"Archive member exceeds size limit: {name}")
        expanded += size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("Archive expanded size exceeds the 8 GiB safety limit.")
