from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tarfile
import tempfile
import zipfile


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
    dest = Path(temp.name)
    try:
        if tarfile.is_tarfile(source):
            with tarfile.open(source) as archive:
                _validate_members(archive.getmembers())
                archive.extractall(dest, filter=_safe_tar_member)
        elif zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                members = archive.infolist()
                _validate_members(members)
                for member in members:
                    target = (dest / member.filename).resolve()
                    if not target.is_relative_to(dest):
                        raise ValueError(f"Archive member escapes extraction root: {member.filename}")
                    archive.extract(member, dest)
        else:
            raise ValueError(f"Unsupported input: {source}")
    except Exception:
        temp.cleanup()
        raise
    roots = [p for p in dest.iterdir() if p.is_dir()]
    root = roots[0] if len(roots) == 1 else dest
    return LoadedCase(root=root, tempdir=temp)


def _safe_tar_member(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    """Extract regular UAC evidence while skipping unsafe archive links."""
    if member.islnk() or member.issym():
        target = member.linkname or ""
        if target.startswith("/") or ".." in target.split("/"):
            return None
    try:
        return tarfile.data_filter(member, path)
    except (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError, tarfile.OutsideDestinationError):
        return None


def _validate_members(members: list[object]) -> None:
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
