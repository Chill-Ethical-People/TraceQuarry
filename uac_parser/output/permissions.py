from __future__ import annotations

from pathlib import Path


def secure_file(path: Path) -> None:
    """Restrict derived evidence to the account running TraceQuarry."""
    path.chmod(0o600)
