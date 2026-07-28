#!/usr/bin/env python3
"""Install TraceQuarry into an isolated per-user Python environment."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shlex
import shutil

# Pip is invoked with an argument vector and never through a shell.
import subprocess  # nosec B404
import sys
import venv
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

MANAGED_MARKER = "TraceQuarry managed launcher"
SUPPORTED_PYTHON = {(3, 11), (3, 12)}


@dataclass(frozen=True)
class InstallLayout:
    platform: str
    install_root: Path
    venv_dir: Path
    bin_dir: Path
    data_dir: Path

    @property
    def venv_python(self) -> Path:
        relative = (
            Path("Scripts/python.exe")
            if self.platform == "windows"
            else Path("bin/python")
        )
        return self.venv_dir / relative


def normalized_platform(value: str | None = None) -> str:
    raw = (value or sys.platform).lower()
    if raw.startswith("linux"):
        return "linux"
    if raw in {"darwin", "mac", "macos"}:
        return "macos"
    if raw in {"win32", "windows"}:
        return "windows"
    raise ValueError(f"Unsupported operating system: {raw}")


def default_install_root(
    platform: str, home: Path, environment: dict[str, str]
) -> Path:
    if platform == "macos":
        return home / "Library" / "Application Support" / "TraceQuarry"
    if platform == "windows":
        local_app_data = environment.get("LOCALAPPDATA")
        return (
            Path(local_app_data) / "TraceQuarry"
            if local_app_data
            else home / "AppData" / "Local" / "TraceQuarry"
        )
    return home / ".local" / "share" / "tracequarry"


def default_bin_dir(platform: str, home: Path, install_root: Path) -> Path:
    return install_root / "bin" if platform == "windows" else home / ".local" / "bin"


def build_layout(args: argparse.Namespace) -> InstallLayout:
    platform = normalized_platform(args.platform)
    home = Path.home()
    install_root = (
        Path(args.install_root).expanduser()
        if args.install_root
        else default_install_root(platform, home, dict(os.environ))
    ).resolve()
    bin_dir = (
        Path(args.bin_dir).expanduser()
        if args.bin_dir
        else default_bin_dir(platform, home, install_root)
    ).resolve()
    data_dir = (
        Path(args.data_dir).expanduser() if args.data_dir else install_root / "data"
    ).resolve()
    return InstallLayout(
        platform=platform,
        install_root=install_root,
        venv_dir=install_root / "venv",
        bin_dir=bin_dir,
        data_dir=data_dir,
    )


def launcher_paths(layout: InstallLayout) -> dict[str, Path]:
    suffix = ".cmd" if layout.platform == "windows" else ""
    return {
        "tracequarry": layout.bin_dir / f"tracequarry{suffix}",
        "tracequarry-web": layout.bin_dir / f"tracequarry-web{suffix}",
    }


def render_unix_launcher(executable: Path, *, work_dir: Path | None = None) -> str:
    command = [shlex.quote(str(executable))]
    if work_dir is not None:
        command.extend(["--work-dir", shlex.quote(str(work_dir / "web_runs"))])
    return "\n".join(
        [
            "#!/bin/sh",
            f"# {MANAGED_MARKER}",
            f'exec {" ".join(command)} "$@"',
            "",
        ]
    )


def _cmd_quote(path: Path) -> str:
    return str(path).replace("%", "%%").replace('"', '""')


def render_windows_launcher(executable: Path, *, work_dir: Path | None = None) -> str:
    command = f'"{_cmd_quote(executable)}"'
    if work_dir is not None:
        command += f' --work-dir "{_cmd_quote(work_dir / "web_runs")}"'
    return "\r\n".join(
        [
            "@echo off",
            f"rem {MANAGED_MARKER}",
            f"{command} %*",
            "",
        ]
    )


def _ensure_supported_python() -> None:
    version = sys.version_info[:2]
    if version not in SUPPORTED_PYTHON:
        supported = ", ".join(
            ".".join(map(str, item)) for item in sorted(SUPPORTED_PYTHON)
        )
        raise SystemExit(
            f"TraceQuarry requires Python {supported}; selected interpreter is "
            f"{sys.version_info.major}.{sys.version_info.minor}."
        )


def _write_launcher(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="")
    temporary.chmod(0o755)
    temporary.replace(path)
    path.chmod(0o755)


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _installed_entrypoint(layout: InstallLayout, name: str) -> Path:
    suffix = ".exe" if layout.platform == "windows" else ""
    scripts = layout.venv_dir / ("Scripts" if layout.platform == "windows" else "bin")
    return scripts / f"{name}{suffix}"


def _project_version(source: Path) -> str:
    import tomllib

    with (source / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def install(layout: InstallLayout, source: Path, *, dry_run: bool = False) -> None:
    if not (source / "pyproject.toml").is_file():
        raise SystemExit(f"TraceQuarry source tree not found at {source}")
    _ensure_supported_python()
    if dry_run:
        print(f"Would install TraceQuarry from {source} into {layout.install_root}")
        print(f"Would create launchers under {layout.bin_dir}")
        print(f"Case data would be stored under {layout.data_dir}")
        return

    for directory in (layout.install_root, layout.data_dir):
        _secure_directory(directory)
    if not layout.venv_python.exists():
        venv.EnvBuilder(with_pip=True).create(layout.venv_dir)
    # The interpreter and source are validated filesystem paths.
    subprocess.run(  # nosec B603
        [
            str(layout.venv_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            str(source),
        ],
        check=True,
    )

    paths = launcher_paths(layout)
    if layout.platform == "windows":
        cli = render_windows_launcher(_installed_entrypoint(layout, "tracequarry"))
        web = render_windows_launcher(
            _installed_entrypoint(layout, "tracequarry-web"), work_dir=layout.data_dir
        )
    else:
        cli = render_unix_launcher(_installed_entrypoint(layout, "tracequarry"))
        web = render_unix_launcher(
            _installed_entrypoint(layout, "tracequarry-web"), work_dir=layout.data_dir
        )
    _write_launcher(paths["tracequarry"], cli)
    _write_launcher(paths["tracequarry-web"], web)

    manifest = {
        "schema_version": "1.0",
        "version": _project_version(source),
        "installed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "platform": layout.platform,
        "python": str(layout.venv_python),
        "source": str(source),
        "data_dir": str(layout.data_dir),
        "launchers": {name: str(path) for name, path in paths.items()},
    }
    manifest_path = layout.install_root / "install.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)

    print(f"TraceQuarry {manifest['version']} installed successfully.")
    print(f"Launchers: {layout.bin_dir}")
    print(f"Persistent case data: {layout.data_dir}")
    print("Start the web workbench with: tracequarry-web")


def _remove_managed_launcher(path: Path) -> None:
    if not path.is_file():
        return
    try:
        managed = MANAGED_MARKER in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        managed = False
    if managed:
        path.unlink()


def uninstall(
    layout: InstallLayout, *, purge_data: bool, dry_run: bool = False
) -> None:
    if dry_run:
        print(f"Would remove the TraceQuarry environment from {layout.install_root}")
        print(
            "Would remove persistent case data."
            if purge_data
            else f"Would preserve {layout.data_dir}"
        )
        return
    for path in launcher_paths(layout).values():
        _remove_managed_launcher(path)
    if layout.venv_dir.exists():
        shutil.rmtree(layout.venv_dir)
    manifest = layout.install_root / "install.json"
    manifest.unlink(missing_ok=True)
    if purge_data and layout.data_dir.exists():
        shutil.rmtree(layout.data_dir)
    with contextlib.suppress(OSError):
        layout.install_root.rmdir()
    print("TraceQuarry application files removed.")
    if purge_data:
        print("Persistent case data removed as requested.")
    else:
        print(f"Persistent case data preserved at {layout.data_dir}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["linux", "macos", "windows"])
    parser.add_argument("--source", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--install-root")
    parser.add_argument("--bin-dir")
    parser.add_argument("--data-dir")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--purge-data", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.purge_data and not args.uninstall:
        raise SystemExit("--purge-data may only be used with --uninstall")
    layout = build_layout(args)
    if args.uninstall:
        uninstall(layout, purge_data=args.purge_data, dry_run=args.dry_run)
    else:
        install(layout, Path(args.source).expanduser().resolve(), dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
