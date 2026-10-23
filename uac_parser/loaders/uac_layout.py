from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

SQLITE_MAGIC = b"SQLite format 3\x00"

ESXI_LOG_SOURCES = {
    "auth": "esxi_auth_log",
    "shell": "esxi_shell_log",
    "hostd": "esxi_hostd_log",
    "vpxa": "esxi_vpxa_log",
    "vobd": "esxi_vobd_log",
    "vmkernel": "esxi_vmkernel_log",
    "vmkwarning": "esxi_vmkernel_log",
    "fdm": "esxi_fdm_log",
    "syslog": "esxi_syslog_log",
    "esxupdate": "esxi_update_log",
    "vmksummary": "esxi_summary_log",
    "envoy-access": "esxi_proxy_log",
    "rhttpproxy": "esxi_proxy_log",
    "vmauthd": "esxi_auth_service_log",
    "hostdcgiserver": "esxi_auth_service_log",
}


@dataclass
class SourceFile:
    path: Path
    relative: str
    source_type: str
    size: int = 0
    sha256: str = ""
    parser_status: str = "discovered"
    event_count: int = 0
    parser_error: str = ""
    parse_coverage: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceFile:
    path: Path
    relative: str
    size: int
    sha256: str = ""
    source_types: list[str] = field(default_factory=list)
    coverage_status: str = "unmatched"
    coverage_reason: str = "No TraceQuarry source pattern matched this file."


PATTERNS = {
    "uac_log": ("uac.log", "*/uac.log"),
    "bodyfile": ("bodyfile*", "*bodyfile*"),
    "bodyfile_privilege": ("bodyfile*", "*bodyfile*"),
    "auth_log": ("*auth.log*", "*secure*"),
    "syslog": ("*syslog*", "*messages*", "*kern.log*"),
    "auditd": ("*audit.log*", "audit.log*"),
    "cron": ("*cron*",),
    "cron_file": (
        "etc/crontab",
        "etc/cron.d/*",
        "var/spool/cron/*",
        "var/spool/cron/crontabs/*",
    ),
    "shell_history": (".bash_history", ".zsh_history", ".sh_history", ".*history"),
    "package_log": (
        "*dpkg.log*",
        "*apt/history.log*",
        "*yum.log*",
        "*dnf.log*",
        "*zypper.log*",
    ),
    "systemd": ("*systemctl*",),
    "journal_text": (
        "*journalctl*",
        "*journal*.txt",
        "*journal*.log",
        "*journal*.out",
    ),
    "journal_binary": ("*.journal", "*.journal~"),
    "systemd_unit": (
        "etc/systemd/system/*.service",
        "etc/systemd/system/*.timer",
        "home/*/.config/systemd/user/*.service",
        "root/.config/systemd/user/*.service",
    ),
    "web_log": ("*access.log*", "*error.log*", "*nginx*", "*apache*", "*httpd*"),
    "login_history": (
        "*last.txt",
        "*lastb.txt",
        "*login_history*",
        "*failed_logins*",
        "*wtmp.txt",
        "*btmp.txt",
    ),
    "login_binary": ("var/log/wtmp", "var/log/btmp", "var/log/lastlog"),
    "passwd": ("etc/passwd",),
    "shadow": ("etc/shadow",),
    "group": ("etc/group",),
    "sudoers": ("etc/sudoers", "etc/sudoers.d/*"),
    "authorized_keys": (
        "home/*/.ssh/authorized_keys",
        "root/.ssh/authorized_keys",
        "etc/ssh/keys-*/authorized_keys",
    ),
    "known_hosts": ("home/*/.ssh/known_hosts", "root/.ssh/known_hosts"),
    "sshd_config": ("etc/ssh/sshd_config", "etc/ssh/sshd_config.d/*"),
    "profile": (
        "etc/profile",
        "etc/profile.d/*",
        "home/*/.bashrc",
        "home/*/.profile",
        "home/*/.bash_profile",
        "root/.bashrc",
        "root/.profile",
    ),
    "ld_preload": ("etc/ld.so.preload",),
    "pam_config": ("etc/pam.d/*",),
    "rc_local": ("etc/rc.local", "etc/init.d/*"),
    "capabilities": ("*capabilities*", "*getcap*"),
    "ss_output": ("*ss_-tanp*", "*ss_-tlnp*", "*ss_tanp*", "*ss_tlnp*"),
    "netstat_output": ("*netstat_-anp*", "*netstat_anp*", "*netstat_-tlnp*"),
    "ps_output": ("*ps_auxwww*", "*ps_-ef*", "*ps_aux*"),
}


def discover_sources(root: Path) -> list[SourceFile]:
    sources: list[SourceFile] = []
    for source_type, patterns in PATTERNS.items():
        for pattern in patterns:
            for path in root.rglob(pattern):
                rel = path.relative_to(root).as_posix()
                if _ignored_artifact(rel):
                    continue
                if path.is_file() and not path.is_symlink():
                    if not _valid_source(source_type, rel):
                        continue
                    sources.append(
                        SourceFile(
                            path=path,
                            relative=rel,
                            source_type=source_type,
                            size=path.stat().st_size,
                        )
                    )
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if _ignored_artifact(rel):
            continue
        if esxi_source_type := _esxi_source_type(rel):
            sources.append(
                SourceFile(
                    path=path,
                    relative=rel,
                    source_type=esxi_source_type,
                    size=path.stat().st_size,
                )
            )
        if _is_sqlite_database(path):
            sources.append(
                SourceFile(
                    path=path,
                    relative=rel,
                    source_type="sqlite_log",
                    size=path.stat().st_size,
                )
            )
    seen: set[str] = set()
    unique: list[SourceFile] = []
    for source in sources:
        key = f"{source.source_type}:{source.path.as_posix()}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(source)
    return unique


def _is_sqlite_database(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(SQLITE_MAGIC)) == SQLITE_MAGIC
    except OSError:
        return False


def discover_evidence_files(
    root: Path, sources: list[SourceFile]
) -> list[EvidenceFile]:
    """Inventory every non-metadata file, including unsupported parser inputs."""
    source_types: dict[str, set[str]] = {}
    for source in sources:
        source_types.setdefault(source.relative, set()).add(source.source_type)
    evidence = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        matched = sorted(source_types.get(relative, set()))
        evidence.append(
            EvidenceFile(
                path=path,
                relative=relative,
                size=path.stat().st_size,
                source_types=matched,
                coverage_status="recognized" if matched else "unmatched",
                coverage_reason=(
                    "Matched one or more TraceQuarry source patterns."
                    if matched
                    else "No TraceQuarry source pattern matched this file."
                ),
            )
        )
    return sorted(evidence, key=lambda item: item.relative)


def discover_exclusions(root: Path) -> list[dict[str, Any]]:
    exclusions = []
    for path in root.rglob("*"):
        if path.is_symlink():
            target = str(path.readlink())
            exclusions.append(
                {
                    "relative": path.relative_to(root).as_posix(),
                    "reason": "symlink_not_followed",
                    "member_type": "symlink",
                    "byte_size": len(target.encode("utf-8", "surrogateescape")),
                    "sha256": sha256(
                        target.encode("utf-8", "surrogateescape")
                    ).hexdigest(),
                    "link_target": target,
                }
            )
            continue
        try:
            file_stat = path.lstat()
        except OSError:
            continue
        special_type = _special_member_type(file_stat.st_mode)
        if special_type:
            device_major = (
                os.major(file_stat.st_rdev)
                if stat.S_ISCHR(file_stat.st_mode) or stat.S_ISBLK(file_stat.st_mode)
                else 0
            )
            device_minor = (
                os.minor(file_stat.st_rdev)
                if stat.S_ISCHR(file_stat.st_mode) or stat.S_ISBLK(file_stat.st_mode)
                else 0
            )
            canonical = (
                f"{special_type.encode('ascii')!r}:{device_major}:{device_minor}"
            ).encode()
            exclusions.append(
                {
                    "relative": path.relative_to(root).as_posix(),
                    "reason": "special_member_not_materialized",
                    "member_type": "special",
                    "type_flag": special_type,
                    "device_major": str(device_major),
                    "device_minor": str(device_minor),
                    "byte_size": len(canonical),
                    "sha256": sha256(canonical).hexdigest(),
                    "link_target": "",
                }
            )
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        reason = _ignored_artifact(relative)
        if reason:
            exclusions.append({"relative": relative, "reason": reason})
    return sorted(exclusions, key=lambda item: item["relative"])


def _special_member_type(mode: int) -> str:
    if stat.S_ISCHR(mode):
        return "3"
    if stat.S_ISBLK(mode):
        return "4"
    if stat.S_ISFIFO(mode):
        return "6"
    if stat.S_ISSOCK(mode):
        return "s"
    return ""


def _ignored_artifact(relative: str) -> str:
    parts = Path(relative).parts
    if "__MACOSX" in parts:
        return "macos_metadata_directory"
    if any(part == ".DS_Store" for part in parts):
        return "macos_finder_metadata"
    if any(part.startswith("._") for part in parts):
        return "macos_appledouble_metadata"
    return ""


def _valid_source(source_type: str, relative: str) -> bool:
    name = Path(relative).name
    if source_type in {"auth_log", "syslog", "web_log"} and _esxi_source_type(relative):
        return False
    if source_type == "auth_log":
        return name.startswith("auth.log") or name.startswith("secure")
    if source_type == "cron":
        return "/var/log/" in f"/{relative}" or name.startswith("cron")
    if source_type == "capabilities":
        return "cap" in name.lower() or "getcap" in name.lower()
    if source_type == "systemd":
        return "systemctl" in name.lower()
    if source_type == "journal_text":
        return "journal" in name.lower() and not name.endswith(
            (".journal", ".journal~")
        )
    if source_type == "ss_output":
        return "ss_" in name.lower() or "ss-" in name.lower()
    if source_type == "netstat_output":
        return "netstat" in name.lower()
    if source_type == "ps_output":
        return "ps_" in name.lower() or "ps-" in name.lower() or name.startswith("ps_")
    if source_type in {"shadow", "passwd", "group"}:
        return not name.endswith("-")
    return True


def _esxi_source_type(relative: str) -> str:
    """Return a dedicated source type for native ESXi vm-support logs."""
    normalized = "/" + relative.lower().lstrip("/")
    native_bundle = any(
        re.match(r"esx-.+-\d{4}-\d{2}-\d{2}--", part) for part in Path(normalized).parts
    )
    if "/var/run/log/" not in normalized and not (
        native_bundle and "/var/log/" in normalized
    ):
        return ""
    name = Path(normalized).name
    for suffix in (".gz", ".bz2", ".xz"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    for prefix, source_type in ESXI_LOG_SOURCES.items():
        if re.fullmatch(rf"{re.escape(prefix)}(?:\.log(?:\.\d+)?|\.\d+)", name):
            return source_type
    return ""
