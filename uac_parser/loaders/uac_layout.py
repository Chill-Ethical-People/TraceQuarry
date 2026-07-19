from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
    "systemd": ("*systemctl*", "*journal*"),
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
    "passwd": ("etc/passwd",),
    "shadow": ("etc/shadow",),
    "group": ("etc/group",),
    "sudoers": ("etc/sudoers", "etc/sudoers.d/*"),
    "authorized_keys": ("home/*/.ssh/authorized_keys", "root/.ssh/authorized_keys"),
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
                if path.is_file() and path.stat().st_size < 200 * 1024 * 1024:
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
    seen: set[str] = set()
    unique: list[SourceFile] = []
    for source in sources:
        key = f"{source.source_type}:{source.path.as_posix()}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(source)
    return unique


def discover_exclusions(root: Path) -> list[dict[str, str]]:
    exclusions = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        reason = _ignored_artifact(relative)
        if reason:
            exclusions.append({"relative": relative, "reason": reason})
    return sorted(exclusions, key=lambda item: item["relative"])


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
    if source_type == "auth_log":
        return name.startswith("auth.log") or name.startswith("secure")
    if source_type == "cron":
        return "/var/log/" in f"/{relative}" or name.startswith("cron")
    if source_type == "capabilities":
        return "cap" in name.lower() or "getcap" in name.lower()
    if source_type == "systemd":
        return "systemctl" in name.lower() or "journal" in name.lower()
    if source_type == "ss_output":
        return "ss_" in name.lower() or "ss-" in name.lower()
    if source_type == "netstat_output":
        return "netstat" in name.lower()
    if source_type == "ps_output":
        return "ps_" in name.lower() or "ps-" in name.lower() or name.startswith("ps_")
    if source_type in {"shadow", "passwd", "group"}:
        return not name.endswith("-")
    return True
