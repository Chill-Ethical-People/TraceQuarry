"""Portable ESXi command observations and bounded, evidence-linked context."""

from __future__ import annotations

import base64
import binascii
import hashlib
import posixpath
import re
import shlex
from datetime import datetime, timedelta
from pathlib import PurePosixPath

from uac_parser.timeline.event import TimelineEvent


def shell_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def invoked_payload(tokens: list[str]) -> tuple[str, list[str], bool]:
    """Resolve a direct program or Python/shell script, never quoted -c code."""
    tokens = list(tokens)
    if tokens and PurePosixPath(tokens[0]).name == "nohup":
        tokens = tokens[1:]
        if tokens and tokens[0] == "--":
            tokens = tokens[1:]
    if not tokens:
        return "", [], False
    executable = PurePosixPath(tokens[0]).name.lower()
    python = bool(re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable))
    if python or executable in {"sh", "bash", "ash", "perl"}:
        for index, argument in enumerate(tokens[1:], 1):
            if argument == "--":
                if index + 1 < len(tokens):
                    return tokens[index + 1], tokens[index + 2 :], python
                break
            # Only known argument-free flags can safely precede a script filename.
            if argument in (
                {"-u", "-B", "-E", "-I", "-s", "-S"} if python else {"-x", "-e"}
            ):
                continue
            if argument.startswith("-"):
                return "", [], python
            return argument, tokens[index + 1 :], python
        return "", [], python
    return tokens[0], tokens[1:], False


def _flag(event: TimelineEvent, name: str) -> None:
    # ATT&CK, severity and contributor-facing wording live in tagging_registry.yml.
    event.detection_names = sorted(set(event.detection_names + [name]))
    event.ttp_flags = sorted(set(event.ttp_flags + [name]))


def classify_shell_activity(event: TimelineEvent, tokens: list[str]) -> None:
    executable = PurePosixPath(tokens[0]).name.lower()
    command = event.command or ""
    key_write = re.search(r">{1,2}\s*['\"]?[^;|<>\n]*authorized_keys\b", command)
    destination = tokens[-1] if tokens else ""
    if (
        key_write
        or (
            executable in {"tee", "cp", "mv", "install"}
            and PurePosixPath(destination).name == "authorized_keys"
        )
        or (
            executable == "sed"
            and any(t.startswith("-i") for t in tokens[1:])
            and PurePosixPath(destination).name == "authorized_keys"
        )
    ):
        _flag(event, "esxi_ssh_key_modified")
        fingerprints = key_fingerprints(command)
        if fingerprints:
            event.extra["ssh_key_fingerprints"] = fingerprints
            event.extra["key_evidence_limit"] = (
                "Key material in a recorded write command; not proof of successful "
                "installation, key authentication, or actor identity."
            )

    payload, arguments, python = invoked_payload(tokens)
    if python and payload:
        _flag(event, "esxi_python_execution")
    _classify_vmkatz(event, payload, arguments)

    # A script targeting VMFS is review-worthy, but its filename does not prove ransomware.
    script = re.fullmatch(r"(?:python(?:\d+(?:\.\d+)*)?|sh|bash|perl)", executable)
    targets = [t for t in tokens[1:] if t.startswith("/vmfs/volumes/")]
    if script and targets:
        _flag(event, "esxi_datastore_script_execution")
        event.extra["datastore_targets"] = targets
        event.extra["evidence_limit"] = (
            "Script command targets VMFS; inspect payload and effects before alleging encryption."
        )

    _classify_ransomware_preparation(event, executable, tokens)

    log_target = re.search(
        r"(?:/var/(?:run/)?log/|(?:^|/|\s)\.[a-z_]*history\b)", command
    )
    truncation = re.search(
        r"(?:^|\s|;)>{1,2}\s*/|/dev/null\s*>|\btruncate\s+-s\s*0\b", command
    )
    if (log_target and (truncation or executable in {"rm", "shred", "truncate"})) or (
        executable == "history" and "-c" in tokens
    ):
        _flag(event, "esxi_log_history_tampering")
    if (
        executable in {"esxcli", "localcli"}
        and "system" in tokens
        and "syslog" in tokens
        and "set" in tokens
    ):
        _flag(event, "esxi_logging_configuration_change")
    if (
        executable in {"esxcli", "localcli"}
        and "network" in tokens
        and "firewall" in tokens
        and "set" in tokens
    ):
        _flag(event, "esxi_firewall_changed")
    if (
        executable in {"esxcli", "localcli"}
        and "software" in tokens
        and any(t in tokens for t in ("install", "remove", "update"))
    ):
        _flag(event, "esxi_software_change")
        if "--no-sig-check" in tokens or "--force" in tokens:
            _flag(event, "esxi_vib_validation_bypass")
    if executable == "vmkfstools" and ("-C" in tokens or "--createfs" in tokens):
        _flag(event, "esxi_filesystem_format_request")
    if executable in {"esxcli", "localcli", "vim-cmd"} and any(
        item in command
        for item in (
            "system account add",
            "system account set",
            "system account remove",
        )
    ):
        _flag(event, "esxi_account_management")
    if (
        executable in {"esxcli", "localcli"}
        and any(
            item in command
            for item in ("vm process list", "network ip", "storage filesystem list")
        )
        or executable == "vim-cmd"
        and "vmsvc/getallvms" in tokens
    ):
        _flag(event, "esxi_inventory_discovery")


def _classify_vmkatz(event: TimelineEvent, payload: str, arguments: list[str]) -> None:
    payload_name = PurePosixPath(payload).name.lower()
    if payload_name not in {"vmkatz", "vmkatz_loader.py"}:
        return
    _flag(event, "esxi_credential_dump_attempt")
    event.extra["tool"] = "vmkatz"
    event.extra["outcome"] = "invocation_recorded_credential_recovery_unproven"
    if payload_name == "vmkatz_loader.py":
        _flag(event, "esxi_in_memory_loader_candidate")
    if "--vmfs-device" in arguments:
        _flag(event, "esxi_raw_vmfs_credential_access")


def _classify_ransomware_preparation(
    event: TimelineEvent, executable: str, tokens: list[str]
) -> None:
    if (
        executable in {"esxcli", "localcli"}
        and tokens[1:4] == ["software", "acceptance", "set"]
        and any(
            t.lower() == "communitysupported"
            or t.lower().endswith("=communitysupported")
            for t in tokens[4:]
        )
    ):
        _flag(event, "esxi_vib_acceptance_lowered")
    if executable == "vim-cmd" and "hostsvc/disable_lockdown_mode" in tokens:
        _flag(event, "esxi_lockdown_disabled")
    if executable in {"killall", "pkill"} and "vmx" in tokens[1:]:
        _flag(event, "esxi_vm_process_termination")
    if executable == "vim-cmd" and any(
        t in tokens for t in ("vmsvc/snapshot.removeall", "vmsvc/snapshot.remove")
    ):
        _flag(event, "esxi_snapshot_removal_requested")
    if (
        executable == "openssl"
        and "enc" in tokens[1:]
        and "-d" not in tokens
        and "-in" in tokens
        and "-out" in tokens
        and any(t.startswith("/vmfs/volumes/") for t in tokens[1:])
    ):
        _flag(event, "esxi_vmfs_encryption_command")


def key_fingerprints(command: str) -> list[str]:
    result = set()
    for match in re.finditer(
        r"\b(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521))\s+([A-Za-z0-9+/]{16,16384}={0,2})(?![A-Za-z0-9+/=])",
        command,
    ):
        try:
            blob = base64.b64decode(match.group(2), validate=True)
            length = int.from_bytes(blob[:4], "big")
            if not 0 < length < len(blob) - 4 or blob[4 : 4 + length].decode(
                "ascii"
            ) != match.group(1):
                continue
            # Verify complete SSH wire-format strings before treating the blob as a key.
            offset, fields = 0, []
            while offset + 4 <= len(blob):
                size = int.from_bytes(blob[offset : offset + 4], "big")
                offset += 4
                if size <= 0 or offset + size > len(blob):
                    break
                fields.append(blob[offset : offset + size])
                offset += size
            expected = 2 if match.group(1) == "ssh-ed25519" else 3
            if offset != len(blob) or len(fields) != expected:
                continue
            if expected == 2 and len(fields[1]) != 32:
                continue
            result.add(
                "SHA256:"
                + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            )
        except (ValueError, UnicodeDecodeError, binascii.Error):
            continue
    return sorted(result)


def enrich_session_context(events: list[TimelineEvent]) -> None:
    """Link only bounded same-host explicit SFTP PIDs and management session IDs."""
    sessions: dict[tuple[str, str, str, str], TimelineEvent] = {}
    directories: dict[
        tuple[str, str, str, str], tuple[str, datetime, TimelineEvent]
    ] = {}
    for event in sorted(
        (e for e in events if e.parser == "esxi" and e.timestamp),
        key=lambda e: (e.timestamp, e.source_path, e.extra.get("line", 0)),
    ):
        scope = (event.collection_id, event.host)
        current = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        if event.event_action in {
            "esxi_host_booted",
            "esxi_host_rebooting",
            "esxi_host_shutdown",
        }:
            sessions = {k: v for k, v in sessions.items() if k[:2] != scope}
            directories = {k: v for k, v in directories.items() if k[:2] != scope}
        channel = "sftp" if event.process == "sftp-server" else "management"
        identifier = event.pid if channel == "sftp" else event.extra.get("sid")
        if identifier:
            key = (*scope, channel, str(identifier))
            if event.event_action in {
                "esxi_sftp_session_opened",
                "esxi_management_login_success",
            }:
                sessions[key] = event
            elif key in sessions:
                opened = sessions[key]
                started = datetime.fromisoformat(
                    opened.timestamp.replace("Z", "+00:00")
                )
                if timedelta(0) <= current - started <= timedelta(hours=24):
                    # A conflicting explicit source/user always wins; do not guess through it.
                    if (not event.src_ip or event.src_ip == opened.src_ip) and (
                        not event.user or event.user == opened.user
                    ):
                        event.src_ip = event.src_ip or opened.src_ip
                        event.user = event.user or opened.user
                        event.extra["session_context"] = {
                            "method": "same_host_explicit_session_identifier_max_24h",
                            "source_path": opened.source_path,
                            "line": opened.extra.get("line"),
                            "timestamp": opened.timestamp,
                        }
                else:
                    sessions.pop(key, None)
            if event.event_action in {
                "esxi_sftp_session_closed",
                "esxi_management_logout",
            }:
                sessions.pop(key, None)
        if event.command and event.pid:
            key = (*scope, event.user or "", event.pid)
            tokens = shell_tokens(event.command)
            previous = directories.get(key)
            if previous and current - previous[1] > timedelta(hours=12):
                directories.pop(key, None)
                previous = None
            if len(tokens) == 2 and tokens[0] == "cd":
                target = tokens[1]
                if target.startswith("/") or previous:
                    directory = posixpath.normpath(
                        target
                        if target.startswith("/")
                        else posixpath.join(previous[0] if previous else "", target)
                    )
                    directories[key] = (directory, current, event)
            elif previous:
                event.extra["working_directory_candidate"] = previous[0]
                event.extra["working_directory_basis"] = {
                    "source_path": previous[2].source_path,
                    "line": previous[2].extra.get("line"),
                    "limitation": "Same shell PID cd command; chdir success is not logged.",
                }
            if tokens and tokens[0] in {"exit", "logout"}:
                directories.pop(key, None)
