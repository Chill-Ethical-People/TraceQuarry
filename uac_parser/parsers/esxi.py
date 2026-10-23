from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_iso

from .common import read_text_lines
from .esxi_activity import classify_shell_activity, shell_tokens

MAX_EVENTS_PER_SOURCE = 100_000

ISO_TIMESTAMP = (
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})"
)
LINE_RE = re.compile(
    rf"^(?P<timestamp>{ISO_TIMESTAMP})\.?\s+"
    r"(?:(?P<level>In|No|Wa|Er|Db|info|notice|warning|error|verbose|debug)"
    r"(?:\(\d+\))?\s+)?"
    r"(?P<component>[\w.-]+)(?:\[(?P<pid>\d+)\])?:?\s+(?P<message>.*)$",
    re.IGNORECASE,
)
AUTH_SUCCESS_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
AUTH_FAILURE_RE = re.compile(
    r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
INVALID_USER_RE = re.compile(
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)
SHELL_COMMAND_RE = re.compile(r"^\[(?P<user>[^]]+)]\s*:\s*(?P<command>.+)$")
VOB_ID_RE = re.compile(
    r"\[(?P<vob>(?:vob|esx\.(?:audit|problem))\.[^]]+)]", re.IGNORECASE
)
IP_RE = re.compile(r"(?<![\w:])(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?![\w:])")
ORIGINATOR_RE = re.compile(r"\[Originator@\d+\s+(?P<meta>[^]]+)]")
META_RE = re.compile(r"(?P<key>sub|opID|sid|user)=([^\s\]]+)", re.IGNORECASE)

SOURCE_TYPES = {
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


def parse(
    path: Path,
    relative: str,
    host: str = "",
    year: int | None = None,
    timezone_name: str = "UTC",
    coverage: dict[str, Any] | None = None,
) -> list[TimelineEvent]:
    """Parse high-value events from one native ESXi log or compressed rotation."""
    del year, timezone_name
    family = _log_family(path.name)
    source_type = SOURCE_TYPES.get(family, "esxi_log")
    resolved_host = host or _host_from_path(relative)
    events: list[TimelineEvent] = []
    examined = matched = 0
    truncated = False

    for line_number, raw in enumerate(read_text_lines(path), start=1):
        examined = line_number
        match = LINE_RE.match(raw)
        if not match:
            continue
        timestamp = parse_iso(match.group("timestamp"))
        if not timestamp:
            continue
        matched += 1
        event = TimelineEvent(
            timestamp=timestamp,
            timestamp_raw=match.group("timestamp"),
            timezone="UTC",
            timezone_confidence=(
                "explicit_utc"
                if match.group("timestamp").endswith("Z")
                else "explicit_offset"
            ),
            timestamp_type="log_time",
            timestamp_precision=(
                "millisecond" if "." in match.group("timestamp") else "second"
            ),
            timestamp_confidence="high",
            host=resolved_host,
            source_path=relative,
            source_type=source_type,
            parser="esxi",
            process=match.group("component"),
            pid=match.group("pid"),
            raw=raw,
            extra={
                "line": line_number,
                "esxi_log_family": family,
                "vmware_level": match.group("level") or "",
                **_originator_metadata(match.group("message")),
            },
        )
        if _classify(event, family, match.group("message")):
            events.append(event)
        if len(events) >= MAX_EVENTS_PER_SOURCE:
            events.append(_truncation_event(event, line_number))
            truncated = True
            break
    source_coverage = {
        "lines_examined": examined,
        "timestamped_records": matched,
        "selected_events": len(events),
        "filtered_timestamped_records": matched
        - sum(event.event_category != "coverage" for event in events),
        "unparsed_lines": examined - matched,
        "selection_policy": "security_and_administration_not_all_log_lines",
        "truncated": truncated,
    }
    if coverage is not None:
        coverage.update(source_coverage)
    if events:
        events[0].extra["source_parse_coverage"] = source_coverage
    return events


def _classify(event: TimelineEvent, family: str, message: str) -> bool:
    if event.process == "sftp-server":
        return _classify_sftp(event, message)
    if (event.process or "").startswith("sshd"):
        return _classify_auth(event, message)
    if family == "auth":
        return _classify_auth(event, message)
    if family == "shell":
        return _classify_shell(event, message)
    if family in {"hostd", "vpxa"}:
        return _classify_management(event, family, message)
    if family == "vobd":
        return _classify_vob(event, message)
    if family in {"vmkernel", "vmkwarning"}:
        return _classify_vmkernel(event, message)
    if family == "fdm":
        return _classify_fdm(event, message)
    if family == "syslog":
        return _classify_syslog(event, message)
    if family == "esxupdate":
        return _classify_update(event, message)
    if family == "vmksummary":
        return _classify_summary(event, message)
    if family in {"envoy-access", "rhttpproxy", "vmauthd", "hostdcgiserver"}:
        return _classify_access_service(event, family, message)
    return False


def _classify_auth(event: TimelineEvent, message: str) -> bool:
    match = AUTH_SUCCESS_RE.search(message)
    if match:
        event.event_category = "authentication"
        event.event_action = "ssh_login_success"
        event.user = match.group("user")
        event.src_ip = match.group("src_ip")
        event.port = match.group("port")
        event.mitre_candidates = ["T1078", "T1021.004"]
        event.extra["authentication_method"] = match.group("method")
        event.extra["outcome"] = "success"
        event.severity = "medium"
        event.confidence = "high"
        event.tags = ["esxi", "ssh", "remote_access", "valid_account"]
        event.summary = (
            f"Successful ESXi SSH login for {event.user} from {event.src_ip}"
        )
        return True

    match = AUTH_FAILURE_RE.search(message) or INVALID_USER_RE.search(message)
    if match:
        event.event_category = "authentication"
        event.event_action = "ssh_login_failure"
        event.user = match.group("user")
        event.src_ip = match.group("src_ip")
        event.port = match.groupdict().get("port")
        event.mitre_candidates = ["T1110"]
        event.extra["outcome"] = "failure"
        event.severity = "low"
        event.confidence = "high"
        event.tags = ["esxi", "ssh", "authentication_failure"]
        event.summary = f"Failed ESXi SSH login for {event.user} from {event.src_ip}"
        return True

    lowered = message.lower()
    if "authentication failure" in lowered or "login failed" in lowered:
        event.event_category = "authentication"
        event.event_action = "esxi_authentication_failure"
        event.src_ip = _first_ip(message)
        event.mitre_candidates = ["T1110"]
        event.severity = "low"
        event.confidence = "medium"
        event.tags = ["esxi", "authentication_failure"]
        event.summary = "ESXi authentication failure"
        return True
    if re.search(
        r"session (?:opened|closed)|disconnect|connection from|running command", lowered
    ):
        event.event_category = "session"
        event.event_action = "esxi_ssh_session_observation"
        event.confidence = "high"
        event.tags = ["esxi", "ssh", "session"]
        user = re.search(r"(?:for user |for '|User ')([^'\s]+)", message)
        if user:
            event.user = user.group(1)
        address = re.search(r"(?:from|user \S+)\s+(\S+)\s+port\s+(\d+)", message)
        if address:
            event.src_ip = _validated_ip(address.group(1))
            event.port = address.group(2)
        event.summary = _bounded_summary(message)
        return True
    return False


def _classify_shell(event: TimelineEvent, message: str) -> bool:
    command_match = SHELL_COMMAND_RE.match(message.strip())
    if command_match:
        command = command_match.group("command").strip()
        event.event_category = "execution"
        event.event_action = "esxi_shell_command"
        event.user = command_match.group("user").strip()
        event.command = command
        event.mitre = ["T1059.004"]
        event.severity = "low"
        event.confidence = "high"
        event.tags = ["esxi", "shell", "command"]
        event.summary = f"ESXi shell command by {event.user}: {command}"
        event.extra["outcome"] = "command_recorded_success_not_established"
        _classify_shell_command(event, command)
        return True

    lowered = message.lower()
    enabled = "shell enabled" in lowered or "ssh enabled" in lowered
    disabled = "shell disabled" in lowered or "ssh disabled" in lowered
    if not enabled and not disabled:
        return False
    event.event_category = "configuration"
    event.event_action = (
        "esxi_remote_service_enabled" if enabled else "esxi_remote_service_disabled"
    )
    event.mitre = ["T1133"] if enabled else []
    event.severity = "medium" if enabled else "informational"
    event.confidence = "high"
    event.tags = ["esxi", "remote_service", "configuration_change"]
    event.summary = message.strip()
    if enabled:
        _detect(event, "esxi_remote_service_enabled")
    return True


def _classify_shell_command(event: TimelineEvent, command: str) -> None:
    tokens = shell_tokens(command)
    if not tokens:
        return
    if Path(tokens[0]).name == "nohup":
        tokens = tokens[1:]
        if tokens and tokens[0] == "--":
            tokens = tokens[1:]
        if not tokens:
            return
        event.extra["execution_wrapper"] = "nohup"
    executable = Path(tokens[0]).name.lower()
    if executable in {"grep", "egrep", "fgrep", "rg", "cat", "less", "head", "tail"}:
        event.extra["read_only_inspection"] = True
        return
    classify_shell_activity(event, tokens)
    if (
        executable in {"echo", "printf"}
        and not any(token in {"|", ";", "&&", "||"} for token in tokens)
        and "$(" not in command
        and "`" not in command
    ):
        # Literal text can contain malicious-looking commands without executing them.
        event.extra["literal_arguments_only"] = True
        if "esxi_ssh_key_modified" not in event.detection_names:
            return
    lowered = command.lower()
    if executable in {"curl", "wget"} and not any(
        x in tokens for x in ("-I", "--head", "--spider")
    ):
        _detect(
            event,
            "esxi_payload_transfer",
            severity="medium",
            mitre=["T1105"],
            tags=["ingress_tool_transfer"],
        )
    if "esxi_ssh_key_modified" in event.detection_names:
        _detect(
            event,
            "esxi_ssh_key_modified",
            severity="high",
            mitre=["T1098.004"],
            tags=["persistence", "ssh_key"],
        )
    if (
        executable in {"esxcli", "esxcfg-advcfg", "localcli"}
        and ("set" in tokens or executable == "esxcfg-advcfg" and "-s" in tokens)
        and ("/user/execinstalledonly" in lowered or "execinstalledonly" in lowered)
        and re.search(r"(?:\s-[is]\s+0\b|\bfalse\b|=\s*0\b)", lowered)
    ):
        _detect(
            event,
            "esxi_exec_installed_only_disabled",
            severity="high",
            mitre=["T1562.001"],
            tags=["defense_evasion", "security_control_change"],
        )
    destructive_operation = re.search(
        r"\b(?:vim-cmd\s+vmsvc/(?:power\.off|destroy|unregister)"
        r"|esxcli\s+vm\s+process\s+kill)\b",
        lowered,
    )
    if destructive_operation and executable in {"vim-cmd", "esxcli", "localcli"}:
        _detect(
            event,
            "esxi_destructive_vm_operation",
            severity="high",
            mitre=_esxi_impact_mitre(destructive_operation.group(0)),
            tags=["impact", "destructive"],
        )
    if executable == "ssh" and any(
        re.match(r"^-[A-Za-z]*[RLD]", token) for token in tokens[1:]
    ):
        _detect(
            event,
            "reverse_shell_or_tunnel_pattern",
            severity="high",
            mitre=["T1572", "T1021.004"],
            tags=["command_and_control", "tunnel"],
        )
        _detect(event, "outbound_ssh_command", severity="high")


def _classify_management(event: TimelineEvent, family: str, message: str) -> bool:
    lowered = message.lower()
    event.user = event.extra.get("user") or None
    login = re.search(
        r"User (?P<user>[^@\s]+)@(?P<ip>\S+) logged (?P<direction>in|out)\b", message
    )
    accepted = re.search(
        r"Accepted (?P<method>\S+) for user (?P<user>\S+) from (?P<ip>\S+)", message
    )
    record = login or accepted
    if record is not None:
        event.user = record.group("user")
        event.src_ip = _validated_ip(record.group("ip"))
        event.event_category = "authentication"
        event.event_action = (
            "esxi_management_logout"
            if login and login.group("direction") == "out"
            else "esxi_management_login_success"
        )
        event.tags = ["esxi", family, "management_session"]
        event.confidence = "high"
        event.summary = _bounded_summary(message)
        if accepted:
            event.extra["authentication_method"] = accepted.group("method")
        event.extra["outcome"] = "success"
        return True
    if re.search(
        r"(?:login|authentication).{0,80}(?:failed|failure|denied|invalid)", lowered
    ):
        event.event_category = "authentication"
        event.event_action = "esxi_management_login_failure"
        event.src_ip = _first_ip(message)
        event.severity = "medium"
        event.confidence = "medium"
        event.tags = ["esxi", family, "authentication_failure"]
        event.summary = f"ESXi {family} management authentication failure"
        return True

    if re.search(r"(?:userlogin|login).{0,80}(?:success|succeeded|logged in)", lowered):
        event.event_category = "authentication"
        event.event_action = "esxi_management_login_success"
        event.src_ip = _first_ip(message)
        event.severity = "low"
        event.confidence = "medium"
        event.tags = ["esxi", family, "management_login"]
        event.summary = f"Successful ESXi {family} management login"
        return True

    task_record = re.search(r"\bTask (?:Created|Completed)\b", message)
    if (
        task_record
        and re.search(r"\.(?:query\w*|list\w*|refresh|installDate)-\d+\b", message)
        and not re.search(r"Status\s+(?:error|failed)", message, re.IGNORECASE)
    ):
        # Polling tasks can dominate hostd. Count them in coverage, not the IR timeline.
        return False
    destructive = re.search(
        r"(?:vim\.VirtualMachine\.(?:powerOff|destroy|unregister|"
        r"removeAllSnapshots)|vim\.ManagedEntity\.destroy)",
        message,
        re.IGNORECASE,
    )
    administrative = re.search(
        r"(?:enterMaintenanceMode|shutdownHost|rebootHost|"
        r"LocalAccountManager\.(?:createUser|removeUser|updateUser|changePassword)|"
        r"FirewallSystem\.(?!refresh))",
        message,
        re.IGNORECASE,
    )
    if task_record:
        event.event_category = "administration"
        event.event_action = (
            "esxi_high_risk_management_operation"
            if destructive or administrative
            else "esxi_management_task"
        )
        event.severity = "medium" if destructive or administrative else "informational"
        event.confidence = "high"
        event.tags = ["esxi", family, "administrative_action"]
        event.summary = _bounded_summary(message)
        task = re.search(r"Task (Created|Completed)\s*:\s*(\S+)", message)
        if task:
            event.extra["task_id"] = task.group(2)
            event.extra["task_stage"] = task.group(1).lower()
        status = re.search(r"Status\s+(\S+)", message, re.IGNORECASE)
        event.extra["outcome"] = status.group(1).lower() if status else "requested"
        if destructive:
            _detect(
                event,
                "esxi_destructive_vm_operation",
                severity="high",
                mitre=_esxi_impact_mitre(destructive.group(0)),
                tags=["impact", "destructive"],
            )
        if administrative and "LocalAccountManager" in message:
            _detect(event, "esxi_account_management", severity="medium")
        return True

    if re.search(
        r"(?:NfcFile.*(?:Delete|Copy)|FileManager.*(?:Delete|Move|Copy)|"
        r"(?:formatVmfs|Format VMFS)|Delete (?:datastore )?file)",
        message,
        re.IGNORECASE,
    ):
        event.event_category = "file"
        event.event_action = "esxi_datastore_file_operation"
        event.tags = ["esxi", family, "datastore_operation"]
        event.summary = _bounded_summary(message)
        event.extra["outcome"] = (
            "failure"
            if re.search(r"failed|error|cannot|could not", lowered)
            else "success"
            if re.search(r"successfully|succeeded", lowered)
            else "observed_outcome_unknown"
        )
        path = re.search(r"(/vmfs/volumes/[^\r\n]+)", message)
        event.file_path = path.group(1).strip() if path else None
        _detect(event, "esxi_datastore_operation", severity="medium")
        return True

    if "connection" in lowered and re.search(
        r"(?:vcenter|vpxa).{0,80}(?:lost|closed|failed|unavailable|disconnected)",
        lowered,
    ):
        event.event_category = "availability"
        event.event_action = "esxi_vcenter_connectivity_lost"
        event.severity = "medium"
        event.confidence = "medium"
        event.tags = ["esxi", family, "vcenter", "connectivity"]
        event.summary = _bounded_summary(message)
        _detect(event, "esxi_vcenter_connectivity_lost")
        return True
    return False


def _classify_vob(event: TimelineEvent, message: str) -> bool:
    match = VOB_ID_RE.search(message)
    if not match:
        return False
    vob_id = match.group("vob").lower()
    if "successfully sent event" in message.lower():
        return False

    session = re.search(
        r"SSH session was (opened|closed) for '([^@']+)@([^']+)'", message
    )
    if session:
        event.event_category = "session"
        event.event_action = "esxi_ssh_session_" + session.group(1)
        event.user = session.group(2)
        event.src_ip = _validated_ip(session.group(3))
        event.extra["authentication_method"] = "not_recorded"
    elif "account.locked" in vob_id:
        event.event_category = "authentication"
        event.event_action = "esxi_account_lockout"
        account = re.search(r"account '([^']+)'", message)
        event.user = account.group(1) if account else None
        event.mitre_candidates = ["T1110"]
        event.extra["source_attribution"] = "not_recorded"
        failures = re.search(r"after (\d+) failed login", message)
        if failures:
            event.extra["reported_failed_attempts"] = int(failures.group(1))
        _detect(event, "esxi_account_lockout", severity="medium")

    elif vob_id == "esx.audit.net.firewall.config.changed" and re.search(
        r"Operation '(?:enable|disable|remove|setallowedip)'[^.]*rule set sshServer",
        message,
        re.IGNORECASE,
    ):
        event.event_category = "configuration"
        event.event_action = "esxi_security_configuration_changed"
        event.severity = "medium"
        _detect(
            event,
            "esxi_firewall_changed",
            severity="medium",
            mitre=["T1562.004"],
        )
    elif any(token in vob_id for token in ("ssh.enabled", "shell.enabled")):
        event.event_category = "configuration"
        event.event_action = "esxi_remote_service_enabled"
        event.severity = "medium"
        _detect(
            event,
            "esxi_remote_service_enabled",
            severity="medium",
            mitre=["T1133"],
        )
    elif any(
        token in vob_id
        for token in (
            ".apd",
            ".pdl",
            "pathstate.off",
            "pathstate.down",
            "pathstate.dead",
            "path.lost",
        )
    ):
        event.event_category = "availability"
        event.event_action = "esxi_storage_path_event"
        event.severity = "high"
        _detect(event, "esxi_storage_path_loss", severity=event.severity)
    elif "linkstate.down" in vob_id:
        event.event_category = "network"
        event.event_action = "esxi_network_link_down"
        event.severity = "medium"
    elif any(token in vob_id for token in ("login.failed", "corrupt", "panic")):
        event.event_category = "security"
        event.event_action = "esxi_security_observation"
        event.severity = "medium"
    elif any(
        token in vob_id
        for token in ("host.boot", "host.stop", "host.reboot", "host.poweroff")
    ):
        event.event_category = "system"
        event.event_action = "esxi_host_lifecycle_observation"
        event.severity = "informational"
    else:
        return False

    event.confidence = "high"
    event.tags = sorted(set(event.tags + ["esxi", "vob", vob_id]))
    event.summary = _bounded_summary(message)
    event.extra["vob_id"] = vob_id
    return True


def _classify_vmkernel(event: TimelineEvent, message: str) -> bool:
    lowered = message.lower()
    patterns = (
        "all paths down",
        "permanent device loss",
        "lost access to volume",
        "device is permanently inaccessible",
        "path is dead",
        "path down",
        "i/o error",
        "metadata corruption",
        "purple screen",
        "panic",
        "watchdog timeout",
    )
    if not any(pattern in lowered for pattern in patterns):
        return False
    event.event_category = "availability"
    event.event_action = "esxi_kernel_availability_event"
    event.severity = "high"
    event.confidence = "medium"
    event.tags = ["esxi", "vmkernel", "availability"]
    event.summary = _bounded_summary(message)
    if any(
        pattern in lowered
        for pattern in (
            "all paths down",
            "permanent device loss",
            "lost access to volume",
            "path is dead",
            "path down",
        )
    ):
        event.event_action = "esxi_storage_path_event"
        _detect(event, "esxi_storage_path_loss", severity="high")
    return True


def _classify_fdm(event: TimelineEvent, message: str) -> bool:
    lowered = message.lower()
    if not re.search(
        r"(?:host isolation|host is isolated|initiating failover|"
        r"failover (?:initiated|completed|failed)|restart(?:ing|ed)? vm|"
        r"master (?:lost|failed|unreachable)|slave (?:lost|failed|unreachable)|"
        r"agent unreachable)",
        lowered,
    ):
        return False
    event.event_category = "availability"
    event.event_action = "esxi_ha_event"
    event.severity = "medium"
    event.confidence = "medium"
    event.tags = ["esxi", "ha", "fdm"]
    event.summary = _bounded_summary(message)
    if "isolat" in lowered:
        event.event_action = "esxi_host_isolated"
        _detect(event, "esxi_host_isolated", severity="high")
    return True


def _classify_syslog(event: TimelineEvent, message: str) -> bool:
    lowered = message.lower()
    if not re.search(
        r"(?:watchdog.{0,80}(?:restart|terminated|failed)|"
        r"(?:ssh|esxi shell).{0,40}(?:enabled|disabled)|"
        r"host is (?:rebooting|shutting down)|system shutdown)",
        lowered,
    ):
        return False
    event.event_category = "system"
    event.event_action = "esxi_system_service_event"
    event.severity = "medium"
    event.confidence = "medium"
    event.tags = ["esxi", "syslog", "service"]
    event.summary = _bounded_summary(message)
    if "enabled" in lowered and ("ssh" in lowered or "shell" in lowered):
        event.event_action = "esxi_remote_service_enabled"
        _detect(
            event, "esxi_remote_service_enabled", severity="medium", mitre=["T1133"]
        )
    return True


def _classify_sftp(event: TimelineEvent, message: str) -> bool:
    event.event_category = "file"
    event.event_action = "esxi_sftp_operation"
    event.tags = ["esxi", "sftp", "file_transfer_observation"]
    event.confidence = "high"
    event.summary = "SFTP: " + _bounded_summary(message)
    session = re.search(
        r"session (opened|closed) for local user (\S+) from \[([^]]+)\]", message
    )
    if session:
        event.event_category = "session"
        event.event_action = "esxi_sftp_session_" + session.group(1)
        event.user = session.group(2)
        event.src_ip = _validated_ip(session.group(3))
    paths = re.findall(r'"([^"\r\n]+)"', message)
    if paths:
        event.file_path = paths[0]
        event.extra["paths"] = paths
    operation = message.split(" ", 1)[0]
    event.extra["sftp_operation"] = operation
    event.extra["outcome"] = "request_or_observation_not_transfer_confirmation"
    counts = re.search(r"bytes read (\d+) written (\d+)", message)
    if counts:
        event.event_action = "esxi_sftp_transfer_accounting"
        event.extra.update(
            bytes_read=int(counts.group(1)), bytes_written=int(counts.group(2))
        )
        event.extra["outcome"] = "server_reported_byte_counts"
        event.extra["transfer_perspective"] = (
            "read=server_to_client; written=client_to_server"
        )
    if re.search(r"flags\s+.*\bWRITE\b", message):
        event.extra["access_mode"] = "write_requested"
    elif re.search(r"flags\s+.*\bREAD\b", message):
        event.extra["access_mode"] = "read_requested"
    if message.startswith("sent status "):
        event.extra["outcome"] = message[len("sent status ") :]
    # Transport/file activity alone establishes neither malicious intent nor exfiltration.
    return True


def _classify_access_service(event: TimelineEvent, family: str, message: str) -> bool:
    request = re.match(r"(GET|POST|PUT|DELETE|HEAD|PATCH)\s+(\S+)\s+(\d{3})\b", message)
    if request:
        api = re.search(r'"([^"\r\n]+)"\s*$', message)
        operation = api.group(1) if api else ""
        if not (
            int(request.group(3)) >= 400
            or request.group(2).startswith(("/folder/", "/host/", "/cgi-bin/"))
            or re.search(
                r"Login|Logout|Delete|Destroy|Remove|PowerOff|Shutdown|Reboot|CreateUser|UpdateUser|ChangePassword|FormatVmfs|Reconfig",
                operation,
                re.IGNORECASE,
            )
        ):
            return False
        event.event_category = "network"
        event.event_action = "esxi_http_request"
        event.extra.update(
            http_method=request.group(1),
            request_uri=request.group(2),
            http_status=int(request.group(3)),
            api_operation=operation,
        )
        event.extra["outcome"] = "http_status_only_not_api_task_completion"
        event.extra["evidence_limit"] = (
            "Proxy records may contain downstream and upstream addresses; no source identity is inferred from their order."
        )
    elif re.search(
        r"authentication|login|logged (?:in|out)|session|permission denied|certificate.*(?:fail|unknown)",
        message,
        re.IGNORECASE,
    ):
        event.event_category = "authentication"
        event.event_action = "esxi_access_service_observation"
    else:
        return False
    event.tags = ["esxi", family, "access_context"]
    event.confidence = "high"
    event.summary = _bounded_summary(message)
    return True


def _classify_update(event: TimelineEvent, message: str) -> bool:
    lowered = message.lower()
    if not re.search(
        r"(?:installation result|vibs (?:installed|removed)|"
        r"(?:install|update|remove).{0,50}(?:completed|successful|failed)|"
        r"profile.{0,50}applied|acceptance level.{0,50}(?:changed|set)|"
        r"(?:installation|dependency|nomatch)error)",
        lowered,
    ):
        return False
    event.event_category = "software"
    event.event_action = "esxi_software_change"
    event.severity = "medium"
    event.confidence = "medium"
    event.tags = ["esxi", "software", "vib", "configuration_change"]
    event.summary = _bounded_summary(message)
    _detect(event, "esxi_software_change")
    return True


def _classify_summary(event: TimelineEvent, message: str) -> bool:
    lowered = message.lower()
    if "host has booted" in lowered:
        action = "esxi_host_booted"
    elif "host is rebooting" in lowered:
        action = "esxi_host_rebooting"
    elif "host is shutting down" in lowered or "host has shut down" in lowered:
        action = "esxi_host_shutdown"
    else:
        return False
    event.event_category = "system"
    event.event_action = action
    event.severity = "informational" if action == "esxi_host_booted" else "medium"
    event.confidence = "high"
    event.tags = ["esxi", "host_lifecycle"]
    event.summary = message.strip()
    return True


def _detect(
    event: TimelineEvent,
    name: str,
    *,
    severity: str | None = None,
    mitre: list[str] | None = None,
    tags: list[str] | None = None,
) -> None:
    event.detection_names = sorted(set(event.detection_names + [name]))
    event.ttp_flags = sorted(set(event.ttp_flags + [name]))
    if severity:
        event.severity = _max_severity(event.severity, severity)
    if mitre:
        event.mitre = sorted(set(event.mitre + mitre))
    if tags:
        event.tags = sorted(set(event.tags + tags))


def _originator_metadata(message: str) -> dict[str, str]:
    match = ORIGINATOR_RE.search(message)
    if not match:
        return {}
    return {
        item.group("key").lower(): item.group(0).split("=", 1)[1]
        for item in META_RE.finditer(match.group("meta"))
    }


def _log_family(name: str) -> str:
    lowered = name.lower()
    for suffix in (".gz", ".bz2", ".xz"):
        if lowered.endswith(suffix):
            lowered = lowered[: -len(suffix)]
            break
    match = re.match(r"(?P<family>[a-z-]+)(?:\.log|\.\d+)", lowered)
    return match.group("family") if match else lowered.split(".", 1)[0]


def _host_from_path(relative: str) -> str:
    first = relative.split("/", 1)[0]
    match = re.match(r"^esx-(?P<host>.+?)-\d{4}-\d{2}-\d{2}--", first, re.IGNORECASE)
    return match.group("host") if match else ""


def _first_ip(message: str) -> str | None:
    match = IP_RE.search(message)
    return _validated_ip(match.group("ip")) if match else None


def _validated_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def _bounded_summary(message: str, limit: int = 320) -> str:
    normalized = " ".join(message.split())
    return normalized if len(normalized) <= limit else normalized[: limit - 3] + "..."


def _max_severity(left: str, right: str) -> str:
    rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return left if rank.get(left, 0) >= rank.get(right, 0) else right


def _esxi_impact_mitre(operation: str) -> list[str]:
    lowered = operation.lower()
    if "power.off" in lowered or "poweroff" in lowered or "process kill" in lowered:
        return ["T1489"]
    if "snapshot.removeall" in lowered or "removeallsnapshots" in lowered:
        return ["T1490"]
    return [] if "unregister" in lowered else ["T1485"]


def _truncation_event(last_event: TimelineEvent, line_number: int) -> TimelineEvent:
    return TimelineEvent(
        timestamp=last_event.timestamp,
        timestamp_raw=last_event.timestamp_raw,
        timezone="UTC",
        timezone_confidence="explicit_utc",
        timestamp_type="log_time",
        timestamp_precision=last_event.timestamp_precision,
        timestamp_confidence="high",
        host=last_event.host,
        source_path=last_event.source_path,
        source_type=last_event.source_type,
        parser="esxi",
        event_category="coverage",
        event_action="esxi_source_event_limit_reached",
        severity="medium",
        confidence="high",
        tags=["esxi", "coverage_gap", "parser_limit"],
        summary=(
            f"ESXi parser stopped after {MAX_EVENTS_PER_SOURCE} selected events; "
            "review the source directly for remaining records."
        ),
        extra={"line": line_number, "event_limit": MAX_EVENTS_PER_SOURCE},
    )
