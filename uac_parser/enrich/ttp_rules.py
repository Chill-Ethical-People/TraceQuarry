from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from uac_parser.timeline.event import TimelineEvent
from uac_parser.enrich.rule_registry import RegistryError, tool_rules


TOOL_GROUPS = {
    "exfil_tool_usage": {"rclone", "megacmd", "aws", "gsutil", "azcopy", "scp", "rsync", "sftp"},
    "tunnel_or_proxy_tool": {"chisel", "frp", "ngrok", "cloudflared", "socat", "ncat", "nc"},
    "miner_execution": {"xmrig", "kinsing", "minerd", "xmr-stak"},
    "network_scanner": {"nmap", "masscan", "zmap"},
    "cloud_container_tool": {"kubectl", "docker", "crictl", "ctr", "nerdctl"},
}


def _add(event: TimelineEvent, action: str, severity: str, tags: list[str], mitre: list[str]) -> None:
    event.detection_names = sorted(set(event.detection_names + [action]))
    event.ttp_flags = sorted(set(event.ttp_flags + [action]))
    event.severity = _max_severity(event.severity, severity)
    event.tags = sorted(set(event.tags + tags))
    event.mitre = sorted(set(event.mitre + mitre))


def _max_severity(a: str, b: str) -> str:
    order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def enrich_events(events: list[TimelineEvent]) -> list[TimelineEvent]:
    try:
        registry_tools = tool_rules()
    except RegistryError:
        registry_tools = {}
    for event in events:
        text = " ".join(filter(None, [event.command, event.file_path, event.summary, event.raw])).lower()
        if not text:
            continue
        execution_text = _execution_text(event)
        indicator_search = _looks_like_indicator_search(event)
        if execution_text and not indicator_search and re.search(r"(curl|wget)\b.*\|\s*(bash|sh|zsh)|base64\b.*(-d|--decode).*\|\s*(bash|sh)", execution_text):
            _add(event, "download_execute_chain", "high", ["download", "shell", "ingress_tool_transfer"], ["T1105", "T1059.004"])
        if execution_text and re.search(r"\bchmod\s+\+?x\b", execution_text):
            _add(event, "chmod_executable", "medium", ["chmod", "execution_prep"], ["T1222.002"])
        if re.search(r"(/tmp|/var/tmp|/dev/shm|/run)/[^\s;|&]+", text):
            _add(event, "execution_or_artifact_from_tmp", "medium", ["suspicious_path", "tmp_execution"], ["T1059.004"])
        if execution_text and re.search(r"\b(sudo\s+-l|sudo\s+su|su\s+-|usermod|useradd|adduser|groupmod|gpasswd)\b", execution_text):
            _add(event, "account_or_privilege_change", "medium", ["account_change", "privilege"], ["T1136.001", "T1548.003"])
        if any(secret in text for secret in ["/etc/shadow", "id_rsa", "id_ed25519", ".aws/credentials", ".kube/config", "authorized_keys"]):
            _add(event, "credential_material_access", "high", ["credential_access", "secrets"], ["T1552.001"])
        if execution_text and re.search(r"\b(crontab|/etc/cron|cron\.d)\b", execution_text):
            _add(event, "cron_modified", "medium", ["persistence", "cron"], ["T1053.003"])
        if execution_text and re.search(r"\b(systemctl\s+(enable|start|restart)|/etc/systemd/system|\.service)\b", execution_text):
            _add(event, "systemd_persistence_or_service_change", "medium", ["persistence", "systemd"], ["T1543.002"])
        if execution_text and re.search(r"\b(history\s+-c|cat\s+/dev/null\s*>\s*.*history|truncate\s+-s\s+0|rm\s+.*(auth\.log|secure|syslog|messages|audit\.log))\b", execution_text):
            _add(event, "log_or_history_tampering", "high", ["defense_evasion", "log_tampering"], ["T1070"])
        if execution_text and re.search(r"\b(tar|zip|7z|rar|gzip|xz)\b.*\b(/home|/var/www|/etc|/root|/opt|/srv)\b", execution_text):
            _add(event, "archive_creation_candidate", "medium", ["collection", "archive"], ["T1560.001"])
        if execution_text and re.search(r"\b(mysqldump|pg_dump|mongodump|redis-cli\s+save)\b", execution_text):
            _add(event, "database_dump", "high", ["collection", "database"], ["T1005"])
        if execution_text and re.search(r"\b(rm\s+-rf|shred|wipe|dd\s+if=)\b", execution_text):
            _add(event, "destructive_command", "high", ["impact", "destructive"], ["T1485"])
        if execution_text and re.search(r"\b(vim-cmd|esxcli)\b", execution_text):
            _add(event, "esxi_or_vmware_admin_command", "high", ["ransomware", "esxi"], ["T1486"])
        if execution_text and not indicator_search and re.search(r"\b(ssh\s+-[rld]|/dev/tcp/|bash\s+-i|pty\.spawn|mkfifo)\b", execution_text):
            _add(event, "reverse_shell_or_tunnel_pattern", "high", ["c2", "reverse_shell"], ["T1095", "T1059.004"])
        if execution_text and re.search(r"\b(curl|wget)\b.*(169\.254\.169\.254|metadata\.google\.internal)", execution_text):
            _add(event, "cloud_metadata_access", "high", ["cloud", "credential_access"], ["T1552.005"])
        if re.search(r"docker\.sock|/var/run/docker\.sock", text):
            _add(event, "docker_socket_access", "high", ["container", "privilege"], ["T1611"])
        if execution_text and not indicator_search and re.search(r"\bssh\s+(?!-[vVT])\S+@\S+|\bssh\s+\S+\s+\S+@", execution_text):
            _add(event, "outbound_ssh_command", "high", ["lateral_movement", "ssh"], ["T1021.004"])
        if execution_text and re.search(r"\b(scp|rsync)\s+.*\S+@\S+:", execution_text):
            _add(event, "outbound_file_transfer_command", "high", ["lateral_movement", "file_transfer"], ["T1021.004", "T1105"])
        if execution_text and re.search(r"\bpasswd\s+\S+", execution_text) and "change" not in execution_text:
            _add(event, "password_set_command", "medium", ["credential_change", "account_management"], ["T1098"])
        if event.source_type == "shell_history" and _looks_like_plaintext_password(event):
            _add(event, "plaintext_password_in_history", "critical", ["credential_exposure", "password_leak"], ["T1552.001"])
        if execution_text and re.search(r"\b(telnet|nc\s+-[zvw])\s+\S+\s+\d+", execution_text):
            _add(event, "network_connectivity_test", "medium", ["reconnaissance", "network_probe"], ["T1046"])
        for action, tools in TOOL_GROUPS.items():
            if not execution_text:
                continue
            if any(re.search(rf"(^|[^a-z0-9_.-]){re.escape(tool)}([^a-z0-9_.-]|$)", execution_text) for tool in tools):
                severity = "high" if action in {"exfil_tool_usage", "miner_execution", "tunnel_or_proxy_tool"} else "medium"
                _add(event, action, severity, ["tooling", action], _tool_mitre(action))
        _apply_registry_tool_tags(event, text, execution_text, indicator_search, registry_tools)
    return events


def _apply_registry_tool_tags(
    event: TimelineEvent,
    text: str,
    execution_text: str,
    indicator_search: bool,
    registry_tools: dict[str, dict[str, object]],
) -> None:
    for tool_id, rule in registry_tools.items():
        literals = [str(value).lower() for value in rule.get("match_literals", []) if str(value).strip()]
        if not literals or not any(_literal_match(text, literal) for literal in literals):
            continue
        category = str(rule.get("category") or "tooling")
        confidence = str(rule.get("confidence_when_matched") or "medium")
        executed = bool(execution_text) and not indicator_search
        action = f"tool_{tool_id}_{'executed' if executed else 'observed'}"
        severity = "high" if executed and confidence == "high" else "medium" if confidence in {"high", "medium"} else "low"
        tags = ["tooling", f"tool.{tool_id}", f"tool_category.{category}", f"tool_confidence.{confidence}"]
        _add(event, action, severity, tags, [str(value) for value in rule.get("mitre", [])])


def _literal_match(text: str, literal: str) -> bool:
    if not literal:
        return False
    if re.fullmatch(r"[a-z0-9_.+-]+", literal):
        return bool(re.search(rf"(?<![a-z0-9_.-]){re.escape(literal)}(?![a-z0-9_.-])", text))
    return literal in text


def _execution_text(event: TimelineEvent) -> str:
    if event.command:
        return event.command.lower()
    if event.event_category == "execution" or event.event_action in {"sudo_command", "process_execution", "shell_command"}:
        return " ".join(filter(None, [event.file_path, event.raw])).lower()
    return ""


def _looks_like_plaintext_password(event: TimelineEvent) -> bool:
    if event.source_type != "shell_history":
        return False
    cmd = (event.command or "").strip()
    if not cmd:
        return False
    if any(cmd.startswith(prefix) for prefix in [
        "echo ", "cat ", "ls ", "cd ", "vi ", "vim ", "nano ", "grep ", "find ",
        "sudo ", "chmod ", "chown ", "mv ", "cp ", "rm ", "mkdir ", "touch ",
        "export ", "source ", ".", "alias ", "unalias ", "#", "man ", "help ",
        "systemctl ", "service ", "yum ", "apt ", "dnf ", "pip ", "git ",
        "docker ", "kubectl ", "curl ", "wget ", "ssh ", "scp ", "rsync ",
        "tar ", "zip ", "unzip ", "gzip ", "passwd ", "useradd ", "adduser ",
        "groupadd ", "usermod ", "groupmod ", "chage ", "mount ", "umount ",
        "fdisk ", "df ", "du ", "free ", "top ", "ps ", "kill ", "pkill ",
        "iptables ", "firewall", "hostname", "ifconfig", "ip ", "route ",
        "netstat ", "ss ", "ping ", "traceroute ", "dig ", "nslookup ",
        "history", "exit", "logout", "reboot", "shutdown", "poweroff",
        "uname ", "whoami", "id ", "who ", "w ", "last ", "uptime",
        "date ", "cal ", "head ", "tail ", "less ", "more ", "wc ",
        "sort ", "awk ", "sed ", "cut ", "tr ", "diff ", "stat ",
        "file ", "type ", "which ", "whereis ", "locate ",
    ]):
        return False
    if " " in cmd or len(cmd) < 4 or len(cmd) > 64:
        return False
    has_upper = any(c.isupper() for c in cmd)
    has_lower = any(c.islower() for c in cmd)
    has_digit = any(c.isdigit() for c in cmd)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?~`" for c in cmd)
    complexity = sum([has_upper, has_lower, has_digit, has_special])
    return complexity >= 3


def _looks_like_indicator_search(event: TimelineEvent) -> bool:
    text = " ".join(filter(None, [event.command, event.raw])).lower()
    if not text:
        return False
    if re.search(r"\b(grep|egrep|fgrep|rg)\b.*(curl\|wget|bash -i|python\.\*connect|exec\.\*socket|/dev/tcp|nc \|)", text):
        return True
    return "profile tampering" in text and "grep -e" in text


def _tool_mitre(action: str) -> list[str]:
    return {
        "exfil_tool_usage": ["T1567", "T1105"],
        "tunnel_or_proxy_tool": ["T1090"],
        "miner_execution": ["T1496"],
        "network_scanner": ["T1046"],
        "cloud_container_tool": ["T1613"],
    }.get(action, [])


SSH_FAILURE_WINDOW = timedelta(minutes=30)


def derive_findings(
    events: list[TimelineEvent],
    *,
    available_source_types: set[str] | None = None,
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    failures: dict[tuple[str | None, str | None], list[TimelineEvent]] = defaultdict(list)
    successes: list[TimelineEvent] = []
    actions = Counter()
    for event in events:
        actions[event.event_action] += 1
        for detection in event.detection_names:
            actions[detection] += 1
        if event.event_action == "ssh_login_failure":
            failures[(event.user, event.src_ip)].append(event)
        elif event.event_action == "ssh_login_success":
            successes.append(event)
    for success in successes:
        prior = failures.get((success.user, success.src_ip), [])
        success_time = _event_datetime(success)
        recent = [
            event for event in prior
            if success_time
            and (failure_time := _event_datetime(event))
            and timedelta(0) <= success_time - failure_time <= SSH_FAILURE_WINDOW
        ]
        if len(recent) >= 5:
            findings.append({
                "title": "Successful SSH login after repeated failures",
                "severity": "high",
                "confidence": "medium",
                "event_ids": [success.event_id] + [e.event_id for e in recent[-5:]],
                "summary": (
                    f"{success.user} logged in from {success.src_ip} after {len(recent)} failed attempts "
                    f"within {int(SSH_FAILURE_WINDOW.total_seconds() // 60)} minutes."
                ),
                "tags": ["ssh_bruteforce", "valid_account"],
                "evidence_window_seconds": int(SSH_FAILURE_WINDOW.total_seconds()),
            })
    finding_policies = {
        "download_execute_chain", "credential_material_access", "log_or_history_tampering",
        "cloud_metadata_access", "docker_socket_access", "exfil_tool_usage",
        "miner_execution", "destructive_command", "reverse_shell_or_tunnel_pattern",
        "uid0_non_root_account", "container_group_privilege_risk", "nopasswd_sudo_rule",
        "dangerous_sudo_rule_candidate", "unrestricted_authorized_key",
        "suspicious_cron_entry", "suspicious_systemd_execstart",
        "ld_so_preload_modified", "pam_backdoor_candidate", "dangerous_file_capability",
        "suid_file_observed", "sgid_file_observed", "audit_exec_from_tmp",
        "audit_credential_access", "audit_ssh_key_tampering", "audit_kernel_module_load",
        "world_writable_sensitive_file", "failed_login_history",
        "audit_authentication_failure", "audit_anomaly",
        "plaintext_password_in_history", "outbound_ssh_command",
        "outbound_file_transfer_command", "outbound_ssh_connection",
        "account_created_since_backup", "account_deleted_since_backup",
        "account_unlocked_since_backup", "root_password_changed",
        "privileged_group_member_added", "password_changed_since_backup",
        "auth_user_created", "auth_user_deleted", "auth_password_changed",
    }
    medium_finding_actions = {
        "suid_file_observed", "sgid_file_observed", "container_group_privilege_risk",
        "failed_login_history", "audit_authentication_failure", "audit_anomaly",
    }
    for action in finding_policies:
        if actions[action]:
            matched_events = [e for e in events if e.event_action == action or action in e.detection_names]
            severity = "medium" if action in medium_finding_actions else "high"
            confidence = "high" if matched_events and all(e.confidence == "high" for e in matched_events) else "medium"
            findings.append({
                "title": action.replace("_", " ").title(),
                "severity": severity,
                "confidence": confidence,
                "event_ids": [event.event_id for event in matched_events[:10]],
                "summary": f"Observed {actions[action]} event(s) matching {action}.",
                "tags": [action],
            })
    findings.extend(_bruteforce_campaign_findings(events))
    findings.extend(_lateral_movement_findings(events, available_source_types))
    findings.extend(_account_lifecycle_findings(events))
    findings.extend(_actor_like_findings(events))
    return findings


def _bruteforce_campaign_findings(events: list[TimelineEvent]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    by_src: dict[str | None, list[TimelineEvent]] = defaultdict(list)
    for event in events:
        if event.event_action == "ssh_login_failure":
            by_src[event.src_ip].append(event)
    for src_ip, failures in by_src.items():
        if len(failures) < 20:
            continue
        targets = sorted({e.user for e in failures if e.user})
        first = min((e.timestamp for e in failures if e.timestamp), default="")
        last = max((e.timestamp for e in failures if e.timestamp), default="")
        findings.append({
            "title": f"SSH Brute-Force Campaign from {src_ip}",
            "severity": "high",
            "confidence": "high",
            "event_ids": [e.event_id for e in failures[:5]],
            "summary": (
                f"{len(failures)} failed SSH attempts from {src_ip} "
                f"targeting {len(targets)} user(s) between {first} and {last}. "
                f"Targeted users include: {', '.join(targets[:10])}"
                + (f" and {len(targets) - 10} more" if len(targets) > 10 else "")
            ),
            "tags": ["bruteforce_campaign", "ssh"],
        })
    return findings


def _lateral_movement_findings(
    events: list[TimelineEvent],
    available_source_types: set[str] | None,
) -> list[dict[str, object]]:
    outbound_ssh_cmds = [e for e in events if "outbound_ssh_command" in e.detection_names]
    outbound_xfer = [e for e in events if "outbound_file_transfer_command" in e.detection_names]
    outbound_conn = [e for e in events if "outbound_ssh_connection" in e.detection_names]
    known_hosts = [e for e in events if e.event_action == "known_host_observed"]
    action_evidence = outbound_ssh_cmds + outbound_xfer + outbound_conn
    if action_evidence:
        destinations = set()
        for e in action_evidence:
            if e.dst_ip:
                destinations.add(e.dst_ip)
        return [{
            "title": "Outbound Lateral Movement Evidence",
            "severity": "high",
            "confidence": "medium",
            "event_ids": [e.event_id for e in action_evidence[:15]],
            "summary": (
                f"Found {len(action_evidence)} action indicator(s) of outbound lateral movement: "
                f"{len(outbound_ssh_cmds)} SSH commands, {len(outbound_xfer)} file transfers, "
                f"and {len(outbound_conn)} active SSH connections. "
                f"Destinations: {', '.join(sorted(destinations)[:10]) or 'see events'}"
            ),
            "tags": ["lateral_movement", "outbound"],
        }]
    available = available_source_types or {event.source_type for event in events}
    coverage_groups = {
        "command history": {"shell_history"},
        "network state": {"ss_output", "netstat_output", "network_state"},
        "SSH host history": {"known_hosts"},
    }
    covered = sorted(label for label, kinds in coverage_groups.items() if available & kinds)
    missing = sorted(set(coverage_groups) - set(covered))
    contextual = []
    if known_hosts:
        contextual.append({
            "title": "Known SSH Destination Observed",
            "severity": "low",
            "confidence": "low",
            "event_ids": [event.event_id for event in known_hosts[:15]],
            "summary": (
                f"Observed {len(known_hosts)} SSH known-host entr{'y' if len(known_hosts) == 1 else 'ies'}. "
                "This is historical destination context and does not establish an outbound connection or lateral movement."
            ),
            "tags": ["ssh", "known_hosts", "contextual_evidence", "not_lateral_movement_by_itself"],
        })
    if missing:
        return contextual + [{
            "title": "Lateral Movement Assessment Has Coverage Gaps",
            "severity": "informational",
            "confidence": "low",
            "event_ids": [],
            "summary": (
                "No outbound lateral-movement evidence was observed in the available sources, but "
                f"coverage is incomplete. Missing: {', '.join(missing)}."
            ),
            "tags": ["lateral_movement", "coverage_gap", "inconclusive_finding"],
            "coverage": {"covered": covered, "missing": missing},
        }]
    return contextual + [{
        "title": "No Outbound Lateral Movement Evidence Observed",
        "severity": "informational",
        "confidence": "medium",
        "event_ids": [],
        "summary": (
            "No evidence of outbound lateral movement was observed in the available command history, "
            "No outbound SSH commands in shell history, no SSH connections in network state, "
            "and no scp/rsync file transfers were detected. Known-host entries, when present, are "
            "reported separately as historical context."
        ),
        "tags": ["lateral_movement", "negative_finding", "coverage_sufficient"],
        "coverage": {"covered": covered, "missing": []},
    }]


def _event_datetime(event: TimelineEvent) -> datetime | None:
    if not event.timestamp:
        return None
    try:
        return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def _account_lifecycle_findings(events: list[TimelineEvent]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    account_events = [e for e in events if e.source_type == "account_diff" or
                      e.event_action in {"user_created", "user_deleted", "user_modified",
                                         "password_changed", "account_unlocked", "account_locked"}]
    if not account_events:
        return []
    created = [e for e in account_events if e.event_action in {"account_created_since_backup", "user_created", "password_set_new_account"}]
    deleted = [e for e in account_events if e.event_action in {"account_deleted_since_backup", "user_deleted"}]
    pw_changed = [e for e in account_events if e.event_action in {"password_changed", "account_unlocked"}]
    group_changes = [e for e in account_events if e.event_action in {"group_member_added", "group_member_removed"}]
    parts = []
    if created:
        users = sorted({e.user for e in created if e.user})
        parts.append(f"{len(created)} account(s) created ({', '.join(users)})")
    if deleted:
        users = sorted({e.user for e in deleted if e.user})
        parts.append(f"{len(deleted)} account(s) deleted ({', '.join(users)})")
    if pw_changed:
        users = sorted({e.user for e in pw_changed if e.user})
        parts.append(f"{len(pw_changed)} password(s) changed/unlocked ({', '.join(users)})")
    if group_changes:
        parts.append(f"{len(group_changes)} group membership change(s)")
    if parts:
        findings.append({
            "title": "Account Lifecycle Changes Detected",
            "severity": "high",
            "confidence": "high",
            "event_ids": [e.event_id for e in account_events[:15]],
            "summary": "Account changes detected via backup file diffing and log analysis: " + "; ".join(parts) + ".",
            "tags": ["account_lifecycle", "account_diff"],
        })
    return findings


def _actor_like_findings(events: list[TimelineEvent]) -> list[dict[str, object]]:
    observed = {event.event_action for event in events}
    for event in events:
        observed.update(event.detection_names)
    profiles: dict[str, tuple[set[str], set[str]]] = {
        "teamtnt_like_cloud_mining_tradecraft": (
            {"miner_execution"},
            {"docker_socket_access", "cloud_metadata_access", "cron_modified", "execution_or_artifact_from_tmp"},
        ),
        "kinsing_like_linux_mining_tradecraft": (
            {"miner_execution"},
            {"cron_modified", "execution_or_artifact_from_tmp", "audit_exec_from_tmp"},
        ),
        "ransomware_extortion_like_tradecraft": (
            {"destructive_command"},
            {"exfil_tool_usage", "archive_creation_candidate", "esxi_or_vmware_admin_command"},
        ),
    }
    findings = []
    for name, (required, supporting) in profiles.items():
        matched_required = sorted(required & observed)
        matched_supporting = sorted(supporting & observed)
        if len(matched_required) == len(required) and matched_supporting:
            matched = matched_required + matched_supporting
            findings.append({
                "title": name.replace("_", " ").title(),
                "severity": "medium",
                "confidence": "low",
                "event_ids": [e.event_id for e in events if e.event_action in matched or set(e.detection_names) & set(matched)][:10],
                "summary": "Tradecraft resembles a known Linux campaign cluster, but this is not attribution.",
                "tags": ["actor_relevant_ttp", "not_attribution"] + matched,
            })
    return findings
