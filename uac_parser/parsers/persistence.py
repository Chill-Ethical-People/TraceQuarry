from __future__ import annotations

from pathlib import Path
import re

from uac_parser.timeline.event import TimelineEvent

from .common import read_text_lines


SUSPICIOUS = re.compile(r"(curl|wget|nc|ncat|bash\s+-i|/dev/tcp|python\s+-c|perl\s+-e|base64|/tmp/|/var/tmp/|/dev/shm|rclone|xmrig)", re.I)


def parse_cron_file(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#") or "=" in text and not re.match(r"(@|\S+\s+\S+\s+\S+\s+\S+\s+\S+)", text):
            continue
        detections = ["cron_entry_observed"]
        severity = "low"
        if SUSPICIOUS.search(text):
            detections.append("suspicious_cron_entry")
            severity = "high"
        events.append(TimelineEvent(
            timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
            host=host, source_path=relative, source_type="cron_file", parser="persistence",
            event_category="persistence", event_action="cron_entry_observed",
            command=text, file_path=relative, severity=severity, confidence="medium",
            tags=["cron", "persistence"], detection_names=detections, ttp_flags=detections,
            mitre=["T1053.003"], summary=f"Cron entry observed in {relative}:{lineno}",
            raw=raw, extra={"line": lineno},
        ))
    return events


def parse_systemd_unit(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    content = "\n".join(read_text_lines(path))
    detections = ["systemd_unit_observed"]
    severity = "low"
    command = ""
    for line in content.splitlines():
        if line.strip().lower().startswith("execstart="):
            command = line.split("=", 1)[1].strip()
            break
    if command:
        detections.append("systemd_service_definition")
        severity = "medium"
    if command and SUSPICIOUS.search(command):
        detections.append("suspicious_systemd_execstart")
        severity = "high"
    if ".timer" in relative:
        detections.append("systemd_timer_observed")
    return [TimelineEvent(
        timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
        host=host, source_path=relative, source_type="systemd_unit", parser="persistence",
        event_category="persistence", event_action="systemd_unit_observed",
        command=command or None, file_path=relative, severity=severity, confidence="medium",
        tags=["systemd", "persistence"], detection_names=detections, ttp_flags=detections,
        mitre=["T1543.002"], summary=f"Systemd unit observed: {relative}", raw=content[:8000],
    )]


def parse_profile(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        detections = ["shell_profile_entry_observed"]
        severity = "informational"
        if SUSPICIOUS.search(text) or "LD_PRELOAD" in text:
            detections.append("suspicious_shell_profile_entry")
            severity = "high"
        events.append(TimelineEvent(
            timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
            host=host, source_path=relative, source_type="shell_profile", parser="persistence",
            event_category="persistence", event_action="shell_profile_entry_observed",
            command=text, file_path=relative, severity=severity, confidence="medium",
            tags=["shell_profile", "persistence"], detection_names=detections, ttp_flags=detections,
            mitre=["T1546.004"], summary=f"Shell profile entry observed in {relative}:{lineno}",
            raw=raw, extra={"line": lineno},
        ))
    return events


def parse_ld_preload(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        events.append(TimelineEvent(
            timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
            host=host, source_path=relative, source_type="ld_preload", parser="persistence",
            event_category="persistence", event_action="ld_preload_entry_observed",
            file_path=text, severity="high", confidence="medium",
            tags=["ld_preload", "persistence", "hijack_execution_flow"],
            detection_names=["ld_so_preload_modified"], ttp_flags=["ld_so_preload_modified"],
            mitre=["T1574.006"], summary=f"LD_PRELOAD entry observed: {text}",
            raw=raw, extra={"line": lineno},
        ))
    return events


def parse_pam_config(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    risky = re.compile(r"(pam_exec|pam_python|pam_permit|pam_unix\.so\s+.*nullok|/tmp/|/dev/shm)", re.I)
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        detections = []
        severity = "informational"
        if risky.search(text):
            detections.append("pam_backdoor_candidate")
            severity = "high"
        events.append(TimelineEvent(
            timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
            host=host, source_path=relative, source_type="pam_config", parser="persistence",
            event_category="configuration", event_action="pam_config_entry_observed",
            command=text, file_path=relative, severity=severity, confidence="medium",
            tags=["pam", "authentication"], detection_names=detections, ttp_flags=detections,
            mitre=["T1556"] if detections else [],
            summary=f"PAM config entry observed in {relative}:{lineno}", raw=raw, extra={"line": lineno},
        ))
    return events


def parse_rc_local(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    return parse_profile(path, relative, host)

