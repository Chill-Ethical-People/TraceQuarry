from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent

from .common import read_text_lines

SS_RE = re.compile(
    r"^(?P<state>\S+)\s+\d+\s+\d+\s+"
    r"(?P<local>\S+):(?P<lport>\d+)\s+"
    r"(?P<peer>\S+):(?P<pport>\d+|\*)\s*"
    r"(?:users:\((?P<procs>.+)\))?"
)

NETSTAT_RE = re.compile(
    r"^(?P<proto>tcp6?|udp6?)\s+\d+\s+\d+\s+"
    r"(?P<local>\S+):(?P<lport>\d+)\s+"
    r"(?P<peer>\S+):(?P<pport>\S+)\s+"
    r"(?P<state>\S+)?\s*(?P<extra>.*)"
)

PROC_IN_PARENS = re.compile(r'"([^"]+)",pid=(\d+)')

SUSPICIOUS_OUTBOUND_PORTS = {
    "4444",
    "4445",
    "5555",
    "6666",
    "6667",
    "6668",
    "6669",
    "1337",
    "31337",
    "8888",
    "9001",
    "9090",
    "1234",
}

WELL_KNOWN_OUTBOUND = {
    "22",
    "25",
    "53",
    "80",
    "443",
    "465",
    "587",
    "993",
    "995",
    "123",
    "514",
    "4505",
    "4506",
    "8443",
    "8080",
    "9443",
}


def parse_ss(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    rows = []
    for raw in read_text_lines(path):
        match = SS_RE.match(raw)
        if not match:
            continue
        proc_name, pid = _extract_proc(match.group("procs") or "")
        rows.append(
            {
                "state": match.group("state"),
                "local": match.group("local").strip("[]"),
                "lport": match.group("lport"),
                "peer": match.group("peer").strip("[]"),
                "pport": match.group("pport"),
                "process": proc_name,
                "pid": pid,
                "raw": raw,
            }
        )
    listeners = _listener_endpoints(rows)
    events = []
    for row in rows:
        if _is_listener_row(row):
            event = _listening_event(
                row["local"],
                row["lport"],
                row["process"],
                row["pid"],
                row["state"],
                row["raw"],
                relative,
                host,
            )
        else:
            event = _connection_event(
                row["local"],
                row["lport"],
                row["peer"],
                row["pport"],
                row["process"],
                row["pid"],
                row["state"],
                row["raw"],
                relative,
                host,
                listeners,
            )
        events.append(event)
    return events


def parse_netstat(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    rows = []
    for raw in read_text_lines(path):
        match = NETSTAT_RE.match(raw)
        if not match:
            continue
        state = (match.group("state") or "").strip()
        local = match.group("local").strip("[]")
        lport = match.group("lport")
        peer = match.group("peer").strip("[]")
        pport = match.group("pport")
        extra = match.group("extra") or ""

        proc_name, pid = "", ""
        proc_match = re.search(r"(\d+)/(\S+)", extra)
        if proc_match:
            pid = proc_match.group(1)
            proc_name = proc_match.group(2)

        rows.append(
            {
                "state": state,
                "local": local,
                "lport": lport,
                "peer": peer,
                "pport": pport,
                "process": proc_name,
                "pid": pid,
                "raw": raw,
            }
        )
    listeners = _listener_endpoints(rows)
    events = []
    for row in rows:
        if _is_listener_row(row):
            event = _listening_event(
                row["local"],
                row["lport"],
                row["process"],
                row["pid"],
                row["state"],
                row["raw"],
                relative,
                host,
            )
        else:
            event = _connection_event(
                row["local"],
                row["lport"],
                row["peer"],
                row["pport"],
                row["process"],
                row["pid"],
                row["state"],
                row["raw"],
                relative,
                host,
                listeners,
            )
        events.append(event)
    return events


def _is_listener_row(row: dict[str, str]) -> bool:
    return row["peer"] in {"*", "0.0.0.0", "::", "[::]"} or row["state"] == "LISTEN"


def _listener_endpoints(rows: list[dict[str, str]]) -> set[tuple[str, str]]:
    return {(row["local"], row["lport"]) for row in rows if _is_listener_row(row)}


def _extract_proc(procs_raw: str) -> tuple[str, str]:
    match = PROC_IN_PARENS.search(procs_raw)
    if match:
        return match.group(1), match.group(2)
    return "", ""


def _listening_event(
    local: str,
    lport: str,
    proc_name: str,
    pid: str,
    state: str,
    raw: str,
    relative: str,
    host: str,
) -> TimelineEvent:
    detections = ["listening_port"]
    severity = "informational"
    try:
        lport_int = int(lport)
    except ValueError:
        lport_int = 0
    unexpected = lport not in {
        "22",
        "25",
        "80",
        "443",
        "8080",
        "8443",
        "3306",
        "5432",
        "6379",
        "27017",
        "53",
        "111",
        "123",
        "514",
        "9090",
        "4505",
        "4506",
    }
    if unexpected and lport_int > 1024:
        detections.append("unexpected_listening_port")
        severity = "medium"
    if lport_int in {4444, 5555, 1337, 31337, 6666, 8888, 1234}:
        detections.append("suspicious_listening_port")
        severity = "high"
    return TimelineEvent(
        timestamp="",
        timestamp_type="state_observed",
        evidence_role="state_observation",
        timezone_confidence="missing",
        host=host,
        source_path=relative,
        source_type="network_state",
        parser="network",
        event_category="network",
        event_action="listening_port",
        process=proc_name or None,
        pid=pid or None,
        port=lport,
        severity=severity,
        confidence="medium",
        tags=["network", "listening"],
        detection_names=detections,
        ttp_flags=detections,
        mitre_candidates=["T1571"] if severity == "high" else [],
        summary=f"Listening on {local}:{lport}"
        + (f" ({proc_name})" if proc_name else ""),
        raw=raw,
        extra={"state": state, "local_addr": local},
    )


def _connection_event(
    local: str,
    lport: str,
    peer: str,
    pport: str,
    proc_name: str,
    pid: str,
    state: str,
    raw: str,
    relative: str,
    host: str,
    listeners: set[tuple[str, str]],
) -> TimelineEvent:
    detections = ["active_connection"]
    severity = "informational"
    tags = ["network", "connection"]
    mitre: list[str] = []

    direction, direction_confidence, direction_reason = _connection_direction(
        local, lport, peer, pport, proc_name, listeners
    )
    is_outbound = direction == "outbound"
    tags.append(direction)

    if is_outbound:
        if pport == "22":
            detections.append("outbound_ssh_connection")
            severity = "high"
            tags.append("lateral_movement")
            mitre = ["T1021.004"]
        elif pport in SUSPICIOUS_OUTBOUND_PORTS:
            detections.append("outbound_suspicious_port")
            severity = "high"
            tags.append("c2_candidate")
            mitre = ["T1571"]
        elif pport not in WELL_KNOWN_OUTBOUND:
            detections.append("outbound_uncommon_port")
            severity = "medium"

    if state in {"ESTAB", "ESTABLISHED"}:
        detections.append("established_connection")

    src_ip = local if is_outbound else peer if direction == "inbound" else None
    dst_ip = peer if is_outbound else local if direction == "inbound" else None
    event_action = (
        f"{direction}_connection"
        if direction in {"inbound", "outbound"}
        else "connection_observed"
    )

    return TimelineEvent(
        timestamp="",
        timestamp_type="state_observed",
        evidence_role="state_observation",
        timezone_confidence="missing",
        host=host,
        source_path=relative,
        source_type="network_state",
        parser="network",
        event_category="network",
        event_action=event_action,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=pport if is_outbound else lport,
        process=proc_name or None,
        pid=pid or None,
        severity=severity,
        confidence=direction_confidence,
        tags=tags,
        detection_names=detections,
        ttp_flags=detections,
        mitre_candidates=mitre,
        summary=f"{direction.title()} {state} {local}:{lport} -> {peer}:{pport}"
        + (f" ({proc_name})" if proc_name else ""),
        raw=raw,
        extra={
            "state": state,
            "direction": direction,
            "direction_confidence": direction_confidence,
            "direction_reason": direction_reason,
            "local_endpoint": f"{local}:{lport}",
            "peer_endpoint": f"{peer}:{pport}",
        },
    )


def _connection_direction(
    local: str,
    lport: str,
    peer: str,
    pport: str,
    proc_name: str,
    listeners: set[tuple[str, str]],
) -> tuple[str, str, str]:
    if (local, lport) in listeners or any(
        listener_port == lport and listener_addr in {"0.0.0.0", "::", "*"}
        for listener_addr, listener_port in listeners
    ):
        return "inbound", "high", "local endpoint matches an observed listener"
    process = proc_name.lower()
    if process in {
        "sshd",
        "nginx",
        "apache2",
        "httpd",
        "mysqld",
        "postgres",
        "redis-server",
    }:
        return "inbound", "medium", f"{proc_name} is acting as a server process"
    if process in {
        "ssh",
        "scp",
        "sftp",
        "curl",
        "wget",
        "rclone",
        "nc",
        "ncat",
        "socat",
    }:
        return "outbound", "medium", f"{proc_name} is acting as a client process"
    try:
        local_port = int(lport)
        peer_port = int(pport)
    except ValueError:
        return "unknown", "low", "socket endpoints do not establish direction"
    if local_port >= 32768 and (peer_port < 1024 or pport in SUSPICIOUS_OUTBOUND_PORTS):
        return "outbound", "medium", "ephemeral local port connects to remote service"
    return (
        "unknown",
        "low",
        "no listener or process-role evidence establishes direction",
    )
