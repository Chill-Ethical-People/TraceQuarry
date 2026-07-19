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
    events = []
    for raw in read_text_lines(path):
        match = SS_RE.match(raw)
        if not match:
            continue
        state = match.group("state")
        local = match.group("local").strip("[]")
        lport = match.group("lport")
        peer = match.group("peer").strip("[]")
        pport = match.group("pport")
        procs_raw = match.group("procs") or ""

        proc_name, pid = _extract_proc(procs_raw)

        if peer in {"*", "0.0.0.0", "::", "[::]"} or state == "LISTEN":
            event = _listening_event(
                local, lport, proc_name, pid, state, raw, relative, host
            )
        else:
            event = _connection_event(
                local, lport, peer, pport, proc_name, pid, state, raw, relative, host
            )
        events.append(event)
    return events


def parse_netstat(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
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

        if peer in {"*", "0.0.0.0", "::", "[::]"} or state == "LISTEN":
            event = _listening_event(
                local, lport, proc_name, pid, state, raw, relative, host
            )
        else:
            event = _connection_event(
                local, lport, peer, pport, proc_name, pid, state, raw, relative, host
            )
        events.append(event)
    return events


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
        mitre=["T1571"] if severity == "high" else [],
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
) -> TimelineEvent:
    detections = ["active_connection"]
    severity = "informational"
    tags = ["network", "connection"]
    mitre: list[str] = []

    is_outbound = not _is_listening_port(lport)
    direction = "outbound" if is_outbound else "inbound"
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

    src_ip = local if is_outbound else peer
    dst_ip = peer if is_outbound else local

    return TimelineEvent(
        timestamp="",
        timestamp_type="state_observed",
        timezone_confidence="missing",
        host=host,
        source_path=relative,
        source_type="network_state",
        parser="network",
        event_category="network",
        event_action=f"{direction}_connection",
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=pport if is_outbound else lport,
        process=proc_name or None,
        pid=pid or None,
        severity=severity,
        confidence="medium",
        tags=tags,
        detection_names=detections,
        ttp_flags=detections,
        mitre=mitre,
        summary=f"{direction.title()} {state} {local}:{lport} -> {peer}:{pport}"
        + (f" ({proc_name})" if proc_name else ""),
        raw=raw,
        extra={"state": state, "direction": direction},
    )


def _is_listening_port(port: str) -> bool:
    try:
        return int(port) < 1024 or int(port) in {
            4505,
            4506,
            8080,
            8443,
            3306,
            5432,
            6379,
            9090,
            27017,
        }
    except ValueError:
        return False
