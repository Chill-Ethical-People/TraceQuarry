from __future__ import annotations

import json
import platform
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, tzinfo
from hashlib import sha256
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from uac_parser import __version__
from uac_parser.assist import (
    append_assisted_summary,
    build_assisted_investigation,
    validate_profile,
    write_assisted_investigation,
)
from uac_parser.enrich.correlation import correlate_state_events
from uac_parser.enrich.iocs import Ioc, ioc_finding, match_iocs, write_ioc_hits
from uac_parser.enrich.rule_registry import registry_path
from uac_parser.enrich.storylines import build_storylines
from uac_parser.enrich.ttp_rules import derive_findings, enrich_events
from uac_parser.loaders.archive import load_input
from uac_parser.loaders.uac_layout import (
    EvidenceFile,
    SourceFile,
    discover_evidence_files,
    discover_exclusions,
    discover_sources,
)
from uac_parser.output.permissions import secure_file
from uac_parser.output.writers import write_csv, write_json, write_jsonl, write_summary
from uac_parser.parsers import (
    accounts,
    auditd,
    auth,
    bodyfile,
    journal,
    persistence,
    privilege,
    ssh,
    syslog,
)
from uac_parser.parsers.account_diff import diff_accounts
from uac_parser.parsers.common import UnsupportedCompressionError
from uac_parser.parsers.login import parse_last_output
from uac_parser.parsers.network import parse_netstat, parse_ss
from uac_parser.parsers.processes import parse_ps
from uac_parser.parsers.simple import (
    parse_cron,
    parse_package_log,
    parse_shell_history,
    parse_systemd,
    parse_web_log,
)
from uac_parser.timeline.engine import (
    assign_event_ids,
    dedupe_events,
    filter_window,
    sort_events,
)
from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_iso

ProgressCallback = Callable[[dict[str, Any]], None]


PARSER_DISPATCH = {
    "bodyfile": bodyfile.parse,
    "bodyfile_privilege": privilege.parse_bodyfile_privilege,
    "auth_log": auth.parse,
    "syslog": syslog.parse,
    "auditd": auditd.parse,
    "cron": parse_cron,
    "cron_file": persistence.parse_cron_file,
    "shell_history": parse_shell_history,
    "package_log": parse_package_log,
    "systemd": parse_systemd,
    "journal_text": journal.parse,
    "systemd_unit": persistence.parse_systemd_unit,
    "web_log": parse_web_log,
    "login_history": parse_last_output,
    "passwd": accounts.parse_passwd,
    "shadow": accounts.parse_shadow,
    "group": accounts.parse_group,
    "sudoers": privilege.parse_sudoers,
    "authorized_keys": ssh.parse_authorized_keys,
    "known_hosts": ssh.parse_known_hosts,
    "sshd_config": ssh.parse_sshd_config,
    "profile": persistence.parse_profile,
    "ld_preload": persistence.parse_ld_preload,
    "pam_config": persistence.parse_pam_config,
    "rc_local": persistence.parse_rc_local,
    "capabilities": privilege.parse_capabilities,
    "ss_output": parse_ss,
    "netstat_output": parse_netstat,
    "ps_output": parse_ps,
}


@dataclass(frozen=True)
class PipelineResult:
    output: Path
    events: int
    mini_events: int
    findings: int
    errors: int
    ioc_hits: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "output": str(self.output),
            "events": self.events,
            "mini_events": self.mini_events,
            "findings": self.findings,
            "errors": self.errors,
            "ioc_hits": self.ioc_hits,
        }


@dataclass(frozen=True)
class CollectionAnalysis:
    collection_id: str
    collection_name: str
    collection_input: str
    collection_host: str
    root: str
    sources: list[SourceFile]
    evidence_inventory: list[EvidenceFile]
    excluded_files: list[dict[str, str]]
    collection_fingerprint: str
    acquisition_time: str
    input_record: dict[str, Any]
    input_verification: dict[str, Any]
    full_events: list[TimelineEvent]
    mini_events: list[TimelineEvent]
    findings: list[dict[str, Any]]
    storylines: list[dict[str, Any]]
    ioc_hits: list[dict[str, Any]]
    parser_errors: list[str]
    output: Path


@dataclass(frozen=True)
class CasePipelineResult:
    output: Path
    collections: int
    events: int
    mini_events: int
    findings: int
    correlations: int
    errors: int
    ioc_hits: int
    host_outputs: list[str]
    duplicate_collections: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "output": str(self.output),
            "collections": self.collections,
            "events": self.events,
            "mini_events": self.mini_events,
            "findings": self.findings,
            "correlations": self.correlations,
            "errors": self.errors,
            "ioc_hits": self.ioc_hits,
            "host_outputs": self.host_outputs,
            "duplicate_collections": self.duplicate_collections,
        }


@dataclass(frozen=True)
class TimeRangeResult:
    earliest: str | None
    latest: str | None
    events: int
    timed_events: int
    log_events: int
    sources: int
    errors: int
    earliest_source: str
    latest_source: str
    range_basis: str
    source_types: list[str]
    excluded_files: int
    evidence_files: int
    unsupported_sources: int
    unmatched_files: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "earliest": self.earliest,
            "latest": self.latest,
            "events": self.events,
            "timed_events": self.timed_events,
            "log_events": self.log_events,
            "sources": self.sources,
            "errors": self.errors,
            "earliest_source": self.earliest_source,
            "latest_source": self.latest_source,
            "range_basis": self.range_basis,
            "source_types": self.source_types,
            "excluded_files": self.excluded_files,
            "evidence_files": self.evidence_files,
            "unsupported_sources": self.unsupported_sources,
            "unmatched_files": self.unmatched_files,
        }


def inspect_time_range(
    input_path: str | Path,
    *,
    year: int | None = None,
    timezone_name: str = "UTC",
    host: str = "",
) -> TimeRangeResult:
    parser_errors: list[str] = []
    loaded = load_input(str(input_path))
    try:
        sources = discover_sources(loaded.root)
        evidence_inventory = discover_evidence_files(loaded.root, sources)
        excluded_files = discover_exclusions(loaded.root)
        events = []
        for source in sources:
            parser = PARSER_DISPATCH.get(source.source_type)
            if not parser:
                source.parser_status = "unsupported"
                source.parser_error = _unsupported_source_reason(source.source_type)
                continue
            try:
                parsed = _parse_source(parser, source, host, year, timezone_name)
                events.extend(parsed)
                source.parser_status = "parsed"
                source.event_count = len(parsed)
            except UnsupportedCompressionError as exc:
                source.parser_status = "unsupported"
                source.parser_error = str(exc)
            except Exception as exc:
                source.parser_status = "error"
                source.parser_error = f"{type(exc).__name__}: {exc}"
                parser_errors.append(f"{source.relative}: {type(exc).__name__}: {exc}")
        _sync_evidence_coverage(evidence_inventory, sources)
        try:
            events.extend(diff_accounts(loaded.root, host=host))
        except Exception as exc:
            parser_errors.append(f"account_diff: {type(exc).__name__}: {exc}")
        events = enrich_events(events)
        events = assign_event_ids(dedupe_events(sort_events(events)))
        events = correlate_state_events(events)
        ordered = sort_events(dedupe_events(events))
        timed = [event for event in ordered if event.timestamp]
        log_timed = [event for event in timed if event.timestamp_type == "log_time"]
        range_events = log_timed or timed
        earliest = range_events[0] if range_events else None
        latest = range_events[-1] if range_events else None
        return TimeRangeResult(
            earliest=earliest.timestamp if earliest else None,
            latest=latest.timestamp if latest else None,
            events=len(ordered),
            timed_events=len(timed),
            log_events=len(log_timed),
            sources=len(sources),
            errors=len(parser_errors),
            earliest_source=earliest.source_path if earliest else "",
            latest_source=latest.source_path if latest else "",
            range_basis="log_time" if log_timed else "timestamped_evidence",
            source_types=sorted({source.source_type for source in sources}),
            excluded_files=len(excluded_files),
            evidence_files=len(evidence_inventory),
            unsupported_sources=sum(
                source.parser_status == "unsupported" for source in sources
            ),
            unmatched_files=sum(
                evidence.coverage_status == "unmatched"
                for evidence in evidence_inventory
            ),
        )
    finally:
        loaded.cleanup()


def run_pipeline(
    input_path: str | Path,
    out_dir: str | Path,
    *,
    incident_start: str | None = None,
    incident_end: str | None = None,
    year: int | None = None,
    timezone_name: str = "UTC",
    host: str = "",
    iocs: list[Ioc] | None = None,
    threat_type: str = "",
    progress_callback: ProgressCallback | None = None,
) -> PipelineResult:
    output_dir = Path(out_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    start = parse_iso(incident_start) if incident_start else None
    end = parse_iso(incident_end) if incident_end else None
    if incident_start and not start:
        raise ValueError(f"Could not parse incident start: {incident_start}")
    if incident_end and not end:
        raise ValueError(f"Could not parse incident end: {incident_end}")
    threat_type = validate_profile(threat_type)

    analysis = _run_collection(
        input_path,
        output_dir,
        start=start,
        end=end,
        year=year,
        timezone_name=timezone_name,
        host=host,
        iocs=iocs or [],
        collection_id="",
        collection_name="",
        collection_input="",
        threat_type=threat_type,
        write_outputs=True,
        progress_callback=progress_callback,
    )
    return PipelineResult(
        output=output_dir,
        events=len(analysis.full_events),
        mini_events=len(analysis.mini_events),
        findings=len(analysis.findings),
        errors=len(analysis.parser_errors),
        ioc_hits=len(analysis.ioc_hits),
    )


def run_case_pipeline(
    inputs: list[str | Path],
    out_dir: str | Path,
    *,
    incident_start: str | None = None,
    incident_end: str | None = None,
    year: int | None = None,
    timezone_name: str = "UTC",
    host: str = "",
    iocs: list[Ioc] | None = None,
    case_name: str = "TraceQuarry Case",
    threat_type: str = "",
    progress_callback: ProgressCallback | None = None,
) -> CasePipelineResult:
    if not inputs:
        raise ValueError("At least one UAC input is required for a case workspace.")
    output_dir = Path(out_dir).expanduser().resolve()
    hosts_dir = output_dir / "hosts"
    hosts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    hosts_dir.chmod(0o700)
    start = parse_iso(incident_start) if incident_start else None
    end = parse_iso(incident_end) if incident_end else None
    if incident_start and not start:
        raise ValueError(f"Could not parse incident start: {incident_start}")
    if incident_end and not end:
        raise ValueError(f"Could not parse incident end: {incident_end}")
    threat_type = validate_profile(threat_type)

    used_ids: set[str] = set()
    analyses: list[CollectionAnalysis] = []
    for index, input_path in enumerate(inputs, start=1):
        collection_name = _collection_name(input_path, index)
        collection_id = _collection_id(input_path, collection_name, index, used_ids)
        host_output = hosts_dir / collection_id
        analysis = _run_collection(
            input_path,
            host_output,
            start=start,
            end=end,
            year=year,
            timezone_name=timezone_name,
            host=host,
            iocs=iocs or [],
            collection_id=collection_id,
            collection_name=collection_name,
            collection_input=str(Path(input_path).expanduser()),
            threat_type=threat_type,
            write_outputs=True,
            progress_callback=progress_callback,
            collection_index=index,
            collection_total=len(inputs),
        )
        analyses.append(analysis)

    duplicate_groups = _duplicate_collection_groups(analyses)
    duplicate_ids = {
        collection_id
        for group in duplicate_groups
        for collection_id in group["duplicate_collection_ids"]
    }
    case_analyses = [
        analysis for analysis in analyses if analysis.collection_id not in duplicate_ids
    ]

    full_events = assign_event_ids(
        dedupe_events(
            sort_events(
                [event for analysis in analyses for event in analysis.full_events]
            )
        )
    )
    mini_events = filter_window(full_events, start, end) if (start or end) else []
    case_events = assign_event_ids(
        dedupe_events(
            sort_events(
                [event for analysis in case_analyses for event in analysis.full_events]
            )
        )
    )
    case_mini_events = filter_window(case_events, start, end) if (start or end) else []
    analysis_events = _analysis_scope(case_events, case_mini_events, bool(start or end))
    findings = derive_findings(
        analysis_events,
        available_source_types={
            source.source_type
            for analysis in case_analyses
            for source in analysis.sources
        },
    )
    ioc_hits = match_iocs(analysis_events, iocs or [])
    known_ioc_finding = ioc_finding(ioc_hits)
    if known_ioc_finding:
        findings.insert(0, known_ioc_finding)
    duplicate_finding = _duplicate_collection_finding(duplicate_groups)
    if duplicate_finding:
        findings.insert(0, duplicate_finding)
    storylines = build_storylines(case_mini_events or case_events)
    correlations = build_case_correlations(analysis_events)
    for correlation in correlations:
        findings.append(_case_correlation_finding(correlation))

    write_jsonl(output_dir / "case_timeline_full.jsonl", full_events)
    write_csv(output_dir / "case_timeline_full.csv", full_events)
    if start or end:
        write_jsonl(output_dir / "case_timeline_mini.jsonl", mini_events)
        write_csv(output_dir / "case_timeline_mini.csv", mini_events)
    write_json(
        output_dir / "case_findings.json",
        {"findings": findings, "storylines": storylines, "correlations": correlations},
    )
    write_json(
        output_dir / "case_source_index.json",
        _case_source_index(
            analyses,
            start,
            end,
            timezone_name,
            iocs or [],
            case_name,
            duplicate_groups,
            threat_type,
        ),
    )
    write_json(
        output_dir / "case_correlation.json",
        {
            "case_name": case_name,
            "duplicate_collection_groups": duplicate_groups,
            "correlations": correlations,
        },
    )
    write_ioc_hits_with_prefix(output_dir, "case_ioc_hits", ioc_hits)
    write_summary(
        output_dir / "case_summary.md",
        mini_events or full_events,
        findings,
        storylines,
        context_events=full_events,
    )
    _append_case_summary(
        output_dir / "case_summary.md",
        analyses,
        correlations,
        case_name,
        duplicate_groups,
    )
    _clear_assisted_outputs(output_dir, prefix="case_")
    if threat_type:
        assisted = build_assisted_investigation(
            threat_type,
            analysis_events,
            findings,
            {
                source.source_type
                for analysis in case_analyses
                for source in analysis.sources
            },
        )
        write_assisted_investigation(output_dir, assisted, prefix="case_")
        append_assisted_summary(
            output_dir / "case_summary.md",
            assisted,
            detail_name="case_assisted_investigation.md",
        )
    parser_errors = [
        f"{analysis.collection_id}: {error}"
        for analysis in analyses
        for error in analysis.parser_errors
    ]
    case_errors_path = output_dir / "case_parser_errors.log"
    case_errors_path.write_text(
        "\n".join(parser_errors) + ("\n" if parser_errors else ""),
        encoding="utf-8",
    )
    secure_file(case_errors_path)
    _write_case_manifest(
        output_dir,
        analyses,
        start,
        end,
        timezone_name,
        case_name,
        duplicate_groups,
        threat_type,
    )
    _emit_progress(
        progress_callback,
        stage="case_complete",
        completed=len(inputs),
        total=len(inputs),
    )

    return CasePipelineResult(
        output=output_dir,
        collections=len(analyses),
        events=len(full_events),
        mini_events=len(mini_events),
        findings=len(findings),
        correlations=len(correlations),
        errors=len(parser_errors),
        ioc_hits=len(ioc_hits),
        host_outputs=[str(analysis.output) for analysis in analyses],
        duplicate_collections=len(duplicate_ids),
    )


def _run_collection(
    input_path: str | Path,
    output_dir: Path,
    *,
    start: str | None,
    end: str | None,
    year: int | None,
    timezone_name: str,
    host: str,
    iocs: list[Ioc],
    collection_id: str,
    collection_name: str,
    collection_input: str,
    threat_type: str,
    write_outputs: bool,
    progress_callback: ProgressCallback | None = None,
    collection_index: int = 1,
    collection_total: int = 1,
) -> CollectionAnalysis:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    parser_errors: list[str] = []
    input_record = _input_record(input_path)
    loaded = load_input(str(input_path))
    try:
        sources = discover_sources(loaded.root)
        evidence_inventory = discover_evidence_files(loaded.root, sources)
        _hash_evidence_inventory(evidence_inventory)
        evidence_hashes = {
            evidence.relative: evidence.sha256 for evidence in evidence_inventory
        }
        for source in sources:
            source.sha256 = evidence_hashes.get(source.relative, "")
        if input_record["kind"] == "directory":
            input_record = _directory_input_record(input_record, evidence_inventory)
        excluded_files = discover_exclusions(loaded.root)
        _emit_progress(
            progress_callback,
            stage="sources_discovered",
            collection_id=collection_id,
            collection_name=collection_name or Path(input_path).name,
            collection_index=collection_index,
            collection_total=collection_total,
            completed=0,
            total=len(sources),
        )
        events = []
        for source_index, source in enumerate(sources, start=1):
            parser = PARSER_DISPATCH.get(source.source_type)
            if not parser:
                source.parser_status = "unsupported"
                source.parser_error = _unsupported_source_reason(source.source_type)
            else:
                try:
                    parsed = _parse_source(parser, source, host, year, timezone_name)
                    events.extend(parsed)
                    source.parser_status = "parsed"
                    source.event_count = len(parsed)
                except UnsupportedCompressionError as exc:
                    source.parser_status = "unsupported"
                    source.parser_error = str(exc)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                    source.parser_status = "error"
                    source.parser_error = error
                    parser_errors.append(f"{source.relative}: {error}")
            _emit_progress(
                progress_callback,
                stage="parsing_sources",
                collection_id=collection_id,
                collection_name=collection_name or Path(input_path).name,
                collection_index=collection_index,
                collection_total=collection_total,
                source=source.relative,
                completed=source_index,
                total=len(sources),
            )
        _sync_evidence_coverage(evidence_inventory, sources)
        try:
            diff_events = diff_accounts(loaded.root, host=host)
            diff_events = _attach_derived_provenance(diff_events, evidence_hashes)
            events.extend(diff_events)
        except Exception as exc:
            parser_errors.append(f"account_diff: {type(exc).__name__}: {exc}")
        acquisition_time = _collection_acquisition_time(input_path, timezone_name)
        events = _anchor_observation_events(events, acquisition_time)
        collection_host = _collection_host(host, collection_name, collection_id, events)
        events = _attach_collection(
            events, collection_id, collection_name, collection_input, collection_host
        )
        events = enrich_events(events)
        events = assign_event_ids(dedupe_events(sort_events(events)))
        events = correlate_state_events(events)
        events = _attach_original_event_ids(events)
        events = assign_event_ids(dedupe_events(sort_events(events)))
        full_events = sort_events(events)
        mini_events = filter_window(full_events, start, end) if (start or end) else []
        analysis_events = _analysis_scope(full_events, mini_events, bool(start or end))
        findings = derive_findings(
            analysis_events,
            available_source_types={source.source_type for source in sources},
        )
        ioc_hits = match_iocs(analysis_events, iocs or [])
        known_ioc_finding = ioc_finding(ioc_hits)
        if known_ioc_finding:
            findings.insert(0, known_ioc_finding)
        storylines = build_storylines(mini_events or full_events)
        input_verification = _verify_input_evidence(
            input_path, input_record, loaded.root, evidence_inventory
        )
        if input_verification["status"] != "verified":
            parser_errors.append(
                "evidence_verification: " + input_verification["summary"]
            )

        analysis = CollectionAnalysis(
            collection_id=collection_id,
            collection_name=collection_name,
            collection_input=collection_input,
            collection_host=collection_host,
            root=str(loaded.root),
            sources=sources,
            evidence_inventory=evidence_inventory,
            excluded_files=excluded_files,
            collection_fingerprint=_collection_fingerprint(evidence_inventory),
            acquisition_time=acquisition_time,
            input_record=input_record,
            input_verification=input_verification,
            full_events=full_events,
            mini_events=mini_events,
            findings=findings,
            storylines=storylines,
            ioc_hits=ioc_hits,
            parser_errors=parser_errors,
            output=output_dir,
        )
        if write_outputs:
            _write_collection_outputs(
                analysis, start, end, timezone_name, len(iocs), threat_type
            )
            _write_run_manifest(analysis, start, end, timezone_name, threat_type)
        return analysis
    finally:
        loaded.cleanup()


def _write_collection_outputs(
    analysis: CollectionAnalysis,
    start: str | None,
    end: str | None,
    timezone_name: str,
    ioc_count: int,
    threat_type: str,
) -> None:
    output_dir = analysis.output
    write_jsonl(output_dir / "timeline_full.jsonl", analysis.full_events)
    write_csv(output_dir / "timeline_full.csv", analysis.full_events)
    if start or end:
        write_jsonl(output_dir / "timeline_mini.jsonl", analysis.mini_events)
        write_csv(output_dir / "timeline_mini.csv", analysis.mini_events)
    write_json(
        output_dir / "findings.json",
        {"findings": analysis.findings, "storylines": analysis.storylines},
    )
    write_json(
        output_dir / "source_index.json",
        {
            "root": analysis.root,
            "collection_id": analysis.collection_id,
            "collection_name": analysis.collection_name,
            "collection_input": analysis.collection_input,
            "collection_host": analysis.collection_host,
            "acquisition_time": analysis.acquisition_time,
            "input": analysis.input_record,
            "input_verification": analysis.input_verification,
            "sources": [_source_record(source) for source in analysis.sources],
            "evidence_inventory": [
                _evidence_record(evidence) for evidence in analysis.evidence_inventory
            ],
            "excluded_files": analysis.excluded_files,
            "incident_start": start,
            "incident_end": end,
            "timezone": timezone_name,
            "ioc_count": ioc_count,
            "threat_type": threat_type,
        },
    )
    write_ioc_hits(output_dir, analysis.ioc_hits)
    write_summary(
        output_dir / "summary.md",
        analysis.mini_events or analysis.full_events,
        analysis.findings,
        analysis.storylines,
        context_events=analysis.full_events,
    )
    _append_evidence_coverage(
        output_dir / "summary.md", analysis.evidence_inventory, analysis.sources
    )
    _clear_assisted_outputs(output_dir)
    if threat_type:
        assisted = build_assisted_investigation(
            threat_type,
            _analysis_scope(
                analysis.full_events, analysis.mini_events, bool(start or end)
            ),
            analysis.findings,
            {source.source_type for source in analysis.sources},
        )
        write_assisted_investigation(output_dir, assisted)
        append_assisted_summary(output_dir / "summary.md", assisted)
    parser_errors_path = output_dir / "parser_errors.log"
    parser_errors_path.write_text(
        "\n".join(analysis.parser_errors) + ("\n" if analysis.parser_errors else ""),
        encoding="utf-8",
    )
    secure_file(parser_errors_path)


def _parse_source(
    parser: Callable[..., list[TimelineEvent]],
    source: SourceFile,
    host: str,
    year: int | None,
    timezone_name: str,
) -> list[TimelineEvent]:
    if (
        source.source_type in {"auth_log", "syslog", "cron", "web_log", "login_history"}
        or source.source_type == "journal_text"
    ):
        parsed = parser(
            source.path,
            source.relative,
            host=host,
            year=year,
            timezone_name=timezone_name,
        )
    else:
        parsed = parser(source.path, source.relative, host=host)
    return [
        replace(
            event,
            source_sha256=source.sha256,
            parser_version=__version__,
            timestamp_precision=(
                event.timestamp_precision
                if event.timestamp_precision != "unknown"
                else "second"
                if event.timestamp
                else "not_applicable"
            ),
            timestamp_confidence=(
                event.timestamp_confidence
                if event.timestamp_confidence != "medium" or event.timestamp
                else "not_applicable"
            ),
        )
        for event in parsed
    ]


def _attach_derived_provenance(
    events: list[TimelineEvent], evidence_hashes: dict[str, str]
) -> list[TimelineEvent]:
    output = []
    for event in events:
        source_paths = [
            part.strip().lstrip("/") for part in event.source_path.split(" vs ")
        ]
        hashes = {
            source_path: evidence_hashes[source_path]
            for source_path in source_paths
            if source_path in evidence_hashes
        }
        combined = ""
        if hashes:
            payload = "\n".join(
                f"{path}|{digest}" for path, digest in sorted(hashes.items())
            )
            combined = sha256(payload.encode("utf-8", "replace")).hexdigest()
        output.append(
            replace(
                event,
                source_sha256=combined,
                parser_version=__version__,
                timestamp_precision="second" if event.timestamp else "not_applicable",
                timestamp_confidence="medium" if event.timestamp else "not_applicable",
                extra={**event.extra, "derived_source_sha256s": hashes},
            )
        )
    return output


def _clear_assisted_outputs(output_dir: Path, *, prefix: str = "") -> None:
    for suffix in ("md", "json"):
        path = output_dir / f"{prefix}assisted_investigation.{suffix}"
        if path.exists():
            path.unlink()


def _collection_name(input_path: str | Path, index: int) -> str:
    path = Path(input_path).expanduser()
    name = path.name or f"collection-{index:02d}"
    for suffix in [".tar.gz", ".tgz", ".tar", ".zip"]:
        if name.endswith(suffix):
            return name[: -len(suffix)] or f"collection-{index:02d}"
    return path.stem or f"collection-{index:02d}"


def _collection_acquisition_time(input_path: str | Path, timezone_name: str) -> str:
    match = re.search(r"(?<!\d)(20\d{12})(?!\d)", Path(input_path).name)
    if not match:
        return ""
    try:
        timezone: tzinfo = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        timezone = UTC
    try:
        observed = datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(
            tzinfo=timezone
        )
    except ValueError:
        return ""
    return observed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _anchor_observation_events(
    events: list[TimelineEvent], acquisition_time: str
) -> list[TimelineEvent]:
    if not acquisition_time:
        return events
    anchored = []
    for event in events:
        if event.timestamp or event.evidence_role == "behavior":
            anchored.append(event)
            continue
        anchored.append(
            replace(
                event,
                time_start=event.time_start or acquisition_time,
                time_end=event.time_end or acquisition_time,
                timestamp_confidence="low",
                extra={
                    **event.extra,
                    "observation_anchor": "uac_collection_filename",
                },
            )
        )
    return anchored


def _collection_id(
    input_path: str | Path, name: str, index: int, used_ids: set[str]
) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.strip().lower()).strip("-._")
    slug = slug or f"collection-{index:02d}"
    digest = sha256(
        str(Path(input_path).expanduser()).encode("utf-8", "replace")
    ).hexdigest()[:8]
    candidate = f"{index:02d}-{slug[:36]}-{digest}"
    while candidate in used_ids:
        candidate = f"{index:02d}-{slug[:30]}-{digest}-{len(used_ids) + 1}"
    used_ids.add(candidate)
    return candidate


def _collection_host(
    host_override: str,
    collection_name: str,
    collection_id: str,
    events: list[TimelineEvent],
) -> str:
    if host_override:
        return host_override
    observed = sorted({event.host for event in events if event.host})
    if observed:
        return observed[0]
    return collection_name or collection_id


def _attach_collection(
    events: list[TimelineEvent],
    collection_id: str,
    collection_name: str,
    collection_input: str,
    collection_host: str,
) -> list[TimelineEvent]:
    if not collection_id:
        return events
    output = []
    for event in events:
        output.append(
            replace(
                event,
                host=event.host or collection_host,
                collection_id=collection_id,
                collection_name=collection_name,
                collection_input=collection_input,
                collection_host=collection_host,
            )
        )
    return output


def _attach_original_event_ids(events: list[TimelineEvent]) -> list[TimelineEvent]:
    prepared = []
    for event in events:
        if not event.collection_id or not event.event_id:
            prepared.append(event)
            continue
        extra = dict(event.extra)
        extra.setdefault("collection_event_id", event.event_id)
        prepared.append(replace(event, event_id="", extra=extra))
    reassigned = assign_event_ids(prepared)
    id_map = {
        event.extra["collection_event_id"]: event.event_id
        for event in reassigned
        if event.extra.get("collection_event_id") and event.event_id
    }
    return [
        replace(
            event,
            related_event_ids=[
                id_map.get(event_id, event_id) for event_id in event.related_event_ids
            ],
        )
        for event in reassigned
    ]


def _analysis_scope(
    full_events: list[TimelineEvent],
    mini_events: list[TimelineEvent],
    windowed: bool,
) -> list[TimelineEvent]:
    if not windowed:
        return full_events
    untimed_high_signal = [
        event
        for event in full_events
        if not event.timestamp and event.severity in {"medium", "high", "critical"}
    ]
    return mini_events + untimed_high_signal


def _case_source_index(
    analyses: list[CollectionAnalysis],
    start: str | None,
    end: str | None,
    timezone_name: str,
    iocs: list[Ioc],
    case_name: str,
    duplicate_groups: list[dict[str, Any]],
    threat_type: str,
) -> dict[str, Any]:
    return {
        "case_name": case_name,
        "incident_start": start,
        "incident_end": end,
        "timezone": timezone_name,
        "ioc_count": len(iocs),
        "threat_type": threat_type,
        "duplicate_collection_groups": duplicate_groups,
        "collections": [
            {
                "collection_id": analysis.collection_id,
                "collection_name": analysis.collection_name,
                "collection_input": analysis.collection_input,
                "collection_host": analysis.collection_host,
                "acquisition_time": analysis.acquisition_time,
                "input": analysis.input_record,
                "input_verification": analysis.input_verification,
                "root": analysis.root,
                "output": str(analysis.output),
                "events": len(analysis.full_events),
                "mini_events": len(analysis.mini_events),
                "findings": len(analysis.findings),
                "parser_errors": len(analysis.parser_errors),
                "sources": [_source_record(source) for source in analysis.sources],
                "evidence_inventory": [
                    _evidence_record(evidence)
                    for evidence in analysis.evidence_inventory
                ],
                "excluded_files": analysis.excluded_files,
                "collection_fingerprint": analysis.collection_fingerprint,
            }
            for analysis in analyses
        ],
    }


def _append_case_summary(
    path: Path,
    analyses: list[CollectionAnalysis],
    correlations: list[dict[str, Any]],
    case_name: str,
    duplicate_groups: list[dict[str, Any]],
) -> None:
    lines = path.read_text(encoding="utf-8", errors="replace").rstrip().splitlines()
    lines.extend(
        [
            "",
            "## Case Workspace",
            f"- Case name: {case_name}",
            f"- Collections parsed: {len(analyses)}",
        ]
    )
    for analysis in analyses:
        lines.append(
            f"  - {analysis.collection_id}: host={analysis.collection_host}, "
            f"events={len(analysis.full_events)}, findings={len(analysis.findings)}"
        )
    evidence_inventory = [
        evidence for analysis in analyses for evidence in analysis.evidence_inventory
    ]
    sources = [source for analysis in analyses for source in analysis.sources]
    lines.extend(_evidence_coverage_lines(evidence_inventory, sources))
    if duplicate_groups:
        lines.extend(["", "## Duplicate Collection Control"])
        for group in duplicate_groups:
            lines.append(
                f"- {', '.join(group['duplicate_collection_ids'])} duplicate "
                f"{group['canonical_collection_id']}; retained as per-collection evidence but excluded "
                "from case findings and correlation."
            )
    lines.extend(["", "## Case Correlations"])
    if correlations:
        for correlation in correlations:
            lines.append(
                f"- **{correlation.get('title')}**: {correlation.get('summary')}"
            )
    else:
        lines.append("- No cross-collection correlations identified.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    secure_file(path)


def _append_evidence_coverage(
    path: Path,
    evidence_inventory: list[EvidenceFile],
    sources: list[SourceFile],
) -> None:
    lines = path.read_text(encoding="utf-8", errors="replace").rstrip().splitlines()
    lines.extend(_evidence_coverage_lines(evidence_inventory, sources))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    secure_file(path)


def _evidence_coverage_lines(
    evidence_inventory: list[EvidenceFile],
    sources: list[SourceFile],
) -> list[str]:
    counts = {
        status: sum(item.coverage_status == status for item in evidence_inventory)
        for status in {
            "parsed",
            "partially_parsed",
            "unsupported",
            "unmatched",
            "error",
        }
    }
    lines = [
        "",
        "## Evidence Coverage",
        f"- Evidence files inventoried: {len(evidence_inventory)}",
        (
            "- Parsed: {parsed}; partially parsed: {partially_parsed}; "
            "unsupported: {unsupported}; unmatched: {unmatched}; failed: {error}"
        ).format(**counts),
    ]
    unsupported = [
        source for source in sources if source.parser_status == "unsupported"
    ]
    for source in unsupported[:10]:
        lines.append(
            f"  - Unsupported: `{source.relative}` ({source.source_type}) - "
            f"{source.parser_error}"
        )
    if len(unsupported) > 10:
        lines.append(
            f"  - {len(unsupported) - 10} additional unsupported source view(s); "
            "see source_index.json."
        )
    if counts["unmatched"]:
        lines.append(
            "- Unmatched files remain hashed in the evidence inventory and collection "
            "fingerprint; see source_index.json for paths."
        )
    return lines


def write_ioc_hits_with_prefix(
    out_dir: Path, prefix: str, hits: list[dict[str, Any]]
) -> None:
    json_path = out_dir / f"{prefix}.json"
    json_path.write_text(
        json.dumps(hits, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    secure_file(json_path)
    fields = [
        "ioc",
        "ioc_kind",
        "ioc_label",
        "event_id",
        "timestamp",
        "source_path",
        "source_type",
        "event_action",
        "user",
        "src_ip",
        "dst_ip",
        "file_path",
        "command",
        "summary",
    ]
    import csv

    csv_path = out_dir / f"{prefix}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for hit in hits:
            writer.writerow({field: hit.get(field) for field in fields})
    secure_file(csv_path)


def build_case_correlations(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    correlations: list[dict[str, Any]] = []
    correlations.extend(_shared_source_ip_correlations(events))
    correlations.extend(_shared_user_correlations(events))
    correlations.extend(_shared_tool_correlations(events))
    correlations.extend(_shared_path_correlations(events))
    correlations.extend(_cross_host_storyline_correlations(events))
    return correlations


def _collection_set(events: list[TimelineEvent]) -> list[str]:
    return sorted(
        {
            event.collection_id or event.collection_host or event.host
            for event in events
            if event.collection_id or event.collection_host or event.host
        }
    )


def _event_refs(events: list[TimelineEvent], limit: int = 20) -> list[str]:
    return [event.event_id for event in events if event.event_id][:limit]


def _shared_source_ip_correlations(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    output = []
    by_ip: dict[str, list[TimelineEvent]] = {}
    for event in events:
        if not event.src_ip:
            continue
        if event.event_category != "authentication" and "bruteforce" not in ",".join(
            event.tags
        ):
            continue
        by_ip.setdefault(event.src_ip, []).append(event)
    for src_ip, matches in sorted(
        by_ip.items(), key=lambda item: len(item[1]), reverse=True
    ):
        collections = _collection_set(matches)
        if len(collections) < 2:
            continue
        failures = [
            event for event in matches if event.event_action == "ssh_login_failure"
        ]
        successes = [
            event for event in matches if event.event_action == "ssh_login_success"
        ]
        output.append(
            {
                "type": "shared_source_ip",
                "severity": "high" if successes else "medium",
                "title": f"Shared authentication source IP across {len(collections)} collections",
                "summary": (
                    f"{src_ip} appears in authentication activity across {len(collections)} collections "
                    f"with {len(failures)} failure(s) and {len(successes)} success(es). "
                    "Treat as shared activity observed unless outbound host-to-host evidence exists."
                ),
                "value": src_ip,
                "collections": collections,
                "event_ids": _event_refs(matches),
            }
        )
    return output


def _shared_user_correlations(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    output = []
    interesting_actions = {
        "ssh_login_success",
        "sudo_command",
        "password_changed",
        "user_created",
        "user_modified",
        "account_unlocked",
    }
    by_user: dict[str, list[TimelineEvent]] = {}
    for event in events:
        if not event.user or event.event_action not in interesting_actions:
            continue
        by_user.setdefault(event.user, []).append(event)
    for user, matches in sorted(
        by_user.items(), key=lambda item: len(item[1]), reverse=True
    ):
        collections = _collection_set(matches)
        if len(collections) < 2:
            continue
        output.append(
            {
                "type": "shared_user_activity",
                "severity": "medium",
                "title": f"Shared suspicious user activity: {user}",
                "summary": f"User {user} appears in suspicious authentication, sudo, or account activity across {len(collections)} collections.",
                "value": user,
                "collections": collections,
                "event_ids": _event_refs(matches),
            }
        )
    return output


def _shared_tool_correlations(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    tools = [
        "rclone",
        "anydesk",
        "teamviewer",
        "rustdesk",
        "screenconnect",
        "logmein",
        "chisel",
        "frp",
        "ngrok",
        "cloudflared",
        "xmrig",
        "kubectl",
        "docker",
        "aws",
        "gsutil",
        "azcopy",
    ]
    output = []
    for tool in tools:
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_.-]){re.escape(tool)}(?![A-Za-z0-9_.-])", re.IGNORECASE
        )
        matches = [
            event
            for event in events
            if pattern.search(
                "\n".join(
                    filter(
                        None, [event.command, event.file_path, event.summary, event.raw]
                    )
                )
            )
        ]
        collections = _collection_set(matches)
        if len(collections) < 2:
            continue
        output.append(
            {
                "type": "shared_tooling",
                "severity": "high"
                if tool in {"rclone", "anydesk", "xmrig", "chisel", "frp", "ngrok"}
                else "medium",
                "title": f"Shared tool observed: {tool}",
                "summary": f"{tool} appears across {len(collections)} collections. Treat as shared tooling observed pending raw-line validation.",
                "value": tool,
                "collections": collections,
                "event_ids": _event_refs(matches),
            }
        )
    return output


def _shared_path_correlations(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    output = []
    by_path: dict[str, list[TimelineEvent]] = {}
    for event in events:
        candidate = event.file_path or ""
        if not candidate:
            match = re.search(
                r"(/tmp|/var/tmp|/dev/shm|/run)/[^\s;|&]+",
                " ".join(filter(None, [event.command, event.summary, event.raw])),
            )
            candidate = match.group(0) if match else ""
        if not candidate or not re.search(
            r"^(/tmp|/var/tmp|/dev/shm|/run|/etc/ssh|/root/.ssh|/home/.+/.ssh)",
            candidate,
        ):
            continue
        by_path.setdefault(candidate, []).append(event)
    for path, matches in sorted(
        by_path.items(), key=lambda item: len(item[1]), reverse=True
    ):
        collections = _collection_set(matches)
        if len(collections) < 2:
            continue
        output.append(
            {
                "type": "shared_suspicious_path",
                "severity": "medium",
                "title": f"Shared suspicious path: {path}",
                "summary": f"{path} appears in suspicious path activity across {len(collections)} collections.",
                "value": path,
                "collections": collections,
                "event_ids": _event_refs(matches),
            }
        )
    return output


def _cross_host_storyline_correlations(
    events: list[TimelineEvent],
) -> list[dict[str, Any]]:
    high_events = [
        event
        for event in sort_events(events)
        if event.timestamp and event.severity in {"high", "critical"}
    ]
    collections = _collection_set(high_events)
    if len(collections) < 2:
        return []
    first = high_events[0].timestamp
    last = high_events[-1].timestamp
    return [
        {
            "type": "cross_host_high_signal_timeline",
            "severity": "medium",
            "title": "Cross-collection high-signal activity timeline",
            "summary": (
                f"{len(high_events)} high-signal event(s) span {len(collections)} collections "
                f"between {first} and {last}. This is a possible campaign-level pattern, not lateral movement by itself."
            ),
            "value": "high_signal_timeline",
            "collections": collections,
            "event_ids": _event_refs(high_events, limit=30),
        }
    ]


def _case_correlation_finding(correlation: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": correlation.get("title", "Case Correlation"),
        "severity": correlation.get("severity", "medium"),
        "confidence": "medium",
        "event_ids": correlation.get("event_ids", []),
        "summary": correlation.get("summary", ""),
        "tags": ["case_correlation", correlation.get("type", "case_correlation")],
        "collections": correlation.get("collections", []),
    }


def _emit_progress(callback: ProgressCallback | None, **payload: object) -> None:
    if callback:
        callback(payload)


def _source_record(source: SourceFile) -> dict[str, Any]:
    return {
        "relative": source.relative,
        "source_type": source.source_type,
        "size": source.size,
        "sha256": source.sha256,
        "parser_status": source.parser_status,
        "event_count": source.event_count,
        "parser_error": source.parser_error,
    }


def _evidence_record(evidence: EvidenceFile) -> dict[str, Any]:
    return {
        "relative": evidence.relative,
        "size": evidence.size,
        "sha256": evidence.sha256,
        "source_types": evidence.source_types,
        "coverage_status": evidence.coverage_status,
        "coverage_reason": evidence.coverage_reason,
    }


def _hash_evidence_inventory(evidence_inventory: list[EvidenceFile]) -> None:
    for evidence in evidence_inventory:
        evidence.sha256 = _file_sha256(evidence.path)


def _sync_evidence_coverage(
    evidence_inventory: list[EvidenceFile], sources: list[SourceFile]
) -> None:
    by_relative: dict[str, list[SourceFile]] = {}
    for source in sources:
        by_relative.setdefault(source.relative, []).append(source)
    for evidence in evidence_inventory:
        matched = by_relative.get(evidence.relative, [])
        statuses = {source.parser_status for source in matched}
        if not matched:
            continue
        if "error" in statuses:
            evidence.coverage_status = "error"
            evidence.coverage_reason = "At least one matched parser failed."
        elif "parsed" in statuses:
            evidence.coverage_status = (
                "parsed" if statuses == {"parsed"} else "partially_parsed"
            )
            evidence.coverage_reason = (
                "All matched parser views completed."
                if evidence.coverage_status == "parsed"
                else "A parser view completed while another view is unsupported."
            )
        elif statuses == {"unsupported"}:
            evidence.coverage_status = "unsupported"
            evidence.coverage_reason = "; ".join(
                sorted({source.parser_error for source in matched})
            )


def _unsupported_source_reason(source_type: str) -> str:
    return {
        "journal_binary": (
            "Native systemd journal databases require an external journal export; "
            "TraceQuarry parses journalctl text exports without modifying the evidence."
        ),
        "login_binary": (
            "Native wtmp, btmp, and lastlog databases require a platform-aware binary "
            "decoder; collect corresponding last/lastb text output for this release."
        ),
    }.get(source_type, f"No parser is registered for source type {source_type}.")


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _input_record(input_path: str | Path) -> dict[str, Any]:
    path = Path(input_path).expanduser().resolve()
    record: dict[str, Any] = {
        "path": str(path),
        "kind": "directory" if path.is_dir() else "archive",
    }
    if path.is_file():
        record.update({"size": path.stat().st_size, "sha256": _file_sha256(path)})
    return record


def _directory_input_record(
    record: dict[str, Any], evidence_inventory: list[EvidenceFile]
) -> dict[str, Any]:
    return {
        **record,
        "files": len(evidence_inventory),
        "size": sum(evidence.size for evidence in evidence_inventory),
        "sha256": _collection_fingerprint(evidence_inventory),
    }


def _verify_input_evidence(
    input_path: str | Path,
    input_record: dict[str, Any],
    root: Path,
    expected_inventory: list[EvidenceFile],
) -> dict[str, Any]:
    path = Path(input_path).expanduser().resolve()
    archive_unchanged = True
    if path.is_file():
        archive_unchanged = path.stat().st_size == input_record.get(
            "size"
        ) and _file_sha256(path) == input_record.get("sha256")
    current = discover_evidence_files(root, discover_sources(root))
    _hash_evidence_inventory(current)
    expected = {item.relative: (item.size, item.sha256) for item in expected_inventory}
    observed = {item.relative: (item.size, item.sha256) for item in current}
    changed = sorted(
        relative
        for relative in set(expected) | set(observed)
        if expected.get(relative) != observed.get(relative)
    )
    verified = archive_unchanged and not changed
    return {
        "status": "verified" if verified else "changed_during_analysis",
        "archive_unchanged": archive_unchanged,
        "inventory_unchanged": not changed,
        "changed_files": changed,
        "summary": (
            "Input archive and extracted evidence inventory remained unchanged."
            if verified and path.is_file()
            else "Evidence directory inventory remained unchanged."
            if verified
            else "Input evidence changed while TraceQuarry was analyzing it."
        ),
    }


def _collection_fingerprint(evidence_inventory: list[EvidenceFile]) -> str:
    """Fingerprint every collected evidence file, including unsupported artifacts."""
    records = {
        (evidence.relative, evidence.size, evidence.sha256)
        for evidence in evidence_inventory
    }
    if not records:
        return ""
    payload = "\n".join(
        f"{relative}|{size}|{digest}" for relative, size, digest in sorted(records)
    )
    return sha256(payload.encode("utf-8", "replace")).hexdigest()


def _duplicate_collection_groups(
    analyses: list[CollectionAnalysis],
) -> list[dict[str, Any]]:
    by_fingerprint: dict[str, list[CollectionAnalysis]] = {}
    for analysis in analyses:
        if not analysis.collection_fingerprint:
            continue
        by_fingerprint.setdefault(analysis.collection_fingerprint, []).append(analysis)
    groups = []
    for fingerprint, members in by_fingerprint.items():
        if len(members) < 2:
            continue
        groups.append(
            {
                "fingerprint": fingerprint,
                "canonical_collection_id": members[0].collection_id,
                "duplicate_collection_ids": [
                    member.collection_id for member in members[1:]
                ],
                "collection_inputs": [member.collection_input for member in members],
            }
        )
    return groups


def _duplicate_collection_finding(
    groups: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not groups:
        return None
    duplicate_ids = [
        collection_id
        for group in groups
        for collection_id in group["duplicate_collection_ids"]
    ]
    return {
        "title": "Duplicate Collection Evidence Detected",
        "severity": "medium",
        "confidence": "high",
        "event_ids": [],
        "summary": (
            f"Detected {len(duplicate_ids)} byte-equivalent repeated collection(s): "
            f"{', '.join(duplicate_ids)}. Per-collection outputs were retained, but repeated evidence "
            "was excluded from case-level findings, IoC counts, and cross-collection correlations."
        ),
        "tags": ["duplicate_collection", "evidence_quality", "case_control"],
        "duplicate_collection_groups": groups,
    }


def _output_records(
    output_dir: Path, *, exclude: set[str] | None = None
) -> list[dict[str, Any]]:
    records = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file() or path.name in (exclude or set()):
            continue
        records.append(
            {
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        )
    return records


def _rules_record() -> dict[str, Any]:
    path = registry_path()
    if not path.exists():
        return {"path": "", "sha256": "", "status": "not_found"}
    return {"path": str(path), "sha256": _file_sha256(path), "status": "available"}


def _write_run_manifest(
    analysis: CollectionAnalysis,
    start: str | None,
    end: str | None,
    timezone_name: str,
    threat_type: str,
) -> None:
    path = analysis.output / "run_manifest.json"
    write_json(
        path,
        {
            "schema_version": "1.1",
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "tracequarry_version": __version__,
            "python_version": platform.python_version(),
            "input": analysis.input_record,
            "input_verification": analysis.input_verification,
            "collection_id": analysis.collection_id,
            "collection_name": analysis.collection_name,
            "collection_host": analysis.collection_host,
            "acquisition_time": analysis.acquisition_time,
            "settings": {
                "incident_start": start,
                "incident_end": end,
                "timezone": timezone_name,
                "threat_type": threat_type,
            },
            "rules": _rules_record(),
            "coverage": {
                "sources_discovered": len(analysis.sources),
                "sources_parsed": sum(
                    source.parser_status == "parsed" for source in analysis.sources
                ),
                "sources_failed": sum(
                    source.parser_status == "error" for source in analysis.sources
                ),
                "sources_unsupported": sum(
                    source.parser_status == "unsupported" for source in analysis.sources
                ),
                "source_types": sorted(
                    {source.source_type for source in analysis.sources}
                ),
                "events": len(analysis.full_events),
                "evidence_files": len(analysis.evidence_inventory),
                "evidence_files_parsed": sum(
                    evidence.coverage_status in {"parsed", "partially_parsed"}
                    for evidence in analysis.evidence_inventory
                ),
                "evidence_files_unsupported": sum(
                    evidence.coverage_status == "unsupported"
                    for evidence in analysis.evidence_inventory
                ),
                "evidence_files_unmatched": sum(
                    evidence.coverage_status == "unmatched"
                    for evidence in analysis.evidence_inventory
                ),
                "excluded_files": len(analysis.excluded_files),
            },
            "sources": [_source_record(source) for source in analysis.sources],
            "evidence_inventory": [
                _evidence_record(evidence) for evidence in analysis.evidence_inventory
            ],
            "excluded_files": analysis.excluded_files,
            "collection_fingerprint": analysis.collection_fingerprint,
            "outputs": _output_records(analysis.output, exclude={path.name}),
        },
    )


def _write_case_manifest(
    output_dir: Path,
    analyses: list[CollectionAnalysis],
    start: str | None,
    end: str | None,
    timezone_name: str,
    case_name: str,
    duplicate_groups: list[dict[str, Any]],
    threat_type: str,
) -> None:
    path = output_dir / "case_manifest.json"
    write_json(
        path,
        {
            "schema_version": "1.1",
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "tracequarry_version": __version__,
            "case_name": case_name,
            "settings": {
                "incident_start": start,
                "incident_end": end,
                "timezone": timezone_name,
                "threat_type": threat_type,
            },
            "rules": _rules_record(),
            "duplicate_collection_groups": duplicate_groups,
            "collections": [
                {
                    "collection_id": analysis.collection_id,
                    "collection_name": analysis.collection_name,
                    "collection_host": analysis.collection_host,
                    "acquisition_time": analysis.acquisition_time,
                    "input": analysis.input_record,
                    "input_verification": analysis.input_verification,
                    "events": len(analysis.full_events),
                    "sources": len(analysis.sources),
                    "evidence_files": len(analysis.evidence_inventory),
                    "parser_errors": len(analysis.parser_errors),
                    "excluded_files": analysis.excluded_files,
                    "collection_fingerprint": analysis.collection_fingerprint,
                }
                for analysis in analyses
            ],
            "outputs": _output_records(output_dir, exclude={path.name}),
        },
    )
