from __future__ import annotations

from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from uac_parser.output.permissions import secure_file
from uac_parser.resources import resource_file
from uac_parser.timeline.event import TimelineEvent


SOURCE_GROUPS = {
    "authentication": {"auth_log", "login_history", "auditd"},
    "web": {"web_log"},
    "execution": {"auditd", "shell_history", "ps_output"},
    "process": {"ps_output", "auditd"},
    "persistence": {"cron", "cron_file", "systemd", "systemd_unit", "profile", "rc_local", "pam_config", "ld_preload", "authorized_keys"},
    "accounts": {"passwd", "shadow", "group", "account_diff", "authorized_keys"},
    "privilege": {"sudoers", "auth_log", "auditd", "capabilities", "bodyfile_privilege"},
    "network": {"ss_output", "netstat_output", "auth_log", "web_log"},
    "filesystem": {"bodyfile", "bodyfile_privilege", "auditd"},
    "cloud_container": {"auditd", "shell_history", "ps_output", "ss_output", "netstat_output"},
}


class InvestigationProfileError(ValueError):
    pass


def profiles_path() -> Path:
    return resource_file("rules", "investigation_profiles.yml")


@lru_cache(maxsize=1)
def load_profiles() -> dict[str, dict[str, Any]]:
    path = profiles_path()
    if not path.exists():
        raise InvestigationProfileError(f"Investigation profiles not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, dict) or not profiles:
        raise InvestigationProfileError("Investigation profiles must contain a non-empty profiles mapping.")
    for profile_id, profile in profiles.items():
        if not isinstance(profile, dict) or not profile.get("label") or not isinstance(profile.get("checklist"), list):
            raise InvestigationProfileError(f"Invalid investigation profile: {profile_id}")
    return profiles


def profile_choices() -> list[dict[str, str]]:
    return [
        {"id": profile_id, "label": str(profile["label"]), "description": str(profile.get("description", ""))}
        for profile_id, profile in load_profiles().items()
    ]


def validate_profile(profile_id: str | None) -> str:
    selected = (profile_id or "").strip()
    if not selected:
        return ""
    if selected not in load_profiles():
        raise InvestigationProfileError(
            f"Unknown threat type {selected!r}. Choose one of: {', '.join(load_profiles())}."
        )
    return selected


def build_assisted_investigation(
    profile_id: str,
    events: list[TimelineEvent],
    findings: list[dict[str, object]],
    available_source_types: set[str],
) -> dict[str, object]:
    profile_id = validate_profile(profile_id)
    if not profile_id:
        return {}
    profile = load_profiles()[profile_id]
    event_by_id = {event.event_id: event for event in events if event.event_id}
    focus_terms = {str(term).lower() for term in profile.get("focus_terms", [])}
    focus_mitre = {str(value) for value in profile.get("mitre", [])}

    ranked = []
    for finding in findings:
        related = [event_by_id[event_id] for event_id in finding.get("event_ids", []) if event_id in event_by_id]
        text = _finding_text(finding, related)
        matched_terms = sorted(term for term in focus_terms if term in text)
        matched_mitre = sorted(focus_mitre & {value for event in related for value in event.mitre})
        severity_score = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}.get(str(finding.get("severity")), 0)
        score = severity_score + min(5, len(matched_terms) * 2) + min(3, len(matched_mitre))
        ranked.append({
            "title": finding.get("title", "Untitled finding"),
            "severity": finding.get("severity", "informational"),
            "confidence": finding.get("confidence", "unknown"),
            "summary": finding.get("summary", ""),
            "event_ids": finding.get("event_ids", []),
            "relevance_score": score,
            "relevance": "primary" if matched_terms or matched_mitre else "supporting",
            "matched_focus_terms": matched_terms,
            "matched_mitre": matched_mitre,
        })
    ranked.sort(key=lambda item: (-int(item["relevance_score"]), str(item["title"])))

    coverage = []
    for group in profile.get("source_groups", []):
        expected = SOURCE_GROUPS.get(str(group), set())
        present = sorted(expected & available_source_types)
        coverage.append({
            "group": group,
            "status": "available" if present else "missing",
            "present_source_types": present,
            "expected_source_types": sorted(expected),
        })

    checklist = []
    for item in profile.get("checklist", []):
        terms = [str(term).lower() for term in item.get("terms", [])]
        matched_events = [event for event in events if any(term in _event_text(event) for term in terms)]
        checklist.append({
            "question": item.get("question", "Review related evidence."),
            "status": "observed" if matched_events else "review_required",
            "matched_events": len(matched_events),
            "event_ids": [event.event_id for event in matched_events[:20] if event.event_id],
            "matched_terms": sorted({term for term in terms if any(term in _event_text(event) for event in matched_events)}),
        })

    signal_counts = Counter(
        signal
        for event in events
        for signal in set(event.detection_names + event.tags + event.mitre)
        if signal.lower() in focus_terms or signal in focus_mitre
    )
    missing_groups = [item["group"] for item in coverage if item["status"] == "missing"]
    return {
        "schema_version": "1.0",
        "profile_id": profile_id,
        "profile_label": profile["label"],
        "description": profile.get("description", ""),
        "working_hypothesis": profile.get("hypothesis", ""),
        "disclaimer": "This profile prioritizes review; it does not suppress evidence, prove the selected threat type, identify malware, or attribute an actor.",
        "evidence_scope": {"events_reviewed": len(events), "findings_reviewed": len(findings)},
        "coverage": coverage,
        "coverage_gaps": missing_groups,
        "observed_focus_signals": [{"signal": key, "events": value} for key, value in signal_counts.most_common(20)],
        "prioritized_findings": ranked,
        "checklist": checklist,
        "recommended_pivots": profile.get("pivots", []),
    }


def write_assisted_investigation(output_dir: Path, report: dict[str, object], *, prefix: str = "") -> None:
    if not report:
        return
    stem = f"{prefix}assisted_investigation"
    import json
    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    secure_file(json_path)
    lines = [
        f"# Assisted Investigation: {report['profile_label']}",
        "",
        f"**Working hypothesis:** {report['working_hypothesis']}",
        "",
        f"> {report['disclaimer']}",
        "",
        "## Evidence Readiness",
    ]
    for item in report["coverage"]:
        present = ", ".join(item["present_source_types"]) or "none"
        lines.append(f"- **{item['group']}**: {item['status']} (present: {present})")
    lines.extend(["", "## Prioritized Findings"])
    primary = [item for item in report["prioritized_findings"] if item["relevance"] == "primary"][:12]
    if primary:
        for item in primary:
            reason = ", ".join(item["matched_focus_terms"] + item["matched_mitre"]) or "severity/context"
            lines.append(f"- **[{str(item['severity']).upper()}] {item['title']}**: {item['summary']} (focus: {reason})")
    else:
        lines.append("- No profile-specific finding was promoted. Review supporting findings and coverage gaps.")
    lines.extend(["", "## Analyst Checklist"])
    for item in report["checklist"]:
        marker = "OBSERVED" if item["status"] == "observed" else "REVIEW"
        lines.append(f"- **{marker}** - {item['question']} ({item['matched_events']} matching event(s))")
    lines.extend(["", "## Recommended Pivots"])
    lines.extend(f"- {pivot}" for pivot in report["recommended_pivots"])
    markdown_path = output_dir / f"{stem}.md"
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    secure_file(markdown_path)


def append_assisted_summary(
    path: Path,
    report: dict[str, object],
    *,
    detail_name: str = "assisted_investigation.md",
) -> None:
    if not report:
        return
    lines = path.read_text(encoding="utf-8", errors="replace").rstrip().splitlines()
    primary = [item for item in report["prioritized_findings"] if item["relevance"] == "primary"]
    observed = sum(item["status"] == "observed" for item in report["checklist"])
    lines.extend([
        "",
        "## Assisted Investigation",
        f"- Profile: {report['profile_label']}",
        f"- Working hypothesis: {report['working_hypothesis']}",
        f"- Profile-relevant findings: {len(primary)}",
        f"- Checklist leads observed: {observed}/{len(report['checklist'])}",
        f"- Coverage gaps: {', '.join(report['coverage_gaps']) or 'none identified'}",
        f"- Guardrail: {report['disclaimer']}",
        f"- Detailed report: `{detail_name}`",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    secure_file(path)


def _event_text(event: TimelineEvent) -> str:
    return " ".join(str(value).lower() for value in [
        event.event_action, event.event_category, event.command, event.file_path, event.summary,
        *event.tags, *event.detection_names, *event.mitre,
    ] if value)


def _finding_text(finding: dict[str, object], related: list[TimelineEvent]) -> str:
    values = [finding.get("title", ""), finding.get("summary", ""), *finding.get("tags", [])]
    return " ".join(str(value).lower() for value in values) + " " + " ".join(_event_text(event) for event in related)
