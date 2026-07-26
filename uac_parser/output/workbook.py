from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import xlsxwriter  # type: ignore[import-untyped]

EXCEL_MAX_ROWS = 1_048_576
TIMELINE_ROWS_PER_SHEET = EXCEL_MAX_ROWS - 1

# Keep exported workbooks visually consistent with the web workbench.
BRAND_COLORS = {
    "night": "#0E1626",
    "depth": "#16213A",
    "fog": "#EDEFE9",
    "moss": "#9DBE8D",
    "slate": "#7C8696",
    "paper": "#F4F2ED",
    "ink": "#1B2430",
    "yuzu": "#E5A84B",
    "ember": "#D96A5B",
    "panel": "#FCFBF8",
    "panel_soft": "#F8F6F0",
    "text": "#27313F",
    "muted": "#667085",
    "line": "#D7D6D0",
}


def write_investigation_workbook(
    target: Path,
    *,
    case_name: str,
    briefing: Mapping[str, Any],
    timeline_rows: Iterable[Mapping[str, Any]],
    timeline_fields: Sequence[str],
    findings: Sequence[Mapping[str, Any]],
    filters: Mapping[str, str] | None = None,
) -> dict[str, int]:
    """Write a review workbook without interpreting evidence beyond the briefing."""
    target.parent.mkdir(parents=True, exist_ok=True)
    workbook = xlsxwriter.Workbook(
        target,
        {
            "constant_memory": True,
            "strings_to_formulas": False,
            "strings_to_urls": False,
            "tmpdir": str(target.parent),
        },
    )
    workbook.set_properties(
        {
            "title": f"TraceQuarry investigation workbook - {case_name}",
            "subject": "Linux DFIR timeline and analyst-selected reconstruction",
            "author": "TraceQuarry",
            "company": "Chill Ethical People",
            "comments": (
                "Generated from normalized evidence and separately stored analyst "
                "annotations. Validate conclusions against retained source evidence."
            ),
        }
    )
    formats = _formats(workbook)
    try:
        _write_executive_briefing(
            workbook,
            formats,
            case_name=case_name,
            briefing=briefing,
            filters=filters or {},
        )
        _write_selected_timeline(workbook, formats, briefing)
        timeline_count, timeline_sheets = _write_timeline_sheets(
            workbook, formats, timeline_rows, timeline_fields
        )
        _write_findings(workbook, formats, findings)
    finally:
        workbook.close()
    return {
        "timeline_rows": timeline_count,
        "timeline_sheets": timeline_sheets,
        "selected_rows": len(briefing.get("selected_events") or []),
        "findings": len(findings),
    }


def _formats(workbook: Any) -> dict[str, Any]:
    colors = BRAND_COLORS
    return {
        "title": workbook.add_format(
            {
                "bold": True,
                "font_size": 20,
                "font_color": colors["fog"],
                "bg_color": colors["night"],
                "top": 5,
                "top_color": colors["yuzu"],
                "align": "center",
                "valign": "vcenter",
            }
        ),
        "classification": workbook.add_format(
            {
                "italic": True,
                "font_color": colors["muted"],
                "align": "center",
                "valign": "vcenter",
            }
        ),
        "section": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["fog"],
                "bg_color": colors["depth"],
                "border": 1,
                "border_color": colors["slate"],
                "valign": "vcenter",
            }
        ),
        "section_red": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["night"],
                "bg_color": colors["ember"],
                "border": 1,
                "border_color": colors["ember"],
                "valign": "vcenter",
            }
        ),
        "section_gold": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["night"],
                "bg_color": colors["yuzu"],
                "border": 1,
                "border_color": colors["yuzu"],
                "valign": "vcenter",
            }
        ),
        "section_impact": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["night"],
                "bg_color": colors["ember"],
                "border": 1,
                "border_color": colors["ember"],
                "valign": "vcenter",
            }
        ),
        "section_sage": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["night"],
                "bg_color": colors["moss"],
                "border": 1,
                "border_color": colors["moss"],
                "valign": "vcenter",
            }
        ),
        "body": workbook.add_format(
            {
                "font_color": colors["text"],
                "font_size": 9,
                "bg_color": colors["panel"],
                "border": 1,
                "border_color": colors["line"],
                "valign": "top",
                "text_wrap": True,
            }
        ),
        "body_alt": workbook.add_format(
            {
                "font_color": colors["text"],
                "font_size": 9,
                "bg_color": colors["panel_soft"],
                "border": 1,
                "border_color": colors["line"],
                "valign": "top",
                "text_wrap": True,
            }
        ),
        "metric": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["night"],
                "font_size": 12,
                "bg_color": colors["panel"],
                "border": 1,
                "border_color": colors["line"],
                "align": "center",
                "valign": "vcenter",
            }
        ),
        "header": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["fog"],
                "bg_color": colors["night"],
                "border": 1,
                "border_color": colors["slate"],
                "text_wrap": True,
                "valign": "vcenter",
            }
        ),
        "phase": workbook.add_format(
            {
                "bold": True,
                "font_size": 8,
                "font_color": colors["night"],
                "bg_color": colors["fog"],
                "border": 1,
                "border_color": colors["moss"],
                "align": "center",
                "text_wrap": True,
            }
        ),
        "warning": workbook.add_format(
            {
                "bold": True,
                "font_color": colors["night"],
                "bg_color": colors["paper"],
                "border": 1,
                "border_color": colors["yuzu"],
                "text_wrap": True,
                "valign": "vcenter",
            }
        ),
        "mono": workbook.add_format(
            {
                "font_name": "Courier New",
                "font_size": 8,
                "font_color": colors["text"],
                "bg_color": colors["panel"],
                "border": 1,
                "border_color": colors["line"],
                "valign": "top",
                "text_wrap": True,
            }
        ),
    }


def _write_executive_briefing(
    workbook: Any,
    formats: Mapping[str, Any],
    *,
    case_name: str,
    briefing: Mapping[str, Any],
    filters: Mapping[str, str],
) -> None:
    worksheet = workbook.add_worksheet("Executive Briefing")
    worksheet.set_tab_color(BRAND_COLORS["yuzu"])
    worksheet.hide_gridlines(2)
    worksheet.set_landscape()
    worksheet.set_paper(9)
    worksheet.fit_to_pages(1, 2)
    worksheet.set_margins(0.25, 0.25, 0.35, 0.35)
    worksheet.set_zoom(80)
    worksheet.set_column("A:A", 18)
    worksheet.set_column("B:F", 13)
    worksheet.set_column("G:K", 12)
    worksheet.set_column("L:P", 13)

    worksheet.set_row(0, 30)
    worksheet.merge_range(
        "A1:P1", "CYBERSECURITY INCIDENT EXECUTIVE BRIEFING", formats["title"]
    )
    worksheet.merge_range(
        "A2:P2",
        f"Case: {case_name} | Confidential - For incident response, leadership, and legal review",
        formats["classification"],
    )
    worksheet.merge_range("A4:F4", "INCIDENT TIMELINE", formats["section"])
    worksheet.merge_range("G4:K4", "KEY METRICS", formats["section"])
    worksheet.merge_range("L4:P4", "OBSERVED ACTIONS", formats["section_red"])

    selected = list(briefing.get("selected_events") or [])
    executive = dict(briefing.get("executive") or {})
    metric_items = list(executive.get("key_metrics") or [])[:5]
    action_items = list(executive.get("threat_actions") or [])[:5]
    for offset in range(5):
        row = 4 + offset
        event = selected[offset] if offset < len(selected) else {}
        worksheet.write(
            row, 0, _display_timestamp(event.get("timestamp")), formats["mono"]
        )
        worksheet.merge_range(
            row,
            1,
            row,
            5,
            str(event.get("summary") or ""),
            formats["body_alt"] if offset % 2 else formats["body"],
        )
        metric = metric_items[offset] if offset < len(metric_items) else {}
        worksheet.merge_range(
            row,
            6,
            row,
            8,
            str(metric.get("label") or ""),
            formats["body_alt"] if offset % 2 else formats["body"],
        )
        worksheet.merge_range(
            row,
            9,
            row,
            10,
            str(metric.get("value") or ""),
            formats["metric"],
        )
        action = action_items[offset] if offset < len(action_items) else {}
        worksheet.merge_range(
            row,
            11,
            row,
            15,
            str(action.get("summary") or ""),
            formats["body_alt"] if offset % 2 else formats["body"],
        )
        worksheet.set_row(row, 34)

    phase_labels = [
        str(item.get("label") or "")
        for item in briefing.get("phase_breakdown") or []
        if int(item.get("selected_events") or 0) > 0
    ]
    worksheet.merge_range("A11:P11", "ATTACK PATH", formats["section"])
    worksheet.merge_range(
        "A12:P12",
        " -> ".join(phase_labels) or "No analyst-selected phase path yet",
        formats["body"],
    )

    worksheet.merge_range("A14:F14", "DATA EXFILTRATION", formats["section_gold"])
    worksheet.merge_range("G14:K14", "IMPACT / RECOVERY", formats["section_impact"])
    worksheet.merge_range("L14:P14", "KEY ACCOUNTS", formats["section_sage"])
    exfil = list(executive.get("data_exfiltration") or [])
    impact = list(executive.get("impact") or [])
    accounts = list(executive.get("accounts") or [])
    for offset in range(4):
        row = 14 + offset
        worksheet.merge_range(
            row,
            0,
            row,
            5,
            _bullet(exfil[offset]) if offset < len(exfil) else "",
            formats["body_alt"] if offset % 2 else formats["body"],
        )
        worksheet.merge_range(
            row,
            6,
            row,
            10,
            _bullet(impact[offset]) if offset < len(impact) else "",
            formats["body_alt"] if offset % 2 else formats["body"],
        )
        worksheet.merge_range(
            row,
            11,
            row,
            15,
            _bullet(accounts[offset]) if offset < len(accounts) else "",
            formats["body_alt"] if offset % 2 else formats["body"],
        )
        worksheet.set_row(row, 28)

    worksheet.merge_range(
        "A20:P20", "MITRE ATT&CK PHASE DISTRIBUTION", formats["section"]
    )
    phases = list(briefing.get("phase_breakdown") or [])
    for column, phase in enumerate(phases[:15]):
        worksheet.write(20, column, str(phase.get("label") or ""), formats["phase"])
    for column, phase in enumerate(phases[:15]):
        worksheet.write(
            21, column, int(phase.get("confirmed_events") or 0), formats["metric"]
        )
    worksheet.set_row(20, 34)

    worksheet.merge_range(
        "A24:P24",
        str(
            executive.get("legal_note")
            or "Legal and notification impact requires review."
        ),
        formats["warning"],
    )
    worksheet.merge_range("A26:P26", "EXECUTIVE SUMMARY", formats["section"])
    worksheet.merge_range(
        "A27:P31",
        str(executive.get("summary") or briefing.get("narrative") or ""),
        formats["body"],
    )
    worksheet.set_row(26, 24)
    worksheet.set_row(27, 28)
    worksheet.set_row(28, 28)
    worksheet.set_row(29, 28)
    worksheet.set_row(30, 28)

    worksheet.merge_range("A33:P33", "MITRE ATT&CK PHASE BREAKDOWN", formats["section"])
    row = 33
    for phase in phases:
        text = (
            f"{phase.get('label')} ({phase.get('tactic_id')}): "
            f"{phase.get('confirmed_events', 0)} confirmed, "
            f"{phase.get('candidate_events', 0)} candidate, "
            f"{phase.get('selected_events', 0)} selected; "
            f"first observed {_display_timestamp(phase.get('first_observed'))}"
        )
        worksheet.merge_range(
            row,
            0,
            row,
            15,
            _bullet(text),
            formats["body_alt"] if row % 2 else formats["body"],
        )
        row += 1
    scope_text = str(briefing.get("scope") or "full")
    filter_text = ", ".join(f"{key}={value}" for key, value in filters.items() if value)
    worksheet.merge_range(
        row + 1,
        0,
        row + 1,
        15,
        (
            f"Prepared {datetime.now(UTC).isoformat()} | Timeline scope: {scope_text}"
            + (f" | Filters: {filter_text}" if filter_text else "")
            + " | Analyst selections remain separate from parser evidence."
        ),
        formats["classification"],
    )
    worksheet.freeze_panes(4, 0)


def _write_selected_timeline(
    workbook: Any, formats: Mapping[str, Any], briefing: Mapping[str, Any]
) -> None:
    worksheet = workbook.add_worksheet("Selected Timeline")
    worksheet.set_tab_color(BRAND_COLORS["moss"])
    headers = [
        "timestamp_utc",
        "host",
        "attack_phases",
        "severity",
        "summary",
        "analyst_disposition",
        "analyst_tags",
        "analyst_note",
        "event_id",
        "source_type",
        "source_path",
        "source_sha256",
        "raw_evidence",
    ]
    _write_header(worksheet, headers, formats["header"])
    for row_index, event in enumerate(briefing.get("selected_events") or [], start=1):
        values = [
            event.get("timestamp"),
            event.get("host"),
            ",".join(event.get("attack_phases") or []),
            event.get("severity"),
            event.get("summary"),
            event.get("analyst_disposition"),
            ",".join(event.get("analyst_tags") or []),
            event.get("analyst_note"),
            event.get("event_id"),
            event.get("source_type"),
            event.get("source_path"),
            event.get("source_sha256"),
            event.get("raw"),
        ]
        for column, value in enumerate(values):
            worksheet.write(
                row_index,
                column,
                _cell(value),
                formats["mono"] if column in {8, 10, 11, 12} else formats["body"],
            )
    worksheet.freeze_panes(1, 0)
    worksheet.autofilter(
        0, 0, max(1, len(briefing.get("selected_events") or [])), len(headers) - 1
    )
    _set_timeline_widths(worksheet, headers)


def _write_timeline_sheets(
    workbook: Any,
    formats: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
    fields: Sequence[str],
) -> tuple[int, int]:
    worksheet = None
    sheet_count = 0
    row_count = 0
    row_in_sheet = 0
    for row in rows:
        if worksheet is None or row_in_sheet >= TIMELINE_ROWS_PER_SHEET:
            sheet_count += 1
            name = "Timeline" if sheet_count == 1 else f"Timeline {sheet_count}"
            worksheet = workbook.add_worksheet(name)
            worksheet.set_tab_color(BRAND_COLORS["slate"])
            _write_header(worksheet, fields, formats["header"])
            worksheet.freeze_panes(1, 0)
            _set_timeline_widths(worksheet, fields)
            row_in_sheet = 0
        for column, field in enumerate(fields):
            value = row.get(field)
            worksheet.write(
                row_in_sheet + 1,
                column,
                _cell(value),
                formats["mono"]
                if field in {"event_id", "source_path", "source_sha256", "raw", "extra"}
                else formats["body"],
            )
        row_count += 1
        row_in_sheet += 1
    if worksheet is None:
        worksheet = workbook.add_worksheet("Timeline")
        worksheet.set_tab_color(BRAND_COLORS["slate"])
        _write_header(worksheet, fields, formats["header"])
        worksheet.freeze_panes(1, 0)
        _set_timeline_widths(worksheet, fields)
        sheet_count = 1
    return row_count, sheet_count


def _write_findings(
    workbook: Any,
    formats: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> None:
    worksheet = workbook.add_worksheet("Findings")
    worksheet.set_tab_color(BRAND_COLORS["ember"])
    headers = [
        "severity",
        "confidence",
        "title",
        "summary",
        "tags",
        "iocs",
        "event_ids",
    ]
    _write_header(worksheet, headers, formats["header"])
    for row_index, finding in enumerate(findings, start=1):
        for column, field in enumerate(headers):
            worksheet.write(
                row_index, column, _cell(finding.get(field)), formats["body"]
            )
    worksheet.freeze_panes(1, 0)
    worksheet.autofilter(0, 0, max(1, len(findings)), len(headers) - 1)
    worksheet.set_column(0, 1, 12)
    worksheet.set_column(2, 2, 30)
    worksheet.set_column(3, 3, 70)
    worksheet.set_column(4, 6, 38)


def _write_header(worksheet: Any, fields: Sequence[str], cell_format: Any) -> None:
    for column, field in enumerate(fields):
        worksheet.write(0, column, field, cell_format)
    worksheet.set_row(0, 30)


def _set_timeline_widths(worksheet: Any, fields: Sequence[str]) -> None:
    widths = {
        "timestamp": 22,
        "timestamp_utc": 22,
        "summary": 52,
        "raw": 80,
        "raw_evidence": 80,
        "analyst_note": 55,
        "source_path": 42,
        "source_sha256": 66,
        "event_id": 27,
        "attack_phases": 35,
        "attack_phase_candidates": 35,
        "extra": 55,
    }
    for column, field in enumerate(fields):
        worksheet.set_column(column, column, widths.get(field, 18))


def _cell(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item) for item in value)
    if isinstance(value, dict):
        import json

        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)[:32767]


def _display_timestamp(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "Untimed"
    return text.replace("T", " ").replace("Z", " (UTC)")


def _bullet(value: Any) -> str:
    text = str(value or "").strip()
    return f"- {text}" if text else ""
