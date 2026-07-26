from __future__ import annotations

import sys
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uac_parser.resources import resource_file  # noqa: E402
from uac_parser.web import render_index  # noqa: E402


class _WebResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inline_scripts = 0
        self.inline_styles = 0
        self.external_scripts: list[str] = []
        self.stylesheets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "script":
            source = attributes.get("src")
            if source:
                self.external_scripts.append(source)
            else:
                self.inline_scripts += 1
        elif tag == "style":
            self.inline_styles += 1
        elif tag == "link" and attributes.get("rel") == "stylesheet":
            href = attributes.get("href")
            if href:
                self.stylesheets.append(href)


def main() -> int:
    template = resource_file("web", "index.html").read_text(encoding="utf-8")
    script = resource_file("web", "app.js").read_text(encoding="utf-8")
    stylesheet = resource_file("web", "app.css").read_text(encoding="utf-8")
    rendered = render_index("quality-check-token")
    parser = _WebResourceParser()
    parser.feed(rendered)

    expected_placeholders = {
        "{{CSRF_TOKEN_ATTR}}",
        "{{THREAT_PROFILES_ATTR}}",
        "{{THREAT_OPTIONS}}",
    }
    present_placeholders = {
        placeholder for placeholder in expected_placeholders if placeholder in template
    }
    if present_placeholders != expected_placeholders:
        missing = sorted(expected_placeholders - present_placeholders)
        raise SystemExit(f"Missing web template placeholders: {', '.join(missing)}")
    if "{{" in rendered or "}}" in rendered:
        raise SystemExit("Rendered TraceQuarry page contains unresolved placeholders.")
    if parser.inline_scripts or parser.inline_styles:
        raise SystemExit(
            "TraceQuarry web resources must not embed script or style blocks."
        )
    if not any(path.startswith("/static/app.js") for path in parser.external_scripts):
        raise SystemExit("TraceQuarry page does not load the packaged JavaScript.")
    if not any(path.startswith("/static/app.css") for path in parser.stylesheets):
        raise SystemExit("TraceQuarry page does not load the packaged stylesheet.")
    if "quality-check-token" not in rendered:
        raise SystemExit("TraceQuarry request token was not rendered.")
    if "new URLSearchParams(body)" not in script:
        raise SystemExit("Web control requests must use bounded URL-encoded metadata.")
    drag_drop_markers = {
        'id="evidence-drop"',
        'id="upload-selection"',
        "uploadDrop.addEventListener('dragenter'",
        "uploadDrop.addEventListener('drop'",
        "selectedUploadFiles",
        "new DataTransfer()",
    }
    combined = template + script
    missing_drag_drop = sorted(
        marker for marker in drag_drop_markers if marker not in combined
    )
    if missing_drag_drop:
        raise SystemExit(
            "TraceQuarry drag-and-drop upload controls are incomplete: "
            + ", ".join(missing_drag_drop)
        )
    previous_case_markers = {
        'id="previous-case-trigger"',
        'role="combobox"',
        'id="previous-case-menu"',
        'role="listbox"',
        "openPreviousCaseMenu",
        "focusAdjacentCaseOption",
    }
    missing_previous_case = sorted(
        marker for marker in previous_case_markers if marker not in combined
    )
    if missing_previous_case:
        raise SystemExit(
            "TraceQuarry previous-case combobox is incomplete: "
            + ", ".join(missing_previous_case)
        )
    if len(script) < 10_000 or len(stylesheet) < 10_000:
        raise SystemExit("TraceQuarry web assets appear incomplete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
