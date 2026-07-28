import csv
import http.client
import io
import json
import stat
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from uac_parser import web
from uac_parser.resources import resource_file
from uac_parser.web import (
    APP_CONTEXT,
    _incident_briefing,
    _input_paths_from_form,
    _is_loopback_authority,
    _is_loopback_origin,
    _list_cases,
    _restore_completed_jobs,
    _save_annotation,
    _timeline_page,
    _utc_iso_to_local_value,
    render_index,
)
from uac_parser.web_runtime import WebSettings


def _configure_context(
    work_dir: Path,
    *,
    input_roots: tuple[Path, ...] | None = None,
    max_request_bytes: int = 1024 * 1024,
    max_work_bytes: int = 10 * 1024 * 1024,
    request_timeout: float = 5,
    debug: bool = False,
    state_retention_days: int = 90,
    max_concurrent_jobs: int | None = None,
) -> None:
    APP_CONTEXT.reset()
    APP_CONTEXT.configure(
        WebSettings(
            work_dir=work_dir,
            input_roots=input_roots or (work_dir.resolve(),),
            max_request_bytes=max_request_bytes,
            max_work_bytes=max_work_bytes,
            minimum_free_bytes=0,
            request_timeout=request_timeout,
            debug=debug,
            state_retention_days=state_retention_days,
        ),
        max_concurrent_jobs=max_concurrent_jobs,
    )


class WebTests(unittest.TestCase):
    def test_public_web_command_uses_tracequarry_brand(self) -> None:
        self.assertEqual(web.build_arg_parser().prog, "tracequarry-web")

    def test_server_side_inputs_are_limited_to_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "evidence"
            allowed.mkdir()
            collection = allowed / "host01"
            collection.mkdir()
            outside = root / "outside"
            outside.mkdir()
            escape = allowed / "escape"
            escape.symlink_to(outside, target_is_directory=True)
            _configure_context(root, input_roots=(allowed.resolve(),))

            try:
                paths = _input_paths_from_form({"input_path": str(collection)})
                self.assertEqual(paths, [str(collection.resolve())])
                with self.assertRaisesRegex(ValueError, "outside the allowed roots"):
                    _input_paths_from_form({"input_path": str(outside)})
                with self.assertRaisesRegex(ValueError, "outside the allowed roots"):
                    _input_paths_from_form({"input_path": str(escape)})
            finally:
                APP_CONTEXT.reset()

    def test_inspected_window_preserves_seconds(self) -> None:
        value = _utc_iso_to_local_value("2026-06-16T10:01:40Z", "Asia/Hong_Kong")

        self.assertEqual(value, "2026-06-16T18:01:40")

    def test_assisted_investigation_selector_and_timeline_are_rendered(self) -> None:
        page = render_index()
        script = resource_file("web", "app.js").read_text(encoding="utf-8")
        css = resource_file("web", "app.css").read_text(encoding="utf-8")
        combined = page + script

        self.assertIn('name="threat_type"', page)
        self.assertIn('value="ransomware_extortion"', page)
        self.assertIn("Prioritizes evidence and analyst pivots", page)
        self.assertIn("native Linux logs", page)
        self.assertIn("CaseWeave import", page)
        self.assertIn("<kbd>tracequarry</kbd>", page)
        self.assertNotIn("CaseWave", page)
        self.assertIn("Explore Timeline", page)
        self.assertIn("Incident Briefing", page)
        self.assertIn('id="timeline-phase"', page)
        self.assertIn('id="timeline-summary"', page)
        self.assertIn("Include in reconstructed summary", script)
        self.assertIn("Raw evidence", combined)
        self.assertIn("/assets/cep-mark.svg", page)
        self.assertNotIn("cep-lockup.svg", page)
        self.assertIn("X-TraceQuarry-CSRF", script)
        self.assertIn("--input-root", page)
        self.assertIn(
            "metrics['Total parsed events'] || metrics['Total events']", script
        )
        self.assertIn("Previous cases", page)
        self.assertIn('id="previous-case-trigger"', page)
        self.assertIn('role="combobox"', page)
        self.assertIn('id="previous-case-menu"', page)
        self.assertIn('role="listbox"', page)
        self.assertIn("openPreviousCaseMenu", script)
        self.assertIn("focusAdjacentCaseOption", script)
        self.assertIn("Export Timeline CSV", page)
        self.assertIn("Export Investigation XLSX", page)
        self.assertIn('name="theme-color" content="#0E1626"', page)
        self.assertIn("investigation.xlsx", script)
        self.assertIn("Cybersecurity incident executive briefing", script)
        self.assertIn("credential_harvesting", script)
        self.assertIn("copied `/var/log` tree", page)
        self.assertIn("Collection queue", page)
        self.assertIn("/api/upload/session", script)
        self.assertIn("XMLHttpRequest", script)
        self.assertIn('id="evidence-drop"', page)
        self.assertIn('id="upload-selection"', page)
        self.assertIn("uploadDrop.addEventListener('dragenter'", script)
        self.assertIn("uploadDrop.addEventListener('drop'", script)
        self.assertIn("selectedUploadFiles", script)
        self.assertIn("new DataTransfer()", script)
        self.assertIn("duplicate(s) skipped", script)
        self.assertIn("Staged", combined)
        self.assertIn("Parsing", combined)
        self.assertNotIn("fonts.googleapis.com", page)
        self.assertIn("/static/app.css", page)
        self.assertIn("/static/app.js", page)
        self.assertNotIn("<style", page)
        self.assertNotIn("<script>", page)
        self.assertNotIn("#275b87", css.lower())
        self.assertNotIn("#347db8", css.lower())

    def test_completed_case_is_restored_from_output_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            output = work_dir / "outputs" / "abc123def456"
            output.mkdir(parents=True)
            (output / "summary.md").write_text("# Restored\n", encoding="utf-8")
            (output / "timeline_full.jsonl").write_text(
                json.dumps({"event_id": "evt_restore"}) + "\n", encoding="utf-8"
            )
            (output / "run_manifest.json").write_text(
                json.dumps(
                    {
                        "created_at": "2026-07-21T10:00:00Z",
                        "collection_name": "Restored host",
                        "settings": {"timezone": "UTC"},
                        "coverage": {"events": 1},
                    }
                ),
                encoding="utf-8",
            )
            _configure_context(work_dir)
            web._register_job(
                {
                    "id": "abc123def456",
                    "status": "interrupted",
                    "job_type": "analysis",
                    "output": str(output),
                    "case_name": "Interrupted metadata",
                }
            )
            try:
                restored = _restore_completed_jobs(work_dir)
                cases = _list_cases()

                self.assertEqual(restored, 1)
                self.assertEqual(cases[0]["id"], "abc123def456")
                self.assertEqual(cases[0]["case_name"], "Restored host")
                self.assertEqual(cases[0]["result"]["events"], 1)
            finally:
                APP_CONTEXT.reset()

    def test_incomplete_job_is_durably_marked_interrupted_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            _configure_context(work_dir, state_retention_days=30)
            web._register_job(
                {
                    "id": "abc123def456",
                    "status": "running",
                    "stage": "parsing",
                    "progress": 51,
                    "created_at": time.time() - 10,
                    "input": "/sensitive/evidence.tar.gz",
                    "case_name": "Interrupted case",
                }
            )
            self.assertTrue((work_dir / "state" / "cases.sqlite3").is_file())
            stored = APP_CONTEXT.cases.get("abc123def456") or {}
            self.assertNotIn("input", stored)
            self.assertNotIn("/sensitive/evidence.tar.gz", json.dumps(stored))
            APP_CONTEXT.cases.reset()

            restored = web._restore_persisted_jobs()
            job = web.get_job("abc123def456")

            self.assertEqual(restored, 1)
            self.assertEqual(job["status"], "interrupted")
            self.assertEqual(job["stage"], "interrupted")
            self.assertTrue(job["restored"])
            APP_CONTEXT.reset()

    def test_loopback_authority_and_origin_validation(self) -> None:
        self.assertTrue(_is_loopback_authority("127.0.0.1:8765", 8765))
        self.assertTrue(_is_loopback_authority("[::1]:8765", 8765))
        self.assertFalse(_is_loopback_authority("attacker.example:8765", 8765))
        self.assertFalse(_is_loopback_authority("127.0.0.1:9999", 8765))
        self.assertTrue(_is_loopback_origin("http://localhost:8765", 8765))
        self.assertFalse(_is_loopback_origin("https://attacker.example", 8765))

    def test_container_public_port_remains_loopback_only(self) -> None:
        with mock.patch.dict(
            web.os.environ,
            {"TRACEQUARRY_CONTAINER": "1", "TRACEQUARRY_PUBLIC_PORT": "18765"},
        ):
            self.assertTrue(_is_loopback_authority("127.0.0.1:18765", 8765))
            self.assertTrue(_is_loopback_origin("http://localhost:18765", 8765))
            self.assertFalse(_is_loopback_authority("analyst.example:18765", 8765))
            self.assertFalse(_is_loopback_origin("https://analyst.example:18765", 8765))

    def test_remote_bind_is_refused_even_with_legacy_flag(self) -> None:
        with self.assertRaisesRegex(SystemExit, "Refusing non-loopback bind"):
            web.main(["--host", "0.0.0.0", "--allow-remote"])

    def test_container_bind_requires_packaged_container_marker(self) -> None:
        with mock.patch.dict(web.os.environ, {}, clear=True):
            self.assertFalse(web._is_packaged_container_bind("0.0.0.0", True))
        with mock.patch.dict(web.os.environ, {"TRACEQUARRY_CONTAINER": "1"}):
            self.assertTrue(web._is_packaged_container_bind("0.0.0.0", True))
            self.assertFalse(web._is_packaged_container_bind("0.0.0.0", False))
            self.assertFalse(web._is_packaged_container_bind("192.0.2.10", True))

    def test_timeline_preview_filters_and_saves_separate_annotations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            output = work_dir / "outputs" / "abc123def456"
            output.mkdir(parents=True)
            events = [
                {
                    "event_id": "evt_abc123",
                    "timestamp": "2026-07-10T01:25:00Z",
                    "severity": "high",
                    "source_type": "auth_log",
                    "summary": "Successful root login",
                    "raw": "Accepted password for root from 198.51.100.50",
                    "tags": ["valid_account", "initial_access"],
                    "mitre": ["T1078"],
                },
                {
                    "event_id": "evt_def456",
                    "timestamp": "2026-07-10T01:30:00Z",
                    "severity": "medium",
                    "source_type": "shell_history",
                    "summary": "Archive created",
                    "raw": "tar -czf /tmp/data.tar.gz /srv/data",
                    "tags": ["archive"],
                    "mitre": ["T1560.001"],
                },
            ]
            timeline = output / "timeline_mini.jsonl"
            timeline.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )
            (output / "timeline_full.jsonl").write_text(
                timeline.read_text(), encoding="utf-8"
            )
            _configure_context(work_dir)
            web._register_job(
                {
                    "id": "abc123def456",
                    "status": "complete",
                    "output": str(output),
                }
            )
            try:
                page = _timeline_page(
                    "abc123def456", {"q": ["root"], "severity": ["high"]}
                )
                self.assertEqual(page["total"], 1)
                self.assertEqual(page["items"][0]["event_id"], "evt_abc123")
                self.assertIn("initial_access", page["items"][0]["attack_phases"])

                phase_page = _timeline_page(
                    "abc123def456", {"attack_phase": ["initial_access"]}
                )
                self.assertEqual(phase_page["total"], 1)

                saved = _save_annotation(
                    "abc123def456",
                    {
                        "event_id": "evt_abc123",
                        "include_in_summary": True,
                        "disposition": "malicious",
                        "tags": ["Confirmed Access", "escalate"],
                        "note": "Validated against the raw authentication record.",
                    },
                )
                self.assertTrue(saved["saved"])
                annotation_doc = json.loads(
                    (output / "analyst_annotations.json").read_text()
                )
                self.assertEqual(
                    stat.S_IMODE((output / "analyst_annotations.json").stat().st_mode),
                    0o600,
                )
                self.assertEqual(
                    annotation_doc["annotations"]["evt_abc123"]["tags"],
                    ["confirmed_access", "escalate"],
                )
                self.assertTrue(
                    annotation_doc["annotations"]["evt_abc123"]["include_in_summary"]
                )
                self.assertNotIn("analyst_annotation", timeline.read_text())
                audit_path = output / "analyst_audit.jsonl"
                self.assertTrue(audit_path.is_file())
                self.assertEqual(
                    stat.S_IMODE(audit_path.stat().st_mode),
                    0o600,
                )
                self.assertTrue(web.audit_status(audit_path)["valid"])
                refreshed = _timeline_page("abc123def456", {"q": ["root"]})
                self.assertEqual(
                    refreshed["items"][0]["analyst_annotation"]["disposition"],
                    "malicious",
                )
                selected = _timeline_page("abc123def456", {"summary": ["selected"]})
                self.assertEqual(selected["total"], 1)
                briefing = _incident_briefing("abc123def456")
                self.assertEqual(briefing["metrics"]["selected_events"], 1)
                self.assertEqual(
                    briefing["selected_events"][0]["event_id"], "evt_abc123"
                )
                self.assertTrue(
                    any(
                        item["key"] == "initial_access" and item["selected_events"] == 1
                        for item in briefing["phase_breakdown"]
                    )
                )
            finally:
                APP_CONTEXT.reset()


class WebSecurityIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temporary.name)
        (self.work_dir / "uploads").mkdir(mode=0o700)
        (self.work_dir / "outputs").mkdir(mode=0o700)
        _configure_context(
            self.work_dir,
            max_concurrent_jobs=1,
        )
        self.server = web.HardenedThreadingHTTPServer(
            ("127.0.0.1", 0), web.UacWebHandler
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        APP_CONTEXT.reset()
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=5
        )
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        result = response.status, dict(response.getheaders()), payload
        connection.close()
        return result

    def test_output_route_rejects_encoded_absolute_job_id(self) -> None:
        status, _, body = self.request("GET", "/outputs/%2F/etc/passwd")

        self.assertEqual(status, 404)
        self.assertNotIn(b"root:", body)

    def test_completed_job_output_is_served_with_security_headers(self) -> None:
        job_id = "abc123def456"
        output = self.work_dir / "outputs" / job_id
        output.mkdir(mode=0o700)
        (output / "summary.md").write_text("# Synthetic\n", encoding="utf-8")
        web._register_job({"id": job_id, "status": "complete", "output": str(output)})

        status, headers, body = self.request("GET", f"/outputs/{job_id}/summary.md")

        self.assertEqual(status, 200)
        self.assertEqual(body, b"# Synthetic\n")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn("Python", headers["Server"])

        for unsafe_path in [
            f"/outputs/{job_id}/%2Fetc/passwd",
            f"/outputs/{job_id}/%2e%2e/%2e%2e/etc/passwd",
        ]:
            unsafe_status, _, unsafe_body = self.request("GET", unsafe_path)
            self.assertEqual(unsafe_status, 404)
            self.assertNotIn(b"root:", unsafe_body)

    def test_packaged_brand_asset_is_served(self) -> None:
        status, headers, body = self.request("GET", "/assets/cep-mark.svg")

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "image/svg+xml")
        self.assertIn(b"Chill Ethical People capybara mark", body)

    def test_packaged_web_assets_use_external_script_policy(self) -> None:
        page_status, page_headers, page = self.request("GET", "/")
        script_status, script_headers, script = self.request("GET", "/static/app.js")
        unsafe_status, _, _ = self.request("GET", "/static/%2e%2e/pyproject.toml")

        self.assertEqual(page_status, 200)
        self.assertEqual(script_status, 200)
        self.assertEqual(unsafe_status, 404)
        self.assertIn(b"/static/app.js", page)
        self.assertIn(b"X-TraceQuarry-CSRF", script)
        self.assertIn("javascript", script_headers["Content-Type"])
        policy = page_headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", policy)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", policy)

    def test_health_endpoint_reports_capacity_and_job_state(self) -> None:
        status, _, body = self.request("GET", "/api/health")
        payload = json.loads(body)

        self.assertEqual(status, 200)
        self.assertTrue(payload["ready"])
        self.assertEqual(payload["status"], "ok")
        self.assertIn("committed_bytes", payload["capacity"])
        self.assertIn("active_reservations", payload["capacity"])
        self.assertEqual(payload["case_repository"]["backend"], "sqlite")
        self.assertEqual(payload["case_repository"]["schema_version"], 2)
        self.assertNotIn(str(self.work_dir), body.decode("utf-8"))

    def test_expired_upload_session_is_rejected_and_purged(self) -> None:
        request_body = json.dumps(
            {"files": [{"name": "auth.log", "size": 200}]}
        ).encode("utf-8")
        status, _, body = self.request(
            "POST",
            "/api/upload/session",
            body=request_body,
            headers={
                "Content-Type": "application/json",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )
        session = json.loads(body)
        self.assertEqual(status, 201)
        session_dir = self.work_dir / session["staging_path"]
        manifest = session_dir / "upload_session.json"
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["expires_at"] = time.time() - 1
        manifest.write_text(json.dumps(document), encoding="utf-8")

        inspect_status, _, inspect_body = self.request(
            "GET", f"/api/upload/{session['upload_id']}"
        )
        removed = web._purge_stale_upload_sessions(self.work_dir)
        capacity = web._capacity_manager().snapshot()

        self.assertEqual(inspect_status, 404)
        self.assertIn(b"expired", inspect_body)
        self.assertEqual(removed, 1)
        self.assertFalse(session_dir.exists())
        self.assertEqual(capacity.reserved_bytes, 0)

    def test_run_endpoint_rejects_legacy_multipart_control_requests(self) -> None:
        status, _, body = self.request(
            "POST",
            "/api/run",
            body=b"--boundary--",
            headers={
                "Content-Type": "multipart/form-data; boundary=boundary",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )

        self.assertEqual(status, 400)
        self.assertIn(b"upload API", body)

    def test_post_requires_token_and_rejects_hostile_origin(self) -> None:
        body = b"input_path=/tmp/does-not-matter"
        base_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        missing_status, _, _ = self.request(
            "POST", "/api/run", body=body, headers=base_headers
        )
        hostile_status, _, _ = self.request(
            "POST",
            "/api/run",
            body=body,
            headers={
                **base_headers,
                "Origin": "https://attacker.example",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )

        self.assertEqual(missing_status, 403)
        self.assertEqual(hostile_status, 403)

        hostile_host_status, _, _ = self.request(
            "GET", "/", headers={"Host": "attacker.example"}
        )
        self.assertEqual(hostile_host_status, 421)

    def test_options_does_not_reflect_request_origin(self) -> None:
        allowed_origin = f"http://127.0.0.1:{self.server.server_port}"

        status, headers, _ = self.request(
            "OPTIONS", "/api/run", headers={"Origin": allowed_origin}
        )
        hostile_status, _, _ = self.request(
            "OPTIONS",
            "/api/run",
            headers={"Origin": "https://attacker.example"},
        )

        self.assertEqual(status, 204)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(hostile_status, 403)

    def test_oversized_request_is_rejected_before_processing(self) -> None:
        APP_CONTEXT.replace_settings(max_request_bytes=4)
        status, _, body = self.request(
            "POST",
            "/api/run",
            body=b"12345",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )

        self.assertEqual(status, 413)
        self.assertIn(b"metadata exceeds", body)

    def test_public_job_response_redacts_local_paths(self) -> None:
        job_id = "abc123def456"
        web._register_job(
            {
                "id": job_id,
                "status": "complete",
                "input": "/sensitive/input.tar.gz",
                "output": "/sensitive/output",
                "options": {
                    "input_path": "/sensitive/input.tar.gz",
                    "timezone_name": "UTC",
                },
                "result": {
                    "output": "/sensitive/output",
                    "host_outputs": ["/sensitive/output/hosts/host01"],
                    "events": 1,
                },
                "traceback": "/sensitive/source.py:1",
            }
        )

        status, _, body = self.request("GET", f"/api/job/{job_id}")

        self.assertEqual(status, 200)
        self.assertNotIn(b"/sensitive", body)
        self.assertNotIn(b"traceback", body)

    def test_review_csv_export_includes_saved_analyst_tags(self) -> None:
        job_id = "abc123def456"
        output = self.work_dir / "outputs" / job_id
        output.mkdir(mode=0o700)
        event = {
            "event_id": "evt_abc123",
            "timestamp": "2026-07-21T10:00:00Z",
            "severity": "high",
            "source_type": "auth_log",
            "summary": "Successful root login",
            "raw": "Accepted publickey for root from 192.0.2.10",
            "tags": ["valid_account"],
        }
        for name in ("timeline_full.jsonl", "timeline_mini.jsonl"):
            (output / name).write_text(json.dumps(event) + "\n", encoding="utf-8")
        (output / "analyst_annotations.json").write_text(
            json.dumps(
                {
                    "annotations": {
                        "evt_abc123": {
                            "disposition": "malicious",
                            "include_in_summary": True,
                            "tags": ["lateral_movement"],
                            "note": "Validated from the source record.",
                            "updated_at": "2026-07-21T10:05:00Z",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        web._register_job(
            {
                "id": job_id,
                "status": "complete",
                "output": str(output),
                "case_name": "Review export",
                "completed_at": 1,
            }
        )

        status, headers, body = self.request(
            "GET", f"/api/job/{job_id}/timeline.csv?scope=mini"
        )
        rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"))))

        self.assertEqual(status, 200)
        self.assertEqual(
            headers["Content-Disposition"],
            'attachment; filename="tracequarry-timeline.csv"',
        )
        self.assertEqual(rows[0]["analyst_disposition"], "malicious")
        self.assertEqual(rows[0]["summary_selection"], "Summary")
        self.assertEqual(rows[0]["analyst_tags"], "lateral_movement")
        self.assertEqual(rows[0]["analyst_note"], "Validated from the source record.")

        briefing_status, _, briefing_body = self.request(
            "GET", f"/api/job/{job_id}/briefing"
        )
        briefing = json.loads(briefing_body)
        self.assertEqual(briefing_status, 200)
        self.assertEqual(briefing["metrics"]["selected_events"], 1)
        self.assertEqual(briefing["selected_events"][0]["event_id"], "evt_abc123")

        workbook_status, workbook_headers, workbook_body = self.request(
            "GET", f"/api/job/{job_id}/investigation.xlsx?scope=full"
        )
        self.assertEqual(workbook_status, 200)
        self.assertEqual(
            workbook_headers["Content-Disposition"],
            'attachment; filename="tracequarry-investigation.xlsx"',
        )
        with zipfile.ZipFile(io.BytesIO(workbook_body)) as archive:
            workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
            self.assertIn("Executive Briefing", workbook_xml)
            self.assertIn("Selected Timeline", workbook_xml)
            self.assertIn("Timeline", workbook_xml)
            self.assertIn("Findings", workbook_xml)

    def test_staged_upload_session_accepts_150_files_and_reports_location(self) -> None:
        content = b"Jul 23 10:00:00 host sshd[1]: synthetic test record\n"
        files = [
            {"name": f"auth.log.{index:03d}", "size": len(content)}
            for index in range(150)
        ]
        request_body = json.dumps({"files": files}).encode("utf-8")
        status, _, body = self.request(
            "POST",
            "/api/upload/session",
            body=request_body,
            headers={
                "Content-Type": "application/json",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )
        session = json.loads(body)

        self.assertEqual(status, 201)
        self.assertEqual(session["file_count"], 150)
        self.assertRegex(session["staging_path"], r"^uploads/staged-[a-f0-9]{12}$")
        for index in range(150):
            upload_status, _, upload_body = self.request(
                "POST",
                f"/api/upload/{session['upload_id']}/{index}",
                body=content,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
                },
            )
            self.assertEqual(upload_status, 200, upload_body.decode("utf-8"))

        inspect_status, _, inspect_body = self.request(
            "GET", f"/api/upload/{session['upload_id']}"
        )
        completed = json.loads(inspect_body)
        staging_dir = self.work_dir / completed["staging_path"]

        self.assertEqual(inspect_status, 200)
        self.assertEqual(completed["status"], "ready")
        self.assertEqual(completed["completed_files"], 150)
        self.assertEqual(completed["uploaded_bytes"], len(content) * 150)
        staged_evidence = [
            path
            for path in staging_dir.rglob("*")
            if path.is_file() and path.name != "upload_session.json"
        ]
        self.assertEqual(len(staged_evidence), 150)
        self.assertTrue(
            all(path.name.startswith("auth.log.") for path in staged_evidence)
        )

    def test_upload_part_rejects_wrong_declared_size(self) -> None:
        request_body = json.dumps({"files": [{"name": "auth.log", "size": 10}]}).encode(
            "utf-8"
        )
        status, _, body = self.request(
            "POST",
            "/api/upload/session",
            body=request_body,
            headers={
                "Content-Type": "application/json",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )
        session = json.loads(body)
        self.assertEqual(status, 201)

        upload_status, _, upload_body = self.request(
            "POST",
            f"/api/upload/{session['upload_id']}/0",
            body=b"short",
            headers={
                "Content-Type": "application/octet-stream",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )

        self.assertEqual(upload_status, 400)
        self.assertIn(b"declared size", upload_body)

    def test_staged_archives_run_as_a_background_case_without_reupload(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        archive = self.work_dir / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(fixture, arcname="uac-synthetic-host")
        content = archive.read_bytes()
        request_body = json.dumps(
            {
                "files": [
                    {"name": "uac-host01.tar.gz", "size": len(content)},
                    {"name": "uac-host02.tar.gz", "size": len(content)},
                ]
            }
        ).encode()
        status, _, body = self.request(
            "POST",
            "/api/upload/session",
            body=request_body,
            headers={
                "Content-Type": "application/json",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )
        session = json.loads(body)
        self.assertEqual(status, 201)
        for index in range(2):
            upload_status, _, upload_body = self.request(
                "POST",
                f"/api/upload/{session['upload_id']}/{index}",
                body=content,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
                },
            )
            self.assertEqual(upload_status, 200, upload_body.decode())

        run_body = (
            f"staged_upload_id={session['upload_id']}&year=2026&timezone=UTC&"
            "case_name=Staged+Case"
        ).encode()
        run_status, _, run_response = self.request(
            "POST",
            "/api/run",
            body=run_body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )
        accepted = json.loads(run_response)
        self.assertEqual(run_status, 200, accepted)
        for _ in range(160):
            poll_status, _, poll_body = self.request(
                "GET", f"/api/job/{accepted['job_id']}"
            )
            job = json.loads(poll_body)
            if job.get("status") not in {"queued", "running"}:
                break
            threading.Event().wait(0.05)

        self.assertEqual(poll_status, 200)
        self.assertEqual(job["status"], "complete", job)
        self.assertEqual(job["job_type"], "analysis")
        self.assertEqual(job["result"]["collections"], 2)
        self.assertTrue(
            all(item["status"] == "complete" for item in job["collections"])
        )
        self.assertRegex(job["staging_path"], r"^uploads/staged-[a-f0-9]{12}$")
        output_dir = self.work_dir / "outputs" / accepted["job_id"]
        self.assertTrue((output_dir / "case_timeline_full.csv").is_file())
        self.assertTrue((output_dir / "case_summary.md").is_file())
        self.assertEqual(len(list((output_dir / "hosts").iterdir())), 2)

    def test_inspection_returns_a_background_job_with_collection_progress(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "uac_sample"
        APP_CONTEXT.replace_settings(input_roots=(fixture.parent.resolve(),))
        request_body = (
            f"input_path={fixture.resolve()}&timezone=UTC&year=2026"
        ).encode()
        status, _, body = self.request(
            "POST",
            "/api/inspect",
            body=request_body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-TraceQuarry-CSRF": APP_CONTEXT.csrf_token,
            },
        )
        accepted = json.loads(body)

        self.assertEqual(status, 202)
        self.assertRegex(accepted["job_id"], r"^[a-f0-9]{12}$")
        for _ in range(100):
            poll_status, _, poll_body = self.request(
                "GET", f"/api/job/{accepted['job_id']}"
            )
            job = json.loads(poll_body)
            if job.get("status") not in {"queued", "running"}:
                break
            threading.Event().wait(0.05)

        self.assertEqual(poll_status, 200)
        self.assertEqual(job["status"], "complete", job)
        self.assertEqual(job["job_type"], "inspection")
        self.assertEqual(job["collections"][0]["status"], "complete")
        self.assertGreater(job["result"]["events"], 0)
        self.assertNotIn(str(fixture.parent), json.dumps(job))
