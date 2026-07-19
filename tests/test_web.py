import http.client
import json
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from uac_parser import web
from uac_parser.web import (
    JOBS,
    JOBS_LOCK,
    SERVER_CONFIG,
    _is_loopback_authority,
    _is_loopback_origin,
    _save_annotation,
    _timeline_page,
    _utc_iso_to_local_value,
    render_index,
)


class WebTests(unittest.TestCase):
    def test_inspected_window_preserves_seconds(self) -> None:
        value = _utc_iso_to_local_value("2026-06-16T10:01:40Z", "Asia/Hong_Kong")

        self.assertEqual(value, "2026-06-16T18:01:40")

    def test_assisted_investigation_selector_and_timeline_are_rendered(self) -> None:
        page = render_index()

        self.assertIn('name="threat_type"', page)
        self.assertIn('value="ransomware_extortion"', page)
        self.assertIn("Prioritizes evidence and analyst pivots", page)
        self.assertIn("Explore Timeline", page)
        self.assertIn("Raw evidence", page)
        self.assertIn("/assets/cep-mark.svg", page)
        self.assertNotIn("cep-lockup.svg", page)
        self.assertIn("X-TraceQuarry-CSRF", page)
        self.assertNotIn("fonts.googleapis.com", page)

    def test_loopback_authority_and_origin_validation(self) -> None:
        self.assertTrue(_is_loopback_authority("127.0.0.1:8765", 8765))
        self.assertTrue(_is_loopback_authority("[::1]:8765", 8765))
        self.assertFalse(_is_loopback_authority("attacker.example:8765", 8765))
        self.assertFalse(_is_loopback_authority("127.0.0.1:9999", 8765))
        self.assertTrue(_is_loopback_origin("http://localhost:8765", 8765))
        self.assertFalse(_is_loopback_origin("https://attacker.example", 8765))

    def test_remote_bind_is_refused_even_with_legacy_flag(self) -> None:
        with self.assertRaisesRegex(SystemExit, "Refusing non-loopback bind"):
            web.main(["--host", "0.0.0.0", "--allow-remote"])

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
                    "tags": ["valid_account"],
                },
                {
                    "event_id": "evt_def456",
                    "timestamp": "2026-07-10T01:30:00Z",
                    "severity": "medium",
                    "source_type": "shell_history",
                    "summary": "Archive created",
                    "raw": "tar -czf /tmp/data.tar.gz /srv/data",
                    "tags": ["archive"],
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
            SERVER_CONFIG["work_dir"] = work_dir
            with JOBS_LOCK:
                JOBS["abc123def456"] = {
                    "id": "abc123def456",
                    "status": "complete",
                    "output": str(output),
                }
            try:
                page = _timeline_page(
                    "abc123def456", {"q": ["root"], "severity": ["high"]}
                )
                self.assertEqual(page["total"], 1)
                self.assertEqual(page["items"][0]["event_id"], "evt_abc123")

                saved = _save_annotation(
                    "abc123def456",
                    {
                        "event_id": "evt_abc123",
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
                self.assertNotIn("analyst_annotation", timeline.read_text())
                refreshed = _timeline_page("abc123def456", {"q": ["root"]})
                self.assertEqual(
                    refreshed["items"][0]["analyst_annotation"]["disposition"],
                    "malicious",
                )
            finally:
                with JOBS_LOCK:
                    JOBS.pop("abc123def456", None)


class WebSecurityIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temporary.name)
        (self.work_dir / "uploads").mkdir(mode=0o700)
        (self.work_dir / "outputs").mkdir(mode=0o700)
        SERVER_CONFIG.clear()
        SERVER_CONFIG.update(
            {
                "work_dir": self.work_dir,
                "max_request_bytes": 1024 * 1024,
                "max_work_bytes": 10 * 1024 * 1024,
                "request_timeout": 5,
                "debug": False,
            }
        )
        web.JOB_SLOTS = threading.BoundedSemaphore(1)
        self.server = web.HardenedThreadingHTTPServer(
            ("127.0.0.1", 0), web.UacWebHandler
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        web.JOB_SLOTS = None
        with JOBS_LOCK:
            JOBS.clear()
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
        with JOBS_LOCK:
            JOBS[job_id] = {"id": job_id, "status": "complete", "output": str(output)}

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
                "X-TraceQuarry-CSRF": web.CSRF_TOKEN,
            },
        )

        self.assertEqual(missing_status, 403)
        self.assertEqual(hostile_status, 403)

        hostile_host_status, _, _ = self.request(
            "GET", "/", headers={"Host": "attacker.example"}
        )
        self.assertEqual(hostile_host_status, 421)

    def test_oversized_request_is_rejected_before_processing(self) -> None:
        SERVER_CONFIG["max_request_bytes"] = 4
        status, _, body = self.request(
            "POST",
            "/api/run",
            body=b"12345",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-TraceQuarry-CSRF": web.CSRF_TOKEN,
            },
        )

        self.assertEqual(status, 413)
        self.assertIn(b"upload limit", body)

    def test_public_job_response_redacts_local_paths(self) -> None:
        job_id = "abc123def456"
        with JOBS_LOCK:
            JOBS[job_id] = {
                "id": job_id,
                "status": "complete",
                "input": "/sensitive/input.tar.gz",
                "output": "/sensitive/output",
                "options": {
                    "input_path": "/sensitive/input.tar.gz",
                    "timezone_name": "UTC",
                },
                "result": {"output": "/sensitive/output", "events": 1},
                "traceback": "/sensitive/source.py:1",
            }

        status, _, body = self.request("GET", f"/api/job/{job_id}")

        self.assertEqual(status, 200)
        self.assertNotIn(b"/sensitive", body)
        self.assertNotIn(b"traceback", body)
