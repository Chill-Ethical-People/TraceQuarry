from __future__ import annotations

import argparse
import cgi
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import shutil
import threading
import time
import traceback
import uuid
from datetime import UTC, datetime, tzinfo
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from uac_parser import __version__
from uac_parser.assist import profile_choices
from uac_parser.enrich.iocs import parse_ioc_text
from uac_parser.pipeline import (
    CasePipelineResult,
    PipelineResult,
    inspect_time_range,
    run_case_pipeline,
    run_pipeline,
)
from uac_parser.resources import resource_directory

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
ANNOTATIONS_LOCK = threading.Lock()
SERVER_CONFIG: dict[str, Any] = {}
CSRF_TOKEN = secrets.token_urlsafe(32)
JOB_SLOTS: threading.BoundedSemaphore | None = None
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_MAX_UPLOAD_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_WORK_BYTES = 40 * 1024 * 1024 * 1024
MIN_FREE_BYTES = 512 * 1024 * 1024
JOB_ID_PATTERN = re.compile(r"[a-f0-9]{12}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uac-timeline-web",
        description="Run the TraceQuarry web GUI.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8765, help="Bind port")
    parser.add_argument(
        "--work-dir",
        default="web_runs",
        help="Directory for uploaded inputs and parser outputs",
    )
    parser.add_argument("--allow-remote", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--max-upload-gib",
        type=float,
        default=8,
        help="Maximum HTTP upload size in GiB (default: 8)",
    )
    parser.add_argument(
        "--max-work-dir-gib",
        type=float,
        default=40,
        help="Maximum work-directory size in GiB (default: 40)",
    )
    parser.add_argument(
        "--max-concurrent-jobs",
        type=int,
        default=2,
        help="Maximum simultaneous inspect/parse jobs (default: 2)",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=120,
        help="Socket timeout per HTTP request in seconds (default: 120)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Include detailed parser errors in local job responses",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    global JOB_SLOTS
    args = build_arg_parser().parse_args(argv)
    if args.host not in LOOPBACK_HOSTS:
        raise SystemExit(
            "Refusing non-loopback bind. Use an authenticated local tunnel or reverse proxy instead; "
            "TraceQuarry does not expose its evidence API directly to a network."
        )
    if args.max_upload_gib <= 0 or args.max_work_dir_gib <= 0:
        raise SystemExit("Upload and work-directory limits must be positive.")
    if args.max_concurrent_jobs < 1:
        raise SystemExit("At least one concurrent job slot is required.")
    if args.request_timeout < 5:
        raise SystemExit("Request timeout must be at least five seconds.")
    os.umask(0o077)
    work_dir = Path(args.work_dir).expanduser().resolve()
    _secure_directory(work_dir)
    _secure_directory(work_dir / "uploads")
    _secure_directory(work_dir / "outputs")
    SERVER_CONFIG.update(
        {
            "work_dir": work_dir,
            "max_request_bytes": int(args.max_upload_gib * 1024**3),
            "max_work_bytes": int(args.max_work_dir_gib * 1024**3),
            "request_timeout": args.request_timeout,
            "debug": args.debug,
        }
    )
    JOB_SLOTS = threading.BoundedSemaphore(args.max_concurrent_jobs)
    server = HardenedThreadingHTTPServer((args.host, args.port), UacWebHandler)
    print(f"TraceQuarry GUI listening on http://{args.host}:{args.port}")
    print(f"Work directory: {work_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping GUI server")
    finally:
        server.server_close()
    return 0


class HardenedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = True


def _work_dir() -> Path:
    value = SERVER_CONFIG.get("work_dir")
    if not isinstance(value, Path):
        raise RuntimeError("TraceQuarry work directory is not configured.")
    return value


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _is_loopback_authority(authority: str, server_port: int) -> bool:
    if not authority:
        return False
    try:
        parsed = urlparse(f"//{authority}")
        port = parsed.port
    except ValueError:
        return False
    return parsed.hostname in LOOPBACK_HOSTS and (port is None or port == server_port)


def _is_loopback_origin(origin: str, server_port: int) -> bool:
    try:
        parsed = urlparse(origin)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname in LOOPBACK_HOSTS
        and port == server_port
    )


def _acquire_job_slot() -> bool:
    return JOB_SLOTS is not None and JOB_SLOTS.acquire(blocking=False)


def _release_job_slot() -> None:
    if JOB_SLOTS is not None:
        JOB_SLOTS.release()


def _directory_size(path: Path) -> int:
    total = 0
    for candidate in path.rglob("*"):
        try:
            if candidate.is_file() and not candidate.is_symlink():
                total += candidate.stat().st_size
        except OSError:
            continue
    return total


def _ensure_work_capacity(work_dir: Path, incoming_bytes: int) -> None:
    max_work_bytes = int(SERVER_CONFIG.get("max_work_bytes", DEFAULT_MAX_WORK_BYTES))
    if _directory_size(work_dir) + incoming_bytes > max_work_bytes:
        raise ValueError("TraceQuarry work-directory quota would be exceeded.")
    if shutil.disk_usage(work_dir).free < incoming_bytes + MIN_FREE_BYTES:
        raise ValueError(
            "Insufficient free disk space for this request and the evidence safety reserve."
        )


def _public_error(exc: Exception) -> str:
    if isinstance(exc, ValueError) or SERVER_CONFIG.get("debug"):
        return str(exc)
    return "TraceQuarry could not process the request. Review the local server log for details."


class UacWebHandler(BaseHTTPRequestHandler):
    server_version = f"TraceQuarryWeb/{__version__}"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(float(SERVER_CONFIG.get("request_timeout", 120)))

    def version_string(self) -> str:
        return self.server_version

    def end_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            ),
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()

    def _admit_request(self, *, state_changing: bool = False) -> bool:
        server_port = cast(HardenedThreadingHTTPServer, self.server).server_port
        if not _is_loopback_authority(self.headers.get("Host", ""), server_port):
            self._send_json({"error": "Untrusted Host header."}, status=421)
            return False
        if not state_changing:
            return True
        origin = self.headers.get("Origin", "").strip()
        if origin and not _is_loopback_origin(origin, server_port):
            self._send_json(
                {"error": "Cross-origin requests are not permitted."}, status=403
            )
            return False
        supplied = self.headers.get("X-TraceQuarry-CSRF", "")
        if not supplied or not hmac.compare_digest(supplied, CSRF_TOKEN):
            self._send_json({"error": "Missing or invalid request token."}, status=403)
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._admit_request():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(render_index(CSRF_TOKEN))
            return
        timeline_match = re.fullmatch(r"/api/job/([a-f0-9]{12})/timeline", parsed.path)
        if timeline_match:
            try:
                self._send_json(
                    _timeline_page(timeline_match.group(1), parse_qs(parsed.query))
                )
            except (ValueError, FileNotFoundError) as exc:
                self._send_json({"error": str(exc)}, status=404)
            return
        job_match = re.fullmatch(r"/api/job/([a-f0-9]{12})", parsed.path)
        if job_match:
            job = get_job(job_match.group(1))
            self._send_json(job, status=404 if "error" in job else 200)
            return
        if parsed.path.startswith("/outputs/"):
            self._serve_output(parsed.path)
            return
        if parsed.path.startswith("/assets/"):
            self._serve_project_asset(parsed.path)
            return
        if parsed.path == "/favicon.svg":
            self._serve_project_asset("/assets/tracequarry-favicon.svg")
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._admit_request(state_changing=True):
            return
        parsed = urlparse(self.path)
        annotation_match = re.fullmatch(
            r"/api/job/([a-f0-9]{12})/annotations", parsed.path
        )
        if annotation_match:
            try:
                payload = self._parse_json_body(max_bytes=16 * 1024)
                result = _save_annotation(annotation_match.group(1), payload)
                self._send_json(result)
            except (ValueError, FileNotFoundError) as exc:
                self._send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/inspect":
            self._handle_inspect()
            return
        if parsed.path != "/api/run":
            self.send_error(404)
            return
        if not _acquire_job_slot():
            self._send_json(
                {
                    "error": "TraceQuarry is at its concurrent analysis limit. Try again shortly."
                },
                status=429,
            )
            return
        slot_transferred = False
        try:
            fields, uploaded_files = self._parse_form()
            job_id = uuid.uuid4().hex[:12]
            work_dir = _work_dir()
            output_dir = work_dir / "outputs" / job_id
            upload_dir = work_dir / "uploads" / job_id
            _secure_directory(upload_dir)

            input_paths = _input_paths_from_form(fields, uploaded_files, upload_dir)
            if not input_paths:
                self._send_json(
                    {
                        "error": "Choose a UAC archive/directory or provide a server-side input path."
                    },
                    status=400,
                )
                return
            timezone_name = fields.get("timezone", "UTC").strip() or "UTC"
            is_case = len(input_paths) > 1

            options: dict[str, Any] = {
                "input_path": input_paths[0],
                "input_paths": input_paths,
                "is_case": is_case,
                "output_dir": str(output_dir),
                "incident_start": _normalize_datetime_input(
                    fields.get("incident_start", ""), timezone_name
                ),
                "incident_end": _normalize_datetime_input(
                    fields.get("incident_end", ""), timezone_name
                ),
                "year": _parse_int(fields.get("year", "")),
                "timezone_name": timezone_name,
                "host": fields.get("host", "").strip(),
                "iocs": parse_ioc_text(fields.get("iocs", "")),
                "case_name": fields.get("case_name", "").strip() or "TraceQuarry Case",
                "threat_type": fields.get("threat_type", "").strip(),
            }
            with JOBS_LOCK:
                JOBS[job_id] = {
                    "id": job_id,
                    "status": "queued",
                    "created_at": time.time(),
                    "input": input_paths[0],
                    "inputs": input_paths,
                    "is_case": is_case,
                    "output": str(output_dir),
                    "options": {
                        key: value
                        for key, value in options.items()
                        if key not in {"iocs"}
                    }
                    | {"ioc_count": len(options["iocs"])},
                }
            thread = threading.Thread(
                target=_run_job, args=(job_id, options), daemon=True
            )
            thread.start()
            slot_transferred = True
            self._send_json({"job_id": job_id, "status_url": f"/api/job/{job_id}"})
        except ValueError as exc:
            status = 413 if "exceeds" in str(exc).lower() else 400
            self._send_json({"error": str(exc)}, status=status)
        except Exception as exc:
            self._send_json({"error": _public_error(exc)}, status=500)
        finally:
            if not slot_transferred:
                _release_job_slot()

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self._admit_request():
            return
        origin = self.headers.get("Origin", "").strip()
        server_port = cast(HardenedThreadingHTTPServer, self.server).server_port
        if origin and not _is_loopback_origin(origin, server_port):
            self._send_json(
                {"error": "Cross-origin requests are not permitted."}, status=403
            )
            return
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Origin", origin or f"http://127.0.0.1:{server_port}"
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, X-TraceQuarry-CSRF"
        )
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def _handle_inspect(self) -> None:
        if not _acquire_job_slot():
            self._send_json(
                {
                    "error": "TraceQuarry is at its concurrent analysis limit. Try again shortly."
                },
                status=429,
            )
            return
        try:
            fields, uploaded_files = self._parse_form()
            inspect_id = uuid.uuid4().hex[:12]
            work_dir = _work_dir()
            upload_dir = work_dir / "uploads" / f"inspect-{inspect_id}"
            _secure_directory(upload_dir)
            input_paths = _input_paths_from_form(fields, uploaded_files, upload_dir)
            if not input_paths:
                self._send_json(
                    {
                        "error": "Choose a UAC archive/directory or provide a server-side input path."
                    },
                    status=400,
                )
                return
            timezone_name = fields.get("timezone", "UTC").strip() or "UTC"
            result = _inspect_inputs(input_paths, fields, timezone_name)
            data = result
            data["timezone"] = timezone_name
            data["earliest_local"] = _utc_iso_to_local_value(
                data.get("earliest"), timezone_name
            )
            data["latest_local"] = _utc_iso_to_local_value(
                data.get("latest"), timezone_name
            )
            data["earliest_display"] = _utc_iso_to_display(
                data.get("earliest"), timezone_name
            )
            data["latest_display"] = _utc_iso_to_display(
                data.get("latest"), timezone_name
            )
            self._send_json(data)
        except ValueError as exc:
            status = 413 if "exceeds" in str(exc).lower() else 400
            self._send_json({"error": str(exc)}, status=status)
        except Exception as exc:
            self._send_json({"error": _public_error(exc)}, status=500)
        finally:
            _release_job_slot()

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")

    def _parse_form(self) -> tuple[dict[str, str], list[cgi.FieldStorage]]:
        content_type = self.headers.get("Content-Type", "")
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Streaming request bodies are not supported.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header.") from exc
        max_request_bytes = int(
            SERVER_CONFIG.get("max_request_bytes", DEFAULT_MAX_UPLOAD_BYTES)
        )
        if length <= 0:
            raise ValueError("A non-empty request body is required.")
        if length > max_request_bytes:
            raise ValueError(
                f"Request exceeds the {max_request_bytes / 1024**3:g} GiB local upload limit."
            )
        _ensure_work_capacity(_work_dir(), length)
        if content_type.startswith("multipart/form-data"):
            form = cgi.FieldStorage(
                fp=cast(Any, self.rfile),
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                },
            )
            fields: dict[str, str] = {}
            uploaded_files: list[cgi.FieldStorage] = []
            for key in form:
                item = form[key]
                items = item if isinstance(item, list) else [item]
                if key == "uac_file":
                    uploaded_files.extend(
                        upload for upload in items if getattr(upload, "filename", None)
                    )
                    continue
                if items and getattr(items[0], "value", None) is not None:
                    fields[key] = str(items[0].value)
            return fields, uploaded_files
        body = self.rfile.read(length).decode("utf-8", "replace")
        parsed = parse_qs(body)
        return {key: values[0] if values else "" for key, values in parsed.items()}, []

    def _parse_json_body(self, *, max_bytes: int) -> dict[str, Any]:
        content_type = (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/json":
            raise ValueError("Annotation requests require application/json.")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > max_bytes:
            raise ValueError("Invalid annotation request size.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Annotation request must be valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValueError("Annotation request must be a JSON object.")
        return payload

    def _serve_output(self, path: str) -> None:
        parts = [unquote(part) for part in path.split("/") if part]
        if len(parts) < 3:
            self.send_error(404)
            return
        _, job_id, *rest = parts
        if not JOB_ID_PATTERN.fullmatch(job_id):
            self.send_error(404)
            return
        try:
            output_root = _job_output_dir(job_id)
        except FileNotFoundError:
            self.send_error(404)
            return
        target = (output_root / Path(*rest)).resolve()
        if (
            not target.is_relative_to(output_root)
            or not target.exists()
            or not target.is_file()
        ):
            self.send_error(404)
            return
        content_type = (
            mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        )
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(target.stat().st_size))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()
        with target.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile)

    def _serve_project_asset(self, path: str) -> None:
        parts = [unquote(part) for part in path.split("/") if part]
        if not parts or parts[0] != "assets":
            self.send_error(404)
            return
        asset_root = resource_directory("assets").resolve()
        target = (asset_root / Path(*parts[1:])).resolve()
        if (
            not target.is_relative_to(asset_root)
            or not target.exists()
            or not target.is_file()
        ):
            self.send_error(404)
            return
        content_type = (
            mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        )
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(target.stat().st_size))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        with target.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile)

    def _send_html(self, body: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, data: object, status: int = 200) -> None:
        encoded = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()
        self.wfile.write(encoded)


def _run_job(job_id: str, options: dict[str, Any]) -> None:
    _update_job(
        job_id, status="running", stage="parsing", progress=18, started_at=time.time()
    )
    try:

        def report_progress(payload: dict[str, Any]) -> None:
            total = max(1, int(payload.get("total") or 1))
            completed = int(payload.get("completed") or 0)
            collection_total = max(1, int(payload.get("collection_total") or 1))
            collection_index = max(1, int(payload.get("collection_index") or 1))
            overall = ((collection_index - 1) + (completed / total)) / collection_total
            _update_job(
                job_id,
                stage=str(payload.get("stage") or "parsing_sources"),
                progress=min(86, 12 + round(overall * 72)),
                progress_detail=payload,
            )

        result: CasePipelineResult | PipelineResult
        if options.get("is_case"):
            result = run_case_pipeline(
                list(options["input_paths"]),
                options["output_dir"],
                incident_start=options["incident_start"],
                incident_end=options["incident_end"],
                year=options["year"],
                timezone_name=options["timezone_name"],
                host=options["host"],
                iocs=options["iocs"],
                case_name=str(options.get("case_name") or "TraceQuarry Case"),
                threat_type=str(options.get("threat_type") or ""),
                progress_callback=report_progress,
            )
        else:
            result = run_pipeline(
                options["input_path"],
                options["output_dir"],
                incident_start=options["incident_start"],
                incident_end=options["incident_end"],
                year=options["year"],
                timezone_name=options["timezone_name"],
                host=options["host"],
                iocs=options["iocs"],
                threat_type=str(options.get("threat_type") or ""),
                progress_callback=report_progress,
            )
        _update_job(job_id, stage="writing_outputs", progress=86)
        _update_job(
            job_id,
            status="complete",
            stage="complete",
            progress=100,
            completed_at=time.time(),
            result=result.to_dict(),
            outputs=_list_outputs(Path(options["output_dir"]), job_id),
        )
    except Exception as exc:
        traceback.print_exc()
        _update_job(
            job_id,
            status="failed",
            stage="failed",
            progress=100,
            completed_at=time.time(),
            error=str(exc),
            **(
                {"traceback": traceback.format_exc()}
                if SERVER_CONFIG.get("debug")
                else {}
            ),
        )
    finally:
        _release_job_slot()


def _save_upload(uploaded_file: cgi.FieldStorage, upload_dir: Path) -> Path:
    filename = Path(uploaded_file.filename or "uac-upload.tar.gz").name
    target = upload_dir / filename
    source = uploaded_file.file
    if source is None:
        raise ValueError("Uploaded evidence file has no readable content.")
    with target.open("wb") as handle:
        shutil.copyfileobj(source, handle)
    target.chmod(0o600)
    return target


def _input_paths_from_form(
    fields: dict[str, str], uploaded_files: list[cgi.FieldStorage], upload_dir: Path
) -> list[str]:
    input_paths = []
    for raw_line in fields.get("input_path", "").splitlines():
        line = raw_line.strip()
        if line:
            input_paths.append(line)
    for uploaded_file in uploaded_files:
        input_paths.append(str(_save_upload(uploaded_file, upload_dir)))
    seen = set()
    unique_paths = []
    for path in input_paths:
        if path in seen:
            continue
        seen.add(path)
        unique_paths.append(path)
    return unique_paths


def _inspect_inputs(
    input_paths: list[str], fields: dict[str, str], timezone_name: str
) -> dict[str, Any]:
    results = [
        inspect_time_range(
            input_path,
            year=_parse_int(fields.get("year", "")),
            timezone_name=timezone_name,
            host=fields.get("host", "").strip(),
        )
        for input_path in input_paths
    ]
    earliest_result = min(
        (result for result in results if result.earliest),
        key=lambda result: result.earliest or "9999",
        default=None,
    )
    latest_result = max(
        (result for result in results if result.latest),
        key=lambda result: result.latest or "",
        default=None,
    )
    log_events = sum(result.log_events for result in results)
    timed_events = sum(result.timed_events for result in results)
    return {
        "earliest": earliest_result.earliest if earliest_result else None,
        "latest": latest_result.latest if latest_result else None,
        "events": sum(result.events for result in results),
        "timed_events": timed_events,
        "excluded_files": sum(result.excluded_files for result in results),
        "log_events": log_events,
        "sources": sum(result.sources for result in results),
        "errors": sum(result.errors for result in results),
        "earliest_source": earliest_result.earliest_source if earliest_result else "",
        "latest_source": latest_result.latest_source if latest_result else "",
        "range_basis": "log_time" if log_events else "timestamped_evidence",
        "source_types": sorted(
            {kind for result in results for kind in result.source_types}
        ),
        "collections": len(input_paths),
        "collection_ranges": [
            result.to_dict() | {"input": input_paths[index]}
            for index, result in enumerate(results)
        ],
    }


def _list_outputs(output_dir: Path, job_id: str) -> list[dict[str, Any]]:
    preferred = [
        "case_summary.md",
        "case_assisted_investigation.md",
        "case_assisted_investigation.json",
        "case_manifest.json",
        "case_findings.json",
        "case_correlation.json",
        "case_ioc_hits.csv",
        "case_ioc_hits.json",
        "case_timeline_mini.csv",
        "case_timeline_mini.jsonl",
        "case_timeline_full.csv",
        "case_timeline_full.jsonl",
        "case_source_index.json",
        "case_parser_errors.log",
        "analyst_annotations.json",
        "summary.md",
        "assisted_investigation.md",
        "assisted_investigation.json",
        "run_manifest.json",
        "findings.json",
        "ioc_hits.csv",
        "ioc_hits.json",
        "timeline_mini.csv",
        "timeline_mini.jsonl",
        "timeline_full.csv",
        "timeline_full.jsonl",
        "source_index.json",
        "parser_errors.log",
    ]
    files = []
    for name in preferred:
        path = output_dir / name
        if path.exists():
            files.append(
                {
                    "name": name,
                    "size": path.stat().st_size,
                    "url": f"/outputs/{job_id}/{name}",
                }
            )
    hosts_dir = output_dir / "hosts"
    if hosts_dir.exists():
        for summary in sorted(hosts_dir.glob("*/summary.md")):
            rel = summary.relative_to(output_dir)
            files.append(
                {
                    "name": str(rel),
                    "size": summary.stat().st_size,
                    "url": f"/outputs/{job_id}/{rel.as_posix()}",
                }
            )
    return files


def _job_output_dir(job_id: str) -> Path:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job.get("status") != "complete":
        raise FileNotFoundError("Completed job not found.")
    output_root = (_work_dir() / "outputs").resolve()
    output_dir = Path(str(job.get("output") or "")).resolve()
    if not output_dir.is_relative_to(output_root) or not output_dir.is_dir():
        raise FileNotFoundError("Job output is unavailable.")
    return output_dir


def _timeline_file(output_dir: Path, scope: str) -> tuple[Path, str]:
    requested = "full" if scope == "full" else "mini"
    candidates = (
        [("case_timeline_mini.jsonl", "mini"), ("case_timeline_full.jsonl", "full")]
        if requested == "mini"
        else [("case_timeline_full.jsonl", "full")]
    )
    candidates += (
        [("timeline_mini.jsonl", "mini"), ("timeline_full.jsonl", "full")]
        if requested == "mini"
        else [("timeline_full.jsonl", "full")]
    )
    for name, actual_scope in candidates:
        path = output_dir / name
        if path.exists():
            return path, actual_scope
    raise FileNotFoundError("Timeline output is unavailable for this job.")


def _timeline_page(job_id: str, query: dict[str, list[str]]) -> dict[str, Any]:
    output_dir = _job_output_dir(job_id)
    scope = _query_value(query, "scope", "mini")
    path, actual_scope = _timeline_file(output_dir, scope)
    search = _query_value(query, "q", "").strip().lower()[:200]
    severity = _query_value(query, "severity", "").strip().lower()
    source_type = _query_value(query, "source_type", "").strip()
    offset = max(0, _query_int(query, "offset", 0))
    limit = min(200, max(20, _query_int(query, "limit", 80)))
    annotations = _load_annotations(output_dir).get("annotations", {})
    items: list[dict[str, Any]] = []
    total = 0
    severity_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_severity = str(event.get("severity") or "informational")
            event_source = str(event.get("source_type") or "unknown")
            severity_counts[event_severity] = severity_counts.get(event_severity, 0) + 1
            source_counts[event_source] = source_counts.get(event_source, 0) + 1
            if severity and event_severity.lower() != severity:
                continue
            if source_type and event_source != source_type:
                continue
            if search and search not in _searchable_event_text(event):
                continue
            if total >= offset and len(items) < limit:
                event_id = str(event.get("event_id") or "")
                event["analyst_annotation"] = annotations.get(event_id, {})
                items.append(event)
            total += 1
    return {
        "job_id": job_id,
        "scope": actual_scope,
        "offset": offset,
        "limit": limit,
        "total": total,
        "has_more": offset + len(items) < total,
        "items": items,
        "facets": {
            "severity": dict(sorted(severity_counts.items())),
            "source_type": dict(sorted(source_counts.items())),
        },
    }


def _save_annotation(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    output_dir = _job_output_dir(job_id)
    event_id = str(payload.get("event_id") or "").strip()
    if not re.fullmatch(r"evt_[A-Za-z0-9]+|evt-[A-Za-z0-9_.-]+", event_id):
        raise ValueError("A valid timeline event ID is required.")
    if not _event_exists(output_dir, event_id):
        raise ValueError("The referenced event does not exist in this job timeline.")
    raw_tags = payload.get("tags") or []
    if not isinstance(raw_tags, list):
        raise ValueError("Annotation tags must be a list.")
    tags = []
    for value in raw_tags[:10]:
        tag = re.sub(r"\s+", "_", str(value).strip().lower())[:40]
        tag = re.sub(r"[^a-z0-9_.-]", "", tag)
        if tag and tag not in tags:
            tags.append(tag)
    note = str(payload.get("note") or "").strip()[:2000]
    disposition = str(payload.get("disposition") or "unreviewed").strip().lower()
    allowed_dispositions = {
        "unreviewed",
        "suspicious",
        "malicious",
        "benign",
        "needs_context",
    }
    if disposition not in allowed_dispositions:
        raise ValueError("Unsupported analyst disposition.")
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    with ANNOTATIONS_LOCK:
        document = _load_annotations(output_dir)
        annotations = document.setdefault("annotations", {})
        if tags or note or disposition != "unreviewed":
            annotations[event_id] = {
                "tags": tags,
                "note": note,
                "disposition": disposition,
                "updated_at": now,
            }
        else:
            annotations.pop(event_id, None)
        document["updated_at"] = now
        target = output_dir / "analyst_annotations.json"
        temporary = output_dir / ".analyst_annotations.json.tmp"
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        temporary.chmod(0o600)
        temporary.replace(target)
        target.chmod(0o600)
    _update_job(job_id, outputs=_list_outputs(output_dir, job_id))
    return {
        "event_id": event_id,
        "annotation": annotations.get(event_id, {}),
        "saved": True,
    }


def _load_annotations(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "analyst_annotations.json"
    if not path.exists():
        return {"schema_version": "1.0", "updated_at": "", "annotations": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": "1.0", "updated_at": "", "annotations": {}}
    if not isinstance(data, dict) or not isinstance(data.get("annotations"), dict):
        return {"schema_version": "1.0", "updated_at": "", "annotations": {}}
    return data


def _event_exists(output_dir: Path, event_id: str) -> bool:
    path, _ = _timeline_file(output_dir, "full")
    needle = f'"event_id": "{event_id}"'
    with path.open(encoding="utf-8", errors="replace") as handle:
        return any(needle in line for line in handle)


def _searchable_event_text(event: dict[str, Any]) -> str:
    fields = [
        "timestamp",
        "host",
        "collection_host",
        "collection_name",
        "source_path",
        "source_type",
        "event_category",
        "event_action",
        "user",
        "src_ip",
        "dst_ip",
        "process",
        "command",
        "file_path",
        "summary",
        "raw",
        "severity",
        "tags",
        "mitre",
        "detection_names",
    ]
    return " ".join(str(event.get(field) or "").lower() for field in fields)


def _query_value(query: dict[str, list[str]], key: str, default: str) -> str:
    values = query.get(key)
    return values[0] if values else default


def _query_int(query: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(_query_value(query, key, str(default)))
    except ValueError:
        return default


def get_job(job_id: str) -> dict[str, Any]:
    with JOBS_LOCK:
        job = dict(JOBS.get(job_id, {}))
    if not job:
        return {"error": "Unknown job."}
    public = {
        key: job[key]
        for key in [
            "id",
            "status",
            "created_at",
            "is_case",
            "stage",
            "progress",
            "started_at",
            "progress_detail",
            "completed_at",
            "outputs",
        ]
        if key in job
    }
    options = job.get("options")
    if isinstance(options, dict):
        public["options"] = {
            key: value
            for key, value in options.items()
            if key not in {"input_path", "input_paths", "output_dir"}
        }
    result = job.get("result")
    if isinstance(result, dict):
        public["result"] = {
            key: value for key, value in result.items() if key != "output"
        }
    if job.get("error"):
        public["error"] = (
            str(job["error"])
            if SERVER_CONFIG.get("debug")
            else "Analysis failed. Review the local server log."
        )
    if SERVER_CONFIG.get("debug") and job.get("traceback"):
        public["traceback"] = job["traceback"]
    return public


def _update_job(job_id: str, **updates: object) -> None:
    with JOBS_LOCK:
        job = JOBS.setdefault(job_id, {"id": job_id})
        job.update(updates)


def _parse_int(value: str) -> int | None:
    value = value.strip()
    return int(value) if value else None


def _normalize_datetime_input(value: str | None, timezone_name: str) -> str | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z") or "+" in text[10:] or "-" in text[10:]:
        return text
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return text
    try:
        tz: tzinfo = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        tz = UTC
    return dt.replace(tzinfo=tz).isoformat()


def _utc_iso_to_local_value(value: str | None, timezone_name: str) -> str:
    dt = _utc_iso_to_datetime(value, timezone_name)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") if dt else ""


def _utc_iso_to_display(value: str | None, timezone_name: str) -> str:
    dt = _utc_iso_to_datetime(value, timezone_name)
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z") if dt else ""


def _utc_iso_to_datetime(value: str | None, timezone_name: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    try:
        tz: tzinfo = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        tz = UTC
    return dt.astimezone(tz)


def render_index(csrf_token: str = CSRF_TOKEN) -> str:
    asset_version = "20260617f"
    year_options = "\n".join(
        f'              <option value="{year}"{" selected" if year == 2026 else ""}>{year}</option>'
        for year in range(2018, 2028)
    )
    timezone_options = "\n".join(
        f'              <option value="{tz}"{" selected" if tz == "Asia/Hong_Kong" else ""}>{tz}</option>'
        for tz in [
            "Asia/Hong_Kong",
            "UTC",
            "Asia/Singapore",
            "Asia/Taipei",
            "Asia/Shanghai",
            "Asia/Tokyo",
            "Europe/London",
            "Europe/Berlin",
            "America/New_York",
            "America/Los_Angeles",
            "Australia/Sydney",
        ]
    )
    threat_profiles = profile_choices()
    threat_options = "\n".join(
        f'              <option value="{html.escape(profile["id"])}">{html.escape(profile["label"])}</option>'
        for profile in threat_profiles
    )
    threat_profiles_json = json.dumps(threat_profiles, ensure_ascii=True).replace(
        "</", "<\\/"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TraceQuarry</title>
  <link rel="icon" href="/favicon.svg?v={asset_version}">
  <style>
    :root {{
      color-scheme: light;
      --night: #0E1626;
      --depth: #16213A;
      --fog: #EDEFE9;
      --moss: #9DBE8D;
      --slate: #7C8696;
      --paper: #F4F2ED;
      --ink: #1B2430;
      --yuzu: #E5A84B;
      --ember: #D96A5B;
      --canvas: #E7E4DC;
      --panel: #FCFBF8;
      --panel-soft: #F8F6F0;
      --text: #27313f;
      --muted: #667085;
      --line: rgba(27,36,48,.14);
      --line-dark: rgba(237,239,233,.14);
      --brand: var(--moss);
      --brand-dark: var(--night);
      --brand-wash: rgba(157,190,141,.18);
      --danger: var(--ember);
      --warn: #9a6700;
      --good: #4f7f48;
      --code: var(--night);
      --display: "Bricolage Grotesque", "Avenir Next", Arial, sans-serif;
      --body: "Instrument Sans", "Avenir Next", Arial, sans-serif;
      --mono: "Space Mono", "SF Mono", Consolas, monospace;
    }}
    * {{ box-sizing: border-box; }}
    html {{ background: var(--canvas); }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: var(--body);
      background: var(--canvas);
      color: var(--text);
      -webkit-font-smoothing: antialiased;
    }}
    header {{
      position: sticky;
      top: 0;
      z-index: 20;
      padding: 14px 24px;
      border-bottom: 1px solid var(--line-dark);
      background: rgba(14, 22, 38, .94);
      backdrop-filter: blur(12px);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
    }}
    .brand-lockup {{
      width: auto;
      height: 54px;
      display: block;
    }}
    .header-right {{ display: flex; align-items: center; gap: 16px; min-width: 0; }}
    .parent-identity {{
      display: flex;
      align-items: center;
      padding-left: 16px;
      border-left: 1px solid rgba(237,239,233,.16);
    }}
    .parent-capybara {{ width: 42px; height: 42px; display: block; object-fit: contain; opacity: .94; }}
    .nav-meta {{
      display: flex;
      align-items: center;
      gap: 10px;
      color: rgba(237,239,233,.68);
      font-size: 12px;
      font-family: var(--mono);
    }}
    .nav-dot {{
      width: 7px;
      height: 7px;
      border-radius: 999px;
      background: var(--yuzu);
      box-shadow: 0 0 0 4px rgba(229,168,75,.16);
    }}
    header kbd {{
      border-color: var(--line-dark);
      background: rgba(237,239,233,.06);
      color: var(--fog);
    }}
    main {{
      position: relative;
      width: 100%;
      max-width: 1240px;
      margin: 0 auto;
      padding: 34px 24px 34px;
    }}
    .intro {{
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(280px, .9fr);
      gap: 38px;
      align-items: end;
      position: relative;
      overflow: hidden;
      border: 1px solid var(--line-dark);
      border-radius: 12px;
      background: var(--night);
      color: var(--fog);
      padding: 34px;
      margin-bottom: 18px;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 14px;
      color: var(--moss);
      background: rgba(157,190,141,.12);
      border: 1px solid rgba(157,190,141,.22);
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 11px;
      font-weight: 760;
      text-transform: uppercase;
      letter-spacing: .08em;
    }}
    h1 {{
      max-width: 980px;
      margin: 0;
      color: var(--ink);
      position: relative;
      z-index: 1;
      color: var(--fog);
      font-family: var(--display);
      font-size: clamp(40px, 5vw, 72px);
      line-height: .98;
      letter-spacing: 0;
      font-weight: 650;
    }}
    .intro-copy {{
      position: relative;
      z-index: 1;
      color: rgba(237,239,233,.74);
      line-height: 1.7;
      font-size: 15px;
      margin: 0;
      max-width: 490px;
    }}
    .intro-side {{
      position: relative;
      z-index: 1;
      display: grid;
      gap: 18px;
      justify-items: end;
      align-content: center;
    }}
    .terminal-demo {{
      width: min(520px, 100%);
      border: 22px solid #768197;
      border-radius: 4px;
      background: #768197;
      box-shadow: 0 22px 44px rgba(0,0,0,.24);
      transform: translateZ(0);
    }}
    .terminal-surface {{
      min-height: 272px;
      border-radius: 6px;
      background: #0d0b0d;
      color: #b9c2d0;
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.52;
      overflow: hidden;
      position: relative;
      padding: 13px 15px 18px;
    }}
    .terminal-bar {{
      display: grid;
      grid-template-columns: auto 1fr auto;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
      color: #8b95a8;
    }}
    .terminal-chip {{
      display: inline-flex;
      align-items: center;
      min-height: 16px;
      padding: 1px 7px 2px;
      border-radius: 2px;
      background: #5d8ec8;
      color: #07111e;
      font-weight: 700;
      box-shadow: inset 0 -1px 0 rgba(0,0,0,.22);
    }}
    .terminal-host {{
      color: #8f98a8;
      font-size: 10px;
      letter-spacing: .02em;
    }}
    .terminal-time {{
      color: #838da0;
      font-size: 10px;
    }}
    .terminal-line {{
      display: block;
      width: max-content;
      max-width: 100%;
      white-space: nowrap;
      overflow: hidden;
      opacity: 0;
      transform: translateY(4px);
      animation: terminal-line-in .42s ease forwards;
    }}
    .terminal-line.line-1 {{ animation-delay: .25s; }}
    .terminal-line.line-2 {{ animation-delay: .95s; }}
    .terminal-line.line-3 {{ animation-delay: 1.75s; }}
    .terminal-line.line-4 {{ animation-delay: 2.55s; }}
    .terminal-line.line-5 {{ animation-delay: 3.2s; }}
    .terminal-prompt {{
      color: #6fa3dc;
      font-weight: 700;
    }}
    .terminal-comment {{
      color: #c2c7d2;
    }}
    .terminal-cmd {{
      color: #e2e6ef;
    }}
    .terminal-result {{
      color: #bcc4d0;
    }}
    .terminal-cursor {{
      display: inline-block;
      width: 7px;
      height: 14px;
      margin-top: 7px;
      background: #5d8ec8;
      animation: terminal-cursor 1s steps(1, end) infinite;
    }}
    .terminal-scan {{
      position: absolute;
      inset: 0;
      pointer-events: none;
      background: linear-gradient(180deg, rgba(255,255,255,.04), transparent 22%, transparent);
      opacity: .28;
    }}
    @keyframes terminal-line-in {{
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    @keyframes terminal-cursor {{
      0%, 46% {{ opacity: 1; }}
      47%, 100% {{ opacity: 0; }}
    }}
    .workbench {{
      display: grid;
      grid-template-columns: minmax(360px, 5fr) minmax(0, 7fr);
      gap: 18px;
      align-items: start;
    }}
    section {{
      background: rgba(252,251,248,.92);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 22px;
      box-shadow: 0 2px 12px rgba(0,0,0,.025);
    }}
    h2 {{ color: var(--ink); font-size: 17px; margin: 0 0 6px; letter-spacing: 0; }}
    .section-lede {{ margin: 0 0 18px; color: var(--muted); font-size: 13px; line-height: 1.55; }}
    label {{ display: block; font-size: 12px; font-weight: 760; margin: 14px 0 6px; color: var(--ink); letter-spacing: .01em; }}
    input, textarea, select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 11px;
      font: inherit;
      background: var(--paper);
      color: var(--text);
      outline: none;
      transition: border-color .18s ease, box-shadow .18s ease, background .18s ease;
    }}
    input:focus-visible, textarea:focus-visible, select:focus-visible {{
      border-color: var(--brand);
      box-shadow: 0 0 0 3px rgba(157,190,141,.28);
    }}
    input:disabled, textarea:disabled, select:disabled {{
      color: #9b9892;
      background: #f3f1ec;
      cursor: not-allowed;
    }}
    textarea {{ min-height: 138px; resize: vertical; font-family: var(--mono); font-size: 12px; }}
    .row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
    .tq-datetime {{
      position: relative;
      isolation: isolate;
    }}
    .tq-dt-trigger {{
      width: 100%;
      min-height: 44px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px 10px 9px 12px;
      background: var(--paper);
      color: var(--text);
      cursor: pointer;
      text-align: left;
      transition: border-color .18s ease, box-shadow .18s ease, background .18s ease;
    }}
    .tq-dt-trigger:hover {{
      border-color: rgba(157,190,141,.78);
      background: #f8f6ef;
    }}
    .tq-dt-trigger:focus-visible {{
      border-color: var(--brand);
      box-shadow: 0 0 0 3px rgba(157,190,141,.28);
      outline: 0;
    }}
    .tq-dt-value {{
      min-width: 0;
      overflow: hidden;
      color: var(--ink);
      font-family: var(--mono);
      font-size: 12px;
      white-space: nowrap;
      text-overflow: ellipsis;
    }}
    .tq-dt-value.placeholder {{
      color: #7b776f;
    }}
    .tq-dt-icon {{
      width: 28px;
      height: 28px;
      display: inline-grid;
      place-items: center;
      border-radius: 7px;
      background: rgba(157,190,141,.16);
      color: var(--night);
    }}
    .tq-dt-icon svg {{
      width: 16px;
      height: 16px;
      display: block;
    }}
    .tq-dt-panel {{
      display: none;
      width: min(310px, calc(100vw - 48px));
      border: 1px solid rgba(27,36,48,.18);
      border-radius: 12px;
      background: #fffefb;
      box-shadow: 0 18px 38px rgba(14,22,38,.18), 0 3px 8px rgba(14,22,38,.08);
      padding: 10px;
      position: absolute;
      top: calc(100% + 8px);
      left: 0;
      z-index: 80;
    }}
    .tq-datetime.open .tq-dt-panel {{
      display: block;
    }}
    .tq-datetime.open {{
      z-index: 90;
    }}
    .tq-datetime.align-right .tq-dt-panel {{
      left: auto;
      right: 0;
    }}
    .tq-datetime.align-right .tq-dt-panel::before {{
      left: auto;
      right: 18px;
    }}
    .tq-dt-panel::before {{
      content: "";
      position: absolute;
      top: -5px;
      left: 18px;
      width: 10px;
      height: 10px;
      border-left: 1px solid rgba(27,36,48,.18);
      border-top: 1px solid rgba(27,36,48,.18);
      background: #fffefb;
      transform: rotate(45deg);
    }}
    .tq-dt-head {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      gap: 6px;
      align-items: center;
      margin-bottom: 8px;
    }}
    .tq-dt-month {{
      color: var(--ink);
      font-weight: 780;
      font-size: 12px;
    }}
    .tq-dt-nav {{
      width: 30px;
      height: 30px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel-soft);
      color: var(--ink);
      display: inline-grid;
      place-items: center;
      padding: 0;
    }}
    .tq-dt-nav:hover {{
      background: rgba(157,190,141,.18);
    }}
    .tq-dt-weekdays,
    .tq-dt-days {{
      display: grid;
      grid-template-columns: repeat(7, minmax(0, 1fr));
      gap: 4px;
    }}
    .tq-dt-weekdays {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 10px;
      text-align: center;
      margin-bottom: 4px;
    }}
    .tq-dt-day {{
      width: 100%;
      aspect-ratio: 1;
      border: 1px solid transparent;
      border-radius: 7px;
      padding: 0;
      background: transparent;
      color: var(--ink);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 650;
      display: inline-grid;
      place-items: center;
    }}
    .tq-dt-day:hover {{
      background: rgba(157,190,141,.16);
      border-color: rgba(157,190,141,.32);
    }}
    .tq-dt-day.muted {{
      color: #a29d94;
    }}
    .tq-dt-day.selected {{
      background: var(--night);
      border-color: var(--night);
      color: var(--fog);
      box-shadow: inset 0 -3px 0 var(--yuzu);
    }}
    .tq-dt-day.today:not(.selected) {{
      border-color: var(--yuzu);
      color: var(--night);
    }}
    .tq-dt-time {{
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 6px;
      margin-top: 10px;
    }}
    .tq-dt-time label {{
      margin: 0;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 600;
    }}
    .tq-dt-time select {{
      margin-top: 4px;
      min-height: 34px;
      padding: 7px 8px;
      border-radius: 7px;
      font-family: var(--mono);
      font-size: 12px;
      background: var(--paper);
    }}
    .tq-dt-actions {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      margin-top: 10px;
    }}
    .tq-dt-action {{
      min-height: 34px;
      border-radius: 7px;
      padding: 8px 10px;
      font-size: 12px;
    }}
    .tq-dt-action.clear {{
      background: var(--panel);
      border: 1px solid var(--line);
      color: var(--muted);
    }}
    .tq-dt-action.now {{
      background: rgba(229,168,75,.18);
      color: var(--night);
      border: 1px solid rgba(229,168,75,.38);
    }}
    .source-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }}
    .source-card {{
      position: relative;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--panel-soft);
      padding: 14px;
      cursor: pointer;
      transition: border-color .2s ease, background .2s ease, box-shadow .2s ease, transform .2s ease;
    }}
    .source-card:hover {{ border-color: rgba(157,190,141,.8); box-shadow: 0 2px 8px rgba(0,0,0,.04); }}
    .source-card:active {{ transform: scale(.99); }}
    .source-card input {{ position: absolute; opacity: 0; pointer-events: none; }}
    .source-card.active {{ border-color: var(--moss); background: rgba(157,190,141,.16); }}
    .source-title {{ display: flex; align-items: center; justify-content: space-between; gap: 8px; color: var(--ink); font-weight: 760; font-size: 13px; }}
    .source-desc {{ display: block; margin-top: 8px; color: var(--muted); font-size: 12px; line-height: 1.45; }}
    .radio-mark {{
      width: 18px;
      height: 18px;
      border: 1px solid #cbc6bd;
      border-radius: 999px;
      display: inline-block;
      background: var(--panel);
    }}
    .source-card.active .radio-mark {{
      border: 5px solid var(--brand);
    }}
    .field-panel {{
      margin-top: 12px;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
      background: var(--panel);
    }}
    .field-panel[hidden] {{ display: none; }}
    .assist-profile {{
      margin-top: 14px;
      border: 1px solid rgba(229,168,75,.34);
      border-left: 4px solid var(--yuzu);
      border-radius: 10px;
      padding: 13px 14px;
      background: rgba(229,168,75,.09);
    }}
    .assist-profile-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 5px; }}
    .assist-profile-mark {{ width: 8px; height: 8px; border-radius: 50%; background: var(--yuzu); box-shadow: 0 0 0 4px rgba(229,168,75,.14); }}
    .assist-profile strong {{ color: var(--ink); font-size: 12px; }}
    .assist-profile p {{ margin: 0; color: var(--muted); font-size: 12px; line-height: 1.5; }}
    .assist-profile small {{ display: block; margin-top: 7px; color: #796338; font: 10px/1.45 var(--mono); }}
    .hint {{ color: var(--muted); font-size: 12px; line-height: 1.45; margin-top: 6px; }}
    .range-panel {{
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(157,190,141,.12);
      padding: 14px;
    }}
    .range-panel[hidden] {{ display: none; }}
    .range-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 10px;
    }}
    .range-item {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 10px;
    }}
    .range-item span {{
      display: block;
      color: var(--muted);
      font-size: 11px;
      font-family: var(--mono);
      margin-bottom: 4px;
    }}
    .range-item strong {{
      display: block;
      color: var(--ink);
      font-size: 13px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }}
    .coverage-readiness {{
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid rgba(27,36,48,.12);
    }}
    .coverage-head {{ display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }}
    .coverage-head strong {{ color: var(--ink); font-size: 12px; }}
    .coverage-head span {{ color: var(--muted); font: 11px var(--mono); }}
    .coverage-groups {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 9px; }}
    .coverage-chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      min-height: 26px;
      padding: 4px 8px;
      border: 1px solid var(--line);
      border-radius: 5px;
      background: var(--panel);
      color: var(--ink);
      font: 11px var(--mono);
    }}
    .coverage-chip::before {{ content: ""; width: 6px; height: 6px; border-radius: 50%; background: var(--good); }}
    .coverage-chip.missing {{ color: var(--muted); background: transparent; }}
    .coverage-chip.missing::before {{ background: var(--danger); }}
    .action-row {{
      display: grid;
      grid-template-columns: minmax(0, .9fr) minmax(0, 1.1fr);
      gap: 10px;
      margin-top: 18px;
    }}
    kbd {{
      font-family: var(--mono);
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--canvas);
      padding: 1px 5px;
      font-size: 11px;
      color: var(--ink);
    }}
    button {{
      margin-top: 0;
      width: 100%;
      border: 0;
      border-radius: 6px;
      background: var(--moss);
      color: var(--night);
      padding: 12px 12px;
      font-weight: 750;
      cursor: pointer;
      transition: background .18s ease, transform .18s ease;
    }}
    button:hover {{ background: #acc99d; }}
    button.secondary {{
      background: var(--panel);
      color: var(--night);
      border: 1px solid var(--line);
    }}
    button.secondary:hover {{ background: var(--paper); }}
    button:active {{ transform: scale(.99); }}
    button:focus-visible {{ outline: 3px solid rgba(157,190,141,.36); outline-offset: 2px; }}
    button:disabled {{ opacity: .6; cursor: wait; }}
    .status {{
      border-left: 4px solid var(--line);
      padding: 12px 0 12px 14px;
      color: var(--muted);
      background: var(--panel-soft);
      border-radius: 8px;
    }}
    .status.running {{ border-color: var(--warn); color: var(--warn); }}
    .status.complete {{ border-color: var(--good); color: var(--good); }}
    .status.failed {{ border-color: var(--danger); color: var(--danger); }}
    .run-progress {{
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--panel-soft);
      padding: 14px;
    }}
    .run-progress[hidden] {{ display: none; }}
    .progress-head {{
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }}
    .progress-head strong {{
      color: var(--ink);
      font-size: 13px;
    }}
    .progress-head span {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
    }}
    .progress-track {{
      height: 9px;
      overflow: hidden;
      border-radius: 999px;
      background: rgba(27,36,48,.08);
      border: 1px solid rgba(27,36,48,.08);
    }}
    .progress-fill {{
      width: 0%;
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, var(--moss), var(--yuzu));
      transition: width .35s ease;
    }}
    .progress-steps {{
      display: grid;
      gap: 8px;
      margin-top: 12px;
    }}
    .progress-step {{
      display: grid;
      grid-template-columns: 18px minmax(0, 1fr);
      gap: 8px;
      align-items: start;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
    }}
    .step-dot {{
      width: 18px;
      height: 18px;
      border-radius: 999px;
      display: inline-grid;
      place-items: center;
      border: 1px solid rgba(27,36,48,.18);
      background: var(--panel);
    }}
    .step-dot::after {{
      content: "";
      width: 6px;
      height: 6px;
      border-radius: 999px;
      background: #b9b3a9;
    }}
    .progress-step.active {{
      color: var(--ink);
      font-weight: 700;
    }}
    .progress-step.active .step-dot {{
      border-color: rgba(229,168,75,.54);
      background: rgba(229,168,75,.16);
      box-shadow: 0 0 0 4px rgba(229,168,75,.12);
    }}
    .progress-step.active .step-dot::after {{
      background: var(--yuzu);
      animation: pulse-dot 1.1s ease-in-out infinite;
    }}
    .progress-step.done {{
      color: var(--ink);
    }}
    .progress-step.done .step-dot {{
      border-color: rgba(157,190,141,.56);
      background: rgba(157,190,141,.18);
    }}
    .progress-step.done .step-dot::after {{
      width: 8px;
      height: 8px;
      background: var(--moss);
    }}
    @keyframes pulse-dot {{
      0%, 100% {{ transform: scale(1); opacity: 1; }}
      50% {{ transform: scale(1.55); opacity: .62; }}
    }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 16px 0; }}
    .metric {{ border: 1px solid var(--line); border-radius: 10px; padding: 13px; background: var(--paper); }}
    .metric strong {{ display: block; font-size: 22px; color: var(--ink); letter-spacing: 0; }}
    .metric span {{ color: var(--muted); font-size: 12px; }}
    .run-actions {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-top: 14px;
    }}
    .run-actions[hidden] {{ display: none; }}
    .run-actions a, .run-actions button {{
      min-height: 42px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 8px;
      font-size: 13px;
      text-decoration: none;
    }}
    .run-actions a {{
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--night);
    }}
    .run-actions button {{
      background: var(--night);
      color: var(--fog);
    }}
    .files {{ list-style: none; padding: 0; margin: 14px 0 0; }}
    .files li {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; border-top: 1px solid var(--line); padding: 10px 0; }}
    a {{ color: var(--night); font-weight: 650; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .console {{
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--night);
      margin-top: 14px;
    }}
    .chrome {{
      height: 34px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 0 12px;
      background: var(--depth);
    }}
    .chrome i {{
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--moss);
      display: block;
    }}
    pre {{ margin: 0; overflow: auto; background: var(--code); color: var(--fog); padding: 14px; font-family: var(--mono); font-size: 12px; max-height: 390px; }}
    .modal-backdrop {{
      position: fixed;
      inset: 0;
      z-index: 100;
      display: grid;
      place-items: center;
      padding: 24px;
      background: rgba(14,22,38,.56);
      backdrop-filter: blur(10px);
    }}
    .modal-backdrop[hidden] {{ display: none; }}
    .summary-modal {{
      width: min(980px, 100%);
      max-height: min(760px, calc(100vh - 48px));
      overflow: hidden;
      border: 1px solid rgba(237,239,233,.16);
      border-radius: 14px;
      background: var(--panel);
      box-shadow: 0 28px 80px rgba(0,0,0,.32);
      display: grid;
      grid-template-rows: auto minmax(0, 1fr) auto;
    }}
    .summary-modal header {{
      position: static;
      padding: 18px 20px;
      background: var(--night);
      border-bottom: 1px solid var(--line-dark);
    }}
    .summary-title {{
      min-width: 0;
    }}
    .summary-modal h2 {{
      color: var(--fog);
      margin: 0;
      font-size: 18px;
    }}
    .summary-kicker {{
      margin: 4px 0 0;
      color: rgba(237,239,233,.62);
      font-family: var(--mono);
      font-size: 11px;
    }}
    .modal-close {{
      width: 36px;
      height: 36px;
      padding: 0;
      border-radius: 8px;
      background: rgba(237,239,233,.08);
      color: var(--fog);
      border: 1px solid rgba(237,239,233,.14);
    }}
    .summary-body {{
      overflow: auto;
      padding: 20px;
      background:
        linear-gradient(180deg, rgba(157,190,141,.08), transparent 180px),
        #fffefb;
    }}
    .summary-report {{
      display: grid;
      gap: 18px;
    }}
    .summary-hero {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 16px;
      align-items: end;
      padding-bottom: 2px;
    }}
    .summary-hero h3 {{
      margin: 0;
      color: var(--ink);
      font-family: var(--display);
      font-size: clamp(24px, 3vw, 34px);
      line-height: 1;
      letter-spacing: 0;
    }}
    .summary-hero p {{
      margin: 8px 0 0;
      color: var(--muted);
      line-height: 1.5;
      font-size: 13px;
    }}
    .summary-badge {{
      border: 1px solid rgba(229,168,75,.32);
      border-radius: 999px;
      background: rgba(229,168,75,.16);
      color: var(--night);
      padding: 8px 11px;
      font-size: 12px;
      font-weight: 760;
      white-space: nowrap;
    }}
    .summary-stat-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }}
    .summary-stat {{
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel);
      padding: 13px;
      box-shadow: 0 1px 0 rgba(255,255,255,.8);
    }}
    .summary-stat span {{
      display: block;
      color: var(--muted);
      font-size: 11px;
      font-family: var(--mono);
      margin-bottom: 6px;
    }}
    .summary-stat strong {{
      display: block;
      color: var(--ink);
      font-size: 24px;
      line-height: 1;
    }}
    .summary-section {{
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(252,251,248,.86);
      overflow: hidden;
    }}
    .summary-section h3 {{
      margin: 0;
      padding: 13px 15px;
      color: var(--ink);
      font-size: 14px;
      border-bottom: 1px solid var(--line);
      background: rgba(244,242,237,.72);
    }}
    .summary-list {{
      display: grid;
      gap: 8px;
      padding: 12px;
    }}
    .finding-card {{
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 10px;
      border: 1px solid rgba(27,36,48,.12);
      border-radius: 10px;
      background: #fff;
      padding: 11px;
    }}
    .finding-card.high {{
      border-color: rgba(217,106,91,.28);
      background: linear-gradient(90deg, rgba(217,106,91,.08), #fff 120px);
    }}
    .finding-card.next {{
      border-color: rgba(157,190,141,.28);
      background: linear-gradient(90deg, rgba(157,190,141,.10), #fff 120px);
    }}
    .finding-dot {{
      width: 9px;
      height: 9px;
      margin-top: 5px;
      border-radius: 999px;
      background: var(--yuzu);
      box-shadow: 0 0 0 4px rgba(229,168,75,.14);
    }}
    .finding-card.high .finding-dot {{ background: var(--ember); box-shadow: 0 0 0 4px rgba(217,106,91,.12); }}
    .finding-card.next .finding-dot {{ background: var(--moss); box-shadow: 0 0 0 4px rgba(157,190,141,.14); }}
    .finding-title {{
      display: block;
      color: var(--ink);
      font-weight: 780;
      font-size: 13px;
      line-height: 1.35;
      margin-bottom: 3px;
    }}
    .finding-text {{
      color: #45505f;
      font-size: 12px;
      line-height: 1.5;
      overflow-wrap: anywhere;
    }}
    .summary-paragraph {{
      margin: 0;
      color: #45505f;
      font-size: 12px;
      line-height: 1.55;
      padding: 12px 14px;
      border-top: 1px solid rgba(27,36,48,.08);
    }}
    .summary-paragraph:first-child {{
      border-top: 0;
    }}
    .summary-empty {{
      margin: 0;
      padding: 14px;
      color: var(--muted);
      font-size: 13px;
    }}
    .summary-raw {{
      white-space: pre-wrap;
      color: var(--ink);
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.55;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 14px;
    }}
    .summary-footer {{
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      padding: 12px 18px;
      border-top: 1px solid var(--line);
      background: var(--panel-soft);
    }}
    .summary-footer a, .summary-footer button {{
      width: auto;
      min-width: 128px;
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 13px;
    }}
    .summary-footer a {{
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--night);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-decoration: none;
    }}
    .timeline-modal {{
      width: min(1260px, 100%);
      height: min(820px, calc(100vh - 40px));
      overflow: hidden;
      border: 1px solid rgba(237,239,233,.16);
      border-radius: 14px;
      background: var(--panel);
      box-shadow: 0 28px 80px rgba(0,0,0,.34);
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
    }}
    .timeline-modal > header {{
      position: static;
      padding: 16px 18px;
      background: var(--night);
      border-bottom: 1px solid var(--line-dark);
    }}
    .timeline-modal h2 {{ margin: 0; color: var(--fog); font-size: 18px; }}
    .timeline-toolbar {{
      display: grid;
      grid-template-columns: minmax(220px, 1fr) 150px 190px 120px;
      gap: 8px;
      padding: 11px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-soft);
    }}
    .timeline-toolbar input, .timeline-toolbar select {{ min-height: 38px; padding: 8px 10px; font-size: 12px; }}
    .timeline-workspace {{ display: grid; grid-template-columns: minmax(420px, 1.05fr) minmax(360px, .95fr); min-height: 0; }}
    .timeline-stream {{ display: grid; grid-template-rows: auto minmax(0, 1fr) auto; min-height: 0; border-right: 1px solid var(--line); }}
    .timeline-stream-head {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--line); }}
    .timeline-stream-head strong {{ color: var(--ink); font-size: 12px; }}
    .timeline-stream-head span {{ color: var(--muted); font: 11px var(--mono); }}
    .timeline-list {{ overflow: auto; background: #fffefb; }}
    .timeline-event {{
      width: 100%;
      display: grid;
      grid-template-columns: 118px 72px minmax(0, 1fr);
      gap: 10px;
      align-items: start;
      padding: 11px 14px;
      border: 0;
      border-bottom: 1px solid rgba(27,36,48,.08);
      border-radius: 0;
      background: transparent;
      color: var(--text);
      text-align: left;
      font-weight: 400;
    }}
    .timeline-event:hover {{ background: rgba(157,190,141,.10); }}
    .timeline-event.active {{ background: rgba(157,190,141,.18); box-shadow: inset 3px 0 var(--moss); }}
    .timeline-time {{ color: #596474; font: 10px/1.45 var(--mono); overflow-wrap: anywhere; }}
    .severity-pill {{ display: inline-flex; justify-content: center; padding: 4px 6px; border-radius: 5px; font: 9px var(--mono); text-transform: uppercase; background: #ece9e1; color: #5e6670; }}
    .severity-pill.high, .severity-pill.critical {{ background: rgba(217,106,91,.14); color: #983b32; }}
    .severity-pill.medium {{ background: rgba(229,168,75,.17); color: #805a18; }}
    .timeline-event-copy {{ min-width: 0; }}
    .timeline-event-copy strong {{ display: block; color: var(--ink); font-size: 12px; line-height: 1.35; overflow-wrap: anywhere; }}
    .timeline-event-copy small {{ display: block; margin-top: 4px; color: var(--muted); font: 10px/1.4 var(--mono); overflow-wrap: anywhere; }}
    .annotation-dot {{ display: inline-block; width: 6px; height: 6px; margin-right: 5px; border-radius: 50%; background: var(--yuzu); vertical-align: 1px; }}
    .timeline-pagination {{ display: grid; grid-template-columns: 90px 1fr 90px; align-items: center; gap: 8px; padding: 9px 12px; border-top: 1px solid var(--line); background: var(--panel-soft); }}
    .timeline-pagination button {{ min-height: 34px; padding: 7px; font-size: 11px; background: var(--panel); color: var(--ink); border: 1px solid var(--line); }}
    .timeline-pagination span {{ text-align: center; color: var(--muted); font: 10px var(--mono); }}
    .event-detail {{ overflow: auto; padding: 16px; background: var(--panel); }}
    .event-empty {{ display: grid; place-items: center; min-height: 100%; color: var(--muted); font-size: 13px; text-align: center; }}
    .event-detail-head {{ margin-bottom: 14px; }}
    .event-detail-head h3 {{ margin: 0; color: var(--ink); font-size: 17px; line-height: 1.35; overflow-wrap: anywhere; }}
    .event-detail-head p {{ margin: 6px 0 0; color: var(--muted); font: 10px/1.5 var(--mono); overflow-wrap: anywhere; }}
    .event-field-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 7px; margin-bottom: 14px; }}
    .event-field {{ padding: 9px; border: 1px solid var(--line); border-radius: 7px; background: var(--panel-soft); min-width: 0; }}
    .event-field span {{ display: block; color: var(--muted); font: 9px var(--mono); text-transform: uppercase; margin-bottom: 4px; }}
    .event-field strong {{ display: block; color: var(--ink); font: 10px/1.45 var(--mono); overflow-wrap: anywhere; }}
    .event-section {{ margin-top: 14px; }}
    .event-section h4 {{ margin: 0 0 7px; color: var(--ink); font-size: 11px; text-transform: uppercase; }}
    .raw-record {{ max-height: 220px; white-space: pre-wrap; overflow-wrap: anywhere; border-radius: 8px; background: var(--night); color: var(--fog); padding: 12px; font: 10px/1.55 var(--mono); }}
    .tag-row {{ display: flex; flex-wrap: wrap; gap: 5px; }}
    .event-tag {{ padding: 4px 6px; border: 1px solid rgba(157,190,141,.34); border-radius: 5px; background: rgba(157,190,141,.12); color: #3f6138; font: 9px var(--mono); }}
    .annotation-form {{ display: grid; gap: 8px; padding: 12px; border: 1px solid rgba(229,168,75,.30); border-radius: 9px; background: rgba(229,168,75,.08); }}
    .annotation-form label {{ margin: 0; }}
    .annotation-form textarea {{ min-height: 78px; font-family: var(--body); }}
    .annotation-form button {{ justify-self: end; width: auto; min-width: 120px; padding: 9px 12px; }}
    .annotation-status {{ min-height: 16px; color: var(--good); font-size: 10px; }}
    @media (max-width: 720px) {{
      .summary-hero, .summary-stat-grid {{ grid-template-columns: 1fr; }}
      .summary-footer {{ flex-direction: column; }}
      .summary-footer a, .summary-footer button {{ width: 100%; }}
      .timeline-toolbar {{ grid-template-columns: 1fr 1fr; }}
      .timeline-workspace {{ grid-template-columns: 1fr; }}
      .timeline-stream {{ min-height: 420px; border-right: 0; border-bottom: 1px solid var(--line); }}
      .timeline-event {{ grid-template-columns: 92px 64px minmax(0, 1fr); }}
    }}
    .reveal {{ opacity: 0; transform: translateY(12px); transition: opacity .6s cubic-bezier(.16,1,.3,1), transform .6s cubic-bezier(.16,1,.3,1); }}
    .reveal.visible {{ opacity: 1; transform: translateY(0); }}
    @media (prefers-reduced-motion: reduce) {{
      * {{ transition: none !important; animation: none !important; }}
      .reveal {{ opacity: 1; transform: none; }}
    }}
    @media (max-width: 940px) {{
      main {{ padding: 24px 14px; }}
      .intro, .workbench {{ grid-template-columns: 1fr; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .nav-meta span:not(.nav-dot), .nav-meta kbd {{ display: none; }}
      .header-right {{ gap: 10px; }}
      .parent-identity {{ padding-left: 10px; }}
      .parent-capybara {{ width: 38px; height: 38px; }}
    }}
    @media (max-width: 560px) {{
      header {{ padding: 12px 14px; }}
      .nav-meta {{ display: none; }}
      .parent-identity {{ border-left: 0; padding-left: 0; }}
      .parent-capybara {{ width: 34px; height: 34px; }}
      .source-grid, .row {{ grid-template-columns: 1fr; }}
      .range-grid, .action-row {{ grid-template-columns: 1fr; }}
      section {{ padding: 16px; }}
      h1 {{ font-size: clamp(36px, 12vw, 52px); }}
      .brand-lockup {{ height: 42px; }}
      .intro-side {{ justify-items: start; }}
      .terminal-demo {{ border-width: 14px; }}
      .terminal-surface {{ min-height: 220px; font-size: 10px; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="brand"><img class="brand-lockup" src="/assets/tracequarry-lockup.svg?v={asset_version}" alt="TraceQuarry"></div>
    <div class="header-right">
      <div class="nav-meta"><span class="nav-dot"></span><span>Local DFIR workbench</span><kbd>uac-timeline</kbd></div>
      <div class="parent-identity" aria-label="Chill Ethical People">
        <img class="parent-capybara" src="/assets/cep-mark.svg?v={asset_version}" alt="Chill Ethical People Capybara mark">
      </div>
    </div>
  </header>
  <main>
    <div class="intro reveal">
      <div>
        <div class="eyebrow">TraceQuarry by Chill Ethical People</div>
        <h1>Excavate the timeline. Preserve the proof.</h1>
      </div>
      <div class="intro-side">
        <div class="terminal-demo" aria-label="Animated terminal showing Linux process masquerading evidence">
          <div class="terminal-surface">
            <div class="terminal-bar">
              <span class="terminal-chip">λ_Terminal</span>
              <span class="terminal-host">sec-lab</span>
              <span class="terminal-time">15:25</span>
            </div>
            <div class="terminal-line line-1"><span class="terminal-prompt">λ</span> <span class="terminal-comment"># a process can fake its name (argv[0])</span></div>
            <div class="terminal-line line-2"><span class="terminal-prompt">λ</span> <span class="terminal-cmd">exec -a '[kworker/0:2]' sleep 300 &amp;</span></div>
            <div class="terminal-line line-3"><span class="terminal-result">[1] 19504</span></div>
            <div class="terminal-line line-4"><span class="terminal-prompt">λ</span> <span class="terminal-cmd">tracequarry --tag process_masquerade</span></div>
            <div class="terminal-line line-5"><span class="terminal-result">tagged: ttp.masquerading · attack.T1036</span></div>
            <span class="terminal-cursor" aria-hidden="true"></span>
            <span class="terminal-scan" aria-hidden="true"></span>
          </div>
        </div>
        <p class="intro-copy">Parse UAC archives into a defensible Linux incident timeline. Choose one evidence source, set the incident window, add known indicators, and keep CLI-compatible outputs ready for review.</p>
      </div>
    </div>
    <div class="workbench">
    <section class="reveal">
      <h2>Evidence Intake</h2>
      <p class="section-lede">Use either browser upload or a server-side path. If both are filled, the selected source mode controls which input is used.</p>
      <form id="run-form">
        <div class="source-grid" role="radiogroup" aria-label="Evidence source mode">
          <label class="source-card active" id="upload-card">
            <input id="source_upload" name="source_mode" type="radio" value="upload" checked>
            <span class="source-title">Archive upload <span class="radio-mark"></span></span>
            <span class="source-desc">Select a `.tar.gz`, `.tgz`, `.tar`, or `.zip` UAC output from this browser.</span>
          </label>
          <label class="source-card" id="path-card">
            <input id="source_path" name="source_mode" type="radio" value="path">
            <span class="source-title">Server path <span class="radio-mark"></span></span>
            <span class="source-desc">Use a file or extracted UAC directory that already exists on this machine.</span>
          </label>
        </div>

        <div class="field-panel" id="upload-panel">
          <label for="uac_file">UAC archive upload</label>
          <input id="uac_file" name="uac_file" type="file" accept=".tar,.gz,.tgz,.zip,.json,.txt" multiple>
          <div class="hint">Select one or more UAC archives. Multiple files create a case workspace under <kbd>web_runs/outputs</kbd>.</div>
        </div>

        <div class="field-panel" id="path-panel" hidden>
          <label for="input_path">Server-side input path</label>
          <textarea id="input_path" name="input_path" placeholder="/cases/uac-host01.tar.gz&#10;/cases/uac-host02.tar.gz"></textarea>
          <div class="hint">One archive or extracted UAC directory per line. Multiple paths create a case workspace.</div>
        </div>

        <label for="case_name">Case name</label>
        <input id="case_name" name="case_name" placeholder="TraceQuarry Case">

        <label for="threat_type">Assisted investigation</label>
        <select id="threat_type" name="threat_type">
          <option value="">No investigation profile</option>
{threat_options}
        </select>
        <div class="assist-profile" id="assist-profile" hidden>
          <div class="assist-profile-head"><span class="assist-profile-mark"></span><strong id="assist-profile-label"></strong></div>
          <p id="assist-profile-description"></p>
          <small>Prioritizes evidence and analyst pivots. The full timeline and all findings remain available.</small>
        </div>

        <div class="row">
          <div>
            <label for="incident_start_trigger">Incident start</label>
            <div class="tq-datetime" data-picker="incident_start">
              <input id="incident_start" name="incident_start" type="hidden">
              <button class="tq-dt-trigger" id="incident_start_trigger" type="button" aria-haspopup="dialog" aria-expanded="false" aria-controls="incident_start_panel">
                <span class="tq-dt-value placeholder" id="incident_start_display">Select start time</span>
                <span class="tq-dt-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M8 2v4M16 2v4M3.5 9.5h17M5.5 5h13A2.5 2.5 0 0 1 21 7.5v11A2.5 2.5 0 0 1 18.5 21h-13A2.5 2.5 0 0 1 3 18.5v-11A2.5 2.5 0 0 1 5.5 5Z"/>
                  </svg>
                </span>
              </button>
              <div class="tq-dt-panel" id="incident_start_panel" role="dialog" aria-label="Incident start picker"></div>
            </div>
          </div>
          <div>
            <label for="incident_end_trigger">Incident end</label>
            <div class="tq-datetime align-right" data-picker="incident_end">
              <input id="incident_end" name="incident_end" type="hidden">
              <button class="tq-dt-trigger" id="incident_end_trigger" type="button" aria-haspopup="dialog" aria-expanded="false" aria-controls="incident_end_panel">
                <span class="tq-dt-value placeholder" id="incident_end_display">Select end time</span>
                <span class="tq-dt-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M8 2v4M16 2v4M3.5 9.5h17M5.5 5h13A2.5 2.5 0 0 1 21 7.5v11A2.5 2.5 0 0 1 18.5 21h-13A2.5 2.5 0 0 1 3 18.5v-11A2.5 2.5 0 0 1 5.5 5Z"/>
                  </svg>
                </span>
              </button>
              <div class="tq-dt-panel" id="incident_end_panel" role="dialog" aria-label="Incident end picker"></div>
            </div>
          </div>
        </div>

        <div class="row">
          <div>
            <label for="year">Log year</label>
            <select id="year" name="year">
{year_options}
            </select>
          </div>
          <div>
            <label for="timezone">Timezone</label>
            <select id="timezone" name="timezone">
{timezone_options}
            </select>
          </div>
        </div>

        <div class="range-panel" id="range-panel" hidden>
          <h2>Parsed Evidence Range</h2>
          <p class="section-lede" id="range-summary">No inspected range yet.</p>
          <div class="range-grid">
            <div class="range-item">
              <span>Earliest</span>
              <strong id="range-earliest">-</strong>
            </div>
            <div class="range-item">
              <span>Latest</span>
              <strong id="range-latest">-</strong>
            </div>
          </div>
          <div class="coverage-readiness">
            <div class="coverage-head"><strong>Evidence readiness</strong><span id="coverage-score">Not inspected</span></div>
            <div class="coverage-groups" id="coverage-groups"></div>
          </div>
        </div>

        <label for="host">Host override</label>
        <input id="host" name="host" placeholder="linux-host01.example.invalid">

        <label for="iocs">Known IoCs</label>
        <textarea id="iocs" name="iocs" placeholder="198.51.100.50,ip,synthetic source&#10;rclone,literal,tooling&#10;/tmp/.x,path,suspicious artifact"></textarea>
        <div class="hint">One per line. Format: <code>value</code> or <code>value,kind,label</code>. Kinds: ip, domain, hash, path, literal.</div>

        <div class="action-row">
          <button id="inspect-button" class="secondary" type="button">Inspect Time Range</button>
          <button id="run-button" type="submit">Start Analysis</button>
        </div>
      </form>
    </section>
    <section class="reveal">
      <h2>Live Run</h2>
      <p class="section-lede">Jobs run in the background. Results appear here as soon as the parser finishes writing the timeline, findings, IoC hits, and source index.</p>
      <div id="status" class="status">No job started.</div>
      <div id="run-progress" class="run-progress" hidden>
        <div class="progress-head">
          <strong id="progress-title">Preparing parser</strong>
          <span id="progress-percent">0%</span>
        </div>
        <div class="progress-track" aria-hidden="true"><div class="progress-fill" id="progress-fill"></div></div>
        <div class="progress-steps" id="progress-steps"></div>
      </div>
      <div id="metrics" class="metrics" hidden></div>
      <div id="run-actions" class="run-actions" hidden>
        <button id="preview-summary" type="button">Preview Summary</button>
        <button id="explore-timeline" type="button">Explore Timeline</button>
        <a id="download-summary" href="#" target="_blank" rel="noopener">Open summary.md</a>
      </div>
      <ul id="files" class="files"></ul>
      <div class="console" id="console" hidden>
        <div class="chrome"><i></i><i></i><i></i></div>
        <pre id="details"></pre>
      </div>
    </section>
    </div>
  </main>
  <div id="summary-modal" class="modal-backdrop" hidden>
    <div class="summary-modal" role="dialog" aria-modal="true" aria-labelledby="summary-modal-title">
      <header>
        <div class="summary-title">
          <h2 id="summary-modal-title">TraceQuarry Summary Preview</h2>
          <p class="summary-kicker">Analyst report view from summary.md</p>
        </div>
        <button id="summary-close" class="modal-close" type="button" aria-label="Close summary preview">×</button>
      </header>
      <div class="summary-body"><div id="summary-preview" class="summary-report"><p class="summary-empty">Loading summary...</p></div></div>
      <div class="summary-footer">
        <a id="summary-open" href="#" target="_blank" rel="noopener">Open file</a>
        <button id="summary-close-footer" type="button">Close</button>
      </div>
    </div>
  </div>
  <div id="timeline-modal" class="modal-backdrop" hidden>
    <div class="timeline-modal" role="dialog" aria-modal="true" aria-labelledby="timeline-modal-title">
      <header>
        <div class="summary-title">
          <h2 id="timeline-modal-title">Evidence Timeline</h2>
          <p class="summary-kicker">Aggregated events, raw records, provenance, and analyst annotations</p>
        </div>
        <button id="timeline-close" class="modal-close" type="button" aria-label="Close timeline explorer">×</button>
      </header>
      <div class="timeline-toolbar">
        <input id="timeline-search" type="search" placeholder="Search raw logs, users, IPs, commands...">
        <select id="timeline-severity" aria-label="Filter severity"><option value="">All severities</option></select>
        <select id="timeline-source" aria-label="Filter source type"><option value="">All source types</option></select>
        <select id="timeline-scope" aria-label="Timeline scope"><option value="mini">Incident window</option><option value="full">Full timeline</option></select>
      </div>
      <div class="timeline-workspace">
        <div class="timeline-stream">
          <div class="timeline-stream-head"><strong>Chronological evidence</strong><span id="timeline-count">Loading...</span></div>
          <div id="timeline-list" class="timeline-list"></div>
          <div class="timeline-pagination">
            <button id="timeline-prev" type="button">Previous</button>
            <span id="timeline-page">-</span>
            <button id="timeline-next" type="button">Next</button>
          </div>
        </div>
        <aside id="event-detail" class="event-detail"><div class="event-empty">Select an event to inspect its normalized fields and original raw record.</div></aside>
      </div>
    </div>
  </div>
  <script>
    const form = document.getElementById('run-form');
    const button = document.getElementById('run-button');
    const inspectButton = document.getElementById('inspect-button');
    const statusBox = document.getElementById('status');
    const runProgress = document.getElementById('run-progress');
    const progressTitle = document.getElementById('progress-title');
    const progressPercent = document.getElementById('progress-percent');
    const progressFill = document.getElementById('progress-fill');
    const progressSteps = document.getElementById('progress-steps');
    const metricsBox = document.getElementById('metrics');
    const runActions = document.getElementById('run-actions');
    const previewSummary = document.getElementById('preview-summary');
    const exploreTimeline = document.getElementById('explore-timeline');
    const downloadSummary = document.getElementById('download-summary');
    const filesBox = document.getElementById('files');
    const consoleBox = document.getElementById('console');
    const detailsBox = document.getElementById('details');
    const summaryModal = document.getElementById('summary-modal');
    const summaryPreview = document.getElementById('summary-preview');
    const summaryOpen = document.getElementById('summary-open');
    const summaryClose = document.getElementById('summary-close');
    const summaryCloseFooter = document.getElementById('summary-close-footer');
    const timelineModal = document.getElementById('timeline-modal');
    const timelineClose = document.getElementById('timeline-close');
    const timelineSearch = document.getElementById('timeline-search');
    const timelineSeverity = document.getElementById('timeline-severity');
    const timelineSource = document.getElementById('timeline-source');
    const timelineScope = document.getElementById('timeline-scope');
    const timelineList = document.getElementById('timeline-list');
    const timelineCount = document.getElementById('timeline-count');
    const timelinePage = document.getElementById('timeline-page');
    const timelinePrev = document.getElementById('timeline-prev');
    const timelineNext = document.getElementById('timeline-next');
    const eventDetail = document.getElementById('event-detail');
    const rangePanel = document.getElementById('range-panel');
    const rangeSummary = document.getElementById('range-summary');
    const rangeEarliest = document.getElementById('range-earliest');
    const rangeLatest = document.getElementById('range-latest');
    const coverageScore = document.getElementById('coverage-score');
    const coverageGroups = document.getElementById('coverage-groups');
    const incidentStart = document.getElementById('incident_start');
    const incidentEnd = document.getElementById('incident_end');
    const sourceRadios = [...document.querySelectorAll('input[name="source_mode"]')];
    const uploadCard = document.getElementById('upload-card');
    const pathCard = document.getElementById('path-card');
    const uploadPanel = document.getElementById('upload-panel');
    const pathPanel = document.getElementById('path-panel');
    const uploadInput = document.getElementById('uac_file');
    const pathInput = document.getElementById('input_path');
    const threatType = document.getElementById('threat_type');
    const assistProfile = document.getElementById('assist-profile');
    const assistProfileLabel = document.getElementById('assist-profile-label');
    const assistProfileDescription = document.getElementById('assist-profile-description');
    const threatProfiles = {threat_profiles_json};
    const csrfToken = {json.dumps(csrf_token)};
    const datePickers = {{
      incident_start: createDateTimePicker('incident_start', 'Select start time'),
      incident_end: createDateTimePicker('incident_end', 'Select end time')
    }};
    let pollTimer = null;
    let activeJobId = null;
    let activeSummaryUrl = '';
    let summaryShownForJob = '';
    let timelineSearchTimer = null;
    let timelineState = {{ offset: 0, limit: 80, total: 0, items: [], selectedEventId: '' }};
    const progressStages = [
      ['queued', 'Job accepted'],
      ['parsing', 'Parsing evidence'],
      ['normalizing', 'Normalizing timeline'],
      ['writing_outputs', 'Writing outputs'],
      ['complete', 'Ready for review']
    ];

    for (const radio of sourceRadios) {{
      radio.addEventListener('change', syncSourceMode);
    }}
    syncSourceMode();
    threatType.addEventListener('change', syncThreatProfile);
    syncThreatProfile();

    function syncThreatProfile() {{
      const selected = threatProfiles.find(profile => profile.id === threatType.value);
      assistProfile.hidden = !selected;
      assistProfileLabel.textContent = selected ? selected.label : '';
      assistProfileDescription.textContent = selected ? selected.description : '';
    }}

    const observer = new IntersectionObserver((entries) => {{
      for (const entry of entries) {{
        if (entry.isIntersecting) entry.target.classList.add('visible');
      }}
    }}, {{ threshold: 0.12 }});
    document.querySelectorAll('.reveal').forEach((node, index) => {{
      node.style.transitionDelay = `${{index * 70}}ms`;
      observer.observe(node);
    }});

    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      const mode = getSourceMode();
      if (!validateEvidenceInput(mode)) return;
      button.disabled = true;
      inspectButton.disabled = true;
      filesBox.innerHTML = '';
      runActions.hidden = true;
      activeSummaryUrl = '';
      summaryShownForJob = '';
      metricsBox.hidden = true;
      consoleBox.hidden = true;
      updateProgress({{ status: 'queued', stage: 'queued', progress: 6 }});
      setStatus('running', 'Submitting job...');
      const body = buildEvidenceFormData(mode);
      const response = await fetch('/api/run', {{
        method: 'POST', headers: {{ 'X-TraceQuarry-CSRF': csrfToken }}, body
      }});
      const data = await response.json();
      if (!response.ok) {{
        setStatus('failed', data.error || 'Unable to start job');
        button.disabled = false;
        inspectButton.disabled = false;
        return;
      }}
      activeJobId = data.job_id;
      pollJob(data.job_id);
    }});

    inspectButton.addEventListener('click', async () => {{
      const mode = getSourceMode();
      if (!validateEvidenceInput(mode)) return;
      button.disabled = true;
      inspectButton.disabled = true;
      setStatus('running', 'Parsing evidence time range...');
      try {{
        const response = await fetch('/api/inspect', {{
          method: 'POST', headers: {{ 'X-TraceQuarry-CSRF': csrfToken }}, body: buildEvidenceFormData(mode)
        }});
        const data = await response.json();
        if (!response.ok) {{
          setStatus('failed', data.error || 'Unable to inspect time range');
          return;
        }}
        renderTimeRange(data);
        setStatus('complete', 'Evidence range parsed. Review or adjust the incident window.');
      }} catch (error) {{
        setStatus('failed', error.message || 'Unable to inspect time range');
      }} finally {{
        button.disabled = false;
        inspectButton.disabled = false;
      }}
    }});

    async function pollJob(jobId) {{
      clearTimeout(pollTimer);
      const response = await fetch(`/api/job/${{jobId}}`);
      const job = await response.json();
      renderJob(job);
      if (job.status === 'queued' || job.status === 'running') {{
        pollTimer = setTimeout(() => pollJob(jobId), 1500);
      }} else {{
        button.disabled = false;
        inspectButton.disabled = false;
      }}
    }}

    function renderJob(job) {{
      if (job.id) activeJobId = job.id;
      setStatus(job.status || 'failed', job.status ? `Job ${{job.id}}: ${{job.status}}` : 'Unknown job');
      updateProgress(job);
      consoleBox.hidden = false;
      detailsBox.textContent = JSON.stringify(job, null, 2);
      if (job.result) {{
        metricsBox.hidden = false;
        const metricItems = [
          metric('Events', job.result.events),
          metric('Mini Events', job.result.mini_events),
          metric('Findings', job.result.findings),
          metric('IoC Hits', job.result.ioc_hits)
        ];
        if (job.result.collections) metricItems.unshift(metric('Collections', job.result.collections));
        if (job.result.correlations) metricItems.push(metric('Correlations', job.result.correlations));
        metricsBox.innerHTML = metricItems.join('');
      }}
      filesBox.innerHTML = '';
      const summaryFile = (job.outputs || []).find(file => file.name === 'case_summary.md') ||
        (job.outputs || []).find(file => file.name === 'summary.md');
      activeSummaryUrl = summaryFile ? summaryFile.url : '';
      runActions.hidden = !(job.status === 'complete' && activeSummaryUrl);
      if (activeSummaryUrl) {{
        downloadSummary.href = activeSummaryUrl;
        summaryOpen.href = activeSummaryUrl;
      }}
      for (const file of job.outputs || []) {{
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = file.url;
        a.textContent = file.name;
        a.target = '_blank';
        const size = document.createElement('span');
        size.className = 'hint';
        size.textContent = formatBytes(file.size);
        li.appendChild(a);
        li.appendChild(size);
        filesBox.appendChild(li);
      }}
      if (job.status === 'complete' && activeSummaryUrl && summaryShownForJob !== job.id) {{
        summaryShownForJob = job.id;
        openSummaryPreview(activeSummaryUrl);
      }}
      if (job.error) setStatus('failed', job.error);
    }}

    previewSummary.addEventListener('click', () => {{
      if (activeSummaryUrl) openSummaryPreview(activeSummaryUrl);
    }});
    exploreTimeline.addEventListener('click', openTimelineExplorer);
    timelineClose.addEventListener('click', closeTimelineExplorer);
    timelineModal.addEventListener('click', (event) => {{
      if (event.target === timelineModal) closeTimelineExplorer();
    }});
    timelineSearch.addEventListener('input', () => {{
      clearTimeout(timelineSearchTimer);
      timelineSearchTimer = setTimeout(() => {{ timelineState.offset = 0; loadTimelinePage(); }}, 280);
    }});
    timelineSeverity.addEventListener('change', () => {{ timelineState.offset = 0; loadTimelinePage(); }});
    timelineSource.addEventListener('change', () => {{ timelineState.offset = 0; loadTimelinePage(); }});
    timelineScope.addEventListener('change', () => {{ timelineState.offset = 0; loadTimelinePage(); }});
    timelinePrev.addEventListener('click', () => {{
      timelineState.offset = Math.max(0, timelineState.offset - timelineState.limit);
      loadTimelinePage();
    }});
    timelineNext.addEventListener('click', () => {{
      if (timelineState.offset + timelineState.limit < timelineState.total) {{
        timelineState.offset += timelineState.limit;
        loadTimelinePage();
      }}
    }});
    summaryClose.addEventListener('click', closeSummaryPreview);
    summaryCloseFooter.addEventListener('click', closeSummaryPreview);
    summaryModal.addEventListener('click', (event) => {{
      if (event.target === summaryModal) closeSummaryPreview();
    }});
    document.addEventListener('keydown', (event) => {{
      if (event.key === 'Escape' && !summaryModal.hidden) closeSummaryPreview();
      if (event.key === 'Escape' && !timelineModal.hidden) closeTimelineExplorer();
    }});

    function openTimelineExplorer() {{
      if (!activeJobId) return;
      timelineModal.hidden = false;
      timelineState = {{ offset: 0, limit: 80, total: 0, items: [], selectedEventId: '' }};
      timelineSearch.value = '';
      timelineSeverity.value = '';
      timelineSource.value = '';
      timelineScope.value = 'mini';
      eventDetail.innerHTML = '<div class="event-empty">Select an event to inspect its normalized fields and original raw record.</div>';
      loadTimelinePage();
      timelineSearch.focus();
    }}

    function closeTimelineExplorer() {{
      timelineModal.hidden = true;
      clearTimeout(timelineSearchTimer);
      if (!runActions.hidden) exploreTimeline.focus();
    }}

    async function loadTimelinePage() {{
      if (!activeJobId) return;
      timelineList.innerHTML = '<p class="summary-empty">Loading timeline evidence...</p>';
      const params = new URLSearchParams({{
        scope: timelineScope.value,
        offset: String(timelineState.offset),
        limit: String(timelineState.limit)
      }});
      if (timelineSearch.value.trim()) params.set('q', timelineSearch.value.trim());
      if (timelineSeverity.value) params.set('severity', timelineSeverity.value);
      if (timelineSource.value) params.set('source_type', timelineSource.value);
      try {{
        const response = await fetch(`/api/job/${{activeJobId}}/timeline?${{params.toString()}}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to load timeline');
        timelineState.total = Number(data.total || 0);
        timelineState.items = data.items || [];
        timelineState.limit = Number(data.limit || 80);
        timelineState.offset = Number(data.offset || 0);
        timelineScope.value = data.scope || timelineScope.value;
        renderTimelineFacets(data.facets || {{}});
        renderTimelineEvents();
        const first = timelineState.items.find(item => item.event_id === timelineState.selectedEventId) || timelineState.items[0];
        if (first) showEventDetail(first.event_id);
        else eventDetail.innerHTML = '<div class="event-empty">No events match the selected filters.</div>';
      }} catch (error) {{
        timelineList.innerHTML = `<p class="summary-empty">${{escapeHtml(String(error.message || error))}}</p>`;
      }}
    }}

    function renderTimelineFacets(facets) {{
      const selectedSeverity = timelineSeverity.value;
      const selectedSource = timelineSource.value;
      timelineSeverity.innerHTML = '<option value="">All severities</option>' + Object.entries(facets.severity || {{}})
        .map(([value, count]) => `<option value="${{escapeHtml(value)}}">${{escapeHtml(value)}} (${{Number(count).toLocaleString()}})</option>`).join('');
      timelineSource.innerHTML = '<option value="">All source types</option>' + Object.entries(facets.source_type || {{}})
        .map(([value, count]) => `<option value="${{escapeHtml(value)}}">${{escapeHtml(value)}} (${{Number(count).toLocaleString()}})</option>`).join('');
      timelineSeverity.value = selectedSeverity;
      timelineSource.value = selectedSource;
    }}

    function renderTimelineEvents() {{
      timelineCount.textContent = `${{timelineState.total.toLocaleString()}} matching event(s)`;
      const start = timelineState.total ? timelineState.offset + 1 : 0;
      const end = Math.min(timelineState.total, timelineState.offset + timelineState.items.length);
      timelinePage.textContent = `${{start.toLocaleString()}}-${{end.toLocaleString()}} of ${{timelineState.total.toLocaleString()}}`;
      timelinePrev.disabled = timelineState.offset <= 0;
      timelineNext.disabled = end >= timelineState.total;
      if (!timelineState.items.length) {{
        timelineList.innerHTML = '<p class="summary-empty">No events match the selected filters.</p>';
        return;
      }}
      timelineList.innerHTML = timelineState.items.map((event) => {{
        const annotation = event.analyst_annotation || {{}};
        const annotated = (annotation.tags || []).length || annotation.note || (annotation.disposition && annotation.disposition !== 'unreviewed');
        const source = [event.collection_host || event.host, event.source_type].filter(Boolean).join(' · ');
        return `
          <button class="timeline-event${{event.event_id === timelineState.selectedEventId ? ' active' : ''}}" type="button" data-event-id="${{escapeHtml(String(event.event_id || ''))}}">
            <span class="timeline-time">${{escapeHtml(formatUtcTimestamps(String(event.timestamp || 'Untimed')))}}</span>
            <span class="severity-pill ${{escapeHtml(String(event.severity || 'informational'))}}">${{escapeHtml(String(event.severity || 'info'))}}</span>
            <span class="timeline-event-copy">
              <strong>${{annotated ? '<span class="annotation-dot"></span>' : ''}}${{escapeHtml(String(event.summary || event.event_action || 'Timeline event'))}}</strong>
              <small>${{escapeHtml(source || event.source_path || 'unknown source')}}</small>
            </span>
          </button>`;
      }}).join('');
      timelineList.querySelectorAll('[data-event-id]').forEach((button) => {{
        button.addEventListener('click', () => showEventDetail(button.dataset.eventId));
      }});
    }}

    function showEventDetail(eventId) {{
      const event = timelineState.items.find(item => item.event_id === eventId);
      if (!event) return;
      timelineState.selectedEventId = eventId;
      renderTimelineEvents();
      const annotation = event.analyst_annotation || {{}};
      const tags = [...(event.tags || []), ...(event.detection_names || []), ...(event.mitre || [])];
      const fields = [
        ['Timestamp', formatUtcTimestamps(String(event.timestamp || 'Untimed'))],
        ['Host', event.collection_host || event.host || '-'],
        ['Collection', event.collection_name || event.collection_id || 'single collection'],
        ['Source', `${{event.source_type || '-'}} · ${{event.source_path || '-' }}`],
        ['Action', event.event_action || '-'],
        ['User', event.user || '-'],
        ['Source IP', event.src_ip || '-'],
        ['Destination', [event.dst_ip, event.port].filter(Boolean).join(':') || '-'],
        ['Process', [event.process, event.pid].filter(Boolean).join(' · ') || '-'],
        ['Confidence', event.confidence || '-']
      ];
      eventDetail.innerHTML = `
        <div class="event-detail-head">
          <h3>${{escapeHtml(String(event.summary || event.event_action || 'Timeline event'))}}</h3>
          <p>${{escapeHtml(String(event.event_id || ''))}}</p>
        </div>
        <div class="event-field-grid">${{fields.map(([label, value]) => `
          <div class="event-field"><span>${{escapeHtml(label)}}</span><strong>${{escapeHtml(String(value))}}</strong></div>`).join('')}}</div>
        <section class="event-section"><h4>Detection and ATT&amp;CK tags</h4><div class="tag-row">${{
          tags.length ? [...new Set(tags)].map(tag => `<span class="event-tag">${{escapeHtml(String(tag))}}</span>`).join('') : '<span class="hint">No parser tags.</span>'
        }}</div></section>
        <section class="event-section"><h4>Raw evidence</h4><div class="raw-record">${{escapeHtml(String(event.raw || event.command || event.file_path || 'No raw record retained.'))}}</div></section>
        ${{event.related_event_ids?.length ? `<section class="event-section"><h4>Related events</h4><div class="tag-row">${{event.related_event_ids.map(id => `<span class="event-tag">${{escapeHtml(String(id))}}</span>`).join('')}}</div></section>` : ''}}
        <section class="event-section"><h4>Analyst annotation</h4>
          <div class="annotation-form">
            <label>Disposition<select id="annotation-disposition">
              ${{annotationDispositionOptions(annotation.disposition || 'unreviewed')}}
            </select></label>
            <label>Tags<input id="annotation-tags" value="${{escapeHtml((annotation.tags || []).join(', '))}}" placeholder="confirmed, escalation, false_positive"></label>
            <label>Note<textarea id="annotation-note" placeholder="Record validation, context, or next action...">${{escapeHtml(String(annotation.note || ''))}}</textarea></label>
            <div id="annotation-status" class="annotation-status"></div>
            <button id="annotation-save" type="button">Save annotation</button>
          </div>
        </section>`;
      document.getElementById('annotation-save').addEventListener('click', () => saveEventAnnotation(event));
    }}

    function annotationDispositionOptions(selected) {{
      const options = [
        ['unreviewed', 'Unreviewed'], ['suspicious', 'Suspicious'], ['malicious', 'Malicious'],
        ['benign', 'Benign'], ['needs_context', 'Needs context']
      ];
      return options.map(([value, label]) => `<option value="${{value}}"${{value === selected ? ' selected' : ''}}>${{label}}</option>`).join('');
    }}

    async function saveEventAnnotation(event) {{
      const status = document.getElementById('annotation-status');
      const payload = {{
        event_id: event.event_id,
        disposition: document.getElementById('annotation-disposition').value,
        tags: document.getElementById('annotation-tags').value.split(',').map(value => value.trim()).filter(Boolean),
        note: document.getElementById('annotation-note').value
      }};
      status.textContent = 'Saving...';
      try {{
        const response = await fetch(`/api/job/${{activeJobId}}/annotations`, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json', 'X-TraceQuarry-CSRF': csrfToken }},
          body: JSON.stringify(payload)
        }});
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to save annotation');
        event.analyst_annotation = data.annotation || {{}};
        status.textContent = 'Annotation saved separately from parser evidence.';
        renderTimelineEvents();
      }} catch (error) {{
        status.textContent = error.message || 'Unable to save annotation.';
      }}
    }}

    function updateProgress(job) {{
      const status = job.status || 'queued';
      const stage = job.stage || status;
      let percent = Number(job.progress || 0);
      if (!percent) {{
        if (status === 'queued') percent = 8;
        else if (status === 'running') percent = 44;
        else if (status === 'complete') percent = 100;
        else if (status === 'failed') percent = 100;
      }}
      runProgress.hidden = false;
      progressFill.style.width = `${{Math.max(0, Math.min(100, percent))}}%`;
      progressPercent.textContent = `${{Math.round(percent)}}%`;
      const detail = status === 'running' ? (job.progress_detail || {{}}) : {{}};
      const sourceDetail = detail.source ? ` · ${{detail.source}}` : '';
      const countDetail = detail.total ? ` (${{Number(detail.completed || 0).toLocaleString()}}/${{Number(detail.total).toLocaleString()}})` : '';
      progressTitle.textContent = status === 'failed'
        ? 'Parser stopped with an error'
        : `${{stageLabel(stage)}}${{countDetail}}${{sourceDetail}}`;
      const activeIndex = status === 'failed'
        ? progressStages.findIndex(([key]) => key === 'writing_outputs')
        : Math.max(0, progressStages.findIndex(([key]) => key === stage));
      progressSteps.innerHTML = progressStages.map(([key, label], index) => {{
        const klass = status === 'complete' || index < activeIndex ? 'done' : index === activeIndex ? 'active' : '';
        return `<div class="progress-step ${{klass}}"><span class="step-dot"></span><span>${{escapeHtml(label)}}</span></div>`;
      }}).join('');
    }}

    function stageLabel(stage) {{
      const labels = {{
        queued: 'Queued for analysis',
        parsing: 'Parsing UAC evidence',
        sources_discovered: 'Indexing discovered evidence',
        parsing_sources: 'Parsing source artifacts',
        case_complete: 'Finalizing case correlation',
        normalizing: 'Normalizing forensic timeline',
        writing_outputs: 'Writing review outputs',
        complete: 'Summary ready for review',
        failed: 'Parser stopped with an error'
      }};
      return labels[stage] || 'Parser is running';
    }}

    async function openSummaryPreview(url) {{
      summaryModal.hidden = false;
      summaryPreview.innerHTML = '<p class="summary-empty">Loading summary...</p>';
      summaryOpen.href = url;
      try {{
        const response = await fetch(url, {{ cache: 'no-store' }});
        if (!response.ok) throw new Error('Unable to load summary.md');
        const rawSummary = await response.text();
        summaryPreview.innerHTML = renderSummaryReport(rawSummary);
      }} catch (error) {{
        summaryPreview.innerHTML = `<pre class="summary-raw">${{escapeHtml(error.message || 'Unable to load summary.md')}}</pre>`;
      }}
      summaryClose.focus();
    }}

    function closeSummaryPreview() {{
      summaryModal.hidden = true;
      if (previewSummary && !previewSummary.disabled && !runActions.hidden) previewSummary.focus();
    }}

    function renderSummaryReport(raw) {{
      const parsed = parseSummary(raw);
      const metrics = parsed.metrics;
      const highCount = Number(metrics['High severity findings'] || 0);
      const statItems = [
        ['Total events', metrics['Total events'] || '0'],
        ['Findings', metrics['Findings'] || '0'],
        ['High severity', metrics['High severity findings'] || '0'],
        ['Storylines', metrics['Storylines'] || '0']
      ];
      const statsHtml = statItems.map(([label, value]) => `
        <div class="summary-stat">
          <span>${{escapeHtml(label)}}</span>
          <strong>${{escapeHtml(String(value))}}</strong>
        </div>
      `).join('');
      const sectionsHtml = parsed.sections.length
        ? parsed.sections.map(renderSummarySection).join('')
        : `<section class="summary-section"><p class="summary-empty">No structured sections found in summary.md.</p></section>`;
      return `
        <div class="summary-hero">
          <div>
            <h3>${{escapeHtml(parsed.title || 'TraceQuarry Summary')}}</h3>
            <p>Review the parser findings, scope notes, storylines, and recommended next steps. Timestamps are displayed in analyst-readable UTC form.</p>
          </div>
          <span class="summary-badge">${{highCount ? `${{highCount}} high severity` : 'No high severity'}}</span>
        </div>
        <div class="summary-stat-grid">${{statsHtml}}</div>
        ${{sectionsHtml}}
      `;
    }}

    function parseSummary(raw) {{
      const lines = raw.split(/\\r?\\n/);
      const metrics = {{}};
      const sections = [];
      let title = 'TraceQuarry Summary';
      let current = null;
      for (const line of lines) {{
        if (line.startsWith('# ')) {{
          title = line.slice(2).trim();
          continue;
        }}
        if (line.startsWith('## ')) {{
          current = {{ title: line.slice(3).trim(), items: [] }};
          sections.push(current);
          continue;
        }}
        if (!current) {{
          const match = line.match(/^([^:]+):\\s*(.+)$/);
          if (match) metrics[match[1].trim()] = match[2].trim();
          continue;
        }}
        if (!line.trim()) continue;
        current.items.push(line);
      }}
      return {{ title, metrics, sections }};
    }}

    function renderSummarySection(section) {{
      const title = section.title || 'Summary';
      const normalized = title.toLowerCase();
      const cardType = normalized.includes('high severity') ? 'high' :
        normalized.includes('recommended next') ? 'next' : '';
      const content = section.items.length
        ? section.items.map((item) => renderSummaryItem(item, cardType)).join('')
        : '<p class="summary-empty">No entries identified.</p>';
      const wrapperClass = section.items.some(item => item.trim().startsWith('-')) ? 'summary-list' : '';
      return `
        <section class="summary-section">
          <h3>${{escapeHtml(title)}}</h3>
          <div class="${{wrapperClass}}">${{content}}</div>
        </section>
      `;
    }}

    function renderSummaryItem(item, cardType) {{
      const trimmed = item.trim();
      if (trimmed.startsWith('-')) {{
        const text = trimmed.replace(/^-\\s*/, '');
        const titleMatch = text.match(/^\\*\\*([^*]+)\\*\\*:\\s*(.*)$/);
        const title = titleMatch ? titleMatch[1] : '';
        const body = titleMatch ? titleMatch[2] : text;
        const klass = ['finding-card', cardType].filter(Boolean).join(' ');
        return `
          <article class="${{klass}}">
            <span class="finding-dot" aria-hidden="true"></span>
            <div>
              ${{title ? `<strong class="finding-title">${{escapeHtml(formatUtcTimestamps(title))}}</strong>` : ''}}
              <div class="finding-text">${{formatSummaryInline(body)}}</div>
            </div>
          </article>
        `;
      }}
      return `<p class="summary-paragraph">${{formatSummaryInline(trimmed)}}</p>`;
    }}

    function formatSummaryInline(value) {{
      return escapeHtml(formatUtcTimestamps(value))
        .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>');
    }}

    function formatUtcTimestamps(value) {{
      return String(value).replace(/(\\d{{4}})-(\\d{{2}})-(\\d{{2}})T(\\d{{2}}):(\\d{{2}}):(\\d{{2}})Z/g, '$1-$2-$3 $4:$5:$6 (UTC)');
    }}

    function renderTimeRange(data) {{
      rangePanel.hidden = false;
      if (!data.earliest || !data.latest) {{
        rangeSummary.textContent = `Parsed ${{Number(data.events || 0).toLocaleString()}} events, but no timestamped events were found.`;
        rangeEarliest.textContent = '-';
        rangeLatest.textContent = '-';
        renderCoverageReadiness(data.source_types || []);
        return;
      }}
      if (data.earliest_local) incidentStart.value = data.earliest_local;
      if (data.latest_local) incidentEnd.value = data.latest_local;
      if (data.earliest_local) updateDateTimePicker('incident_start', data.earliest_local);
      if (data.latest_local) updateDateTimePicker('incident_end', data.latest_local);
      const basis = data.range_basis === 'log_time' ? `${{Number(data.log_events || 0).toLocaleString()}} log-time events` : `${{Number(data.timed_events || 0).toLocaleString()}} timestamped events`;
      const collectionText = data.collections && data.collections > 1 ? ` across ${{Number(data.collections).toLocaleString()}} collections` : '';
      const exclusionText = data.excluded_files ? ` ${{Number(data.excluded_files).toLocaleString()}} non-evidence metadata file(s) excluded and recorded.` : '';
      rangeSummary.textContent = `${{basis}} across ${{Number(data.sources || 0).toLocaleString()}} sources${{collectionText}}. Window filled in ${{data.timezone || 'UTC'}}.${{exclusionText}}`;
      rangeEarliest.textContent = data.earliest_display || data.earliest;
      rangeLatest.textContent = data.latest_display || data.latest;
      renderCoverageReadiness(data.source_types || []);
    }}

    function renderCoverageReadiness(sourceTypes) {{
      const available = new Set(sourceTypes);
      const groups = [
        ['Authentication', ['auth_log', 'login_history']],
        ['Audit', ['auditd']],
        ['Command history', ['shell_history']],
        ['Network state', ['ss_output', 'netstat_output']],
        ['Processes', ['ps_output']],
        ['Accounts', ['passwd', 'shadow', 'group']],
        ['Persistence', ['cron_file', 'systemd_unit', 'authorized_keys', 'pam_config']],
        ['Filesystem', ['bodyfile']]
      ];
      const states = groups.map(([label, kinds]) => [label, kinds.some(kind => available.has(kind))]);
      const present = states.filter(([, ready]) => ready).length;
      coverageScore.textContent = `${{present}}/${{states.length}} evidence classes present`;
      coverageGroups.innerHTML = states.map(([label, ready]) =>
        `<span class="coverage-chip${{ready ? '' : ' missing'}}" title="${{ready ? 'Evidence discovered' : 'Evidence not discovered'}}">${{escapeHtml(label)}}</span>`
      ).join('');
    }}

    function createDateTimePicker(id, placeholder) {{
      const root = document.querySelector(`[data-picker="${{id}}"]`);
      const input = document.getElementById(id);
      const trigger = document.getElementById(`${{id}}_trigger`);
      const display = document.getElementById(`${{id}}_display`);
      const panel = document.getElementById(`${{id}}_panel`);
      const now = new Date();
      const selected = parsePickerValue(input.value) || new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours(), now.getMinutes(), 0);
      const picker = {{
        id,
        root,
        input,
        trigger,
        display,
        panel,
        placeholder,
        viewYear: selected.getFullYear(),
        viewMonth: selected.getMonth(),
        selected
      }};
      trigger.addEventListener('click', (event) => {{
        event.stopPropagation();
        toggleDateTimePicker(id);
      }});
      panel.addEventListener('click', (event) => event.stopPropagation());
      renderDateTimePicker(picker);
      syncDateTimeDisplay(picker);
      return picker;
    }}

    document.addEventListener('click', () => closeDateTimePickers());
    document.addEventListener('keydown', (event) => {{
      if (event.key === 'Escape') closeDateTimePickers();
    }});

    function toggleDateTimePicker(id) {{
      const picker = datePickers[id];
      const willOpen = !picker.root.classList.contains('open');
      closeDateTimePickers();
      picker.root.classList.toggle('open', willOpen);
      picker.trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
    }}

    function closeDateTimePickers() {{
      for (const picker of Object.values(datePickers)) {{
        picker.root.classList.remove('open');
        picker.trigger.setAttribute('aria-expanded', 'false');
      }}
    }}

    function updateDateTimePicker(id, value) {{
      const picker = datePickers[id];
      const parsed = parsePickerValue(value);
      if (!picker || !parsed) return;
      picker.selected = parsed;
      picker.viewYear = parsed.getFullYear();
      picker.viewMonth = parsed.getMonth();
      picker.input.value = toLocalInputValue(parsed);
      renderDateTimePicker(picker);
      syncDateTimeDisplay(picker);
    }}

    function renderDateTimePicker(picker) {{
      const monthName = new Intl.DateTimeFormat('en', {{ month: 'long', year: 'numeric' }}).format(new Date(picker.viewYear, picker.viewMonth, 1));
      const selectedHour = String(picker.selected.getHours()).padStart(2, '0');
      const selectedMinute = String(picker.selected.getMinutes()).padStart(2, '0');
      const selectedSecond = String(picker.selected.getSeconds()).padStart(2, '0');
      picker.panel.innerHTML = `
        <div class="tq-dt-head">
          <div class="tq-dt-month">${{escapeHtml(monthName)}}</div>
          <button class="tq-dt-nav" type="button" data-dt-prev aria-label="Previous month">‹</button>
          <button class="tq-dt-nav" type="button" data-dt-next aria-label="Next month">›</button>
        </div>
        <div class="tq-dt-weekdays" aria-hidden="true">
          <span>Su</span><span>Mo</span><span>Tu</span><span>We</span><span>Th</span><span>Fr</span><span>Sa</span>
        </div>
        <div class="tq-dt-days">${{renderCalendarDays(picker)}}</div>
        <div class="tq-dt-time">
          ${{renderTimeSelect('Hour', 'hour', 0, 23, selectedHour)}}
          ${{renderTimeSelect('Min', 'minute', 0, 59, selectedMinute)}}
          ${{renderTimeSelect('Sec', 'second', 0, 59, selectedSecond)}}
        </div>
        <div class="tq-dt-actions">
          <button class="tq-dt-action clear" type="button" data-dt-clear>Clear</button>
          <button class="tq-dt-action now" type="button" data-dt-now>Use now</button>
        </div>
      `;
      picker.panel.querySelector('[data-dt-prev]').addEventListener('click', () => shiftPickerMonth(picker, -1));
      picker.panel.querySelector('[data-dt-next]').addEventListener('click', () => shiftPickerMonth(picker, 1));
      picker.panel.querySelector('[data-dt-clear]').addEventListener('click', () => clearDateTimePicker(picker));
      picker.panel.querySelector('[data-dt-now]').addEventListener('click', () => setPickerDate(picker, new Date()));
      picker.panel.querySelectorAll('[data-dt-day]').forEach((button) => {{
        button.addEventListener('click', () => {{
          const date = new Date(Number(button.dataset.year), Number(button.dataset.month), Number(button.dataset.day), picker.selected.getHours(), picker.selected.getMinutes(), picker.selected.getSeconds());
          setPickerDate(picker, date);
        }});
      }});
      picker.panel.querySelectorAll('[data-dt-time]').forEach((select) => {{
        select.addEventListener('change', () => {{
          const next = new Date(picker.selected);
          if (select.dataset.dtTime === 'hour') next.setHours(Number(select.value));
          if (select.dataset.dtTime === 'minute') next.setMinutes(Number(select.value));
          if (select.dataset.dtTime === 'second') next.setSeconds(Number(select.value));
          setPickerDate(picker, next, false);
        }});
      }});
    }}

    function renderCalendarDays(picker) {{
      const first = new Date(picker.viewYear, picker.viewMonth, 1);
      const start = new Date(picker.viewYear, picker.viewMonth, 1 - first.getDay());
      const todayKey = dateKey(new Date());
      const selectedKey = dateKey(picker.selected);
      let html = '';
      for (let i = 0; i < 42; i++) {{
        const date = new Date(start.getFullYear(), start.getMonth(), start.getDate() + i);
        const key = dateKey(date);
        const classes = [
          'tq-dt-day',
          date.getMonth() !== picker.viewMonth ? 'muted' : '',
          key === todayKey ? 'today' : '',
          key === selectedKey ? 'selected' : ''
        ].filter(Boolean).join(' ');
        html += `<button class="${{classes}}" type="button" data-dt-day data-year="${{date.getFullYear()}}" data-month="${{date.getMonth()}}" data-day="${{date.getDate()}}" aria-label="${{escapeHtml(formatDateLabel(date))}}">${{date.getDate()}}</button>`;
      }}
      return html;
    }}

    function renderTimeSelect(label, key, min, max, selected) {{
      let options = '';
      for (let value = min; value <= max; value++) {{
        const text = String(value).padStart(2, '0');
        options += `<option value="${{text}}"${{text === selected ? ' selected' : ''}}>${{text}}</option>`;
      }}
      return `<label>${{label}}<select data-dt-time="${{key}}">${{options}}</select></label>`;
    }}

    function shiftPickerMonth(picker, delta) {{
      const next = new Date(picker.viewYear, picker.viewMonth + delta, 1);
      picker.viewYear = next.getFullYear();
      picker.viewMonth = next.getMonth();
      renderDateTimePicker(picker);
    }}

    function setPickerDate(picker, date, rerender = true) {{
      picker.selected = new Date(date.getFullYear(), date.getMonth(), date.getDate(), date.getHours(), date.getMinutes(), date.getSeconds());
      picker.viewYear = picker.selected.getFullYear();
      picker.viewMonth = picker.selected.getMonth();
      picker.input.value = toLocalInputValue(picker.selected);
      syncDateTimeDisplay(picker);
      if (rerender) renderDateTimePicker(picker);
    }}

    function clearDateTimePicker(picker) {{
      picker.input.value = '';
      syncDateTimeDisplay(picker);
      closeDateTimePickers();
    }}

    function syncDateTimeDisplay(picker) {{
      if (!picker.input.value) {{
        picker.display.textContent = picker.placeholder;
        picker.display.classList.add('placeholder');
        return;
      }}
      const parsed = parsePickerValue(picker.input.value);
      picker.display.textContent = parsed ? formatPickerDisplay(parsed) : picker.input.value;
      picker.display.classList.remove('placeholder');
    }}

    function parsePickerValue(value) {{
      if (!value) return null;
      const match = String(value).match(/^(\\d{{4}})-(\\d{{2}})-(\\d{{2}})T(\\d{{2}}):(\\d{{2}})(?::(\\d{{2}}))?/);
      if (!match) return null;
      return new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0));
    }}

    function toLocalInputValue(date) {{
      return `${{date.getFullYear()}}-${{String(date.getMonth() + 1).padStart(2, '0')}}-${{String(date.getDate()).padStart(2, '0')}}T${{String(date.getHours()).padStart(2, '0')}}:${{String(date.getMinutes()).padStart(2, '0')}}:${{String(date.getSeconds()).padStart(2, '0')}}`;
    }}

    function dateKey(date) {{
      return `${{date.getFullYear()}}-${{date.getMonth()}}-${{date.getDate()}}`;
    }}

    function formatPickerDisplay(date) {{
      const day = String(date.getDate()).padStart(2, '0');
      const month = new Intl.DateTimeFormat('en', {{ month: 'short' }}).format(date);
      return `${{day}} ${{month}} ${{date.getFullYear()}}, ${{String(date.getHours()).padStart(2, '0')}}:${{String(date.getMinutes()).padStart(2, '0')}}:${{String(date.getSeconds()).padStart(2, '0')}}`;
    }}

    function formatDateLabel(date) {{
      return new Intl.DateTimeFormat('en', {{ weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }}).format(date);
    }}

    function syncSourceMode() {{
      const mode = getSourceMode();
      const uploadActive = mode === 'upload';
      uploadCard.classList.toggle('active', uploadActive);
      pathCard.classList.toggle('active', !uploadActive);
      uploadPanel.hidden = !uploadActive;
      pathPanel.hidden = uploadActive;
      uploadInput.disabled = !uploadActive;
      pathInput.disabled = uploadActive;
    }}

    function getSourceMode() {{
      return document.querySelector('input[name="source_mode"]:checked')?.value || 'upload';
    }}

    function validateEvidenceInput(mode) {{
      if (mode === 'upload' && !uploadInput.files.length) {{
        setStatus('failed', 'Choose a UAC archive upload, or switch to server path.');
        uploadInput.focus();
        return false;
      }}
      if (mode === 'path' && !pathInput.value.trim()) {{
        setStatus('failed', 'Provide a server-side input path, or switch to archive upload.');
        pathInput.focus();
        return false;
      }}
      return true;
    }}

    function buildEvidenceFormData(mode) {{
      const body = new FormData(form);
      if (mode === 'upload') body.set('input_path', '');
      if (mode === 'path') body.delete('uac_file');
      return body;
    }}

    function setStatus(kind, text) {{
      statusBox.className = `status ${{kind}}`;
      statusBox.textContent = text;
    }}

    function metric(label, value) {{
      return `<div class="metric"><strong>${{Number(value || 0).toLocaleString()}}</strong><span>${{escapeHtml(label)}}</span></div>`;
    }}

    function formatBytes(bytes) {{
      if (!bytes) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB'];
      let size = bytes;
      let idx = 0;
      while (size >= 1024 && idx < units.length - 1) {{ size /= 1024; idx++; }}
      return `${{size.toFixed(idx ? 1 : 0)}} ${{units[idx]}}`;
    }}

    function escapeHtml(value) {{
      return value.replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
    }}
  </script>
</body>
</html>"""


if __name__ == "__main__":
    raise SystemExit(main())
