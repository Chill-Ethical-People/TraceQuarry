from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import shutil
import tempfile
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, tzinfo
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from uac_parser import __version__
from uac_parser.analyst_audit import audit_status
from uac_parser.assist import profile_choices
from uac_parser.case_repository import CaseRepository
from uac_parser.enrich.iocs import parse_ioc_text
from uac_parser.output.workbook import write_investigation_workbook
from uac_parser.pipeline import (
    CasePipelineResult,
    PipelineResult,
    inspect_time_range,
    run_case_pipeline,
    run_pipeline,
)
from uac_parser.resources import resource_directory, resource_file
from uac_parser.web_briefing import (
    build_incident_briefing as _build_incident_briefing,
)
from uac_parser.web_briefing import (
    findings_for_output as _findings_for_output,
)
from uac_parser.web_runtime import ApplicationContext, WebSettings, WorkCapacityManager
from uac_parser.web_timeline import (
    CSV_EXPORT_FIELDS,
)
from uac_parser.web_timeline import (
    ResponseTextWriter as _ResponseTextWriter,
)
from uac_parser.web_timeline import (
    iter_review_rows as _iter_review_rows,
)
from uac_parser.web_timeline import (
    load_annotations as _load_annotations_impl,
)
from uac_parser.web_timeline import (
    query_value as _query_value_impl,
)
from uac_parser.web_timeline import (
    save_annotation as _save_annotation_for_output,
)
from uac_parser.web_timeline import (
    timeline_file as _timeline_file_impl,
)
from uac_parser.web_timeline import (
    timeline_page as _timeline_page_impl,
)

APP_CONTEXT = ApplicationContext()
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
CONTAINER_BIND_HOSTS = {"0.0.0.0", "::"}
DEFAULT_MAX_UPLOAD_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_WORK_BYTES = 40 * 1024 * 1024 * 1024
MIN_FREE_BYTES = 512 * 1024 * 1024
JOB_ID_PATTERN = re.compile(r"[a-f0-9]{12}")
UPLOAD_ID_PATTERN = re.compile(r"[a-f0-9]{12}")
MAX_UPLOAD_FILES = 1000
UPLOAD_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_MAINTENANCE_INTERVAL_SECONDS = 300


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracequarry-web",
        description="Run the TraceQuarry web GUI.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8765, help="Bind port")
    parser.add_argument(
        "--work-dir",
        default="web_runs",
        help="Directory for uploaded inputs and parser outputs",
    )
    parser.add_argument(
        "--input-root",
        action="append",
        default=[],
        help=(
            "Allowed root for server-side evidence paths. Repeat for multiple roots; "
            "defaults to the current directory."
        ),
    )
    parser.add_argument("--allow-remote", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--container-bind", action="store_true", help=argparse.SUPPRESS)
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
        "--case-workers",
        type=int,
        default=2,
        help="Collections parsed concurrently within a case (default: 2)",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=1800,
        help="Socket timeout per HTTP request in seconds (default: 1800)",
    )
    parser.add_argument(
        "--maintenance-interval",
        type=float,
        default=DEFAULT_MAINTENANCE_INTERVAL_SECONDS,
        help="Upload retention and capacity maintenance interval in seconds (default: 300)",
    )
    parser.add_argument(
        "--state-retention-days",
        type=int,
        default=90,
        help="Retain durable local job-state records for this many days (default: 90)",
    )
    parser.add_argument(
        "--log-format",
        choices=("text", "json"),
        default="text",
        help="Operational log format (default: text)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Include detailed parser errors in local job responses",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.host not in LOOPBACK_HOSTS and not _is_packaged_container_bind(
        args.host, args.container_bind
    ):
        raise SystemExit(
            "Refusing non-loopback bind. Use an authenticated local tunnel or reverse proxy instead; "
            "TraceQuarry does not expose its evidence API directly to a network."
        )
    if args.max_upload_gib <= 0 or args.max_work_dir_gib <= 0:
        raise SystemExit("Upload and work-directory limits must be positive.")
    if args.max_concurrent_jobs < 1:
        raise SystemExit("At least one concurrent job slot is required.")
    if args.case_workers < 1:
        raise SystemExit("At least one case worker is required.")
    if args.request_timeout < 5:
        raise SystemExit("Request timeout must be at least five seconds.")
    if args.maintenance_interval < 10:
        raise SystemExit("Maintenance interval must be at least ten seconds.")
    if args.state_retention_days < 1:
        raise SystemExit("Job-state retention must be at least one day.")
    os.umask(0o077)
    work_dir = Path(args.work_dir).expanduser().resolve()
    raw_input_roots = args.input_root or [str(Path.cwd())]
    try:
        input_roots = tuple(
            Path(value).expanduser().resolve(strict=True) for value in raw_input_roots
        )
    except OSError as exc:
        raise SystemExit(f"Unable to resolve an input root: {exc}") from exc
    if any(not root.is_dir() for root in input_roots):
        raise SystemExit("Every --input-root must be an existing directory.")
    _secure_directory(work_dir)
    _secure_directory(work_dir / "uploads")
    _secure_directory(work_dir / "outputs")
    _secure_directory(work_dir / "state")
    APP_CONTEXT.configure(
        WebSettings(
            work_dir=work_dir,
            input_roots=input_roots,
            max_request_bytes=int(args.max_upload_gib * 1024**3),
            max_work_bytes=int(args.max_work_dir_gib * 1024**3),
            minimum_free_bytes=MIN_FREE_BYTES,
            request_timeout=args.request_timeout,
            case_workers=args.case_workers,
            debug=args.debug,
            maintenance_interval=args.maintenance_interval,
            state_retention_days=args.state_retention_days,
            log_format=args.log_format,
        ),
        max_concurrent_jobs=args.max_concurrent_jobs,
    )
    _capacity_manager()
    _purge_stale_upload_sessions(work_dir)
    _case_repository()
    _restore_persisted_jobs()
    _restore_completed_jobs(work_dir)
    APP_CONTEXT.maintenance_stop.clear()
    APP_CONTEXT.maintenance_thread = threading.Thread(
        target=_maintenance_loop,
        args=(work_dir, args.maintenance_interval),
        name="tracequarry-maintenance",
        daemon=True,
    )
    APP_CONTEXT.maintenance_thread.start()
    server = HardenedThreadingHTTPServer(
        (args.host, args.port), UacWebHandler, context=APP_CONTEXT
    )
    _runtime_log(
        "server_started",
        message=f"TraceQuarry GUI listening on http://{args.host}:{args.port}",
        host=args.host,
        port=args.port,
        work_dir=str(work_dir),
        input_roots=[str(path) for path in input_roots],
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _runtime_log("server_stopping", message="Stopping TraceQuarry GUI server")
    finally:
        server.server_close()
        APP_CONTEXT.maintenance_stop.set()
        if APP_CONTEXT.maintenance_thread is not None:
            APP_CONTEXT.maintenance_thread.join(
                timeout=max(1.0, args.maintenance_interval + 1)
            )
        APP_CONTEXT.reset(flush=True)
    return 0


class HardenedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        *,
        context: ApplicationContext | None = None,
    ) -> None:
        self.context = context or APP_CONTEXT
        super().__init__(server_address, request_handler_class)


def _settings() -> WebSettings:
    return APP_CONTEXT.settings


def _work_dir() -> Path:
    return _settings().work_dir


def _capacity_manager() -> WorkCapacityManager:
    settings = _settings()
    APP_CONTEXT.capacity.configure(
        settings.work_dir,
        max_work_bytes=settings.max_work_bytes,
        minimum_free_bytes=settings.minimum_free_bytes,
        session_ttl_seconds=UPLOAD_SESSION_TTL_SECONDS,
    )
    return APP_CONTEXT.capacity


def _case_repository() -> CaseRepository:
    settings = _settings()
    APP_CONTEXT.cases.configure(
        settings.work_dir,
        retention_days=settings.state_retention_days,
    )
    return APP_CONTEXT.cases


def _runtime_log(
    event: str,
    *,
    level: str = "info",
    message: str = "",
    **fields: object,
) -> None:
    document = {
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "level": level,
        "event": event,
        **fields,
    }
    if message:
        document["message"] = message
    if _settings().log_format == "json":
        print(json.dumps(document, ensure_ascii=False, sort_keys=True), flush=True)
        return
    suffix = " ".join(
        f"{key}={value}"
        for key, value in fields.items()
        if value not in (None, "", [], {})
    )
    rendered = message or event.replace("_", " ")
    print(f"{rendered}{f' [{suffix}]' if suffix else ''}", flush=True)


def _input_roots() -> tuple[Path, ...]:
    return _settings().input_roots


def _resolve_server_input(raw_path: str) -> Path:
    try:
        candidate = Path(raw_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(
            "Server-side input does not exist or cannot be resolved."
        ) from exc
    if not any(
        candidate == root or candidate.is_relative_to(root) for root in _input_roots()
    ):
        raise ValueError(
            "Server-side input is outside the allowed roots. Restart TraceQuarry "
            "with --input-root for the evidence directory."
        )
    if not candidate.is_file() and not candidate.is_dir():
        raise ValueError("Server-side input must be a regular file or directory.")
    return candidate


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _is_packaged_container_bind(host: str, requested: bool) -> bool:
    """Allow the image entrypoint to listen inside its isolated network namespace."""
    return (
        requested
        and host in CONTAINER_BIND_HOSTS
        and os.environ.get("TRACEQUARRY_CONTAINER") == "1"
    )


def _trusted_request_ports(server_port: int) -> set[int]:
    ports = {server_port}
    if os.environ.get("TRACEQUARRY_CONTAINER") != "1":
        return ports
    try:
        public_port = int(os.environ.get("TRACEQUARRY_PUBLIC_PORT", ""))
    except ValueError:
        return ports
    if 1 <= public_port <= 65535:
        ports.add(public_port)
    return ports


def _is_loopback_authority(authority: str, server_port: int) -> bool:
    if not authority:
        return False
    try:
        parsed = urlparse(f"//{authority}")
        port = parsed.port
    except ValueError:
        return False
    return parsed.hostname in LOOPBACK_HOSTS and (
        port is None or port in _trusted_request_ports(server_port)
    )


def _is_loopback_origin(origin: str, server_port: int) -> bool:
    try:
        parsed = urlparse(origin)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname in LOOPBACK_HOSTS
        and port in _trusted_request_ports(server_port)
    )


def _acquire_job_slot() -> bool:
    return APP_CONTEXT.acquire_job_slot()


def _release_job_slot() -> None:
    APP_CONTEXT.release_job_slot()


def _upload_session_dir(upload_id: str) -> Path:
    if not UPLOAD_ID_PATTERN.fullmatch(upload_id):
        raise ValueError("Invalid upload session.")
    uploads_root = (_work_dir() / "uploads").resolve()
    session_dir = (uploads_root / f"staged-{upload_id}").resolve()
    if not session_dir.is_relative_to(uploads_root):
        raise ValueError("Invalid upload session.")
    return session_dir


def _upload_manifest_path(upload_id: str) -> Path:
    return _upload_session_dir(upload_id) / "upload_session.json"


def _write_upload_session(document: dict[str, Any]) -> None:
    upload_id = str(document.get("id") or "")
    target = _upload_manifest_path(upload_id)
    temporary = target.with_name(".upload_session.json.tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(target)
    target.chmod(0o600)


def _load_upload_session(upload_id: str) -> dict[str, Any]:
    path = _upload_manifest_path(upload_id)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Upload session was not found or is no longer available."
        ) from exc
    if not isinstance(document, dict) or document.get("id") != upload_id:
        raise ValueError("Upload session metadata is invalid.")
    try:
        expires_at = float(document.get("expires_at") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Upload session metadata is invalid.") from exc
    if expires_at <= time.time():
        raise ValueError(
            "Upload session expired. Select the evidence again to create a new session."
        )
    return document


def _safe_upload_name(value: object, index: int) -> str:
    raw = str(value or "").replace("\\", "/")
    name = Path(raw).name.strip()
    if not name or name in {".", ".."} or any(ord(char) < 32 for char in name):
        raise ValueError(f"Upload file {index + 1} has an invalid name.")
    if len(name.encode("utf-8")) > 220:
        raise ValueError(f"Upload file {index + 1} name is too long.")
    return name


def _public_upload_session(document: dict[str, Any]) -> dict[str, Any]:
    files = []
    for item in list(document.get("files") or []):
        files.append(
            {
                key: item.get(key)
                for key in (
                    "index",
                    "name",
                    "size",
                    "status",
                    "uploaded_bytes",
                    "sha256",
                    "error",
                )
                if key in item
            }
        )
    return {
        "upload_id": document.get("id"),
        "status": document.get("status", "pending"),
        "file_count": len(files),
        "completed_files": sum(item.get("status") == "staged" for item in files),
        "total_bytes": int(document.get("total_bytes") or 0),
        "uploaded_bytes": sum(int(item.get("uploaded_bytes") or 0) for item in files),
        "staging_path": document.get("staging_path"),
        "expires_at": document.get("expires_at"),
        "files": files,
    }


def _create_upload_session(payload: dict[str, Any]) -> dict[str, Any]:
    raw_files = payload.get("files")
    if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_UPLOAD_FILES:
        raise ValueError(
            f"Choose between 1 and {MAX_UPLOAD_FILES} evidence files per upload session."
        )
    files = []
    total_bytes = 0
    for index, raw_item in enumerate(raw_files):
        if not isinstance(raw_item, dict):
            raise ValueError(f"Upload file {index + 1} metadata is invalid.")
        try:
            size = int(raw_item.get("size", -1))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Upload file {index + 1} size is invalid.") from exc
        if size < 0:
            raise ValueError(f"Upload file {index + 1} size is invalid.")
        name = _safe_upload_name(raw_item.get("name"), index)
        total_bytes += size
        files.append(
            {
                "index": index,
                "name": name,
                "stored_name": f"{index + 1:04d}/{name}",
                "size": size,
                "status": "pending",
                "uploaded_bytes": 0,
            }
        )
    max_bytes = _settings().max_request_bytes
    if total_bytes > max_bytes:
        raise ValueError(
            f"Selected evidence exceeds the {max_bytes / 1024**3:g} GiB upload-session limit."
        )
    upload_id = uuid.uuid4().hex[:12]
    manager = _capacity_manager()
    manager.reserve(upload_id, total_bytes)
    try:
        session_dir = _upload_session_dir(upload_id)
        _secure_directory(session_dir)
        now = time.time()
        document = {
            "schema_version": "1.0",
            "id": upload_id,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
            "expires_at": now + UPLOAD_SESSION_TTL_SECONDS,
            "total_bytes": total_bytes,
            "staging_path": f"uploads/staged-{upload_id}",
            "files": files,
        }
        with APP_CONTEXT.uploads_lock:
            _write_upload_session(document)
    except Exception:
        manager.release(upload_id)
        shutil.rmtree(_upload_session_dir(upload_id), ignore_errors=True)
        raise
    return _public_upload_session(document)


def _upload_session_paths(upload_id: str) -> list[str]:
    with APP_CONTEXT.uploads_lock:
        document = _load_upload_session(upload_id)
    files = list(document.get("files") or [])
    if not files or any(item.get("status") != "staged" for item in files):
        raise ValueError(
            "Finish staging every selected evidence file before continuing."
        )
    session_dir = _upload_session_dir(upload_id)
    paths = []
    for item in files:
        candidate = (session_dir / str(item.get("stored_name") or "")).resolve()
        if not candidate.is_relative_to(session_dir) or not candidate.is_file():
            raise ValueError("A staged evidence file is missing or invalid.")
        paths.append(str(candidate))
    return paths


def _purge_stale_upload_sessions(work_dir: Path) -> int:
    uploads_root = work_dir / "uploads"
    now = time.time()
    removed = 0
    removed_ids: list[str] = []
    with APP_CONTEXT.uploads_lock:
        for session_dir in uploads_root.glob("staged-*"):
            if not session_dir.is_dir() or not re.fullmatch(
                r"staged-[a-f0-9]{12}", session_dir.name
            ):
                continue
            manifest = session_dir / "upload_session.json"
            expires_at = session_dir.stat().st_mtime + UPLOAD_SESSION_TTL_SECONDS
            try:
                document = json.loads(manifest.read_text(encoding="utf-8"))
                expires_at = float(document.get("expires_at") or expires_at)
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                pass
            if expires_at > now:
                continue
            try:
                shutil.rmtree(session_dir)
                removed += 1
                removed_ids.append(session_dir.name.removeprefix("staged-"))
            except OSError:
                continue
    manager = _capacity_manager()
    for upload_id in removed_ids:
        manager.release(upload_id)
    if removed:
        manager.invalidate()
    return removed


def _maintenance_loop(work_dir: Path, interval_seconds: float) -> None:
    while not APP_CONTEXT.maintenance_stop.wait(interval_seconds):
        try:
            removed = _purge_stale_upload_sessions(work_dir)
            pruned_jobs = _case_repository().prune()
            if removed:
                _runtime_log(
                    "upload_sessions_pruned",
                    message=(
                        f"TraceQuarry maintenance removed {removed} expired "
                        "upload session(s)"
                    ),
                    removed=removed,
                )
            if pruned_jobs:
                _runtime_log(
                    "job_state_pruned",
                    message=(
                        f"TraceQuarry maintenance pruned {pruned_jobs} expired "
                        "job-state record(s)"
                    ),
                    removed=pruned_jobs,
                )
        except Exception as exc:
            _runtime_log(
                "maintenance_failed",
                level="error",
                message="TraceQuarry maintenance failed",
                error=str(exc),
            )
            if _settings().debug:
                traceback.print_exc()


def _public_error(exc: Exception) -> str:
    if isinstance(exc, ValueError) or _settings().debug:
        return str(exc)
    return "TraceQuarry could not process the request. Review the local server log for details."


def _health_payload() -> dict[str, Any]:
    capacity = _capacity_manager().snapshot()
    status_counts = _case_repository().status_counts()
    upload_sessions = sum(
        1 for path in (_work_dir() / "uploads").glob("staged-*") if path.is_dir()
    )
    ready = (
        capacity.committed_bytes <= capacity.max_work_bytes
        and capacity.disk_free_bytes >= capacity.minimum_free_bytes
    )
    started_at = _settings().started_at
    return {
        "status": "ok" if ready else "degraded",
        "ready": ready,
        "version": __version__,
        "uptime_seconds": max(0, round(time.time() - started_at)),
        "jobs": status_counts,
        "case_repository": _case_repository().diagnostics(),
        "upload_sessions": upload_sessions,
        "capacity": capacity.to_dict(),
        "maintenance": {
            "running": bool(
                APP_CONTEXT.maintenance_thread is not None
                and APP_CONTEXT.maintenance_thread.is_alive()
            ),
            "interval_seconds": float(_settings().maintenance_interval),
        },
    }


class UacWebHandler(BaseHTTPRequestHandler):
    server_version = f"TraceQuarryWeb/{__version__}"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        context = cast(HardenedThreadingHTTPServer, self.server).context
        self.connection.settimeout(context.settings.request_timeout)

    def version_string(self) -> str:
        return self.server_version

    def end_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
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
        token = cast(HardenedThreadingHTTPServer, self.server).context.csrf_token
        if not supplied or not hmac.compare_digest(supplied, token):
            self._send_json({"error": "Missing or invalid request token."}, status=403)
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._admit_request():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/":
            token = cast(HardenedThreadingHTTPServer, self.server).context.csrf_token
            self._send_html(render_index(token))
            return
        if self._handle_service_get(parsed.path):
            return
        if self._handle_job_artifact_get(parsed.path, parsed.query):
            return
        if self._handle_static_get(parsed.path):
            return
        self.send_error(404)

    def _handle_service_get(self, path: str) -> bool:
        """Serve health, collection, upload-session, and job status resources."""
        if path in {"/api/health", "/api/ready"}:
            payload = _health_payload()
            status = 200 if payload["ready"] else 503
            self._send_json(payload, status=status)
            return True
        if path == "/api/cases":
            self._send_json({"cases": _list_cases()})
            return True
        if path == "/api/jobs":
            self._send_json({"jobs": _list_jobs()})
            return True
        upload_match = re.fullmatch(r"/api/upload/([a-f0-9]{12})", path)
        if upload_match:
            try:
                with APP_CONTEXT.uploads_lock:
                    session = _load_upload_session(upload_match.group(1))
                self._send_json(_public_upload_session(session))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=404)
            return True
        job_match = re.fullmatch(r"/api/job/([a-f0-9]{12})", path)
        if job_match:
            job = get_job(job_match.group(1))
            self._send_json(job, status=404 if "error" in job else 200)
            return True
        return False

    def _handle_job_artifact_get(self, path: str, query: str) -> bool:
        """Serve timeline, briefing, audit, and workbook resources for a job."""
        timeline_csv_match = re.fullmatch(
            r"/api/job/([a-f0-9]{12})/timeline\.csv", path
        )
        if timeline_csv_match:
            try:
                self._serve_timeline_csv(timeline_csv_match.group(1), parse_qs(query))
            except (ValueError, FileNotFoundError) as exc:
                self._send_json({"error": str(exc)}, status=404)
            return True
        workbook_match = re.fullmatch(
            r"/api/job/([a-f0-9]{12})/investigation\.xlsx", path
        )
        if workbook_match:
            try:
                self._serve_investigation_workbook(
                    workbook_match.group(1), parse_qs(query)
                )
            except (ValueError, FileNotFoundError) as exc:
                self._send_json({"error": str(exc)}, status=404)
            return True
        briefing_match = re.fullmatch(r"/api/job/([a-f0-9]{12})/briefing", path)
        if briefing_match:
            try:
                self._send_json(_incident_briefing(briefing_match.group(1)))
            except (ValueError, FileNotFoundError) as exc:
                self._send_json({"error": str(exc)}, status=404)
            return True
        audit_match = re.fullmatch(r"/api/job/([a-f0-9]{12})/audit", path)
        if audit_match:
            try:
                output_dir = _job_output_dir(audit_match.group(1))
                self._send_json(audit_status(output_dir / "analyst_audit.jsonl"))
            except FileNotFoundError as exc:
                self._send_json({"error": str(exc)}, status=404)
            return True
        timeline_match = re.fullmatch(r"/api/job/([a-f0-9]{12})/timeline", path)
        if timeline_match:
            try:
                self._send_json(
                    _timeline_page(timeline_match.group(1), parse_qs(query))
                )
            except (ValueError, FileNotFoundError) as exc:
                self._send_json({"error": str(exc)}, status=404)
            return True
        return False

    def _handle_static_get(self, path: str) -> bool:
        """Serve parser outputs and immutable interface assets."""
        if path.startswith("/outputs/"):
            self._serve_output(path)
            return True
        if path.startswith("/assets/"):
            self._serve_project_asset(path)
            return True
        if path.startswith("/static/"):
            self._serve_web_asset(path)
            return True
        if path == "/favicon.svg":
            self._serve_project_asset("/assets/tracequarry-favicon.svg")
            return True
        return False

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
        if parsed.path == "/api/upload/session":
            try:
                payload = self._parse_json_body(max_bytes=1024 * 1024)
                self._send_json(_create_upload_session(payload), status=201)
            except ValueError as exc:
                status = 413 if "exceeds" in str(exc).lower() else 400
                self._send_json({"error": str(exc)}, status=status)
            return
        upload_part_match = re.fullmatch(
            r"/api/upload/([a-f0-9]{12})/(\d{1,4})", parsed.path
        )
        if upload_part_match:
            self._handle_upload_part(
                upload_part_match.group(1), int(upload_part_match.group(2))
            )
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
            fields = self._parse_form()
            job_id = uuid.uuid4().hex[:12]
            work_dir = _work_dir()
            output_dir = work_dir / "outputs" / job_id

            input_paths = _input_paths_from_form(fields)
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
            collection_queue = _job_collection_entries(input_paths, fields)

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
                "case_reference": fields.get("case_reference", "").strip(),
                "threat_type": fields.get("threat_type", "").strip(),
            }
            _register_job(
                {
                    "id": job_id,
                    "status": "queued",
                    "created_at": time.time(),
                    "case_name": options["case_name"],
                    "input": input_paths[0],
                    "inputs": input_paths,
                    "is_case": is_case,
                    "job_type": "analysis",
                    "collections": collection_queue,
                    "staging_path": _staging_path_for_fields(fields),
                    "output": str(output_dir),
                    "options": {
                        key: value
                        for key, value in options.items()
                        if key not in {"iocs"}
                    }
                    | {"ioc_count": len(options["iocs"])},
                }
            )
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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, X-TraceQuarry-CSRF"
        )
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def _handle_upload_part(self, upload_id: str, file_index: int) -> None:
        try:
            length, item, existing = self._prepare_upload_part(upload_id, file_index)
            if existing is not None:
                self._send_json(existing)
                return
            digest = self._stage_upload_part(upload_id, item, length)
            document = self._complete_upload_part(upload_id, file_index, length, digest)
            _capacity_manager().consume(upload_id, length)
            self._send_json(_public_upload_session(document))
        except ValueError as exc:
            self._mark_upload_part_failed(upload_id, file_index, str(exc))
            self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            traceback.print_exc()
            self._mark_upload_part_failed(
                upload_id, file_index, "Local staging failed."
            )
            self._send_json({"error": _public_error(exc)}, status=500)

    def _prepare_upload_part(
        self, upload_id: str, file_index: int
    ) -> tuple[int, dict[str, Any], dict[str, Any] | None]:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header.") from exc
        content_type = (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/octet-stream":
            raise ValueError("Evidence chunks require application/octet-stream.")
        with APP_CONTEXT.uploads_lock:
            document = _load_upload_session(upload_id)
            files = list(document.get("files") or [])
            if not 0 <= file_index < len(files):
                raise ValueError("Upload file index is outside this session.")
            item = files[file_index]
            expected_size = int(item.get("size") or 0)
            if length != expected_size:
                raise ValueError(
                    f"Upload size does not match the declared size for {item.get('name')}."
                )
            if item.get("status") == "staged":
                return length, item, _public_upload_session(document)
            if item.get("status") == "uploading":
                raise ValueError("This evidence file is already uploading.")
            item["status"] = "uploading"
            item.pop("error", None)
            document["updated_at"] = time.time()
            document["status"] = "uploading"
            _write_upload_session(document)
        return length, item, None

    def _stage_upload_part(
        self, upload_id: str, item: dict[str, Any], length: int
    ) -> str:
        session_dir = _upload_session_dir(upload_id)
        target = (session_dir / str(item["stored_name"])).resolve()
        if not target.is_relative_to(session_dir):
            raise ValueError("Upload destination is invalid.")
        _secure_directory(target.parent)
        temporary = target.with_name(f".{target.name}.part")
        digest = hashlib.sha256()
        remaining = length
        try:
            with temporary.open("wb") as handle:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError(
                            "Upload ended before the evidence file was complete."
                        )
                    handle.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            temporary.chmod(0o600)
            temporary.replace(target)
            target.chmod(0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return digest.hexdigest()

    def _complete_upload_part(
        self, upload_id: str, file_index: int, length: int, digest: str
    ) -> dict[str, Any]:
        with APP_CONTEXT.uploads_lock:
            document = _load_upload_session(upload_id)
            item = list(document.get("files") or [])[file_index]
            item.update(
                {
                    "status": "staged",
                    "uploaded_bytes": length,
                    "sha256": digest,
                }
            )
            document["updated_at"] = time.time()
            document["expires_at"] = time.time() + UPLOAD_SESSION_TTL_SECONDS
            document["status"] = (
                "ready"
                if all(entry.get("status") == "staged" for entry in document["files"])
                else "uploading"
            )
            _write_upload_session(document)
        return document

    def _mark_upload_part_failed(
        self, upload_id: str, file_index: int, message: str
    ) -> None:
        try:
            with APP_CONTEXT.uploads_lock:
                document = _load_upload_session(upload_id)
                files = list(document.get("files") or [])
                if not 0 <= file_index < len(files):
                    return
                files[file_index]["status"] = "failed"
                files[file_index]["error"] = message
                document["status"] = "failed"
                document["updated_at"] = time.time()
                _write_upload_session(document)
        except ValueError:
            return

    def _handle_inspect(self) -> None:
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
            fields = self._parse_form()
            inspect_id = uuid.uuid4().hex[:12]
            input_paths = _input_paths_from_form(fields)
            if not input_paths:
                self._send_json(
                    {
                        "error": "Choose a UAC archive/directory or provide a server-side input path."
                    },
                    status=400,
                )
                return
            timezone_name = fields.get("timezone", "UTC").strip() or "UTC"
            _register_job(
                {
                    "id": inspect_id,
                    "job_type": "inspection",
                    "status": "queued",
                    "stage": "queued",
                    "progress": 2,
                    "created_at": time.time(),
                    "case_name": fields.get("case_name", "").strip()
                    or "Evidence inspection",
                    "is_case": len(input_paths) > 1,
                    "input": input_paths[0],
                    "inputs": input_paths,
                    "collections": _job_collection_entries(input_paths, fields),
                    "staging_path": _staging_path_for_fields(fields),
                }
            )
            thread = threading.Thread(
                target=_run_inspect_job,
                args=(inspect_id, input_paths, fields, timezone_name),
                daemon=True,
            )
            thread.start()
            slot_transferred = True
            self._send_json(
                {"job_id": inspect_id, "status_url": f"/api/job/{inspect_id}"},
                status=202,
            )
        except ValueError as exc:
            status = 413 if "exceeds" in str(exc).lower() else 400
            self._send_json({"error": str(exc)}, status=status)
        except Exception as exc:
            self._send_json({"error": _public_error(exc)}, status=500)
        finally:
            if not slot_transferred:
                _release_job_slot()

    def log_message(self, format: str, *args: object) -> None:
        _runtime_log(
            "http_request",
            message=format % args,
            client=self.address_string(),
        )

    def _parse_form(self) -> dict[str, str]:
        content_type = (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/x-www-form-urlencoded":
            raise ValueError(
                "Run and inspection requests require application/x-www-form-urlencoded. "
                "Stage evidence through the upload API first."
            )
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Streaming request bodies are not supported.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header.") from exc
        max_request_bytes = min(
            1024 * 1024,
            _settings().max_request_bytes,
        )
        if length <= 0:
            raise ValueError("A non-empty request body is required.")
        if length > max_request_bytes:
            raise ValueError(
                f"Run or inspection request metadata exceeds {max_request_bytes} bytes."
            )
        body = self.rfile.read(length).decode("utf-8", "replace")
        parsed = parse_qs(body)
        return {key: values[0] if values else "" for key, values in parsed.items()}

    def _parse_json_body(self, *, max_bytes: int) -> dict[str, Any]:
        content_type = (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/json":
            raise ValueError("JSON requests require application/json.")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > max_bytes:
            raise ValueError("Invalid JSON request size.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
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

    def _serve_timeline_csv(self, job_id: str, query: dict[str, list[str]]) -> None:
        output_dir = _job_output_dir(job_id)
        scope = _query_value(query, "scope", "mini")
        path, actual_scope = _timeline_file(output_dir, scope)
        search = _query_value(query, "q", "").strip().lower()[:200]
        severity = _query_value(query, "severity", "").strip().lower()
        source_type = _query_value(query, "source_type", "").strip()
        attack_phase = _query_value(query, "attack_phase", "").strip().lower()
        summary_filter = _query_value(query, "summary", "").strip().lower()
        annotations = _load_annotations(output_dir).get("annotations", {})
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header(
            "Content-Disposition",
            'attachment; filename="tracequarry-timeline.csv"',
        )
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()
        writer = csv.DictWriter(_ResponseTextWriter(self.wfile), CSV_EXPORT_FIELDS)
        writer.writeheader()
        for row in _iter_review_rows(
            path,
            annotations,
            search=search,
            severity=severity,
            source_type=source_type,
            attack_phase=attack_phase,
            summary_filter=summary_filter,
        ):
            writer.writerow(row)

    def _serve_investigation_workbook(
        self, job_id: str, query: dict[str, list[str]]
    ) -> None:
        output_dir = _job_output_dir(job_id)
        requested_scope = _query_value(query, "scope", "full")
        path, actual_scope = _timeline_file(output_dir, requested_scope)
        search = _query_value(query, "q", "").strip().lower()[:200]
        severity = _query_value(query, "severity", "").strip().lower()
        source_type = _query_value(query, "source_type", "").strip()
        attack_phase = _query_value(query, "attack_phase", "").strip().lower()
        summary_filter = _query_value(query, "summary", "").strip().lower()
        annotations = _load_annotations(output_dir).get("annotations", {})
        if not isinstance(annotations, dict):
            annotations = {}
        briefing = _incident_briefing(job_id, actual_scope)
        findings = _findings_for_output(output_dir)
        export_dir = _work_dir() / ".exports"
        _secure_directory(export_dir)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="tracequarry-export-",
                suffix=".xlsx",
                dir=export_dir,
                delete=False,
            ) as handle:
                temporary_path = Path(handle.name)
            write_investigation_workbook(
                temporary_path,
                case_name=str(briefing.get("case_name") or f"Case {job_id}"),
                briefing=briefing,
                timeline_rows=_iter_review_rows(
                    path,
                    annotations,
                    search=search,
                    severity=severity,
                    source_type=source_type,
                    attack_phase=attack_phase,
                    summary_filter=summary_filter,
                ),
                timeline_fields=CSV_EXPORT_FIELDS,
                findings=findings,
                filters={
                    "search": search,
                    "severity": severity,
                    "source_type": source_type,
                    "attack_phase": attack_phase,
                    "summary": summary_filter,
                },
            )
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            self.send_header(
                "Content-Disposition",
                'attachment; filename="tracequarry-investigation.xlsx"',
            )
            self.send_header("Content-Length", str(temporary_path.stat().st_size))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.end_headers()
            with temporary_path.open("rb") as handle:
                shutil.copyfileobj(handle, self.wfile)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

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
        content = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _serve_web_asset(self, path: str) -> None:
        parts = [unquote(part) for part in path.split("/") if part]
        if len(parts) != 2 or parts[0] != "static":
            self.send_error(404)
            return
        asset_root = resource_directory("web").resolve()
        target = (asset_root / parts[1]).resolve()
        if (
            not target.is_relative_to(asset_root)
            or target.name not in {"app.css", "app.js"}
            or not target.is_file()
        ):
            self.send_error(404)
            return
        content_type = (
            mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        )
        content = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache, max-age=0")
        self.end_headers()
        self.wfile.write(content)

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
        job_id, status="running", stage="parsing", progress=28, started_at=time.time()
    )
    try:
        report_progress = _job_progress_reporter(job_id, start=30, span=58)

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
                case_reference=str(options.get("case_reference") or ""),
                threat_type=str(options.get("threat_type") or ""),
                progress_callback=report_progress,
                max_workers=_settings().case_workers,
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
                case_reference=str(options.get("case_reference") or ""),
                progress_callback=report_progress,
            )
        _update_job(job_id, stage="writing_outputs", progress=86)
        completed_at = time.time()
        _update_job(
            job_id,
            status="complete",
            stage="complete",
            progress=100,
            completed_at=completed_at,
            result=result.to_dict(),
            outputs=_list_outputs(Path(options["output_dir"]), job_id),
        )
        _write_web_job_record(job_id)
    except Exception as exc:
        traceback.print_exc()
        _mark_incomplete_collections_failed(job_id)
        _update_job(
            job_id,
            status="failed",
            stage="failed",
            progress=100,
            completed_at=time.time(),
            error=str(exc),
            **({"traceback": traceback.format_exc()} if _settings().debug else {}),
        )
    finally:
        _release_job_slot()


def _run_inspect_job(
    job_id: str,
    input_paths: list[str],
    fields: dict[str, str],
    timezone_name: str,
) -> None:
    _update_job(
        job_id,
        status="running",
        stage="inspecting",
        progress=28,
        started_at=time.time(),
    )
    try:
        report_progress = _job_progress_reporter(job_id, start=30, span=68)
        data = _inspect_inputs(
            input_paths,
            fields,
            timezone_name,
            progress_callback=report_progress,
            max_workers=_settings().case_workers,
        )
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
        data["latest_display"] = _utc_iso_to_display(data.get("latest"), timezone_name)
        _update_job(
            job_id,
            status="complete",
            stage="inspection_complete",
            progress=100,
            completed_at=time.time(),
            result=data,
        )
    except Exception as exc:
        traceback.print_exc()
        _mark_incomplete_collections_failed(job_id)
        _update_job(
            job_id,
            status="failed",
            stage="failed",
            progress=100,
            completed_at=time.time(),
            error=str(exc),
            **({"traceback": traceback.format_exc()} if _settings().debug else {}),
        )
    finally:
        _release_job_slot()


def _progress_fraction(payload: dict[str, Any]) -> float:
    stage = str(payload.get("stage") or "")
    total = max(1, int(payload.get("total") or 1))
    completed = max(0, min(total, int(payload.get("completed") or 0)))
    within_stage = completed / total
    if stage == "loading_collection":
        return 0.03
    if stage == "sources_discovered":
        return 0.08
    if stage == "hashing_evidence":
        return 0.12
    if stage == "parsing_sources":
        return 0.12 + within_stage * 0.70
    if stage == "enriching_collection":
        return 0.86
    if stage == "writing_collection":
        return 0.94
    if stage in {"collection_complete", "case_complete"}:
        return 1.0
    return min(0.9, within_stage)


def _job_progress_reporter(job_id: str, *, start: int, span: int) -> Any:
    fractions: dict[int, float] = {}
    progress_lock = threading.Lock()

    def report(payload: dict[str, Any]) -> None:
        collection_total = max(1, int(payload.get("collection_total") or 1))
        collection_index = max(1, int(payload.get("collection_index") or 1))
        fraction = _progress_fraction(payload)
        with progress_lock:
            fractions[collection_index] = max(
                fraction, fractions.get(collection_index, 0.0)
            )
            overall = sum(fractions.values()) / collection_total
            _update_job_collection(job_id, collection_index, payload, fraction)
            _update_job(
                job_id,
                stage=str(payload.get("stage") or "parsing_sources"),
                progress=min(start + span, start + round(overall * span)),
                progress_detail=payload,
            )

    return report


def _update_job_collection(
    job_id: str,
    collection_index: int,
    payload: dict[str, Any],
    fraction: float,
) -> None:
    if payload.get("stage") == "case_complete":
        return
    job = _case_repository().get(job_id)
    collections = job.get("collections") if job else None
    if not isinstance(collections, list) or not 1 <= collection_index <= len(
        collections
    ):
        return
    item = collections[collection_index - 1]
    if not isinstance(item, dict):
        return
    stage = str(payload.get("stage") or "parsing_sources")
    item.update(
        {
            "status": "complete" if stage == "collection_complete" else "parsing",
            "stage": stage,
            "progress": round(fraction * 100),
            "completed": int(payload.get("completed") or 0),
            "total": int(payload.get("total") or 0),
        }
    )
    if payload.get("source"):
        item["source"] = str(payload["source"])
    if payload.get("collection_id"):
        item["collection_id"] = str(payload["collection_id"])
    _case_repository().update(job_id, {"collections": collections})


def _mark_incomplete_collections_failed(job_id: str) -> None:
    job = _case_repository().get(job_id)
    collections = job.get("collections") if job else None
    if not isinstance(collections, list):
        return
    for item in collections:
        if isinstance(item, dict) and item.get("status") != "complete":
            item["status"] = "failed"
            item["stage"] = "failed"
    _case_repository().update(job_id, {"collections": collections}, force=True)


def _staging_path_for_fields(fields: dict[str, str]) -> str:
    upload_id = fields.get("staged_upload_id", "").strip()
    if not upload_id:
        return ""
    with APP_CONTEXT.uploads_lock:
        document = _load_upload_session(upload_id)
    return str(document.get("staging_path") or "")


def _job_collection_entries(
    input_paths: list[str], fields: dict[str, str]
) -> list[dict[str, Any]]:
    upload_id = fields.get("staged_upload_id", "").strip()
    if upload_id:
        with APP_CONTEXT.uploads_lock:
            document = _load_upload_session(upload_id)
        return [
            {
                "index": int(item.get("index") or 0) + 1,
                "name": str(item.get("name") or "Evidence collection"),
                "size": int(item.get("size") or 0),
                "status": "queued",
                "stage": "queued",
                "progress": 0,
            }
            for item in list(document.get("files") or [])
        ]
    entries = []
    for index, input_path in enumerate(input_paths, start=1):
        path = Path(input_path)
        try:
            size = path.stat().st_size if path.is_file() else None
        except OSError:
            size = None
        entries.append(
            {
                "index": index,
                "name": path.name or f"Collection {index}",
                "size": size,
                "status": "queued",
                "stage": "queued",
                "progress": 0,
            }
        )
    return entries


def _input_paths_from_form(fields: dict[str, str]) -> list[str]:
    input_paths = []
    for raw_line in fields.get("input_path", "").splitlines():
        line = raw_line.strip()
        if line:
            input_paths.append(str(_resolve_server_input(line)))
    staged_upload_id = fields.get("staged_upload_id", "").strip()
    if staged_upload_id:
        input_paths.extend(_upload_session_paths(staged_upload_id))
    seen = set()
    unique_paths = []
    for path in input_paths:
        if path in seen:
            continue
        seen.add(path)
        unique_paths.append(path)
    return unique_paths


def _inspect_inputs(
    input_paths: list[str],
    fields: dict[str, str],
    timezone_name: str,
    *,
    progress_callback: Any = None,
    max_workers: int = 1,
) -> dict[str, Any]:
    def inspect_one(index: int, input_path: str) -> tuple[int, Any]:
        return index, inspect_time_range(
            input_path,
            year=_parse_int(fields.get("year", "")),
            timezone_name=timezone_name,
            host=fields.get("host", "").strip(),
            progress_callback=progress_callback,
            collection_index=index + 1,
            collection_total=len(input_paths),
            collection_name=Path(input_path).name,
            scratch_dir=_work_dir() / ".scratch",
        )

    results_by_index: dict[int, Any] = {}
    worker_count = min(max(1, max_workers), len(input_paths))
    if worker_count == 1:
        for index, input_path in enumerate(input_paths):
            result_index, result = inspect_one(index, input_path)
            results_by_index[result_index] = result
    else:
        with ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="tracequarry-inspect"
        ) as executor:
            futures = {
                executor.submit(inspect_one, index, input_path): index
                for index, input_path in enumerate(input_paths)
            }
            for future in as_completed(futures):
                result_index, result = future.result()
                results_by_index[result_index] = result
    results = [results_by_index[index] for index in range(len(input_paths))]
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
        "evidence_files": sum(result.evidence_files for result in results),
        "unsupported_sources": sum(result.unsupported_sources for result in results),
        "unmatched_files": sum(result.unmatched_files for result in results),
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
            result.to_dict() | {"input": Path(input_paths[index]).name}
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
        "caseweave_exports.json",
        "caseweave_custody.json",
        "caseweave_import_bundle.zip",
        "caseweave_source_package.tar",
        "analyst_annotations.json",
        "analyst_audit.jsonl",
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
        for bundle in sorted(hosts_dir.glob("*/caseweave_import_bundle.zip")):
            rel = bundle.relative_to(output_dir)
            files.append(
                {
                    "name": str(rel),
                    "size": bundle.stat().st_size,
                    "url": f"/outputs/{job_id}/{rel.as_posix()}",
                }
            )
        for package in sorted(hosts_dir.glob("*/caseweave_source_package.tar")):
            rel = package.relative_to(output_dir)
            files.append(
                {
                    "name": str(rel),
                    "size": package.stat().st_size,
                    "url": f"/outputs/{job_id}/{rel.as_posix()}",
                }
            )
    return files


def _write_web_job_record(job_id: str) -> None:
    job = _case_repository().get(job_id) or {}
    if not job or job.get("status") != "complete":
        return
    output_dir = Path(str(job.get("output") or ""))
    record = {
        "schema_version": "1.0",
        "job_id": job_id,
        "status": "complete",
        "case_name": job.get("case_name") or "TraceQuarry Case",
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "is_case": bool(job.get("is_case")),
        "options": {
            key: value
            for key, value in dict(job.get("options") or {}).items()
            if key not in {"input_path", "input_paths", "output_dir"}
        },
        "result": {
            key: value
            for key, value in dict(job.get("result") or {}).items()
            if key not in {"output", "host_outputs"}
        },
    }
    temporary = output_dir / ".web_job.json.tmp"
    target = output_dir / "web_job.json"
    temporary.write_text(
        json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(target)
    target.chmod(0o600)


def _job_state_document(job: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "id",
        "status",
        "stage",
        "progress",
        "progress_detail",
        "created_at",
        "started_at",
        "completed_at",
        "is_case",
        "job_type",
        "case_name",
        "collections",
        "staging_path",
        "output",
        "options",
        "result",
        "outputs",
        "restored",
        "error",
        "revision",
    }
    document = {
        key: value
        for key, value in job.items()
        if key in allowed and key != "traceback"
    }
    options = document.get("options")
    if isinstance(options, dict):
        document["options"] = {
            key: value
            for key, value in options.items()
            if key not in {"input_path", "input_paths", "output_dir"}
        }
    return document


def _register_job(
    job: dict[str, Any],
    *,
    allow_recovery: bool = False,
) -> None:
    job_id = str(job.get("id") or "")
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise ValueError("Invalid job identifier.")
    _case_repository().register(
        _job_state_document(job),
        allow_recovery=allow_recovery,
    )


def _restore_persisted_jobs() -> int:
    repository = _case_repository()
    repository.import_legacy_json(_work_dir() / "state" / "jobs")
    repository.prune()
    restored = 0
    for document in repository.list_jobs(limit=None):
        job_id = str(document.get("id") or "")
        if not JOB_ID_PATTERN.fullmatch(job_id):
            continue
        status = str(document.get("status") or "")
        if (
            status == "complete"
            and document.get("job_type") != "inspection"
            and not _stored_output_available(document)
        ):
            repository.delete(job_id)
            continue
        if status in {"queued", "running"}:
            repository.update(
                job_id,
                {
                    "status": "interrupted",
                    "stage": "interrupted",
                    "completed_at": time.time(),
                    "error": (
                        "Analysis was interrupted by a service restart. Evidence "
                        "remains available for a new run."
                    ),
                    "restored": True,
                },
                force=True,
            )
        restored += 1
    return restored


def _restore_completed_jobs(work_dir: Path) -> int:
    output_root = work_dir / "outputs"
    restored = 0
    for output_dir in sorted(output_root.iterdir() if output_root.exists() else []):
        job_id = output_dir.name
        if not output_dir.is_dir() or not JOB_ID_PATTERN.fullmatch(job_id):
            continue
        existing = _case_repository().get(job_id)
        if existing and existing.get("status") == "complete":
            continue
        job = _restored_job(output_dir, job_id)
        if not job:
            continue
        _register_job(job, allow_recovery=True)
        restored += 1
    return restored


def _stored_output_available(document: dict[str, Any]) -> bool:
    output_value = str(document.get("output") or "")
    if not output_value:
        return False
    output_root = (_work_dir() / "outputs").resolve()
    output_dir = Path(output_value).resolve()
    return output_dir.is_relative_to(output_root) and output_dir.is_dir()


def _restored_job(output_dir: Path, job_id: str) -> dict[str, Any] | None:
    record = _read_json_document(output_dir / "web_job.json")
    is_case = (output_dir / "case_manifest.json").is_file()
    manifest_name = "case_manifest.json" if is_case else "run_manifest.json"
    manifest = _read_json_document(output_dir / manifest_name)
    summary_name = "case_summary.md" if is_case else "summary.md"
    timeline_name = "case_timeline_full.jsonl" if is_case else "timeline_full.jsonl"
    if (
        not (output_dir / summary_name).is_file()
        or not (output_dir / timeline_name).is_file()
    ):
        return None
    if record:
        result = dict(record.get("result") or {})
        options = dict(record.get("options") or {})
        case_name = str(record.get("case_name") or "TraceQuarry Case")
        created_at = _numeric_time(record.get("created_at"), output_dir.stat().st_mtime)
        completed_at = _numeric_time(
            record.get("completed_at"), output_dir.stat().st_mtime
        )
    else:
        settings = dict(manifest.get("settings") or {})
        options = {
            "incident_start": settings.get("incident_start"),
            "incident_end": settings.get("incident_end"),
            "timezone_name": settings.get("timezone", "UTC"),
            "threat_type": settings.get("threat_type", ""),
        }
        result = _infer_result(output_dir, manifest, is_case)
        case_name = str(
            manifest.get("case_name")
            or manifest.get("collection_name")
            or "TraceQuarry Case"
        )
        created_at = _numeric_time(
            manifest.get("created_at"), output_dir.stat().st_mtime
        )
        completed_at = output_dir.stat().st_mtime
    return {
        "id": job_id,
        "status": "complete",
        "stage": "complete",
        "progress": 100,
        "created_at": created_at,
        "completed_at": completed_at,
        "case_name": case_name,
        "is_case": is_case,
        "output": str(output_dir),
        "options": options,
        "result": result,
        "outputs": _list_outputs(output_dir, job_id),
        "restored": True,
    }


def _infer_result(
    output_dir: Path, manifest: dict[str, Any], is_case: bool
) -> dict[str, Any]:
    if is_case:
        collections = list(manifest.get("collections") or [])
        result: dict[str, Any] = {
            "collections": len(collections),
            "events": sum(int(item.get("events") or 0) for item in collections),
        }
        findings = _read_json_document(output_dir / "case_findings.json")
        result["findings"] = len(findings.get("findings") or [])
        result["correlations"] = len(findings.get("correlations") or [])
        mini_path = output_dir / "case_timeline_mini.jsonl"
    else:
        coverage = dict(manifest.get("coverage") or {})
        result = {"events": int(coverage.get("events") or 0)}
        findings = _read_json_document(output_dir / "findings.json")
        result["findings"] = len(findings.get("findings") or [])
        mini_path = output_dir / "timeline_mini.jsonl"
    result["mini_events"] = _line_count(mini_path) if mini_path.is_file() else 0
    result["ioc_hits"] = 0
    result["errors"] = 0
    return result


def _read_json_document(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _line_count(path: Path) -> int:
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def _numeric_time(value: Any, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return default


def _list_cases() -> list[dict[str, Any]]:
    case_jobs = _case_repository().list_completed_cases(limit=100)
    return [
        {
            "id": str(job.get("id") or ""),
            "case_name": str(job.get("case_name") or "TraceQuarry Case"),
            "is_case": bool(job.get("is_case")),
            "completed_at": job.get("completed_at"),
            "result": {
                key: value
                for key, value in dict(job.get("result") or {}).items()
                if key not in {"output", "host_outputs"}
            },
        }
        for job in case_jobs
    ]


def _list_jobs() -> list[dict[str, Any]]:
    job_ids = [
        str(job.get("id") or "") for job in _case_repository().list_jobs(limit=200)
    ]
    return [
        public
        for job_id in job_ids
        if JOB_ID_PATTERN.fullmatch(job_id) and "id" in (public := get_job(job_id))
    ]


def _job_output_dir(job_id: str) -> Path:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise FileNotFoundError("Completed job not found.")
    job = _case_repository().get(job_id)
    if not job or job.get("status") != "complete":
        raise FileNotFoundError("Completed job not found.")
    output_root = (_work_dir() / "outputs").resolve()
    output_dir = Path(str(job.get("output") or "")).resolve()
    if not output_dir.is_relative_to(output_root) or not output_dir.is_dir():
        raise FileNotFoundError("Job output is unavailable.")
    return output_dir


def _timeline_file(output_dir: Path, scope: str) -> tuple[Path, str]:
    return _timeline_file_impl(output_dir, scope)


def _timeline_page(job_id: str, query: dict[str, list[str]]) -> dict[str, Any]:
    output_dir = _job_output_dir(job_id)
    return _timeline_page_impl(output_dir, job_id, query)


def _save_annotation(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    output_dir = _job_output_dir(job_id)
    result = _save_annotation_for_output(output_dir, payload)
    _update_job(job_id, outputs=_list_outputs(output_dir, job_id))
    return result


def _load_annotations(output_dir: Path) -> dict[str, Any]:
    return _load_annotations_impl(output_dir)


def _incident_briefing(job_id: str, requested_scope: str = "mini") -> dict[str, Any]:
    output_dir = _job_output_dir(job_id)
    case_name = _briefing_case_name(job_id)
    return _build_incident_briefing(
        output_dir,
        job_id,
        case_name,
        requested_scope,
    )


def _briefing_case_name(job_id: str) -> str:
    job = _case_repository().get(job_id) or {}
    name = str(job.get("case_name") or "").strip()
    return name or f"TraceQuarry Case {job_id}"


def _query_value(query: dict[str, list[str]], key: str, default: str) -> str:
    return _query_value_impl(query, key, default)


def get_job(job_id: str) -> dict[str, Any]:
    job = _case_repository().get(job_id) or {}
    if not job:
        return {"error": "Unknown job."}
    public = {
        key: job[key]
        for key in [
            "id",
            "status",
            "created_at",
            "is_case",
            "job_type",
            "stage",
            "progress",
            "started_at",
            "progress_detail",
            "completed_at",
            "outputs",
            "case_name",
            "restored",
            "collections",
            "staging_path",
            "revision",
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
            key: value
            for key, value in result.items()
            if key not in {"output", "host_outputs"}
        }
    if job.get("error"):
        public["error"] = (
            str(job["error"])
            if _settings().debug
            else "Analysis failed. Review the local server log."
        )
    if _settings().debug and job.get("traceback"):
        public["traceback"] = job["traceback"]
    return public


def _update_job(job_id: str, **updates: object) -> None:
    sanitized = _job_state_document({"id": job_id, **updates})
    status = str(sanitized.get("status") or "")
    _case_repository().update(
        job_id,
        sanitized,
        force=status not in {"queued", "running"},
    )


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


def render_index(csrf_token: str | None = None) -> str:
    csrf_token = csrf_token or APP_CONTEXT.csrf_token
    threat_profiles = profile_choices()
    threat_options = "\n".join(
        f'              <option value="{html.escape(profile["id"])}">'
        f"{html.escape(profile['label'])}</option>"
        for profile in threat_profiles
    )
    threat_profiles_json = json.dumps(
        threat_profiles, ensure_ascii=True, separators=(",", ":")
    ).replace("</", "<\\/")
    template = resource_file("web", "index.html").read_text(encoding="utf-8")
    return (
        template.replace("{{THREAT_OPTIONS}}", threat_options)
        .replace(
            "{{THREAT_PROFILES_ATTR}}",
            html.escape(threat_profiles_json, quote=True),
        )
        .replace("{{CSRF_TOKEN_ATTR}}", html.escape(csrf_token, quote=True))
    )


if __name__ == "__main__":
    raise SystemExit(main())
