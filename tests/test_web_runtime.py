import json
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path

from uac_parser.case_repository import CaseRepository
from uac_parser.job_models import JobStateError, JobVersionConflict
from uac_parser.web_runtime import ApplicationContext, WebSettings, WorkCapacityManager


class WorkCapacityManagerTests(unittest.TestCase):
    def test_concurrent_reservations_cannot_overcommit_quota(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            (work_dir / "uploads").mkdir()
            manager = WorkCapacityManager(cache_seconds=60)
            manager.configure(
                work_dir,
                max_work_bytes=1000,
                minimum_free_bytes=0,
                session_ttl_seconds=3600,
            )
            accepted: list[str] = []
            lock = threading.Lock()

            def reserve(index: int) -> None:
                try:
                    manager.reserve(f"session-{index}", 200)
                except ValueError:
                    return
                with lock:
                    accepted.append(f"session-{index}")

            threads = [
                threading.Thread(target=reserve, args=(index,)) for index in range(10)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            snapshot = manager.snapshot()
            self.assertEqual(len(accepted), 5)
            self.assertEqual(snapshot.reserved_bytes, 1000)
            self.assertLessEqual(snapshot.committed_bytes, snapshot.max_work_bytes)

    def test_restart_recovers_only_unwritten_active_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            session_dir = work_dir / "uploads" / "staged-abc123def456"
            session_dir.mkdir(parents=True)
            (session_dir / "upload_session.json").write_text(
                json.dumps(
                    {
                        "id": "abc123def456",
                        "expires_at": time.time() + 3600,
                        "files": [
                            {
                                "size": 100,
                                "uploaded_bytes": 100,
                                "status": "staged",
                            },
                            {
                                "size": 200,
                                "uploaded_bytes": 50,
                                "status": "failed",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manager = WorkCapacityManager()
            manager.configure(
                work_dir,
                max_work_bytes=10_000,
                minimum_free_bytes=0,
                session_ttl_seconds=3600,
            )

            snapshot = manager.snapshot()

            self.assertEqual(snapshot.reserved_bytes, 150)
            self.assertEqual(snapshot.active_reservations, 1)

    def test_consuming_and_releasing_reservations_updates_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            work_dir.mkdir(exist_ok=True)
            manager = WorkCapacityManager()
            manager.configure(
                work_dir,
                max_work_bytes=10_000,
                minimum_free_bytes=0,
                session_ttl_seconds=3600,
            )
            manager.reserve("one", 500)
            manager.consume("one", 200)
            self.assertEqual(manager.snapshot().reserved_bytes, 300)

            manager.release("one")

            self.assertEqual(manager.snapshot().reserved_bytes, 0)


class CaseRepositoryTests(unittest.TestCase):
    def test_job_lifecycle_rejects_terminal_state_regression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = CaseRepository()
            repository.configure(Path(directory), retention_days=30)
            repository.register({"id": "abc123def456", "status": "running"})
            repository.update("abc123def456", {"status": "complete"}, force=True)

            with self.assertRaisesRegex(JobStateError, "complete -> running"):
                repository.update("abc123def456", {"status": "running"}, force=True)

    def test_output_reconciliation_is_an_explicit_recovery_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = CaseRepository()
            repository.configure(Path(directory), retention_days=30)
            repository.register({"id": "abc123def456", "status": "interrupted"})

            with self.assertRaisesRegex(JobStateError, "interrupted -> complete"):
                repository.update("abc123def456", {"status": "complete"}, force=True)

            recovered = repository.update(
                "abc123def456",
                {"status": "complete"},
                force=True,
                allow_recovery=True,
            )
            self.assertEqual(recovered["status"], "complete")

    def test_expected_revision_prevents_lost_updates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = CaseRepository()
            repository.configure(Path(directory), retention_days=30)
            repository.register({"id": "abc123def456", "status": "running"})
            initial = repository.get("abc123def456") or {}
            repository.update(
                "abc123def456",
                {"progress": 20},
                expected_revision=int(initial["revision"]),
                force=True,
            )

            with self.assertRaises(JobVersionConflict):
                repository.update(
                    "abc123def456",
                    {"progress": 30},
                    expected_revision=int(initial["revision"]),
                    force=True,
                )

    def test_case_state_is_private_and_restorable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = CaseRepository()
            repository.configure(Path(directory), retention_days=30)
            repository.register(
                {"id": "abc123def456", "status": "running", "progress": 42},
            )
            target = Path(directory) / "state" / "cases.sqlite3"
            repository.reset()

            restored_repository = CaseRepository()
            restored_repository.configure(Path(directory), retention_days=30)
            restored = restored_repository.get("abc123def456")

            self.assertIsNotNone(restored)
            self.assertEqual((restored or {})["progress"], 42)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_prune_removes_expired_transient_state_but_keeps_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = CaseRepository()
            work_dir = Path(directory)
            repository.configure(work_dir, retention_days=1)
            repository.register(
                {
                    "id": "abc123def456",
                    "status": "failed",
                    "job_type": "analysis",
                }
            )
            repository.register(
                {
                    "id": "def456abc123",
                    "status": "complete",
                    "job_type": "analysis",
                }
            )
            old = time.time() - 2 * 24 * 60 * 60
            with sqlite3.connect(repository.database_path) as database:
                database.execute("UPDATE case_records SET updated_at = ?", (old,))

            removed = repository.prune()

            self.assertEqual(removed, 1)
            self.assertIsNone(repository.get("abc123def456"))
            self.assertIsNotNone(repository.get("def456abc123"))

    def test_legacy_json_is_imported_without_overwriting_current_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            legacy = work_dir / "state" / "jobs"
            legacy.mkdir(parents=True)
            (legacy / "abc123def456.json").write_text(
                json.dumps({"id": "abc123def456", "status": "running", "progress": 10}),
                encoding="utf-8",
            )
            repository = CaseRepository()
            repository.configure(work_dir, retention_days=30)

            imported = repository.import_legacy_json(legacy)
            repository.update("abc123def456", {"progress": 90}, force=True)
            imported_again = repository.import_legacy_json(legacy)

            self.assertEqual(imported, 1)
            self.assertEqual(imported_again, 0)
            self.assertEqual((repository.get("abc123def456") or {})["progress"], 90)

    def test_concurrent_updates_preserve_a_valid_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = CaseRepository()
            repository.configure(Path(directory), retention_days=30)
            repository.register({"id": "abc123def456", "status": "running"})

            threads = [
                threading.Thread(
                    target=repository.update,
                    args=("abc123def456", {"progress": progress}),
                    kwargs={"force": True},
                )
                for progress in range(20)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            stored = repository.get("abc123def456") or {}
            self.assertEqual(stored["status"], "running")
            self.assertIn(stored["progress"], range(20))
            self.assertGreaterEqual(stored["revision"], 21)
            with sqlite3.connect(repository.database_path) as database:
                self.assertEqual(
                    database.execute("PRAGMA quick_check").fetchone()[0], "ok"
                )


class ApplicationContextTests(unittest.TestCase):
    def test_context_owns_runtime_services_and_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = ApplicationContext()
            work_dir = Path(directory)
            context.configure(
                WebSettings(
                    work_dir=work_dir,
                    input_roots=(work_dir,),
                    minimum_free_bytes=0,
                ),
                max_concurrent_jobs=1,
            )

            self.assertEqual(context.settings.work_dir, work_dir.resolve())
            self.assertTrue(context.acquire_job_slot())
            self.assertFalse(context.acquire_job_slot())
            context.release_job_slot()
            self.assertEqual(context.cases.diagnostics()["schema_version"], 2)
            context.reset()


if __name__ == "__main__":
    unittest.main()
