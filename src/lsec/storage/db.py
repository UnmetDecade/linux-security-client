"""SQLite storage with explicit, transactional migrations.

A failed migration is rolled back and the database file is restored from the
pre-migration backup so the daemon never operates on a half-migrated schema.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from ..common.logging import get_logger
from ..common.timeutil import now_iso

log = get_logger("storage")

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS components (
            component_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            installed INTEGER NOT NULL DEFAULT 0,
            version TEXT,
            service_status TEXT NOT NULL DEFAULT 'unknown',
            health_status TEXT NOT NULL DEFAULT 'unknown',
            capabilities TEXT NOT NULL DEFAULT '[]',
            last_check_at TEXT,
            last_update_at TEXT,
            error_code TEXT,
            error_message TEXT,
            details TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS scan_tasks (
            task_id TEXT PRIMARY KEY,
            task_type TEXT NOT NULL,
            target_paths TEXT NOT NULL,
            selected_engines TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            status TEXT NOT NULL,
            progress REAL,
            files_scanned INTEGER NOT NULL DEFAULT 0,
            detections_count INTEGER NOT NULL DEFAULT 0,
            errors_count INTEGER NOT NULL DEFAULT 0,
            result_summary TEXT NOT NULL DEFAULT '{}',
            error_details TEXT NOT NULL DEFAULT '[]',
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            requested_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scan_tasks_status
            ON scan_tasks(status, created_at);

        CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            schema_version INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            host TEXT NOT NULL,
            target TEXT NOT NULL,
            evidence TEXT NOT NULL,
            status TEXT NOT NULL,
            recommended_actions TEXT NOT NULL DEFAULT '[]',
            dedup_key TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            occurrences INTEGER NOT NULL DEFAULT 1,
            source_refs TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_status_severity
            ON events(status, severity);
        CREATE INDEX IF NOT EXISTS idx_events_dedup ON events(dedup_key);

        CREATE TABLE IF NOT EXISTS audit_records (
            record_id TEXT PRIMARY KEY,
            request_id TEXT,
            actor TEXT NOT NULL,
            client TEXT,
            action TEXT NOT NULL,
            target TEXT,
            before_state TEXT,
            after_state TEXT,
            confirmed INTEGER NOT NULL DEFAULT 0,
            result TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_records(created_at DESC);

        CREATE TABLE IF NOT EXISTS quarantine_items (
            item_id TEXT PRIMARY KEY,
            original_path TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            detected_at TEXT,
            engine TEXT,
            detection_name TEXT,
            event_id TEXT,
            quarantined_by TEXT NOT NULL,
            status TEXT NOT NULL,
            restored_at TEXT,
            deleted_at TEXT,
            notes TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_quarantine_time
            ON quarantine_items(detected_at DESC);

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            csrf_token TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            remote_addr TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS audit_runs (
            audit_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            scope TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            requested_by TEXT NOT NULL,
            checks_total INTEGER NOT NULL DEFAULT 0,
            findings_count INTEGER NOT NULL DEFAULT 0,
            errors_count INTEGER NOT NULL DEFAULT 0,
            severity_counts TEXT NOT NULL DEFAULT '{}',
            hardening_index INTEGER,
            lynis_available INTEGER NOT NULL DEFAULT 0,
            lynis_version TEXT,
            evidence_path TEXT,
            error TEXT,
            result_summary TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_runs_time
            ON audit_runs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_runs_status
            ON audit_runs(status, created_at);
        """,
    ),
]


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.path), timeout=15.0, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o750)
        except OSError:
            pass
        with self.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            applied = {
                row["version"]
                for row in conn.execute("SELECT version FROM schema_migrations")
            }
        for version, sql in MIGRATIONS:
            if version in applied:
                continue
            backup = self._backup(version)
            conn = self.connect()
            try:
                # executescript() would implicitly COMMIT and break atomicity;
                # execute the (internal, semicolon-delimited) migration
                # statements one by one inside an explicit transaction.
                conn.execute("BEGIN IMMEDIATE")
                for statement in sql.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, now_iso()),
                )
                conn.execute("COMMIT")
                log.info("数据库迁移完成 version=%s", version)
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                conn.close()
                if backup:
                    shutil.copy2(backup, self.path)
                    log.error("迁移失败，已从备份恢复: %s", backup)
                raise
            else:
                conn.close()

    def _backup(self, version: int) -> Path | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        backup = self.path.with_name(f"{self.path.name}.pre-v{version}.bak")
        try:
            src = self.connect()
            dst = sqlite3.connect(str(backup))
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
            os.chmod(backup, 0o600)
            return backup
        except sqlite3.Error as exc:  # pragma: no cover - disk errors
            log.warning("创建迁移备份失败: %s", exc)
            return None

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        conn = self.connect()
        try:
            return [dict(row) for row in conn.execute(sql, params)]
        finally:
            conn.close()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self.write() as conn:
            cur = conn.execute(sql, params)
            return cur.rowcount

    def integrity_check(self) -> tuple[bool, str]:
        try:
            row = self.query_one("PRAGMA integrity_check")
            result = row["integrity_check"] if row else "no result"
            return result == "ok", result
        except sqlite3.Error as exc:  # pragma: no cover
            return False, str(exc)

    def backup_to(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        src = self.connect()
        dst = sqlite3.connect(str(destination))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
