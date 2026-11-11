"""Scan task persistence and the task state machine."""

from __future__ import annotations

import json
from typing import Any

from ..common.errors import conflict, invalid, not_found
from ..common.ids import new_id
from ..common.timeutil import now_iso
from .db import Database

TASK_TYPES = ("quick", "full", "custom", "malware", "yara", "audit", "container")
SUPPORTED_TASK_TYPES = ("quick", "full", "custom", "yara")
STATUSES = (
    "queued",
    "running",
    "cancel_requested",
    "cancelled",
    "succeeded",
    "failed",
    "partial",
)
TERMINAL = {"cancelled", "succeeded", "failed", "partial"}

# Only these transitions are legal. Anything else indicates a bug.
TRANSITIONS: dict[str, set[str]] = {
    "queued": {"running", "cancelled", "failed"},
    "running": {"cancel_requested", "succeeded", "failed", "partial"},
    "cancel_requested": {"cancelled", "failed"},
    "cancelled": set(),
    "succeeded": set(),
    "failed": set(),
    "partial": set(),
}

_COLUMNS = (
    "task_id, task_type, target_paths, selected_engines, created_at, started_at, "
    "finished_at, status, progress, files_scanned, detections_count, errors_count, "
    "result_summary, error_details, cancel_requested, requested_by"
)


def _row_to_task(row: dict[str, Any]) -> dict[str, Any]:
    task = dict(row)
    for key, default in (
        ("target_paths", []),
        ("selected_engines", []),
        ("result_summary", {}),
        ("error_details", []),
    ):
        try:
            task[key] = json.loads(task[key]) if task.get(key) else default
        except (TypeError, json.JSONDecodeError):
            task[key] = default
    task["cancel_requested"] = bool(task.get("cancel_requested"))
    return task


def create_task(
    db: Database,
    *,
    task_type: str,
    targets: list[str],
    engines: list[str],
    actor: str,
) -> dict[str, Any]:
    if task_type not in TASK_TYPES:
        raise invalid("无效的任务类型")
    if task_type not in SUPPORTED_TASK_TYPES:
        raise invalid(
            f"任务类型 {task_type} 尚未在当前阶段实现",
            {"supported": list(SUPPORTED_TASK_TYPES)},
        )
    if not targets:
        raise invalid("扫描目标不能为空")
    task_id = new_id()
    now = now_iso()
    with db.write() as conn:
        conn.execute(
            "INSERT INTO scan_tasks (task_id, task_type, target_paths, "
            "selected_engines, created_at, status, requested_by) "
            "VALUES (?,?,?,?,?,'queued',?)",
            (
                task_id,
                task_type,
                json.dumps(targets, ensure_ascii=False),
                json.dumps(engines, ensure_ascii=False),
                now,
                actor,
            ),
        )
    return get_task(db, task_id)


def get_task(db: Database, task_id: str) -> dict[str, Any]:
    row = db.query_one(f"SELECT {_COLUMNS} FROM scan_tasks WHERE task_id = ?", (task_id,))
    if not row:
        raise not_found("任务不存在")
    return _row_to_task(row)


def list_tasks(
    db: Database,
    *,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    where = ""
    params: list[Any] = []
    if status:
        if status not in STATUSES:
            raise invalid("无效的任务状态")
        where = "WHERE status = ?"
        params.append(status)
    total = db.query_one(f"SELECT COUNT(*) AS n FROM scan_tasks {where}", params)
    rows = db.query(
        f"SELECT {_COLUMNS} FROM scan_tasks {where} "
        "ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    return [_row_to_task(row) for row in rows], int(total["n"] if total else 0)


def next_queued(db: Database) -> dict[str, Any] | None:
    row = db.query_one(
        f"SELECT {_COLUMNS} FROM scan_tasks WHERE status = 'queued' "
        "ORDER BY created_at ASC LIMIT 1"
    )
    return _row_to_task(row) if row else None


def latest_finished(db: Database) -> dict[str, Any] | None:
    row = db.query_one(
        f"SELECT {_COLUMNS} FROM scan_tasks WHERE status IN "
        "('succeeded','failed','partial','cancelled') "
        "ORDER BY finished_at DESC LIMIT 1"
    )
    return _row_to_task(row) if row else None


def latest_active(db: Database) -> dict[str, Any] | None:
    row = db.query_one(
        f"SELECT {_COLUMNS} FROM scan_tasks WHERE status IN "
        "('queued','running','cancel_requested') ORDER BY created_at ASC LIMIT 1"
    )
    return _row_to_task(row) if row else None


def _transition(conn: Any, task_id: str, from_statuses: tuple[str, ...], to_status: str) -> bool:
    placeholders = ",".join("?" for _ in from_statuses)
    cur = conn.execute(
        f"UPDATE scan_tasks SET status = ? WHERE task_id = ? AND status IN ({placeholders})",
        (to_status, task_id, *from_statuses),
    )
    return cur.rowcount == 1


def mark_running(db: Database, task_id: str) -> bool:
    with db.write() as conn:
        updated = _transition(conn, task_id, ("queued",), "running")
        if updated:
            conn.execute(
                "UPDATE scan_tasks SET started_at = ? WHERE task_id = ?",
                (now_iso(), task_id),
            )
        return updated


def update_progress(
    db: Database,
    task_id: str,
    *,
    files_scanned: int,
    detections: int,
    errors: int,
    progress: float | None,
) -> None:
    with db.write() as conn:
        conn.execute(
            "UPDATE scan_tasks SET files_scanned = ?, detections_count = ?, "
            "errors_count = ?, progress = ? WHERE task_id = ? "
            "AND status IN ('running','cancel_requested')",
            (files_scanned, detections, errors, progress, task_id),
        )


def cancel_requested(db: Database, task_id: str) -> bool:
    row = db.query_one(
        "SELECT cancel_requested FROM scan_tasks WHERE task_id = ?", (task_id,)
    )
    if not row:
        raise not_found("任务不存在")
    return bool(row["cancel_requested"])


def request_cancel(db: Database, task_id: str) -> dict[str, Any]:
    task = get_task(db, task_id)
    if task["status"] in TERMINAL:
        raise conflict("任务已结束，无法取消", {"status": task["status"]})
    with db.write() as conn:
        conn.execute(
            "UPDATE scan_tasks SET cancel_requested = 1 WHERE task_id = ?",
            (task_id,),
        )
        if task["status"] == "queued":
            updated = _transition(conn, task_id, ("queued",), "cancelled")
            if updated:
                conn.execute(
                    "UPDATE scan_tasks SET finished_at = ?, progress = NULL "
                    "WHERE task_id = ?",
                    (now_iso(), task_id),
                )
        else:
            conn.execute(
                "UPDATE scan_tasks SET status = 'cancel_requested' "
                "WHERE task_id = ? AND status = 'running'",
                (task_id,),
            )
    return get_task(db, task_id)


def finish(
    db: Database,
    task_id: str,
    *,
    status: str,
    summary: dict[str, Any],
    errors: list[dict[str, Any]],
    files_scanned: int,
    detections: int,
    error_count: int,
    progress: float | None,
) -> dict[str, Any]:
    if status not in TERMINAL:
        raise ValueError(f"finish requires a terminal status, got {status}")
    with db.write() as conn:
        conn.execute(
            "UPDATE scan_tasks SET status = ?, finished_at = ?, result_summary = ?, "
            "error_details = ?, files_scanned = ?, detections_count = ?, "
            "errors_count = ?, progress = ? WHERE task_id = ?",
            (
                status,
                now_iso(),
                json.dumps(summary, ensure_ascii=False),
                json.dumps(errors[:100], ensure_ascii=False),
                files_scanned,
                detections,
                error_count,
                progress,
                task_id,
            ),
        )
    return get_task(db, task_id)


def recover_interrupted(db: Database) -> int:
    """Tasks left running after a daemon restart are marked failed, never left running."""
    now = now_iso()
    count = 0
    with db.write() as conn:
        rows = conn.execute(
            "SELECT task_id FROM scan_tasks WHERE status IN ('running','cancel_requested')"
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE scan_tasks SET status = 'failed', finished_at = ?, "
                "error_details = ?, result_summary = ? WHERE task_id = ?",
                (
                    now,
                    json.dumps(
                        [{"error": "守护进程重启，任务中断且未自动恢复"}],
                        ensure_ascii=False,
                    ),
                    json.dumps({"interrupted": True}, ensure_ascii=False),
                    row["task_id"],
                ),
            )
            count += 1
    return count
