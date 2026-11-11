"""Persistence for host audit runs.

Only parsed, bounded results are stored in SQLite. Raw Lynis output lives in
the evidence directory and is referenced by path.
"""

from __future__ import annotations

import json
from typing import Any

from ..common.errors import not_found
from ..common.ids import new_id
from ..common.timeutil import now_iso
from .db import Database

STATUSES = ("queued", "running", "succeeded", "partial", "failed")
ACTIVE_STATUSES = ("queued", "running")

_META_COLUMNS = (
    "audit_id, status, scope, started_at, finished_at, requested_by, "
    "checks_total, findings_count, errors_count, severity_counts, "
    "hardening_index, lynis_available, lynis_version, evidence_path, error, "
    "created_at"
)
_ALL_COLUMNS = f"{_META_COLUMNS}, result_summary"


def _row(row: dict[str, Any], *, include_summary: bool) -> dict[str, Any]:
    item = dict(row)
    for key in ("severity_counts",):
        try:
            item[key] = json.loads(item.get(key) or "{}")
        except (TypeError, json.JSONDecodeError):
            item[key] = {}
    item["lynis_available"] = bool(item.get("lynis_available"))
    if include_summary:
        try:
            item["result_summary"] = json.loads(item.get("result_summary") or "{}")
        except (TypeError, json.JSONDecodeError):
            item["result_summary"] = {}
    else:
        item.pop("result_summary", None)
    return item


def create_run(db: Database, *, scope: str, requested_by: str) -> dict[str, Any]:
    audit_id = new_id()
    now = now_iso()
    with db.write() as conn:
        conn.execute(
            "INSERT INTO audit_runs (audit_id, status, scope, requested_by, "
            "created_at) VALUES (?,?,?,?,?)",
            (audit_id, "queued", scope[:100], requested_by[:100], now),
        )
    return get_run(db, audit_id)


def mark_running(db: Database, audit_id: str) -> bool:
    with db.write() as conn:
        cur = conn.execute(
            "UPDATE audit_runs SET status = 'running', started_at = ? "
            "WHERE audit_id = ? AND status = 'queued'",
            (now_iso(), audit_id),
        )
        return cur.rowcount == 1


def finish_run(
    db: Database,
    audit_id: str,
    *,
    status: str,
    summary: dict[str, Any],
    checks_total: int,
    findings_count: int,
    errors_count: int,
    severity_counts: dict[str, int],
    hardening_index: int | None = None,
    lynis_available: bool = False,
    lynis_version: str | None = None,
    evidence_path: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    if status not in STATUSES:
        status = "failed"
    with db.write() as conn:
        conn.execute(
            "UPDATE audit_runs SET status = ?, finished_at = ?, checks_total = ?, "
            "findings_count = ?, errors_count = ?, severity_counts = ?, "
            "hardening_index = ?, lynis_available = ?, lynis_version = ?, "
            "evidence_path = ?, error = ?, result_summary = ? WHERE audit_id = ?",
            (
                status,
                now_iso(),
                int(checks_total),
                int(findings_count),
                int(errors_count),
                json.dumps(severity_counts, ensure_ascii=False),
                hardening_index,
                1 if lynis_available else 0,
                (lynis_version or "")[:120] or None,
                evidence_path,
                (error or "")[:2000] or None,
                json.dumps(summary, ensure_ascii=False, default=str),
                audit_id,
            ),
        )
    return get_run(db, audit_id)


def recover_interrupted(db: Database) -> int:
    with db.write() as conn:
        cur = conn.execute(
            "UPDATE audit_runs SET status = 'failed', finished_at = ?, "
            "error = ? WHERE status IN ('queued','running')",
            (now_iso(), "守护进程重启，体检已中断；请重新运行"),
        )
        return cur.rowcount


def get_run(db: Database, audit_id: str) -> dict[str, Any]:
    row = db.query_one(
        f"SELECT {_ALL_COLUMNS} FROM audit_runs WHERE audit_id = ?", (audit_id,)
    )
    if not row:
        raise not_found("体检记录不存在")
    return _row(row, include_summary=True)


def list_runs(
    db: Database, *, limit: int = 20, offset: int = 0
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    total = db.query_one("SELECT COUNT(*) AS n FROM audit_runs")
    rows = db.query(
        f"SELECT {_META_COLUMNS} FROM audit_runs "
        "ORDER BY created_at DESC, audit_id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    return [_row(row, include_summary=False) for row in rows], int(
        total["n"] if total else 0
    )


def latest_active(db: Database) -> dict[str, Any] | None:
    row = db.query_one(
        f"SELECT {_META_COLUMNS} FROM audit_runs "
        "WHERE status IN ('queued','running') "
        "ORDER BY created_at DESC LIMIT 1"
    )
    return _row(row, include_summary=False) if row else None


def latest_finished(db: Database) -> dict[str, Any] | None:
    row = db.query_one(
        f"SELECT {_META_COLUMNS} FROM audit_runs "
        "WHERE status IN ('succeeded','partial','failed') "
        "ORDER BY finished_at DESC LIMIT 1"
    )
    return _row(row, include_summary=False) if row else None
