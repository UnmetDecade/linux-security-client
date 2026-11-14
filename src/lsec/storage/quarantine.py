"""Quarantine metadata. Files themselves live in a daemon-only directory."""

from __future__ import annotations

from typing import Any

from ..common.errors import not_found
from ..common.timeutil import now_iso
from ..common.ids import new_id
from .db import Database

STATUSES = ("quarantined", "restored", "deleted", "missing")


def add_item(
    db: Database,
    *,
    original_path: str,
    stored_name: str,
    sha256: str,
    size: int,
    actor: str,
    detected_at: str | None = None,
    engine: str | None = None,
    detection_name: str | None = None,
    event_id: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    item_id = new_id()
    with db.write() as conn:
        conn.execute(
            "INSERT INTO quarantine_items (item_id, original_path, stored_name, "
            "sha256, size, detected_at, engine, detection_name, event_id, "
            "quarantined_by, status, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                item_id,
                original_path,
                stored_name,
                sha256,
                size,
                detected_at or now_iso(),
                engine,
                detection_name,
                event_id,
                actor,
                "quarantined",
                notes,
            ),
        )
    return get_item(db, item_id)


def get_item(db: Database, item_id: str) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM quarantine_items WHERE item_id = ?", (item_id,))
    if not row:
        raise not_found("quarantine item not found")
    return dict(row)


def list_items(
    db: Database, *, status: str | None = None, limit: int = 100, offset: int = 0
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    where = ""
    params: list[Any] = []
    if status:
        where = "WHERE status = ?"
        params.append(status)
    total = db.query_one(f"SELECT COUNT(*) AS n FROM quarantine_items {where}", params)
    rows = db.query(
        f"SELECT * FROM quarantine_items {where} ORDER BY detected_at DESC "
        "LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    return [dict(row) for row in rows], int(total["n"] if total else 0)


def mark_restored(db: Database, item_id: str) -> dict[str, Any]:
    with db.write() as conn:
        conn.execute(
            "UPDATE quarantine_items SET status = 'restored', restored_at = ? "
            "WHERE item_id = ?",
            (now_iso(), item_id),
        )
    return get_item(db, item_id)


def mark_deleted(db: Database, item_id: str) -> dict[str, Any]:
    with db.write() as conn:
        conn.execute(
            "UPDATE quarantine_items SET status = 'deleted', deleted_at = ? "
            "WHERE item_id = ?",
            (now_iso(), item_id),
        )
    return get_item(db, item_id)


def mark_missing(db: Database, item_id: str, note: str) -> dict[str, Any]:
    with db.write() as conn:
        conn.execute(
            "UPDATE quarantine_items SET status = 'missing', notes = ? WHERE item_id = ?",
            (note[:2000], item_id),
        )
    return get_item(db, item_id)


def total_size(db: Database) -> int:
    row = db.query_one(
        "SELECT COALESCE(SUM(size), 0) AS total FROM quarantine_items "
        "WHERE status = 'quarantined'"
    )
    return int(row["total"] if row else 0)
