"""Append-only audit trail for privileged operations."""

from __future__ import annotations

import json
from typing import Any

from ..common.ids import new_id
from ..common.timeutil import now_iso
from .db import Database

MAX_STATE_BYTES = 16 * 1024


def _dump_state(value: Any) -> str | None:
    if value is None:
        return None
    text = json.dumps(value, ensure_ascii=False, default=str)
    if len(text.encode("utf-8")) > MAX_STATE_BYTES:
        return json.dumps({"truncated": True, "preview": text[: MAX_STATE_BYTES // 2]}, ensure_ascii=False)
    return text


def record(
    db: Database,
    *,
    action: str,
    actor: str,
    result: str,
    client: str | None = None,
    request_id: str | None = None,
    target: str | None = None,
    before_state: Any = None,
    after_state: Any = None,
    confirmed: bool = False,
    error: str | None = None,
) -> dict[str, Any]:
    record_id = new_id()
    created = now_iso()
    with db.write() as conn:
        conn.execute(
            "INSERT INTO audit_records (record_id, request_id, actor, client, action, "
            "target, before_state, after_state, confirmed, result, error, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record_id,
                request_id,
                actor,
                client,
                action,
                target,
                _dump_state(before_state),
                _dump_state(after_state),
                1 if confirmed else 0,
                result,
                error,
                created,
            ),
        )
    return get_record(db, record_id)


def _row(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["confirmed"] = bool(item.get("confirmed"))
    for key in ("before_state", "after_state"):
        if item.get(key):
            try:
                item[key] = json.loads(item[key])
            except (TypeError, json.JSONDecodeError):
                pass
    return item


def get_record(db: Database, record_id: str) -> dict[str, Any] | None:
    row = db.query_one("SELECT * FROM audit_records WHERE record_id = ?", (record_id,))
    return _row(row) if row else None


def list_records(
    db: Database, *, limit: int = 100, offset: int = 0, action: str | None = None
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    where = ""
    params: list[Any] = []
    if action:
        where = "WHERE action = ?"
        params.append(action)
    total = db.query_one(f"SELECT COUNT(*) AS n FROM audit_records {where}", params)
    rows = db.query(
        f"SELECT * FROM audit_records {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    return [_row(row) for row in rows], int(total["n"] if total else 0)
