"""Component status persistence."""

from __future__ import annotations

import json
from typing import Any

from ..common.timeutil import now_iso
from .db import Database


def upsert_component(db: Database, status: dict[str, Any]) -> dict[str, Any]:
    now = now_iso()
    with db.write() as conn:
        conn.execute(
            "INSERT INTO components (component_id, display_name, installed, version, "
            "service_status, health_status, capabilities, last_check_at, last_update_at, "
            "error_code, error_message, details) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(component_id) DO UPDATE SET "
            "display_name=excluded.display_name, installed=excluded.installed, "
            "version=excluded.version, service_status=excluded.service_status, "
            "health_status=excluded.health_status, capabilities=excluded.capabilities, "
            "last_check_at=excluded.last_check_at, last_update_at=excluded.last_update_at, "
            "error_code=excluded.error_code, error_message=excluded.error_message, "
            "details=excluded.details",
            (
                status["component_id"],
                status["display_name"],
                1 if status.get("installed") else 0,
                status.get("version"),
                status.get("service_status", "unknown"),
                status.get("health_status", "unknown"),
                json.dumps(status.get("capabilities", []), ensure_ascii=False),
                status.get("last_check_at") or now,
                status.get("last_update_at"),
                status.get("error_code"),
                status.get("error_message"),
                json.dumps(status.get("details", {}), ensure_ascii=False),
            ),
        )
    return get_component(db, status["component_id"])


def _row(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["installed"] = bool(item.get("installed"))
    for key, default in (("capabilities", []), ("details", {})):
        try:
            item[key] = json.loads(item[key]) if item.get(key) else default
        except (TypeError, json.JSONDecodeError):
            item[key] = default
    return item


def get_component(db: Database, component_id: str) -> dict[str, Any] | None:
    row = db.query_one("SELECT * FROM components WHERE component_id = ?", (component_id,))
    return _row(row) if row else None


def list_components(db: Database) -> list[dict[str, Any]]:
    return [
        _row(row)
        for row in db.query("SELECT * FROM components ORDER BY component_id")
    ]


def mark_update(db: Database, component_id: str, version: str | None = None) -> None:
    with db.write() as conn:
        if version:
            conn.execute(
                "UPDATE components SET last_update_at = ?, version = ? "
                "WHERE component_id = ?",
                (now_iso(), version, component_id),
            )
        else:
            conn.execute(
                "UPDATE components SET last_update_at = ? WHERE component_id = ?",
                (now_iso(), component_id),
            )
