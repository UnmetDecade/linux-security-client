"""Runtime settings stored as JSON values with an explicit allow-list."""

from __future__ import annotations

import json
from typing import Any

from ..common.errors import invalid
from ..common.timeutil import now_iso
from .db import Database

SETTING_KEYS = {
    "response_mode",  # alert | suggest | auto
    "auto_quarantine_enabled",
    "scheduled_scan",  # {"enabled": bool, "type": "quick", "interval_hours": int, "last_run_at": str|null}
}


def ensure_defaults(db: Database, defaults: dict[str, Any]) -> None:
    with db.write() as conn:
        for key, value in defaults.items():
            if key not in SETTING_KEYS:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?,?,?)",
                (key, json.dumps(value, ensure_ascii=False), now_iso()),
            )


def _decode(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None


def get_all(db: Database) -> dict[str, Any]:
    rows = db.query("SELECT key, value FROM settings ORDER BY key")
    return {row["key"]: _decode(row["value"]) for row in rows}


def get(db: Database, key: str, default: Any = None) -> Any:
    row = db.query_one("SELECT value FROM settings WHERE key = ?", (key,))
    if not row:
        return default
    value = _decode(row["value"])
    return default if value is None else value


def set_value(db: Database, key: str, value: Any) -> None:
    if key not in SETTING_KEYS:
        raise invalid(f"unknown setting: {key}")
    with db.write() as conn:
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, json.dumps(value, ensure_ascii=False), now_iso()),
        )


def validate_settings(patch: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in patch.items():
        if key not in SETTING_KEYS:
            raise invalid(f"unknown setting: {key}")
        if key == "response_mode":
            if value not in {"alert", "suggest", "auto"}:
                raise invalid("response_mode must be one of alert/suggest/auto")
            clean[key] = value
        elif key == "auto_quarantine_enabled":
            if not isinstance(value, bool):
                raise invalid("auto_quarantine_enabled must be a boolean")
            clean[key] = value
        elif key == "scheduled_scan":
            if not isinstance(value, dict):
                raise invalid("scheduled_scan must be an object")
            enabled = value.get("enabled", False)
            scan_type = value.get("type", "quick")
            interval = value.get("interval_hours", 24)
            if not isinstance(enabled, bool):
                raise invalid("scheduled_scan.enabled must be a boolean")
            if scan_type not in {"quick", "full", "custom"}:
                raise invalid("invalid scheduled_scan.type")
            if not isinstance(interval, int) or not 1 <= interval <= 720:
                raise invalid("scheduled_scan.interval_hours must be between 1 and 720")
            clean[key] = {
                "enabled": enabled,
                "type": scan_type,
                "interval_hours": interval,
                "last_run_at": value.get("last_run_at"),
            }
    return clean
