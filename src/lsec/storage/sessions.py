"""Login sessions (Web UI) persisted so restarts do not silently authorize."""

from __future__ import annotations

import json
import secrets
from datetime import timedelta
from typing import Any

from ..common.timeutil import now_iso, to_iso, utcnow
from .db import Database

ROLES = ("admin", "viewer")


def create(db: Database, *, role: str, ttl_hours: int, remote_addr: str | None) -> dict[str, Any]:
    if role not in ROLES:
        raise ValueError(f"bad role: {role}")
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    created = now_iso()
    expires = to_iso(utcnow() + timedelta(hours=max(1, ttl_hours)))
    with db.write() as conn:
        conn.execute(
            "INSERT INTO sessions (session_id, role, csrf_token, created_at, "
            "expires_at, remote_addr) VALUES (?,?,?,?,?,?)",
            (session_id, role, csrf_token, created, expires, remote_addr),
        )
    return {
        "session_id": session_id,
        "role": role,
        "csrf_token": csrf_token,
        "created_at": created,
        "expires_at": expires,
    }


def get_valid(db: Database, session_id: str) -> dict[str, Any] | None:
    if not session_id:
        return None
    row = db.query_one(
        "SELECT * FROM sessions WHERE session_id = ? AND expires_at > ?",
        (session_id, now_iso()),
    )
    return dict(row) if row else None


def delete(db: Database, session_id: str) -> None:
    with db.write() as conn:
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))


def prune_expired(db: Database) -> int:
    with db.write() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))
        return cur.rowcount
