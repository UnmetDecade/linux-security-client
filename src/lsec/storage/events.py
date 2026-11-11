"""Event persistence, filtering and deduplication."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from ..common.errors import invalid, not_found
from ..common.timeutil import now_iso, parse_iso, to_iso, utcnow
from ..common.ids import new_id
from .db import Database

SEVERITIES = ("critical", "high", "medium", "low", "info")
OPEN_STATUSES = ("new", "acknowledged", "investigating")
STATUSES = ("new", "acknowledged", "investigating", "resolved", "ignored")

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "new": {"acknowledged", "investigating", "resolved", "ignored"},
    "acknowledged": {"investigating", "resolved", "ignored"},
    "investigating": {"resolved", "ignored"},
    "resolved": {"new"},
    "ignored": {"new"},
}

_EVENT_COLUMNS = (
    "seq, event_id, schema_version, timestamp, source, category, severity, "
    "title, description, host, target, evidence, status, recommended_actions, "
    "dedup_key, first_seen_at, last_seen_at, occurrences, source_refs, updated_at"
)


def _row_to_event(row: dict[str, Any]) -> dict[str, Any]:
    event = dict(row)
    for key in ("host", "target", "evidence"):
        try:
            event[key] = json.loads(event[key]) if event.get(key) else {}
        except (TypeError, json.JSONDecodeError):
            event[key] = {}
    for key in ("recommended_actions", "source_refs"):
        try:
            event[key] = json.loads(event[key]) if event.get(key) else []
        except (TypeError, json.JSONDecodeError):
            event[key] = []
    return event


def event_to_api(row: dict[str, Any]) -> dict[str, Any]:
    ev = _row_to_event(row)
    return ev


def insert_event(
    db: Database,
    event: dict[str, Any],
    *,
    dedup_window_hours: int = 24,
) -> tuple[dict[str, Any], bool]:
    """Insert an event or merge it into an open duplicate.

    Returns (event, created). Merging preserves first/last seen, occurrence
    count and source references as required by the product specification.
    """
    dedup_key = event["dedup_key"]
    cutoff = to_iso(utcnow() - timedelta(hours=max(dedup_window_hours, 0)))
    existing = db.query_one(
        f"SELECT {_EVENT_COLUMNS} FROM events "
        "WHERE dedup_key = ? AND status IN ('new','acknowledged','investigating') "
        "AND last_seen_at >= ? ORDER BY last_seen_at DESC LIMIT 1",
        (dedup_key, cutoff),
    )
    now = now_iso()
    if existing:
        refs = []
        try:
            refs = json.loads(existing["source_refs"]) or []
        except (TypeError, json.JSONDecodeError):
            refs = []
        source_ref = event.get("source_ref")
        if source_ref:
            refs.append(source_ref)
            refs = refs[-10:]
        with db.write() as conn:
            conn.execute(
                "UPDATE events SET last_seen_at = ?, occurrences = occurrences + 1, "
                "source_refs = ?, updated_at = ? WHERE event_id = ?",
                (now, json.dumps(refs, ensure_ascii=False), now, existing["event_id"]),
            )
        merged = db.query_one(
            f"SELECT {_EVENT_COLUMNS} FROM events WHERE event_id = ?",
            (existing["event_id"],),
        )
        return _row_to_event(merged or existing), False

    event_id = event.get("event_id") or new_id()
    timestamp = event.get("timestamp") or now
    with db.write() as conn:
        conn.execute(
            "INSERT INTO events (event_id, schema_version, timestamp, source, category, "
            "severity, title, description, host, target, evidence, status, "
            "recommended_actions, dedup_key, first_seen_at, last_seen_at, "
            "occurrences, source_refs, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                int(event.get("schema_version", 1)),
                timestamp,
                event["source"],
                event["category"],
                event["severity"],
                event["title"],
                event.get("description", ""),
                json.dumps(event.get("host", {}), ensure_ascii=False),
                json.dumps(event.get("target", {}), ensure_ascii=False),
                json.dumps(event.get("evidence", {}), ensure_ascii=False),
                event.get("status", "new"),
                json.dumps(event.get("recommended_actions", []), ensure_ascii=False),
                dedup_key,
                timestamp,
                timestamp,
                1,
                json.dumps([event["source_ref"]] if event.get("source_ref") else [], ensure_ascii=False),
                now,
            ),
        )
    row = db.query_one(
        f"SELECT {_EVENT_COLUMNS} FROM events WHERE event_id = ?", (event_id,)
    )
    return _row_to_event(row or {}), True


def _build_filters(
    severity: str | None = None,
    source: str | None = None,
    category: str | None = None,
    status: str | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if search:
        clauses.append(
            "(title LIKE ? OR description LIKE ? OR target LIKE ?)"
        )
        like = f"%{search[:200]}%"
        params.extend([like, like, like])
    if since:
        clauses.append("last_seen_at >= ?")
        params.append(since)
    if until:
        clauses.append("last_seen_at <= ?")
        params.append(until)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def list_events(
    db: Database,
    *,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    source: str | None = None,
    category: str | None = None,
    status: str | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    where, params = _build_filters(
        severity, source, category, status, search, since, until
    )
    total_row = db.query_one(f"SELECT COUNT(*) AS n FROM events {where}", params)
    rows = db.query(
        f"SELECT {_EVENT_COLUMNS} FROM events {where} "
        "ORDER BY last_seen_at DESC, seq DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    return [_row_to_event(row) for row in rows], int(total_row["n"] if total_row else 0)


def get_event(db: Database, event_id: str) -> dict[str, Any]:
    row = db.query_one(
        f"SELECT {_EVENT_COLUMNS} FROM events WHERE event_id = ?", (event_id,)
    )
    if not row:
        raise not_found("事件不存在")
    return _row_to_event(row)


def update_status(
    db: Database, event_id: str, new_status: str, *, actor: str, note: str | None = None
) -> dict[str, Any]:
    if new_status not in STATUSES:
        raise invalid("无效的事件状态")
    current = get_event(db, event_id)
    if new_status == current["status"]:
        return current
    if new_status not in ALLOWED_TRANSITIONS.get(current["status"], set()):
        raise invalid(
            f"不允许从 {current['status']} 变更为 {new_status}",
            {"allowed": sorted(ALLOWED_TRANSITIONS.get(current["status"], []))},
        )
    now = now_iso()
    evidence = current.get("evidence") or {}
    if note:
        notes = evidence.setdefault("status_notes", [])
        notes.append({"at": now, "actor": actor, "status": new_status, "note": note[:2000]})
        evidence["status_notes"] = notes[-20:]
    with db.write() as conn:
        conn.execute(
            "UPDATE events SET status = ?, evidence = ?, updated_at = ? WHERE event_id = ?",
            (new_status, json.dumps(evidence, ensure_ascii=False), now, event_id),
        )
    return get_event(db, event_id)


def open_counts(db: Database) -> dict[str, int]:
    rows = db.query(
        "SELECT severity, COUNT(*) AS n FROM events "
        "WHERE status IN ('new','acknowledged','investigating') GROUP BY severity"
    )
    counts = {severity: 0 for severity in SEVERITIES}
    for row in rows:
        counts[row["severity"]] = int(row["n"])
    counts["total_open"] = sum(counts[s] for s in SEVERITIES)
    return counts


def status_counts(db: Database) -> dict[str, int]:
    rows = db.query("SELECT status, COUNT(*) AS n FROM events GROUP BY status")
    counts = {status: 0 for status in STATUSES}
    for row in rows:
        counts[row["status"]] = int(row["n"])
    return counts


def event_sources(db: Database) -> list[str]:
    return [row["source"] for row in db.query("SELECT DISTINCT source FROM events ORDER BY source")]


def export_events(db: Database, *, limit: int = 5000, **filters: Any) -> list[dict[str, Any]]:
    where, params = _build_filters(**filters)
    rows = db.query(
        f"SELECT {_EVENT_COLUMNS} FROM events {where} "
        "ORDER BY last_seen_at DESC, seq DESC LIMIT ?",
        params + [max(1, min(limit, 20000))],
    )
    return [_row_to_event(row) for row in rows]


def prune_events(db: Database, *, retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    cutoff = to_iso(utcnow() - timedelta(days=retention_days))
    with db.write() as conn:
        cur = conn.execute(
            "DELETE FROM events WHERE status IN ('resolved','ignored') "
            "AND last_seen_at < ?",
            (cutoff,),
        )
        return cur.rowcount
