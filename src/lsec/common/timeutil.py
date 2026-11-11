"""UTC time helpers. All persisted timestamps are UTC ISO-8601 with Z."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def now_iso() -> str:
    return to_iso(utcnow())


def parse_iso(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def age_hours(timestamp: str | None) -> float | None:
    if not timestamp:
        return None
    try:
        delta = utcnow() - parse_iso(timestamp)
    except (ValueError, TypeError):
        return None
    return round(max(delta.total_seconds(), 0.0) / 3600.0, 2)
