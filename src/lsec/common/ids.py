"""Identifier helpers."""

from __future__ import annotations

import re
import uuid

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def new_id() -> str:
    return str(uuid.uuid4())


def is_uuid(value: object) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.match(value))


def new_id_or_value(value: str | None) -> str:
    """Use a caller supplied request id when it is a valid UUID, else mint one."""
    if is_uuid(value):
        return value  # type: ignore[return-value]
    return new_id()
