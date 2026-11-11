"""Falco JSON alert normalization.

Falco is a host-side runtime sensor. lsec only receives its already-evaluated
alerts through an authenticated integration endpoint; it does not reinterpret
raw syscalls or fabricate runtime detections.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

from ..common.errors import invalid
from ..common.timeutil import now_iso
from .events import _compact, validate_event

PRIORITY_MAP = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "informational": "info",
    "info": "info",
    "debug": "info",
}

_CONTAINER_ID_RE = re.compile(r"^[0-9a-fA-F]{12,64}$")
_FIELD_KEYS = (
    "container.id",
    "container.name",
    "container.image.repository",
    "container.image.tag",
    "proc.name",
    "proc.pid",
    "proc.cmdline",
    "user.name",
    "fd.name",
    "evt.type",
    "k8s.ns.name",
    "k8s.pod.name",
)


def _text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return ""
    return str(value)[:limit]


def _dedup_key(*parts: str) -> str:
    return hashlib.sha256(
        "|".join(parts).encode("utf-8", errors="replace")
    ).hexdigest()


def normalize_falco_event(
    payload: dict[str, Any],
    *,
    host_provider: Callable[[], dict[str, Any]],
    max_event_bytes: int = 32768,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise invalid("Falco 事件必须是 JSON 对象")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    except (TypeError, ValueError):
        raise invalid("Falco 事件无法序列化") from None
    if len(encoded) > max_event_bytes:
        raise invalid("Falco 事件超过大小上限")

    rule = _text(payload.get("rule"), 200)
    output = _text(payload.get("output"), 2000)
    priority_raw = _text(payload.get("priority"), 40)
    if not rule and not output:
        raise invalid("Falco 事件缺少 rule 和 output")
    priority = priority_raw.lower()
    severity = PRIORITY_MAP.get(priority, "medium")

    raw_fields = payload.get("output_fields")
    if raw_fields is None:
        raw_fields = {}
    if not isinstance(raw_fields, dict):
        raise invalid("Falco output_fields 必须是对象")
    fields: dict[str, Any] = {}
    for key in _FIELD_KEYS:
        if key not in raw_fields:
            continue
        value = raw_fields[key]
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            continue
        if isinstance(value, str):
            fields[key] = value[:500]
        else:
            fields[key] = value

    container_id = _text(fields.get("container.id"), 128)
    if container_id and not _CONTAINER_ID_RE.match(container_id):
        container_id = ""
    container_name = _text(fields.get("container.name"), 300)
    image = _text(fields.get("container.image.repository"), 500)
    image_tag = _text(fields.get("container.image.tag"), 100)
    if image and image_tag:
        image = f"{image}:{image_tag}"
    proc_name = _text(fields.get("proc.name"), 200)
    pid_value = fields.get("proc.pid")
    try:
        pid = int(pid_value) if pid_value is not None else None
    except (TypeError, ValueError):
        pid = None

    title = f"Falco 告警: {rule}" if rule else "Falco 运行时告警"
    source_ref = {
        "source": "falco",
        "rule": rule[:200],
        "priority": priority_raw[:40],
    }
    uuid = _text(payload.get("uuid"), 100)
    if uuid:
        source_ref["uuid"] = uuid

    event = {
        "schema_version": 1,
        "timestamp": now_iso(),
        "source": "falco",
        "category": "runtime",
        "severity": severity,
        "title": title[:300],
        "description": (output or title)[:4000],
        "host": _compact(host_provider()),
        "target": {
            "type": "container" if (container_id or container_name) else "host",
            "path": None,
            "pid": pid,
            "container_id": container_id or None,
            "name": container_name or None,
        },
        "evidence": _compact(
            {
                "rule_id": rule[:200] or None,
                "detection_name": rule[:200] or None,
                "priority": priority_raw[:40] or None,
                "output": output[:2000] or None,
                "source_time": _text(payload.get("time"), 80) or None,
                "hostname": _text(payload.get("hostname"), 200) or None,
                "container_image": image or None,
                "output_fields": fields,
                "engine": "falco",
            }
        ),
        "status": "new",
        "recommended_actions": [
            "核实容器与进程行为，结合 Falco 原始输出判断是否误报",
            "保留容器 ID、镜像和进程信息作为调查证据",
            "在确认影响前不要停止生产容器或结束未知进程",
        ],
        "dedup_key": _dedup_key(
            "falco",
            "runtime",
            rule or "unknown",
            container_id or "host",
            proc_name or "",
        ),
        "source_ref": source_ref,
    }
    validate_event(event)
    return event
