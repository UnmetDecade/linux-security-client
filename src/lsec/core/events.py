"""Event normalization and alert management.

All engines are mapped onto the single SecurityEvent model. Severity mapping is
deterministic and documented; raw tool output is truncated and never stored
unbounded.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from ..adapters.base import Detection
from ..common.errors import invalid
from ..common.timeutil import now_iso
from ..storage import events as event_store
from ..storage.db import Database

VALID_SOURCES = ("clamav", "falco", "wazuh", "yara", "lynis", "system", "docker")
VALID_CATEGORIES = (
    "malware",
    "intrusion",
    "runtime",
    "integrity",
    "vulnerability",
    "configuration",
)
MAX_DETAILS_BYTES = 32 * 1024


def severity_for_detection(name: str) -> str:
    """Map a ClamAV signature name to a product severity.

    EICAR is the industry test signature: it proves the pipeline works but is
    not real malware, so it maps to medium rather than critical.
    """
    lower = (name or "").lower()
    if "eicar" in lower:
        return "medium"
    if any(token in lower for token in ("trojan", "backdoor", "ransom", "rootkit", "exploit", "worm")):
        return "critical"
    if any(token in lower for token in ("pup", "pua", "adware", "toolbar")):
        return "low"
    return "high"


def _wazuh_level(value: Any) -> int:
    try:
        level = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(15, level))


def wazuh_severity(level: int) -> str:
    """Map Wazuh rule levels to product severities (documented in docs)."""
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    if level >= 1:
        return "low"
    return "info"


def _wazuh_groups(value: Any) -> list[str]:
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = value.split(",")
    else:
        items = []
    return [str(item).strip()[:80] for item in items if str(item).strip()][:30]


def wazuh_category(rule: dict[str, Any]) -> str:
    groups = " ".join(_wazuh_groups(rule.get("groups"))).lower()
    if any(token in groups for token in ("malware", "virus", "rootcheck", "trojan")):
        return "malware"
    if any(
        token in groups
        for token in ("authentication", "sshd", "access_control", "brute", "login")
    ):
        return "intrusion"
    if any(token in groups for token in ("syscheck", "integrity", "fim")):
        return "integrity"
    if any(token in groups for token in ("vulnerability", "cve", "vuln")):
        return "vulnerability"
    if any(token in groups for token in ("sca", "policy", "configuration", "audit")):
        return "configuration"
    return "runtime"


def _compact(value: Any, limit_bytes: int = MAX_DETAILS_BYTES) -> Any:
    try:
        encoded = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"error": "evidence could not be serialized"}
    if len(encoded.encode("utf-8")) <= limit_bytes:
        return value
    return {"truncated": True, "preview": encoded[: limit_bytes // 2]}


def _dedup_key(*parts: str) -> str:
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


class EventService:
    def __init__(
        self,
        db: Database,
        *,
        host_provider: Callable[[], dict[str, Any]],
        dedup_window_hours: int = 24,
    ) -> None:
        self.db = db
        self.host_provider = host_provider
        self.dedup_window_hours = dedup_window_hours

    # ------------------------------------------------------------- ingestion
    def ingest_clamav_detection(
        self, detection: Detection, *, task_id: str, task_type: str
    ) -> dict[str, Any]:
        name = detection.detection_name[:300]
        path = detection.path[:4096]
        severity = severity_for_detection(name)
        event = {
            "schema_version": 1,
            "timestamp": now_iso(),
            "source": "clamav",
            "category": "malware",
            "severity": severity,
            "title": f"Malicious file detected: {name}",
            "description": (
                f"ClamAV found a malicious file during scan task {task_id} ({task_type}). "
                "The file has not been handled automatically; verify it before deciding whether to quarantine it."
            )[:4000],
            "host": _compact(self.host_provider()),
            "target": {
                "type": "file",
                "path": path,
                "pid": None,
                "container_id": None,
                "name": None,
            },
            "evidence": _compact(
                {
                    "sha256": detection.sha256,
                    "rule_id": None,
                    "detection_name": name,
                    "details": {
                        "engine": "clamav",
                        "task_id": task_id,
                        "task_type": task_type,
                        "size": detection.size,
                        **detection.details,
                    },
                }
            ),
            "status": "new",
            "recommended_actions": [
                "Verify the file's origin and purpose",
                "Quarantine the file and rescan after confirmation",
                "If it cannot be confirmed, preserve the evidence and escalate",
            ],
            "dedup_key": _dedup_key("clamav", "malware", path, name),
            "source_ref": {"source": "clamav", "task_id": task_id, "detection_name": name},
        }
        stored, created = event_store.insert_event(
            self.db, event, dedup_window_hours=self.dedup_window_hours
        )
        return stored

    def ingest_yara_detection(
        self, detection: Detection, *, task_id: str, task_type: str
    ) -> dict[str, Any]:
        """Normalize one YARA rule match into the unified event model."""
        details = detection.details or {}
        rule = detection.detection_name[:300]
        path = detection.path[:4096]
        pack_id = str(details.get("pack_id") or "")[:120]
        pack_version = str(details.get("pack_version") or "")[:120]
        tags = [str(tag)[:80] for tag in (details.get("tags") or [])[:30]]
        severity = str(details.get("severity") or "")
        if severity not in event_store.SEVERITIES:
            severity = severity_for_detection(rule)
        title = f"YARA rule match: {rule}"[:300]
        event = {
            "schema_version": 1,
            "timestamp": now_iso(),
            "source": "yara",
            "category": "malware",
            "severity": severity,
            "title": title,
            "description": (
                f"YARA rule pack {pack_id or 'unknown'} ({pack_version or 'unknown version'}) "
                f"matched a file during scan task {task_id} ({task_type}). "
                "A rule match means the content pattern matched and is not equivalent to confirmed malware; "
                "the file has not been quarantined or deleted automatically. Verify the rule, the file's origin and purpose."
            )[:4000],
            "host": _compact(self.host_provider()),
            "target": {
                "type": "file",
                "path": path,
                "pid": None,
                "container_id": None,
                "name": None,
            },
            "evidence": _compact(
                {
                    "sha256": detection.sha256,
                    "rule_id": f"{pack_id}:{rule}"[:240],
                    "detection_name": rule,
                    "details": {
                        "engine": "yara",
                        "task_id": task_id,
                        "task_type": task_type,
                        "pack_id": pack_id,
                        "pack_version": pack_version,
                        "rule": rule,
                        "tags": tags,
                        "size": detection.size,
                    },
                }
            ),
            "status": "new",
            "recommended_actions": [
                "Review the rule content, tags and file origin to determine whether this is a real threat or a false positive",
                "If confirmed, quarantine the file through the quarantine store and record the reason",
                "Do not delete system files or stop production services solely because of a rule match",
            ],
            "dedup_key": _dedup_key(
                "yara", "malware", pack_id, pack_version, rule, path
            ),
            "source_ref": {
                "source": "yara",
                "task_id": task_id,
                "pack_id": pack_id,
                "pack_version": pack_version,
                "rule": rule,
            },
        }
        stored, _created = event_store.insert_event(
            self.db, event, dedup_window_hours=self.dedup_window_hours
        )
        return stored

    def ingest_wazuh_alert(
        self, alert: dict[str, Any], *, max_event_bytes: int = 32768
    ) -> dict[str, Any]:
        """Normalize one local Wazuh Agent alert into the unified event model.

        Only alerts read from the local ``alerts.json`` reach this method. lsec
        never contacts a Wazuh Manager and never claims manager capability.
        """
        if not isinstance(alert, dict):
            raise invalid("Wazuh alerts must be JSON objects")
        try:
            encoded = json.dumps(alert, ensure_ascii=False, default=str).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise invalid(f"Wazuh alert could not be serialized: {exc}") from exc
        if len(encoded) > max_event_bytes:
            raise invalid(
                "Wazuh alert exceeds the size limit",
                {"bytes": len(encoded), "max_event_bytes": max_event_bytes},
            )

        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
        manager = alert.get("manager") if isinstance(alert.get("manager"), dict) else {}
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        syscheck = (
            alert.get("syscheck") if isinstance(alert.get("syscheck"), dict) else {}
        )
        level = _wazuh_level(rule.get("level"))
        severity = wazuh_severity(level)
        category = wazuh_category(rule)
        description = str(rule.get("description") or "unnamed Wazuh alert")[:500]
        rule_id = str(rule.get("id") or "")[:80]
        groups = _wazuh_groups(rule.get("groups"))
        agent_id = str(agent.get("id") or "")[:80]
        agent_name = str(agent.get("name") or "")[:200]
        alert_id = str(alert.get("id") or "")[:120]

        path = str(syscheck.get("path") or "")[:4096]
        srcip = str(data.get("srcip") or "")[:200]
        if path:
            target = {
                "type": "file",
                "path": path,
                "pid": None,
                "container_id": None,
                "name": None,
            }
        elif srcip:
            target = {
                "type": "network",
                "path": None,
                "pid": None,
                "container_id": None,
                "name": srcip,
            }
        else:
            target = {
                "type": "host",
                "path": None,
                "pid": None,
                "container_id": None,
                "name": agent_name or agent_id or None,
            }

        subject = path or srcip or agent_name or "this host"
        event = {
            "schema_version": 1,
            "timestamp": now_iso(),
            "source": "wazuh",
            "category": category,
            "severity": severity,
            "title": f"Wazuh alert: {description}"[:300],
            "description": (
                f"Local Wazuh Agent {agent_name or agent_id or 'unknown'} produced a level-"
                f"{level} alert (rule {rule_id or 'unknown'}). "
                "The event comes from the local alerts.json and only represents alerts received/generated by the Agent; "
                "lsec is not a Wazuh Manager, does not verify full Manager capability, and never quarantines or deletes files automatically."
            )[:4000],
            "host": _compact(self.host_provider()),
            "target": target,
            "evidence": _compact(
                {
                    "sha256": None,
                    "rule_id": rule_id or None,
                    "detection_name": description,
                    "details": {
                        "engine": "wazuh",
                        "alert_id": alert_id,
                        "alert_timestamp": alert.get("timestamp"),
                        "rule_level": level,
                        "rule_groups": groups,
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                        "agent_ip": str(agent.get("ip") or "")[:200] or None,
                        "manager_name": str(manager.get("name") or "")[:200] or None,
                        "location": str(alert.get("location") or "")[:500] or None,
                        "decoder": str(alert.get("decoder") or "")[:120] or None,
                        "full_log": str(alert.get("full_log") or "")[:8000] or None,
                        "data": _compact(data, 8192),
                        "scope": "local_agent_alert_file",
                        "raw": _compact(alert, 24576),
                    },
                }
            ),
            "status": "new",
            "recommended_actions": [
                "Review the Wazuh rule, Agent and alert context to determine whether this is a real threat",
                "Confirm the related rules and full investigation details on the Wazuh Manager side (this client does not provide a Manager API)",
                "If action is needed, use the quarantine store and record the reason; files are never deleted and system configuration is never changed automatically",
            ],
            "dedup_key": _dedup_key(
                "wazuh", "alert", agent_id, rule_id, description, subject
            ),
            "source_ref": {
                "source": "wazuh",
                "scope": "local_agent_alert_file",
                "alert_id": alert_id or None,
                "rule_id": rule_id or None,
                "agent_id": agent_id or None,
                "manager_connection_verified": False,
            },
        }
        stored, _created = event_store.insert_event(
            self.db, event, dedup_window_hours=self.dedup_window_hours
        )
        return stored

    def ingest_finding(
        self,
        *,
        source: str,
        category: str,
        severity: str,
        title: str,
        description: str,
        check_id: str,
        target: dict[str, Any],
        evidence: dict[str, Any],
        recommended_actions: list[str],
        dedup_hint: str = "",
        source_ref: dict[str, Any] | None = None,
        with_created: bool = False,
    ) -> dict[str, Any] | tuple[dict[str, Any], bool]:
        """Normalize a host-audit or Lynis finding into the event model."""
        if source not in VALID_SOURCES:
            raise invalid("invalid event source")
        if category not in VALID_CATEGORIES:
            raise invalid("invalid event category")
        if severity not in event_store.SEVERITIES:
            raise invalid("invalid event severity")
        title = (title or "security baseline finding")[:300]
        target = target or {"type": "host"}
        body = {
            "schema_version": 1,
            "timestamp": now_iso(),
            "source": source,
            "category": category,
            "severity": severity,
            "title": title,
            "description": (description or "")[:4000],
            "host": _compact(self.host_provider()),
            "target": {
                "type": target.get("type") or "host",
                "path": target.get("path"),
                "pid": target.get("pid"),
                "container_id": target.get("container_id"),
                "name": target.get("name"),
            },
            "evidence": _compact(
                {
                    "check_id": check_id[:120],
                    "rule_id": check_id[:120],
                    "detection_name": None,
                    "details": evidence,
                }
            ),
            "status": "new",
            "recommended_actions": [
                action[:500] for action in (recommended_actions or [])[:10]
            ],
            "dedup_key": _dedup_key(
                source,
                category,
                check_id,
                dedup_hint or title,
            ),
            "source_ref": source_ref
            or {"source": source, "check_id": check_id, "dedup_hint": dedup_hint},
        }
        validate_event(body)
        stored, created = event_store.insert_event(
            self.db, body, dedup_window_hours=self.dedup_window_hours
        )
        if with_created:
            return stored, created
        return stored

    def ingest_falco_event(
        self, payload: dict[str, Any], *, max_event_bytes: int = 32768
    ) -> tuple[dict[str, Any], bool]:
        """Validate and store one Falco JSON alert."""
        from .falco import normalize_falco_event

        event = normalize_falco_event(
            payload,
            host_provider=self.host_provider,
            max_event_bytes=max_event_bytes,
        )
        return event_store.insert_event(
            self.db, event, dedup_window_hours=self.dedup_window_hours
        )

    # ----------------------------------------------------------------- query
    def list(self, **params: Any) -> tuple[list[dict[str, Any]], int]:
        return event_store.list_events(self.db, **params)

    def get(self, event_id: str) -> dict[str, Any]:
        return event_store.get_event(self.db, event_id)

    def update_status(
        self, event_id: str, status: str, *, actor: str, note: str | None = None
    ) -> dict[str, Any]:
        return event_store.update_status(
            self.db, event_id, status, actor=actor, note=note
        )

    def counts(self) -> dict[str, int]:
        return event_store.open_counts(self.db)

    def status_counts(self) -> dict[str, int]:
        return event_store.status_counts(self.db)

    def export(self, **filters: Any) -> list[dict[str, Any]]:
        return event_store.export_events(self.db, **filters)

    def prune(self, retention_days: int) -> int:
        return event_store.prune_events(self.db, retention_days=retention_days)


def validate_event(event: dict[str, Any]) -> None:
    if event.get("source") not in VALID_SOURCES:
        raise invalid("invalid event source")
    if event.get("category") not in VALID_CATEGORIES:
        raise invalid("invalid event category")
    if event.get("severity") not in event_store.SEVERITIES:
        raise invalid("invalid event severity")
