"""Aggregated, truthful protection status.

The summary never collapses "installed" into "protecting" and never turns a
missing engine or an unsupported real-time capability into a green state.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from ..common.config import Config
from ..common.timeutil import now_iso, parse_iso, utcnow
from ..storage import components as component_store
from ..storage import scans as scan_store
from ..storage.db import Database
from .events import EventService

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


class StatusService:
    def __init__(
        self,
        db: Database,
        config: Config,
        events: EventService,
        audits: Any | None = None,
        containers: Any | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.events = events
        self.audits = audits
        self.containers = containers

    def build(self) -> dict[str, Any]:
        components = component_store.list_components(self.db)
        by_id = {item["component_id"]: item for item in components}
        clamav = by_id.get("clamav")
        open_counts = self.events.counts()
        last_scan = scan_store.latest_finished(self.db)
        active_scan = scan_store.latest_active(self.db)

        protection = self._protection(clamav)
        host_baseline = self._host_baseline()
        container_status = self._containers(by_id.get("docker"))
        reasons: list[str] = []
        if open_counts["critical"]:
            reasons.append(f"{open_counts['critical']} unhandled critical events")
        if open_counts["high"]:
            reasons.append(f"{open_counts['high']} unhandled high-severity events")
        if protection["on_demand"]["state"] != "ready":
            reasons.append(protection["on_demand"]["reason"])
        if protection["real_time"]["state"] != "active":
            reasons.append(protection["real_time"]["reason"])
        if host_baseline["state"] == "failed":
            reasons.append(
                host_baseline.get("last_audit", {}).get("error")
                or "the most recent host audit failed"
            )
        container_unavailable = bool(
            self.config.containers.enabled
            and container_status["state"]
            in {"initializing", "degraded", "unavailable", "permission_denied"}
        )
        if container_unavailable:
            reasons.append(f"container monitoring unavailable: {container_status['note']}")
        elif container_status.get("risky"):
            reasons.append(
                f"{container_status['risky']} containers with configuration risks detected"
            )

        if open_counts["critical"] or open_counts["high"]:
            overall = "at_risk"
        elif (
            protection["on_demand"]["state"] != "ready"
            or protection["real_time"]["state"] != "active"
            or container_unavailable
        ):
            overall = "protection_incomplete"
        else:
            overall = "healthy"

        labels = {
            "healthy": "Protection healthy",
            "at_risk": "At risk",
            "protection_incomplete": "Protection incomplete",
        }
        if overall == "healthy":
            summary = "On-demand scanning and real-time protection are both in a healthy state."
        elif overall == "at_risk":
            summary = "Unhandled high-risk events were found; review them in the security event center."
        else:
            summary = "Some protection capabilities are unavailable or incomplete; the reasons listed below need attention."

        return {
            "overall": overall,
            "overall_label": labels[overall],
            "summary": summary,
            "reasons": reasons,
            "protection": protection,
            "events": {
                **open_counts,
                "by_status": self.events.status_counts(),
            },
            "last_scan": last_scan,
            "active_scan": active_scan,
            "components": {
                "total": len(components),
                "installed": sum(1 for item in components if item["installed"]),
                "healthy": sum(1 for item in components if item["health_status"] == "ok"),
                "degraded": sum(1 for item in components if item["health_status"] in {"degraded", "incompatible", "permission_denied"}),
                "unavailable": sum(1 for item in components if item["health_status"] in {"unavailable", "check_failed"}),
                "unknown": sum(1 for item in components if item["health_status"] == "unknown"),
                "items": components,
            },
            "host_baseline": host_baseline,
            "containers": container_status,
            "yara": self._yara(by_id.get("yara")),
            "quarantine": {
                "mode": "manual_confirm",
                "auto_quarantine_enabled": bool(
                    self._setting("auto_quarantine_enabled", False)
                ),
            },
            "generated_at": now_iso(),
        }

    def _containers(self, runtime: dict[str, Any] | None) -> dict[str, Any]:
        if not self.containers:
            return {
                "state": "disabled",
                "note": "container monitoring is not enabled",
                "enabled": False,
                "runtime": runtime,
                "total": 0,
                "running": 0,
                "risky": 0,
                "by_risk": {},
                "last_checked_at": None,
                "stale": False,
            }
        snapshot = self.containers.snapshot()
        summary = snapshot.get("summary") or {}
        return {
            "state": snapshot.get("state", "unknown"),
            "note": snapshot.get("note") or "",
            "enabled": bool(self.config.containers.enabled),
            "runtime": runtime,
            "total": summary.get("total", 0),
            "running": summary.get("running", 0),
            "stopped": summary.get("stopped", 0),
            "risky": summary.get("risky", 0),
            "unknown": summary.get("unknown", 0),
            "findings": summary.get("findings", 0),
            "by_risk": summary.get("by_risk") or {},
            "last_checked_at": snapshot.get("last_success_at"),
            "stale": bool(snapshot.get("stale")),
            "error": snapshot.get("error"),
            "engine": snapshot.get("engine"),
            "scope_note": snapshot.get("scope_note"),
            "limitations": snapshot.get("limitations") or [],
        }

    def _yara(self, component: dict[str, Any] | None) -> dict[str, Any]:
        if not self.config.yara.enabled:
            return {
                "state": "disabled",
                "enabled": False,
                "installed": bool(component and component.get("installed")),
                "note": "YARA rule scanning is disabled in the configuration",
                "packs_count": 0,
                "active_count": 0,
                "active": [],
                "signature_required": bool(self.config.yara.require_signature),
                "public_key_present": False,
            }
        details = (component or {}).get("details") or {}
        active = details.get("active") or []
        active_count = int(details.get("active_count") or 0)
        if not component:
            state = "unknown"
            note = "YARA component status has not been probed yet"
        elif not component.get("installed"):
            state = "unavailable"
            note = "YARA is not installed; rule scanning is unavailable"
        elif active_count <= 0:
            state = "unavailable"
            note = "YARA is installed but there are no active rule packs; it cannot be considered actively detecting"
        elif component.get("health_status") != "ok":
            state = "degraded"
            note = component.get("error_message") or "YARA status is abnormal"
        else:
            state = "ready"
            note = f"{active_count} rule packs active; a rule match is not equivalent to confirmed malware"
        signature = details.get("signature") or {}
        return {
            "state": state,
            "enabled": True,
            "installed": bool(component and component.get("installed")),
            "version": (component or {}).get("version"),
            "health": (component or {}).get("health_status"),
            "error_code": (component or {}).get("error_code"),
            "note": note,
            "packs_count": int(details.get("packs_count") or 0),
            "active_count": active_count,
            "active": active,
            "signature_required": bool(self.config.yara.require_signature),
            "public_key_present": bool(signature.get("public_key_present")),
        }

    def _host_baseline(self) -> dict[str, Any]:
        latest = self.audits.latest() if self.audits else None
        if not latest:
            return {
                "state": "not_run",
                "note": "host security audit has not run yet; there is no host baseline conclusion",
                "last_audit": None,
            }
        last = {
            "audit_id": latest.get("audit_id"),
            "status": latest.get("status"),
            "finished_at": latest.get("finished_at"),
            "findings_count": latest.get("findings_count", 0),
            "errors_count": latest.get("errors_count", 0),
            "checks_total": latest.get("checks_total", 0),
            "severity_counts": latest.get("severity_counts") or {},
            "hardening_index": latest.get("hardening_index"),
            "lynis_available": bool(latest.get("lynis_available")),
            "lynis_version": latest.get("lynis_version"),
            "evidence_path": latest.get("evidence_path"),
            "error": latest.get("error"),
            "scope": latest.get("scope"),
        }
        if latest.get("status") == "failed":
            state = "failed"
            note = latest.get("error") or "the most recent host audit failed"
        else:
            state = "current"
            finished = latest.get("finished_at")
            if finished:
                try:
                    age = utcnow() - parse_iso(finished)
                    if age > timedelta(hours=self.config.audit.stale_after_hours):
                        state = "stale"
                except ValueError:
                    state = "stale"
            findings = latest.get("findings_count", 0)
            errors = latest.get("errors_count", 0)
            note = f"the most recent audit found {findings} risks"
            if errors:
                note += f", {errors} checks could not run"
            if latest.get("hardening_index") is not None:
                note += f", Lynis hardening index {latest['hardening_index']}"
            if state == "stale":
                note += "; the result is older than the freshness threshold; consider running it again"
        return {"state": state, "note": note, "last_audit": last}

    def _setting(self, key: str, default: Any) -> Any:
        from ..storage import settings as settings_store

        return settings_store.get(self.db, key, default)

    def _protection(self, clamav: dict[str, Any] | None) -> dict[str, Any]:
        if not clamav:
            return {
                "on_demand": {
                    "state": "unavailable",
                    "reason": "ClamAV component status has not been probed",
                },
                "real_time": {
                    "state": "unsupported",
                    "reason": "ClamAV has not been probed; real-time protection is unavailable",
                },
                "virus_database": {
                    "state": "unknown",
                    "updated_at": None,
                    "age_hours": None,
                },
            }
        details = clamav.get("details") or {}
        database = details.get("database") or {}
        real_time = details.get("real_time_protection") or {
            "supported": False,
            "state": "unsupported",
            "reason": "no real-time protection capability provided",
        }
        db_state = "unknown"
        if not database.get("present"):
            db_state = "missing"
        elif clamav.get("error_code") == "database_outdated":
            db_state = "outdated"
        elif database.get("updated_at"):
            db_state = "current"

        if not clamav.get("installed"):
            on_demand = {
                "state": "unavailable",
                "reason": "ClamAV is not installed; virus scanning cannot run",
            }
        elif clamav.get("service_status") != "running":
            on_demand = {
                "state": "stopped",
                "reason": "ClamAV is installed but clamd is not running; on-demand scanning is unavailable",
            }
        elif db_state in {"missing", "outdated"}:
            on_demand = {
                "state": "degraded",
                "reason": clamav.get("error_message")
                or "the virus database is missing or outdated; scan results are not trustworthy",
            }
        else:
            on_demand = {
                "state": "ready",
                "reason": "ClamAV on-demand scanning is available",
            }

        return {
            "on_demand": on_demand,
            "real_time": {
                "state": real_time.get("state", "unsupported"),
                "supported": bool(real_time.get("supported")),
                "reason": real_time.get("reason", "real-time protection is not enabled"),
            },
            "virus_database": {
                "state": db_state,
                "updated_at": database.get("updated_at"),
                "age_hours": database.get("age_hours"),
            },
        }
