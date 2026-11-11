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
            reasons.append(f"存在 {open_counts['critical']} 个未处理的严重事件")
        if open_counts["high"]:
            reasons.append(f"存在 {open_counts['high']} 个未处理的高危事件")
        if protection["on_demand"]["state"] != "ready":
            reasons.append(protection["on_demand"]["reason"])
        if protection["real_time"]["state"] != "active":
            reasons.append(protection["real_time"]["reason"])
        if host_baseline["state"] == "failed":
            reasons.append(
                host_baseline.get("last_audit", {}).get("error")
                or "最近一次主机体检执行失败"
            )
        container_unavailable = bool(
            self.config.containers.enabled
            and container_status["state"]
            in {"initializing", "degraded", "unavailable", "permission_denied"}
        )
        if container_unavailable:
            reasons.append(f"容器监控不可用：{container_status['note']}")
        elif container_status.get("risky"):
            reasons.append(
                f"已发现 {container_status['risky']} 个存在配置风险的容器"
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
            "healthy": "防护正常",
            "at_risk": "存在风险",
            "protection_incomplete": "防护不完整",
        }
        if overall == "healthy":
            summary = "按需扫描与实时防护均处于正常状态。"
        elif overall == "at_risk":
            summary = "发现未处理的高风险事件，请前往安全事件中心核实。"
        else:
            summary = "部分防护能力不可用或不完整，下方列出的原因需要处理。"

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
                "note": "容器监控未启用",
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
                "note": "YARA 规则扫描已在配置中禁用",
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
            note = "尚未探测到 YARA 组件状态"
        elif not component.get("installed"):
            state = "unavailable"
            note = "YARA 未安装，规则扫描不可用"
        elif active_count <= 0:
            state = "unavailable"
            note = "YARA 已安装，但没有已激活的规则包；不能视为正在检测"
        elif component.get("health_status") != "ok":
            state = "degraded"
            note = component.get("error_message") or "YARA 状态异常"
        else:
            state = "ready"
            note = f"已激活 {active_count} 个规则包；规则命中不等同于已确认恶意软件"
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
                "note": "尚未运行主机安全体检；当前没有主机基线结论",
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
            note = latest.get("error") or "最近一次主机体检执行失败"
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
            note = f"最近体检发现 {findings} 项风险"
            if errors:
                note += f"，{errors} 项检查未能执行"
            if latest.get("hardening_index") is not None:
                note += f"，Lynis 加固指数 {latest['hardening_index']}"
            if state == "stale":
                note += "；结果已超过时效，建议重新运行"
        return {"state": state, "note": note, "last_audit": last}

    def _setting(self, key: str, default: Any) -> Any:
        from ..storage import settings as settings_store

        return settings_store.get(self.db, key, default)

    def _protection(self, clamav: dict[str, Any] | None) -> dict[str, Any]:
        if not clamav:
            return {
                "on_demand": {
                    "state": "unavailable",
                    "reason": "未探测到 ClamAV 组件状态",
                },
                "real_time": {
                    "state": "unsupported",
                    "reason": "未探测到 ClamAV，实时防护不可用",
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
            "reason": "未提供实时防护能力",
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
                "reason": "ClamAV 未安装，无法执行病毒扫描",
            }
        elif clamav.get("service_status") != "running":
            on_demand = {
                "state": "stopped",
                "reason": "ClamAV 已安装但 clamd 未运行，按需扫描不可用",
            }
        elif db_state in {"missing", "outdated"}:
            on_demand = {
                "state": "degraded",
                "reason": clamav.get("error_message")
                or "病毒库缺失或过期，扫描结果不可信",
            }
        else:
            on_demand = {
                "state": "ready",
                "reason": "ClamAV 按需扫描可用",
            }

        return {
            "on_demand": on_demand,
            "real_time": {
                "state": real_time.get("state", "unsupported"),
                "supported": bool(real_time.get("supported")),
                "reason": real_time.get("reason", "实时防护未启用"),
            },
            "virus_database": {
                "state": db_state,
                "updated_at": database.get("updated_at"),
                "age_hours": database.get("age_hours"),
            },
        }
