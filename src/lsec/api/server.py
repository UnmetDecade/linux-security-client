"""HTTP API and Web UI server (standard library only)."""

from __future__ import annotations

import csv
import io
import json
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from .. import API_VERSION, SCHEMA_VERSION, __version__
from ..common.config import Config
from ..common.errors import ErrorCode, LsecError, invalid, not_found, unauthorized
from ..common.hostinfo import host_info
from ..common.ids import is_uuid, new_id_or_value
from ..common.logging import get_logger
from ..common.timeutil import now_iso
from ..storage import audit as audit_store
from ..storage import components as component_store
from ..storage import settings as settings_store
from .auth import (
    COOKIE_NAME,
    ROLE_ADMIN,
    ROLE_VIEWER,
    AuthService,
    csrf_valid,
    require_admin,
)

log = get_logger("api")
UI_DIR = Path(__file__).resolve().parent.parent / "web"
ASSET_RE = re.compile(r"^[A-Za-z0-9._-]+$")
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


@dataclass
class ApiResponse:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)


def json_response(payload: Any, status: int = 200) -> ApiResponse:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    return ApiResponse(status=status, body=body)


def error_response(exc: LsecError, request_id: str) -> ApiResponse:
    payload = {"ok": False, "error": {**exc.to_dict(), "request_id": request_id}}
    return json_response(payload, status=exc.http_status)


@dataclass
class RequestContext:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: Any
    body: dict[str, Any] | None
    remote_addr: str
    request_id: str
    role: str | None = None
    actor: str = "anonymous"
    client: str = ""
    session: dict[str, Any] | None = None
    bearer: bool = False
    app: "Application | None" = None

    def q(self, name: str, default: str | None = None) -> str | None:
        values = self.query.get(name)
        return values[0] if values else default

    def q_int(self, name: str, default: int, minimum: int = 0, maximum: int = 100000) -> int:
        raw = self.q(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise invalid(f"查询参数 {name} 必须是整数") from None
        if not minimum <= value <= maximum:
            raise invalid(f"查询参数 {name} 超出范围")
        return value

    def q_enum(self, name: str, allowed: tuple[str, ...]) -> str | None:
        raw = self.q(name)
        if raw is not None and raw not in allowed:
            raise invalid(f"查询参数 {name} 取值无效", {"allowed": list(allowed)})
        return raw

    def require_json_object(self) -> dict[str, Any]:
        if self.body is None:
            raise invalid("请求体必须是 JSON 对象")
        return self.body


Handler = Callable[[RequestContext, "Application"], ApiResponse]


class Application:
    def __init__(
        self,
        *,
        config: Config,
        db: Any,
        auth: AuthService,
        components: Any,
        events: Any,
        scans: Any,
        quarantine: Any,
        audits: Any,
        containers: Any,
        status: Any,
        doctor: Any,
        updates: Any,
        yara: Any = None,
        wazuh: Any = None,
        wazuh_ingest: Any = None,
    ) -> None:
        self.config = config
        self.db = db
        self.auth = auth
        self.components = components
        self.events = events
        self.scans = scans
        self.quarantine = quarantine
        self.audits = audits
        self.containers = containers
        self.status = status
        self.doctor = doctor
        self.updates = updates
        self.yara = yara
        self.wazuh = wazuh
        self.wazuh_ingest = wazuh_ingest
        self.started_at = time.monotonic()
        self.started_iso = now_iso()

    # ------------------------------------------------------------ capabilities
    def capabilities(self) -> dict[str, Any]:
        clamav = component_store.get_component(self.db, "clamav") or {}
        lynis = component_store.get_component(self.db, "lynis") or {}
        docker = component_store.get_component(self.db, "docker") or {}
        falco = component_store.get_component(self.db, "falco") or {}
        yara_component = component_store.get_component(self.db, "yara") or {}
        wazuh_component = component_store.get_component(self.db, "wazuh") or {}
        container_snapshot = (
            self.containers.snapshot()
            if self.containers
            else {
                "state": "disabled",
                "note": "容器监控未启用",
                "summary": {},
                "engine": None,
            }
        )
        container_state = {
            "monitored": "available",
            "initializing": "initializing",
            "disabled": "disabled",
            "degraded": "degraded",
            "permission_denied": "permission_denied",
            "unavailable": "unavailable",
        }.get(container_snapshot.get("state"), "unavailable")
        falco_details = falco.get("details") or {}
        falco_capability = falco_details.get("capability") or {}
        if not self.config.falco.enabled:
            falco_state = "disabled"
        elif not falco.get("installed"):
            falco_state = "unavailable"
        else:
            falco_state = {
                "compatible": "available",
                "unsupported": "incompatible",
                "requires_privileges": "requires_privileges",
                "requires_setup": "requires_setup",
                "unknown": "unknown",
            }.get(falco_capability.get("state"), "unknown")
        scan_ready = bool(
            clamav.get("installed")
            and clamav.get("service_status") == "running"
            and (clamav.get("details") or {}).get("database", {}).get("present")
        )
        reason = None
        if not scan_ready:
            reason = clamav.get("error_message") or "ClamAV 未就绪"
        if lynis.get("installed"):
            audit_reason = (
                f"内置只读基线检查与 Lynis {lynis.get('version') or ''} 可用；"
                "审计范围为容器可见环境"
            ).strip()
        else:
            audit_reason = (
                "内置只读基线检查可用；Lynis 未安装时不会生成 Lynis 结果，"
                "审计范围为容器可见环境"
            )
        return {
            "malware_scan": {
                "state": "available" if scan_ready else "unavailable",
                "reason": reason,
                "engines": {
                    "clamav": {
                        "state": "available" if scan_ready else "unavailable",
                        "reason": reason,
                    },
                    "yara": {
                        "state": self._yara_state(yara_component),
                        "reason": yara_component.get("error_message")
                        or (
                            "YARA 规则扫描可用"
                            if yara_component.get("health_status") == "ok"
                            else "YARA 状态未知"
                        ),
                    },
                },
            },
            "real_time_protection": {
                "state": "unsupported",
                "reason": "容器部署未启用 ClamAV On-Access 实时防护；当前仅提供按需扫描",
            },
            "quarantine": {"state": "available"},
            "event_center": {"state": "available"},
            "scheduled_scan": {"state": "available"},
            "host_audit": {
                "state": "available",
                "reason": audit_reason,
                "lynis": {
                    "installed": bool(lynis.get("installed")),
                    "version": lynis.get("version"),
                    "enabled": bool(self.config.audit.lynis_enabled),
                    "health": lynis.get("health_status"),
                },
            },
            "container_security": {
                "state": container_state,
                "reason": container_snapshot.get("note") or "容器监控未启用",
                "monitor": {
                    "enabled": bool(self.config.containers.enabled),
                    "api_url": self.config.containers.api_url,
                    "state": container_snapshot.get("state"),
                    "total": (container_snapshot.get("summary") or {}).get("total", 0),
                    "running": (container_snapshot.get("summary") or {}).get(
                        "running", 0
                    ),
                    "risky": (container_snapshot.get("summary") or {}).get(
                        "risky", 0
                    ),
                    "checked_at": container_snapshot.get("last_success_at"),
                    "engine": container_snapshot.get("engine"),
                    "runtime": docker,
                },
            },
            "falco": {
                "state": falco_state,
                "reason": falco.get("error_message")
                or ("Falco 未安装" if not falco.get("installed") else "Falco 状态未知"),
                "installed": bool(falco.get("installed")),
                "version": falco.get("version"),
                "capability": falco_capability,
                "event_ingest": {
                    "state": "enabled" if self.auth.falco_token else "disabled",
                    "endpoint": "/api/v1/integrations/falco",
                    "token_path": str(self.config.falco_token_path),
                },
            },
            "yara": {
                "state": self._yara_state(yara_component),
                "reason": yara_component.get("error_message")
                or (
                    "YARA 规则扫描可用"
                    if yara_component.get("health_status") == "ok"
                    else "YARA 状态未知"
                ),
                "installed": bool(yara_component.get("installed")),
                "version": yara_component.get("version"),
                "health": yara_component.get("health_status"),
                "error_code": yara_component.get("error_code"),
                "packs": self._yara_summary(),
            },
            "wazuh": {
                "state": self._wazuh_state(wazuh_component),
                "reason": wazuh_component.get("error_message")
                or (
                    "Wazuh 集成未启用（可选）"
                    if not self.config.wazuh.enabled
                    else "本地 Wazuh Agent 状态未知"
                ),
                "installed": bool(wazuh_component.get("installed")),
                "version": wazuh_component.get("version"),
                "health": wazuh_component.get("health_status"),
                "error_code": wazuh_component.get("error_code"),
                "scope": "local_agent_only",
                "manager": (wazuh_component.get("details") or {}).get("manager"),
                "registration_present": bool(
                    (wazuh_component.get("details") or {}).get(
                        "registration_present"
                    )
                ),
                "connection_verified": False,
                "note": (
                    "仅读取本地 Agent 状态与本地告警；不是 Wazuh Manager，"
                    "不提供 Manager API、集群管理或其他 Agent 管理能力"
                ),
                "ingest": self._wazuh_ingest_summary(),
                "install_plan_available": not bool(wazuh_component.get("installed")),
            },
        }

    def _wazuh_state(self, component: dict[str, Any]) -> str:
        if not self.config.wazuh.enabled:
            return "disabled"
        if not component:
            return "unknown"
        if not component.get("installed"):
            return "unavailable"
        if component.get("error_code") in {
            "manager_connection_unverified",
            "agent_not_running",
            "config_missing",
            "manager_not_configured",
        }:
            # Never upgrade "agent present" to "full Wazuh capability".
            return "degraded"
        return {
            "ok": "available",
            "degraded": "degraded",
            "permission_denied": "permission_denied",
            "unavailable": "unavailable",
            "unknown": "degraded",
        }.get(component.get("health_status"), "unknown")

    def _wazuh_ingest_summary(self) -> dict[str, Any]:
        if not self.wazuh_ingest:
            return {
                "enabled": bool(self.config.wazuh.enabled),
                "ingest_enabled": bool(self.config.wazuh.ingest_enabled),
                "running": False,
                "events_total": 0,
                "note": "本地 Wazuh 告警接入未初始化",
            }
        try:
            return self.wazuh_ingest.status()
        except Exception as exc:  # status must not break capabilities
            log.warning("读取 Wazuh 接入状态失败: %s", exc)
            return {
                "enabled": bool(self.config.wazuh.enabled),
                "ingest_enabled": bool(self.config.wazuh.ingest_enabled),
                "running": False,
                "events_total": 0,
                "error": "无法读取 Wazuh 接入状态",
            }

    def _yara_state(self, component: dict[str, Any]) -> str:
        if not self.config.yara.enabled:
            return "disabled"
        if not component:
            return "unknown"
        if not component.get("installed"):
            return "unavailable"
        error_code = component.get("error_code")
        if error_code == "disabled":
            return "disabled"
        if error_code:
            return "unavailable"
        health = component.get("health_status")
        return {
            "ok": "available",
            "degraded": "degraded",
            "permission_denied": "permission_denied",
            "unavailable": "unavailable",
            "unknown": "unknown",
        }.get(health, "unknown")

    def _yara_summary(self) -> dict[str, Any]:
        if not self.yara:
            return {"packs_count": 0, "active_count": 0, "active": []}
        try:
            snapshot = self.yara.scan_snapshot()
        except Exception as exc:  # a broken rules store must not break status
            log.warning("读取 YARA 规则状态失败: %s", exc)
            return {
                "packs_count": 0,
                "active_count": 0,
                "active": [],
                "error": "无法读取 YARA 规则状态",
            }
        return {
            "packs_count": snapshot.get("packs_count", 0),
            "active_count": snapshot.get("active_count", 0),
            "active": snapshot.get("active", []),
            "inbox_dir": snapshot.get("inbox_dir"),
            "signature": snapshot.get("signature"),
            "state_error": snapshot.get("state_error"),
        }


# ---------------------------------------------------------------- handlers
def handle_health(req: RequestContext, app: Application) -> ApiResponse:
    return json_response(
        {"ok": True, "status": "alive", "version": __version__, "api": API_VERSION}
    )


def handle_login(req: RequestContext, app: Application) -> ApiResponse:
    body = req.require_json_object()
    token = body.get("token")
    if not isinstance(token, str) or not token or len(token) > 512:
        raise invalid("必须提供访问令牌")
    session, role = app.auth.login(token, req.remote_addr)
    if not session:
        try:
            audit_store.record(
                app.db,
                action="auth.login",
                actor="unknown",
                client=req.remote_addr,
                result="failure",
                error="无效令牌",
                request_id=req.request_id,
            )
        except Exception:
            pass
        raise unauthorized("访问令牌无效")
    audit_store.record(
        app.db,
        action="auth.login",
        actor=role,
        client=req.remote_addr,
        result="success",
        request_id=req.request_id,
    )
    response = json_response(
        {
            "ok": True,
            "role": role,
            "csrf_token": session["csrf_token"],
            "expires_at": session["expires_at"],
        }
    )
    cookie = (
        f"{COOKIE_NAME}={session['session_id']}; Path=/; HttpOnly; "
        f"SameSite=Strict; Max-Age={app.config.server.session_ttl_hours * 3600}"
    )
    if app.config.server.tls_cert:
        cookie += "; Secure"
    response.headers["Set-Cookie"] = cookie
    return response


def handle_logout(req: RequestContext, app: Application) -> ApiResponse:
    app.auth.logout(req.session["session_id"] if req.session else None)
    response = json_response({"ok": True})
    response.headers["Set-Cookie"] = (
        f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
    )
    return response


def handle_version(req: RequestContext, app: Application) -> ApiResponse:
    return json_response(
        {
            "ok": True,
            "daemon_version": __version__,
            "api_version": API_VERSION,
            "schema_version": SCHEMA_VERSION,
            "started_at": app.started_iso,
        }
    )


def handle_system_info(req: RequestContext, app: Application) -> ApiResponse:
    return json_response(
        {
            "ok": True,
            "host": host_info(),
            "daemon": {
                "version": __version__,
                "api_version": API_VERSION,
                "started_at": app.started_iso,
                "uptime_seconds": round(time.monotonic() - app.started_at, 1),
                "data_dir": str(app.config.data_dir),
                "config_path": app.config.config_path,
                "config_loaded": app.config.config_loaded,
            },
        }
    )


def handle_status(req: RequestContext, app: Application) -> ApiResponse:
    return json_response({"ok": True, "status": app.status.build()})


def handle_capabilities(req: RequestContext, app: Application) -> ApiResponse:
    return json_response({"ok": True, "capabilities": app.capabilities()})


def handle_components(req: RequestContext, app: Application) -> ApiResponse:
    return json_response({"ok": True, "components": app.components.list()})


def handle_component_install_plan(
    req: RequestContext, app: Application, match: re.Match[str]
) -> ApiResponse:
    return json_response(
        {"ok": True, "plan": app.components.install_plan(match.group(1))}
    )


def handle_component_probe(req: RequestContext, app: Application) -> ApiResponse:
    return json_response({"ok": True, "components": app.components.probe_all()})


def handle_component_action(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    component_id, action = match.group(1), match.group(2)
    before = component_store.get_component(app.db, component_id)
    try:
        if action == "start":
            result = app.components.start(component_id)
        elif action == "stop":
            result = app.components.stop(component_id)
        elif action == "update":
            outcome = app.updates.run_update(
                actor=req.actor, request_id=req.request_id, client=req.client
            )
            return json_response({"ok": True, "update": outcome})
        else:  # pragma: no cover - routing prevents this
            raise not_found("未知操作")
    except LsecError as exc:
        audit_store.record(
            app.db,
            action=f"component.{action}",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            target=component_id,
            before_state=before,
            result="failure",
            error=exc.message,
            confirmed=True,
        )
        raise
    audit_store.record(
        app.db,
        action=f"component.{action}",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=component_id,
        before_state=before,
        after_state=result,
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "component": result})


def handle_scans_list(req: RequestContext, app: Application) -> ApiResponse:
    status = req.q_enum("status", ("queued", "running", "cancel_requested", "cancelled", "succeeded", "failed", "partial"))
    items, total = app.scans.list(
        status=status, limit=req.q_int("limit", 50, 1, 200), offset=req.q_int("offset", 0)
    )
    return json_response({"ok": True, "tasks": items, "total": total})


def handle_scan_create(req: RequestContext, app: Application) -> ApiResponse:
    body = req.require_json_object()
    task_type = body.get("type")
    if not isinstance(task_type, str):
        raise invalid("必须提供扫描类型 type")
    paths = body.get("paths") or []
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        raise invalid("paths 必须是字符串数组")
    engines = body.get("engines") or ["clamav"]
    if not isinstance(engines, list) or not all(isinstance(e, str) for e in engines):
        raise invalid("engines 必须是字符串数组")
    try:
        task = app.scans.create_task(
            task_type=task_type, targets=paths, engines=engines, actor=req.actor
        )
    except LsecError as exc:
        audit_store.record(
            app.db,
            action="scan.create",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            target=task_type,
            before_state={"paths": paths, "engines": engines},
            result="failure",
            error=exc.message,
        )
        raise
    audit_store.record(
        app.db,
        action="scan.create",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=task["task_id"],
        before_state={"type": task_type, "paths": paths, "engines": engines},
        after_state={"task_id": task["task_id"], "status": task["status"]},
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "task": task}, status=201)


def handle_scan_get(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    task_id = match.group(1)
    if not is_uuid(task_id):
        raise invalid("任务 ID 格式无效")
    return json_response({"ok": True, "task": app.scans.get(task_id)})


def handle_scan_cancel(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    task_id = match.group(1)
    if not is_uuid(task_id):
        raise invalid("任务 ID 格式无效")
    try:
        task = app.scans.cancel(task_id)
    except LsecError as exc:
        audit_store.record(
            app.db,
            action="scan.cancel",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            target=task_id,
            result="failure",
            error=exc.message,
        )
        raise
    audit_store.record(
        app.db,
        action="scan.cancel",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=task_id,
        after_state={"status": task["status"]},
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "task": task})


def handle_events_list(req: RequestContext, app: Application) -> ApiResponse:
    items, total = app.events.list(
        severity=req.q_enum("severity", ("critical", "high", "medium", "low", "info")),
        source=req.q("source"),
        category=req.q_enum("category", ("malware", "intrusion", "runtime", "integrity", "vulnerability", "configuration")),
        status=req.q_enum("status", ("new", "acknowledged", "investigating", "resolved", "ignored")),
        search=req.q("q"),
        since=req.q("since"),
        until=req.q("until"),
        limit=req.q_int("limit", 50, 1, 200),
        offset=req.q_int("offset", 0),
    )
    return json_response({"ok": True, "events": items, "total": total})


def handle_event_get(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    return json_response({"ok": True, "event": app.events.get(match.group(1))})


def handle_event_patch(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    event_id = match.group(1)
    body = req.require_json_object()
    status = body.get("status")
    note = body.get("note")
    if not isinstance(status, str):
        raise invalid("必须提供新状态 status")
    if note is not None and not isinstance(note, str):
        raise invalid("note 必须是字符串")
    before = app.events.get(event_id)
    try:
        event = app.events.update_status(
            event_id, status, actor=req.actor, note=note[:2000] if note else None
        )
    except LsecError as exc:
        audit_store.record(
            app.db,
            action="event.status",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            target=event_id,
            before_state={"status": before.get("status")},
            after_state={"status": status},
            result="failure",
            error=exc.message,
        )
        raise
    audit_store.record(
        app.db,
        action="event.status",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=event_id,
        before_state={"status": before.get("status")},
        after_state={"status": event["status"]},
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "event": event})


def handle_events_export(req: RequestContext, app: Application) -> ApiResponse:
    filters = {
        "severity": req.q_enum("severity", ("critical", "high", "medium", "low", "info")),
        "source": req.q("source"),
        "category": req.q_enum("category", ("malware", "intrusion", "runtime", "integrity", "vulnerability", "configuration")),
        "status": req.q_enum("status", ("new", "acknowledged", "investigating", "resolved", "ignored")),
        "search": req.q("q"),
        "since": req.q("since"),
        "until": req.q("until"),
    }
    fmt = req.q("format", "json")
    events = app.events.export(**filters)
    stamp = now_iso()[:10]
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "event_id",
                "timestamp",
                "first_seen_at",
                "last_seen_at",
                "occurrences",
                "severity",
                "source",
                "category",
                "status",
                "title",
                "target_path",
                "detection_name",
                "sha256",
            ]
        )
        for event in events:
            target = event.get("target") or {}
            evidence = event.get("evidence") or {}
            writer.writerow(
                [
                    _csv_safe(event.get("event_id")),
                    _csv_safe(event.get("timestamp")),
                    _csv_safe(event.get("first_seen_at")),
                    _csv_safe(event.get("last_seen_at")),
                    event.get("occurrences", 1),
                    _csv_safe(event.get("severity")),
                    _csv_safe(event.get("source")),
                    _csv_safe(event.get("category")),
                    _csv_safe(event.get("status")),
                    _csv_safe(event.get("title")),
                    _csv_safe(target.get("path")),
                    _csv_safe(evidence.get("detection_name")),
                    _csv_safe(evidence.get("sha256")),
                ]
            )
        return ApiResponse(
            body=buffer.getvalue().encode("utf-8-sig"),
            content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="lsec-events-{stamp}.csv"'},
        )
    if fmt != "json":
        raise invalid("format 只能是 json 或 csv")
    body = json.dumps(
        {"ok": True, "events": events, "exported_at": now_iso()},
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return ApiResponse(
        body=body,
        headers={"Content-Disposition": f'attachment; filename="lsec-events-{stamp}.json"'},
    )


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    if text[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        text = "'" + text
    return text


def handle_quarantine_list(req: RequestContext, app: Application) -> ApiResponse:
    status = req.q_enum("status", ("quarantined", "restored", "deleted", "missing"))
    items, total = app.quarantine.list(
        status=status, limit=req.q_int("limit", 100, 1, 500), offset=req.q_int("offset", 0)
    )
    return json_response({"ok": True, "items": items, "total": total})


def handle_quarantine_get(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    return json_response({"ok": True, "item": app.quarantine.get(match.group(1))})


def handle_quarantine_create(req: RequestContext, app: Application) -> ApiResponse:
    body = req.require_json_object()
    path = body.get("path")
    if not isinstance(path, str):
        raise invalid("必须提供文件路径 path")
    confirmed = body.get("confirm") is True
    event_id = body.get("event_id")
    if event_id is not None and not isinstance(event_id, str):
        raise invalid("event_id 必须是字符串")
    item = app.quarantine.quarantine(
        path=path,
        actor=req.actor,
        request_id=req.request_id,
        client=req.client,
        confirmed=confirmed,
        event_id=event_id,
        engine=body.get("engine") if isinstance(body.get("engine"), str) else None,
        detection_name=body.get("detection_name")
        if isinstance(body.get("detection_name"), str)
        else None,
    )
    return json_response({"ok": True, "item": item}, status=201)


def handle_quarantine_action(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    item_id, action = match.group(1), match.group(2)
    body = req.require_json_object()
    confirmed = body.get("confirm") is True
    if action == "restore":
        item = app.quarantine.restore(
            item_id=item_id,
            actor=req.actor,
            request_id=req.request_id,
            client=req.client,
            confirmed=confirmed,
        )
    elif action == "delete":
        item = app.quarantine.delete(
            item_id=item_id,
            actor=req.actor,
            request_id=req.request_id,
            client=req.client,
            confirmed=confirmed,
        )
    else:  # pragma: no cover - routing prevents this
        raise not_found("未知操作")
    return json_response({"ok": True, "item": item})


def handle_audit_list(req: RequestContext, app: Application) -> ApiResponse:
    items, total = audit_store.list_records(
        app.db,
        limit=req.q_int("limit", 100, 1, 500),
        offset=req.q_int("offset", 0),
        action=req.q("action"),
    )
    return json_response({"ok": True, "records": items, "total": total})


def handle_audits_list(req: RequestContext, app: Application) -> ApiResponse:
    items, total = app.audits.list(
        limit=req.q_int("limit", 20, 1, 100),
        offset=req.q_int("offset", 0),
    )
    return json_response(
        {
            "ok": True,
            "audits": items,
            "total": total,
            "active": app.audits.latest_active(),
        }
    )


def handle_audit_create(req: RequestContext, app: Application) -> ApiResponse:
    try:
        run = app.audits.create(req.actor)
    except LsecError as exc:
        audit_store.record(
            app.db,
            action="audit.run",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            result="failure",
            error=exc.message,
        )
        raise
    audit_store.record(
        app.db,
        action="audit.run",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=run["audit_id"],
        after_state={"audit_id": run["audit_id"], "status": run["status"]},
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "audit": run}, status=202)


def handle_audit_get(req: RequestContext, app: Application, match: re.Match[str]) -> ApiResponse:
    audit_id = match.group(1)
    if not is_uuid(audit_id):
        raise invalid("体检 ID 格式无效")
    return json_response({"ok": True, "audit": app.audits.get(audit_id)})


def handle_containers_list(req: RequestContext, app: Application) -> ApiResponse:
    return json_response({"ok": True, "containers": app.containers.snapshot()})


def handle_container_get(
    req: RequestContext, app: Application, match: re.Match[str]
) -> ApiResponse:
    container = app.containers.get(match.group(1))
    return json_response({"ok": True, "container": container})


def handle_containers_refresh(req: RequestContext, app: Application) -> ApiResponse:
    snapshot = app.containers.refresh()
    audit_store.record(
        app.db,
        action="container.refresh",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target="docker",
        after_state={
            "state": snapshot.get("state"),
            "total": (snapshot.get("summary") or {}).get("total"),
            "risky": (snapshot.get("summary") or {}).get("risky"),
        },
        result="success" if snapshot.get("state") in {"monitored", "degraded"} else "failure",
        error=snapshot.get("error"),
        confirmed=True,
    )
    return json_response({"ok": True, "containers": snapshot})


def handle_falco_status(req: RequestContext, app: Application) -> ApiResponse:
    falco = component_store.get_component(app.db, "falco") or {}
    row = app.db.query_one(
        "SELECT COUNT(*) AS total, MAX(last_seen_at) AS last_seen_at "
        "FROM events WHERE source = 'falco'"
    ) or {}
    return json_response(
        {
            "ok": True,
            "falco": {
                "component": falco,
                "install_plan_available": True,
                "event_ingest": {
                    "enabled": bool(app.auth.falco_token),
                    "endpoint": "/api/v1/integrations/falco",
                    "token_path": str(app.config.falco_token_path),
                    "events_total": int(row.get("total") or 0),
                    "last_event_at": row.get("last_seen_at"),
                },
            },
        }
    )


def handle_falco_ingest(req: RequestContext, app: Application) -> ApiResponse:
    if not app.auth.falco_token:
        raise unauthorized("Falco 事件接入未启用")
    if not app.auth.integration_rate_limiter.check(req.remote_addr):
        raise LsecError(
            ErrorCode.RATE_LIMITED,
            "Falco 事件接入过于频繁，请稍后再试",
            http_status=429,
        )
    payload = req.require_json_object()
    event, created = app.events.ingest_falco_event(
        payload, max_event_bytes=app.config.falco.max_event_bytes
    )
    return json_response(
        {
            "ok": True,
            "event_id": event.get("event_id"),
            "created": created,
        },
        status=202,
    )


def _require_confirmation(req: RequestContext, action: str) -> dict[str, Any]:
    body = req.require_json_object()
    if body.get("confirm") is not True:
        raise invalid(f"{action}需要显式 confirm=true 二次确认")
    return body


def handle_yara_status(req: RequestContext, app: Application) -> ApiResponse:
    component = component_store.get_component(app.db, "yara") or {}
    snapshot = (
        app.yara.scan_snapshot()
        if app.yara
        else {
            "enabled": False,
            "packs_count": 0,
            "active_count": 0,
            "active": [],
            "state_error": "YARA 规则服务未初始化",
        }
    )
    scan_ready = bool(
        app.config.yara.enabled
        and component.get("installed")
        and component.get("health_status") == "ok"
        and snapshot.get("active_count")
    )
    return json_response(
        {
            "ok": True,
            "yara": {
                "component": component,
                "rules": snapshot,
                "scan_ready": scan_ready,
                "note": (
                    "规则包安装、签名校验和激活均需管理员显式确认；"
                    "规则命中不会自动隔离或删除文件"
                ),
            },
        }
    )


def handle_yara_packs(req: RequestContext, app: Application) -> ApiResponse:
    if not app.yara:
        raise LsecError(ErrorCode.NOT_IMPLEMENTED, "YARA 规则服务未初始化")
    return json_response(
        {
            "ok": True,
            "packs": app.yara.list_packs(),
            "inbox_dir": str(app.yara.inbox),
        }
    )


def handle_yara_pack_install(req: RequestContext, app: Application) -> ApiResponse:
    if not app.yara:
        raise LsecError(ErrorCode.NOT_IMPLEMENTED, "YARA 规则服务未初始化")
    body = _require_confirmation(req, "安装 YARA 规则包")
    path = body.get("path")
    activate = body.get("activate", True)
    if not isinstance(path, str) or not path:
        raise invalid("必须提供规则包路径 path")
    if not isinstance(activate, bool):
        raise invalid("activate 必须是布尔值")
    try:
        result = app.yara.install(path, activate=activate)
    except LsecError as exc:
        audit_store.record(
            app.db,
            action="yara.pack.install",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            target=path[:500],
            before_state={"path": path, "activate": activate},
            result="failure",
            error=exc.message,
        )
        raise
    component = app.components.probe("yara")
    audit_store.record(
        app.db,
        action="yara.pack.install",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=f"{result['pack_id']}@{result['version']}",
        before_state={"path": path, "activate": activate},
        after_state={
            "pack_id": result["pack_id"],
            "version": result["version"],
            "signature_verified": result["signature_verified"],
            "activated": result["activated"],
        },
        result="success",
        confirmed=True,
    )
    return json_response(
        {"ok": True, "pack": result, "component": component}, status=201
    )


def handle_yara_pack_activate(
    req: RequestContext, app: Application, match: re.Match[str]
) -> ApiResponse:
    if not app.yara:
        raise LsecError(ErrorCode.NOT_IMPLEMENTED, "YARA 规则服务未初始化")
    body = _require_confirmation(req, "激活 YARA 规则包版本")
    pack_id, version = match.group(1), match.group(2)
    try:
        result = app.yara.activate(pack_id, version)
    except LsecError as exc:
        audit_store.record(
            app.db,
            action="yara.pack.activate",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            target=f"{pack_id}@{version}",
            result="failure",
            error=exc.message,
        )
        raise
    component = app.components.probe("yara")
    audit_store.record(
        app.db,
        action="yara.pack.activate",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=f"{pack_id}@{version}",
        after_state=result,
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "pack": result, "component": component})


def handle_yara_pack_delete(
    req: RequestContext, app: Application, match: re.Match[str]
) -> ApiResponse:
    if not app.yara:
        raise LsecError(ErrorCode.NOT_IMPLEMENTED, "YARA 规则服务未初始化")
    _require_confirmation(req, "删除 YARA 规则包版本")
    pack_id, version = match.group(1), match.group(2)
    try:
        result = app.yara.delete(pack_id, version)
    except LsecError as exc:
        audit_store.record(
            app.db,
            action="yara.pack.delete",
            actor=req.actor,
            client=req.client,
            request_id=req.request_id,
            target=f"{pack_id}@{version}",
            result="failure",
            error=exc.message,
        )
        raise
    component = app.components.probe("yara")
    audit_store.record(
        app.db,
        action="yara.pack.delete",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target=f"{pack_id}@{version}",
        after_state=result,
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "pack": result, "component": component})


def handle_wazuh_status(req: RequestContext, app: Application) -> ApiResponse:
    component = component_store.get_component(app.db, "wazuh") or {}
    ingest = app._wazuh_ingest_summary()
    return json_response(
        {
            "ok": True,
            "wazuh": {
                "component": component,
                "ingest": ingest,
                "state": app._wazuh_state(component),
                "scope": "local_agent_only",
                "connection_verified": False,
                "note": (
                    "仅本地 Wazuh Agent 状态与可选 alerts.json 接入；"
                    "lsec 不是 Wazuh Manager，不提供 Manager 能力，"
                    "也不会自动隔离或删除文件"
                ),
                "install_plan_available": not bool(component.get("installed")),
            },
        }
    )


def handle_wazuh_install_plan(req: RequestContext, app: Application) -> ApiResponse:
    if not app.wazuh or not hasattr(app.wazuh, "install_plan"):
        raise LsecError(ErrorCode.NOT_IMPLEMENTED, "Wazuh 安装计划不可用")
    return json_response({"ok": True, "plan": app.wazuh.install_plan()})


def handle_doctor(req: RequestContext, app: Application) -> ApiResponse:
    return json_response({"ok": True, "report": app.doctor.run()})


def handle_settings_get(req: RequestContext, app: Application) -> ApiResponse:
    values = settings_store.get_all(app.db)
    return json_response(
        {
            "ok": True,
            "settings": values,
            "editable": {
                "response_mode": ["alert", "suggest"],
                "auto_quarantine_enabled": False,
                "scheduled_scan": True,
            },
            "notes": {
                "response_mode": "受控自动处置（auto）尚未实现，当前仅支持 alert/suggest",
                "auto_quarantine_enabled": "自动隔离默认关闭；启用后仍只作用于明确命中的下载文件（尚未实现）",
            },
        }
    )


def handle_settings_patch(req: RequestContext, app: Application) -> ApiResponse:
    body = req.require_json_object()
    clean = settings_store.validate_settings(body)
    if clean.get("response_mode") == "auto":
        raise LsecError(
            ErrorCode.NOT_IMPLEMENTED,
            "自动处置尚未实现；当前只支持仅告警或建议处置",
        )
    if clean.get("auto_quarantine_enabled") is True:
        raise LsecError(
            ErrorCode.NOT_IMPLEMENTED,
            "自动隔离尚未实现；请在隔离区手动确认后处置",
        )
    before = settings_store.get_all(app.db)
    for key, value in clean.items():
        if key == "scheduled_scan":
            current = settings_store.get(app.db, key, {}) or {}
            merged = {**current, **value}
            settings_store.set_value(app.db, key, merged)
        else:
            settings_store.set_value(app.db, key, value)
    after = settings_store.get_all(app.db)
    audit_store.record(
        app.db,
        action="settings.update",
        actor=req.actor,
        client=req.client,
        request_id=req.request_id,
        target="settings",
        before_state=before,
        after_state=after,
        result="success",
        confirmed=True,
    )
    return json_response({"ok": True, "settings": after})


def handle_logs(req: RequestContext, app: Application) -> ApiResponse:
    lines = req.q_int("lines", 200, 1, 500)
    path = Path(app.config.logging.file)
    if not path.exists():
        return json_response({"ok": True, "file": str(path), "lines": []})
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            content = fh.readlines()[-lines:]
    except OSError as exc:
        raise invalid(f"无法读取日志文件: {exc}") from None
    return json_response({"ok": True, "file": str(path), "lines": [line.rstrip("\n") for line in content]})


def handle_static(req: RequestContext, app: Application) -> ApiResponse:
    return serve_static("/")


def serve_static(path: str) -> ApiResponse:
    if path in {"", "/"}:
        relative = "index.html"
    elif path.startswith("/assets/"):
        name = path[len("/assets/"):]
        if not ASSET_RE.match(name):
            raise not_found("资源不存在")
        relative = name
    else:
        raise not_found("页面不存在")
    target = (UI_DIR / relative).resolve()
    try:
        target.relative_to(UI_DIR.resolve())
    except ValueError:
        raise not_found("资源不存在") from None
    if not target.is_file():
        raise not_found("资源不存在")
    data = target.read_bytes()
    content_type = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
    cache = "no-cache" if relative == "index.html" else "public, max-age=300"
    return ApiResponse(
        body=data,
        content_type=content_type,
        headers={"Cache-Control": cache},
    )


# ------------------------------------------------------------------ routes
ROUTES: list[tuple[str, str, Callable[..., ApiResponse], str]] = [
    ("GET", r"^/api/v1/health$", handle_health, "public"),
    ("POST", r"^/api/v1/auth/login$", handle_login, "public"),
    ("POST", r"^/api/v1/auth/logout$", handle_logout, "auth"),
    ("GET", r"^/api/v1/version$", handle_version, "auth"),
    ("GET", r"^/api/v1/system/info$", handle_system_info, "auth"),
    ("GET", r"^/api/v1/status$", handle_status, "auth"),
    ("GET", r"^/api/v1/capabilities$", handle_capabilities, "auth"),
    ("GET", r"^/api/v1/components$", handle_components, "auth"),
    ("POST", r"^/api/v1/components/probe$", lambda r, a: handle_component_probe(r, a), "admin"),
    ("GET", r"^/api/v1/components/([\w.-]+)/install-plan$", handle_component_install_plan, "auth"),
    ("POST", r"^/api/v1/components/([\w.-]+)/(start|stop|update)$", handle_component_action, "admin"),
    ("GET", r"^/api/v1/scans$", handle_scans_list, "auth"),
    ("POST", r"^/api/v1/scans$", handle_scan_create, "admin"),
    ("GET", r"^/api/v1/scans/([0-9a-fA-F-]+)$", handle_scan_get, "auth"),
    ("POST", r"^/api/v1/scans/([0-9a-fA-F-]+)/cancel$", handle_scan_cancel, "admin"),
    ("GET", r"^/api/v1/events$", handle_events_list, "auth"),
    ("GET", r"^/api/v1/events/export$", handle_events_export, "auth"),
    ("GET", r"^/api/v1/events/([0-9a-fA-F-]+)$", handle_event_get, "auth"),
    ("PATCH", r"^/api/v1/events/([0-9a-fA-F-]+)$", handle_event_patch, "admin"),
    ("GET", r"^/api/v1/quarantine$", handle_quarantine_list, "auth"),
    ("POST", r"^/api/v1/quarantine$", handle_quarantine_create, "admin"),
    ("GET", r"^/api/v1/quarantine/([0-9a-fA-F-]+)$", handle_quarantine_get, "auth"),
    ("POST", r"^/api/v1/quarantine/([0-9a-fA-F-]+)/(restore|delete)$", handle_quarantine_action, "admin"),
    ("GET", r"^/api/v1/audit$", handle_audit_list, "auth"),
    ("GET", r"^/api/v1/audits$", handle_audits_list, "auth"),
    ("POST", r"^/api/v1/audits$", handle_audit_create, "admin"),
    ("GET", r"^/api/v1/audits/([0-9a-fA-F-]+)$", handle_audit_get, "auth"),
    ("GET", r"^/api/v1/containers$", handle_containers_list, "auth"),
    ("POST", r"^/api/v1/containers/refresh$", handle_containers_refresh, "admin"),
    (
        "GET",
        r"^/api/v1/containers/([A-Za-z0-9][A-Za-z0-9_.-]{0,127})$",
        handle_container_get,
        "auth",
    ),
    ("GET", r"^/api/v1/falco$", handle_falco_status, "auth"),
    ("POST", r"^/api/v1/integrations/falco$", handle_falco_ingest, "integration"),
    ("GET", r"^/api/v1/wazuh$", handle_wazuh_status, "auth"),
    (
        "GET",
        r"^/api/v1/wazuh/install-plan$",
        handle_wazuh_install_plan,
        "auth",
    ),
    ("GET", r"^/api/v1/yara$", handle_yara_status, "auth"),
    ("GET", r"^/api/v1/yara/packs$", handle_yara_packs, "auth"),
    ("POST", r"^/api/v1/yara/packs$", handle_yara_pack_install, "admin"),
    (
        "POST",
        r"^/api/v1/yara/packs/([A-Za-z0-9][A-Za-z0-9_.-]{0,63})/"
        r"([A-Za-z0-9][A-Za-z0-9_.-]{0,63})/activate$",
        handle_yara_pack_activate,
        "admin",
    ),
    (
        "DELETE",
        r"^/api/v1/yara/packs/([A-Za-z0-9][A-Za-z0-9_.-]{0,63})/"
        r"([A-Za-z0-9][A-Za-z0-9_.-]{0,63})$",
        handle_yara_pack_delete,
        "admin",
    ),
    ("GET", r"^/api/v1/doctor$", handle_doctor, "auth"),
    ("GET", r"^/api/v1/settings$", handle_settings_get, "auth"),
    ("PATCH", r"^/api/v1/settings$", handle_settings_patch, "admin"),
    ("GET", r"^/api/v1/logs$", handle_logs, "admin"),
]

_COMPILED_ROUTES = [
    (method, re.compile(pattern), handler, access)
    for method, pattern, handler, access in ROUTES
]


class Handler(BaseHTTPRequestHandler):
    server_version = "lsec/0.1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # Silence the default stderr logging.
    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("%s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    # ------------------------------------------------------------ internals
    def _dispatch(self, method: str) -> None:
        app: Application = self.server.app  # type: ignore[attr-defined]
        started = time.monotonic()
        request_id = new_id_or_value(self.headers.get("X-Request-ID"))
        path = urlsplit(self.path).path
        status_code = 500
        try:
            if path == "/" or path.startswith("/assets/"):
                if method != "GET":
                    raise LsecError(ErrorCode.INVALID_ARGUMENT, "不支持的请求方法", http_status=405)
                response = serve_static(path)
                self._send(response)
                status_code = response.status
                return

            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            body = self._read_body() if method in {"POST", "PATCH", "DELETE"} else None
            remote = self.client_address[0] if self.client_address else "unknown"
            req = RequestContext(
                method=method,
                path=path,
                query=query,
                headers=self.headers,
                body=body,
                remote_addr=remote,
                request_id=request_id,
                app=app,
            )
            self._authenticate(req)

            route = self._match(method, path)
            if not route:
                raise not_found("接口不存在")
            _method, match, handler, access = route
            self._enforce_access(req, access)
            if method in {"POST", "PATCH", "DELETE"}:
                self._enforce_csrf(req, access)
            response = handler(req, app) if match is None else handler(req, app, match)
            self._send(response)
            status_code = response.status
        except LsecError as exc:
            response = error_response(exc, request_id)
            self._send(response)
            status_code = response.status
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            log.exception("未处理请求异常 method=%s path=%s", method, path)
            response = error_response(
                LsecError(ErrorCode.INTERNAL, "内部错误，请提供请求 ID 联系管理员"),
                request_id,
            )
            try:
                self._send(response)
            except (BrokenPipeError, ConnectionResetError):
                pass
            status_code = 500
        finally:
            log.info(
                "http method=%s path=%s status=%s duration_ms=%s remote=%s request_id=%s",
                method,
                path,
                status_code,
                round((time.monotonic() - started) * 1000, 1),
                self.client_address[0] if self.client_address else "-",
                request_id,
            )

    def _match(self, method: str, path: str) -> tuple[str, re.Match[str] | None, Callable[..., ApiResponse], str] | None:
        for route_method, pattern, handler, access in _COMPILED_ROUTES:
            if route_method != method:
                continue
            match = pattern.match(path)
            if match:
                # Patterns without capture groups still produce a Match object;
                # only pass it through when the handler expects parameters.
                return route_method, match if pattern.groups else None, handler, access
        return None

    def _authenticate(self, req: RequestContext) -> None:
        app = req.app
        assert app is not None
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[len("Bearer "):].strip()
            if req.path == "/api/v1/integrations/falco":
                if not app.auth.falco_token:
                    raise unauthorized("Falco 事件接入未启用")
                if not app.auth.falco_token_valid(token):
                    raise unauthorized("Falco 接入令牌无效")
                req.role = "integration"
                req.actor = "falco"
                req.bearer = True
                req.client = f"{req.remote_addr}/falco"
                return
            role = app.auth.token_role(token)
            if not role:
                raise unauthorized("访问令牌无效")
            req.role = role
            req.actor = role
            req.bearer = True
            req.client = f"{req.remote_addr}/token"
            return
        cookie = SimpleCookie(self.headers.get("Cookie"))
        morsel = cookie.get(COOKIE_NAME)
        session = app.auth.session(morsel.value if morsel else None)
        if session:
            req.session = session
            req.role = session["role"]
            req.actor = session["role"]
            req.client = f"{req.remote_addr}/session"

    def _enforce_access(self, req: RequestContext, access: str) -> None:
        if access == "public":
            return
        if access == "integration":
            if req.role != "integration":
                raise unauthorized("Falco 接入令牌无效")
            return
        if not req.role:
            raise unauthorized()
        if access == "admin":
            require_admin(req.role)

    def _enforce_csrf(self, req: RequestContext, access: str = "auth") -> None:
        if access == "public" or req.bearer:
            return
        if not req.session:
            raise unauthorized()
        supplied = self.headers.get("X-LSEC-CSRF")
        if not csrf_valid(req.session, supplied):
            raise LsecError(ErrorCode.FORBIDDEN, "CSRF 校验失败，请重新登录")
        origin = self.headers.get("Origin")
        if origin:
            host = self.headers.get("Host", "")
            origin_host = urlsplit(origin).netloc
            if origin_host and host and origin_host != host:
                raise LsecError(ErrorCode.FORBIDDEN, "跨站请求被拒绝")

    def _read_body(self) -> dict[str, Any] | None:
        app: Application = self.server.app  # type: ignore[attr-defined]
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return None
        try:
            length = int(raw_length)
        except ValueError:
            raise invalid("Content-Length 无效") from None
        if length <= 0:
            return None
        if length > app.config.server.max_body_bytes:
            raise LsecError(ErrorCode.INVALID_ARGUMENT, "请求体过大", http_status=413)
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise LsecError(ErrorCode.INVALID_ARGUMENT, "Content-Type 必须是 application/json", http_status=415)
        data = self.rfile.read(length)
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise invalid("请求体不是合法 JSON") from None
        if not isinstance(parsed, dict):
            raise invalid("请求体必须是 JSON 对象")
        return parsed

    def _send(self, response: ApiResponse) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            # Inline style attributes are generated by the first-party UI for
            # progress widths/spacing; scripts remain restricted to 'self'.
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        if not response.content_type.startswith("application/json"):
            self.send_header("Cache-Control", response.headers.get("Cache-Control", "no-store"))
        else:
            self.send_header("Cache-Control", "no-store")
        app = getattr(self.server, "app", None)
        if app and app.config.server.tls_cert:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for key, value in response.headers.items():
            if key.lower() == "cache-control":
                continue
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)


class LsecHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], app: Application) -> None:
        self.app = app
        super().__init__(address, Handler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        log.exception("连接处理异常 client=%s", client_address)


def create_server(app: Application) -> LsecHTTPServer:
    bind = app.config.server.bind
    port = app.config.server.port
    if ":" in bind:
        import socket

        LsecHTTPServer.address_family = socket.AF_INET6  # type: ignore[attr-defined]
    server = LsecHTTPServer((bind, port), app)
    if app.config.server.tls_cert and app.config.server.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(app.config.server.tls_cert, app.config.server.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
