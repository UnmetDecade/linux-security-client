"""Read-only container inventory and risk monitoring.

Inventory is collected through the Docker Engine API (normally a GET-only
proxy). Risk findings are normalized into the unified event center. The
service never starts, stops, restarts or modifies a container.
"""

from __future__ import annotations

import copy
import threading
from typing import Any

from ..common.config import ContainersConfig
from ..common.errors import conflict, not_found
from ..common.logging import get_logger
from ..common.timeutil import now_iso
from .container_checks import evaluate_container
from .docker_api import DockerApiClient, DockerApiError
from .events import EventService

log = get_logger("core.containers")

SCOPE_NOTE = (
    "容器清单来自 Docker Engine API；只能看到该 API 所连接的容器运行时。"
    "Containerd 当前仅探测安装与 Socket，不采集容器清单。"
)
LIMITATIONS = [
    "容器监控通过只读 Docker API 代理读取，Web 进程不直接挂载 Docker Socket。",
    "只有运行中的容器会生成配置风险事件；已停止容器的配置仍会显示在清单中。",
    "本客户端不会自动停止、重启、删除或修改任何容器。",
    "配置检查是启发式规则，不等同于漏洞扫描或运行时行为检测。",
    "Falco 事件通过独立接入令牌写入统一事件中心；未安装 Falco 时不会伪造运行时告警。",
]


class ContainerService:
    def __init__(
        self,
        config: ContainersConfig,
        events: EventService,
    ) -> None:
        self.config = config
        self.events = events
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known_risks: set[tuple[str, str]] = set()
        self._snapshot: dict[str, Any] = self._empty_snapshot(
            "disabled" if not config.enabled else "initializing",
            "容器监控未启用"
            if not config.enabled
            else "尚未完成首次容器采集",
        )

    # ----------------------------------------------------------------- state
    @staticmethod
    def _empty_snapshot(state: str, note: str) -> dict[str, Any]:
        return {
            "state": state,
            "note": note,
            "error_code": None,
            "error": None,
            "engine": None,
            "containers": [],
            "summary": {
                "total": 0,
                "running": 0,
                "stopped": 0,
                "risky": 0,
                "unknown": 0,
                "findings": 0,
                "by_risk": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "none": 0,
                    "unknown": 0,
                },
                "inspect_errors": 0,
            },
            "checked_at": None,
            "last_success_at": None,
            "stale": False,
            "truncated": False,
            "scope_note": SCOPE_NOTE,
            "limitations": list(LIMITATIONS),
            "ingest": {"created": 0, "merged": 0, "errors": 0},
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._snapshot)

    def get(self, container_ref: str) -> dict[str, Any]:
        snapshot = self.snapshot()
        if snapshot["state"] == "disabled":
            raise not_found("容器监控未启用，没有容器清单")
        containers = snapshot.get("containers") or []
        exact = [
            item
            for item in containers
            if item.get("container_id") == container_ref
            or item.get("name") == container_ref
        ]
        if exact:
            return exact[0]
        prefix = [
            item
            for item in containers
            if str(item.get("container_id", "")).startswith(container_ref)
        ]
        if len(prefix) == 1:
            return prefix[0]
        if len(prefix) > 1:
            raise conflict("容器 ID 前缀不唯一，请提供更完整的 ID")
        raise not_found("未找到容器")

    # ---------------------------------------------------------------- thread
    def start(self) -> None:
        if not self.config.enabled:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="container-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception:
                log.exception("容器监控刷新异常")
            if self._stop.wait(max(15, self.config.refresh_seconds)):
                break

    # --------------------------------------------------------------- refresh
    def refresh(self) -> dict[str, Any]:
        if not self.config.enabled:
            with self._lock:
                self._snapshot = self._empty_snapshot(
                    "disabled", "容器监控未启用"
                )
            return self.snapshot()

        with self._refresh_lock:
            previous = self.snapshot()
            try:
                client = DockerApiClient(
                    self.config.api_url, timeout=self.config.timeout_seconds
                )
                version = client.version()
                info = client.info()
                listed = client.list_containers()
                truncated = len(listed) > self.config.max_containers
                listed = listed[: self.config.max_containers]
                containers, inspect_errors = self._inspect_all(client, listed)
                summary = self._summarize(containers, len(inspect_errors))
                ingest = self._ingest_risks(containers)
                checked = now_iso()
                state = "monitored"
                note = self._monitored_note(summary)
                if inspect_errors:
                    state = "degraded"
                    note += f"；{len(inspect_errors)} 个容器详情读取失败，风险结论不完整"
                if truncated:
                    state = "degraded"
                    note += (
                        f"；容器数量超过上限 {self.config.max_containers}，清单已截断"
                    )
                snapshot = {
                    "state": state,
                    "note": note,
                    "error_code": None,
                    "error": None,
                    "engine": self._engine(version, info),
                    "containers": containers,
                    "summary": summary,
                    "checked_at": checked,
                    "last_success_at": checked,
                    "stale": False,
                    "truncated": truncated,
                    "inspect_errors": inspect_errors[:20],
                    "scope_note": SCOPE_NOTE,
                    "limitations": list(LIMITATIONS),
                    "ingest": ingest,
                }
                with self._lock:
                    self._snapshot = snapshot
                log.info(
                    "容器清单刷新完成 total=%s running=%s risky=%s state=%s",
                    summary["total"],
                    summary["running"],
                    summary["risky"],
                    state,
                )
                return self.snapshot()
            except DockerApiError as exc:
                return self._record_failure(previous, exc.code, exc.message)
            except Exception as exc:  # a broken monitor must not crash the daemon
                log.exception("容器监控失败")
                return self._record_failure(previous, "internal_error", str(exc)[:500])

    def _record_failure(
        self, previous: dict[str, Any], code: str, message: str
    ) -> dict[str, Any]:
        state = {
            "permission_denied": "permission_denied",
            "unavailable": "unavailable",
            "timeout": "unavailable",
            "invalid_config": "unavailable",
            "protocol_error": "degraded",
            "internal_error": "degraded",
        }.get(code, "unavailable")
        has_old = bool(previous.get("last_success_at"))
        snapshot = copy.deepcopy(previous)
        snapshot.update(
            {
                "state": state,
                "note": (
                    f"容器监控失败：{message}"
                    + ("；下方为上次成功采集的数据，已标记为过期" if has_old else "")
                ),
                "error_code": code,
                "error": message,
                "checked_at": now_iso(),
                "stale": has_old,
                "scope_note": SCOPE_NOTE,
                "limitations": list(LIMITATIONS),
            }
        )
        if not has_old:
            snapshot["containers"] = []
            snapshot["engine"] = None
            snapshot["summary"] = self._empty_snapshot(state, "")["summary"]
            snapshot["last_success_at"] = None
        with self._lock:
            self._snapshot = snapshot
        log.warning("容器监控不可用 state=%s code=%s error=%s", state, code, message)
        return self.snapshot()

    def _inspect_all(
        self, client: DockerApiClient, listed: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        containers: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for item in listed:
            container_id = str(item.get("Id") or "")
            if not container_id:
                continue
            try:
                inspect = client.inspect_container(container_id)
                containers.append(evaluate_container(inspect, item))
            except DockerApiError as exc:
                errors.append(
                    {
                        "container_id": container_id[:128],
                        "name": _list_name(item),
                        "error": exc.message[:500],
                    }
                )
                containers.append(
                    {
                        "container_id": container_id[:128],
                        "name": _list_name(item) or container_id[:12],
                        "image": str(item.get("Image") or "")[:500],
                        "image_id": str(item.get("ImageID") or "")[:200],
                        "state": str(item.get("State") or "")[:40],
                        "status_text": str(item.get("Status") or "")[:300],
                        "created_at": None,
                        "started_at": None,
                        "finished_at": None,
                        "pid": None,
                        "restart_count": None,
                        "oom_killed": False,
                        "user": "-",
                        "user_is_root": False,
                        "privileged": None,
                        "network_mode": "-",
                        "pid_mode": "",
                        "ipc_mode": "",
                        "userns_mode": "",
                        "cap_add": [],
                        "cap_drop": [],
                        "security_opt": [],
                        "read_only_rootfs": None,
                        "restart_policy": "",
                        "devices": [],
                        "mounts": [],
                        "ports": [],
                        "findings": [],
                        "risk_level": "unknown",
                        "risk_count": 0,
                        "evaluated": False,
                        "evaluation_error": f"读取容器详情失败：{exc.message[:300]}",
                    }
                )
        return containers, errors

    @staticmethod
    def _engine(version: dict[str, Any], info: dict[str, Any]) -> dict[str, Any]:
        return {
            "runtime": "docker",
            "server_version": str(version.get("Version") or "")[:100] or None,
            "api_version": str(version.get("ApiVersion") or "")[:40] or None,
            "min_api_version": str(version.get("MinAPIVersion") or "")[:40] or None,
            "os": str(info.get("OperatingSystem") or "")[:200] or None,
            "kernel": str(info.get("KernelVersion") or "")[:100] or None,
            "architecture": str(info.get("Architecture") or "")[:40] or None,
            "containers_running": info.get("ContainersRunning")
            if isinstance(info.get("ContainersRunning"), int)
            else None,
            "containers_stopped": info.get("ContainersStopped")
            if isinstance(info.get("ContainersStopped"), int)
            else None,
        }

    @staticmethod
    def _summarize(
        containers: list[dict[str, Any]], inspect_error_count: int
    ) -> dict[str, Any]:
        by_risk = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0,
            "unknown": 0,
        }
        running = 0
        stopped = 0
        risky = 0
        unknown = 0
        findings = 0
        for container in containers:
            state = str(container.get("state") or "").lower()
            if state == "running":
                running += 1
            else:
                stopped += 1
            risk = container.get("risk_level") or "unknown"
            if risk not in by_risk:
                risk = "unknown"
            by_risk[risk] += 1
            if risk in {"critical", "high", "medium", "low"}:
                risky += 1
            if not container.get("evaluated"):
                unknown += 1
            findings += int(container.get("risk_count") or 0)
        return {
            "total": len(containers),
            "running": running,
            "stopped": stopped,
            "risky": risky,
            "unknown": unknown,
            "findings": findings,
            "by_risk": by_risk,
            "inspect_errors": inspect_error_count,
        }

    @staticmethod
    def _monitored_note(summary: dict[str, Any]) -> str:
        note = (
            f"已读取 {summary['total']} 个容器，运行中 {summary['running']} 个；"
            f"{summary['risky']} 个存在配置风险"
        )
        if summary["unknown"]:
            note += f"，{summary['unknown']} 个无法评估"
        return note

    def _ingest_risks(self, containers: list[dict[str, Any]]) -> dict[str, int]:
        current: set[tuple[str, str]] = set()
        created = 0
        merged = 0
        errors = 0
        for container in containers:
            if str(container.get("state") or "").lower() != "running":
                continue
            if not container.get("evaluated"):
                continue
            container_id = str(container.get("container_id") or "")
            for finding in container.get("findings") or []:
                key = str(finding.get("key") or "")
                if not container_id or not key:
                    continue
                risk_key = (container_id, key)
                current.add(risk_key)
                if risk_key in self._known_risks:
                    continue
                try:
                    _stored, was_created = self.events.ingest_finding(
                        source="docker",
                        category="configuration",
                        severity=str(finding.get("severity") or "medium"),
                        title=str(finding.get("title") or "容器配置风险"),
                        description=(
                            f"容器 {container.get('name')}（镜像 {container.get('image')}，"
                            f"状态 {container.get('state')}）存在配置风险："
                            f"{finding.get('description')} "
                            "本客户端不会自动停止或修改该容器。"
                        ),
                        check_id=key,
                        target={
                            "type": "container",
                            "container_id": container_id,
                            "name": container.get("name"),
                        },
                        evidence={
                            "engine": "docker",
                            "rule_id": finding.get("rule_id"),
                            "container_id": container_id,
                            "container_name": container.get("name"),
                            "image": container.get("image"),
                            "state": container.get("state"),
                            "details": finding.get("evidence") or {},
                        },
                        recommended_actions=[
                            str(finding.get("recommendation") or "核实容器配置"),
                            "在确认影响前不要直接停止生产容器",
                            "保留容器与镜像信息作为处置证据",
                        ],
                        dedup_hint=f"{container_id}:{key}",
                        source_ref={
                            "source": "docker",
                            "container_id": container_id,
                            "rule_id": finding.get("rule_id"),
                        },
                        with_created=True,
                    )
                    if was_created:
                        created += 1
                    else:
                        merged += 1
                except Exception:
                    errors += 1
                    log.exception(
                        "容器风险事件写入失败 container=%s rule=%s",
                        container.get("name"),
                        finding.get("rule_id"),
                    )
        self._known_risks = current
        return {"created": created, "merged": merged, "errors": errors}


def _list_name(item: dict[str, Any]) -> str:
    names = item.get("Names")
    if isinstance(names, list) and names and isinstance(names[0], str):
        return names[0].lstrip("/")[:300]
    return ""
