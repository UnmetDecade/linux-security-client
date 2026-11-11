"""Adapter contract.

Every external security tool is wrapped by exactly one Adapter. Business code
never shells out directly and adapters never accept arbitrary shell strings.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from ..common.errors import not_implemented
from ..common.timeutil import now_iso

HEALTH_OK = "ok"
HEALTH_DEGRADED = "degraded"
HEALTH_UNAVAILABLE = "unavailable"
HEALTH_UNKNOWN = "unknown"
HEALTH_INCOMPATIBLE = "incompatible"
HEALTH_CHECK_FAILED = "check_failed"
HEALTH_PERMISSION_DENIED = "permission_denied"

SERVICE_RUNNING = "running"
SERVICE_STOPPED = "stopped"
SERVICE_NOT_INSTALLED = "not_installed"
SERVICE_UNKNOWN = "unknown"


@dataclass
class ProbeResult:
    component_id: str
    display_name: str
    installed: bool
    version: str | None = None
    service_status: str = SERVICE_UNKNOWN
    health_status: str = HEALTH_UNKNOWN
    capabilities: list[str] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    last_check_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "display_name": self.display_name,
            "installed": self.installed,
            "version": self.version,
            "service_status": self.service_status,
            "health_status": self.health_status,
            "capabilities": list(self.capabilities),
            "error_code": self.error_code,
            "error_message": self.error_message,
            "details": self.details,
            "last_check_at": self.last_check_at,
        }


@dataclass
class Detection:
    path: str
    detection_name: str
    size: int = 0
    sha256: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanOutcome:
    files_scanned: int = 0
    detections: int = 0
    errors: int = 0
    summary: dict[str, Any] = field(default_factory=dict)
    error_details: list[dict[str, Any]] = field(default_factory=list)
    cancelled: bool = False


@dataclass
class TaskContext:
    task_id: str
    cancel_event: threading.Event
    progress: Callable[[int, int, int, int, float | None], None]
    on_detection: Callable[[Detection], None]


class Adapter:
    component_id: str = "base"
    display_name: str = "Base"

    def probe(self) -> ProbeResult:
        raise not_implemented(f"{self.component_id} 未实现 probe")

    def install_plan(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "installable_from_ui": False,
            "note": "本客户端不会在运行期自动安装系统软件包；请通过受控镜像或发行版包管理器安装",
        }

    def start(self) -> ProbeResult:
        raise not_implemented(f"{self.component_id} 不支持启动操作")

    def stop(self) -> ProbeResult:
        raise not_implemented(f"{self.component_id} 不支持停止操作")

    def health(self) -> ProbeResult:
        return self.probe()

    def configure(self, config: dict[str, Any]) -> None:
        raise not_implemented(f"{self.component_id} 不支持配置操作")

    def run_task(self, task: dict[str, Any], context: TaskContext) -> ScanOutcome:
        raise not_implemented(f"{self.component_id} 不支持任务执行")

    def update(self) -> dict[str, Any]:
        raise not_implemented(f"{self.component_id} 不支持更新操作")

    def collect_events(self, cursor: str | None = None) -> list[dict[str, Any]]:
        return []

    def parse_result(self, raw: Any) -> list[dict[str, Any]]:
        return []
