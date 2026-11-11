"""Probe-only adapters for tools whose functional integration lands in later
phases. They report installation truthfully; they never claim protection.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from ..common.config import ContainersConfig, WazuhConfig
from ..common.executor import run, which
from ..common.timeutil import now_iso
from ..core.docker_api import DockerApiClient, DockerApiError
from .falco import FalcoAdapter
from .lynis import LynisAdapter
from .wazuh import WazuhAdapter
from .base import (
    HEALTH_CHECK_FAILED,
    HEALTH_DEGRADED,
    HEALTH_OK,
    HEALTH_PERMISSION_DENIED,
    HEALTH_UNAVAILABLE,
    HEALTH_UNKNOWN,
    SERVICE_NOT_INSTALLED,
    SERVICE_RUNNING,
    SERVICE_STOPPED,
    SERVICE_UNKNOWN,
    Adapter,
    ProbeResult,
)

_PENDING_NOTE = "已检测到安装，但本阶段仅提供组件探测；功能集成将在后续阶段交付，不视为正在防护"


class ProbeOnlyAdapter(Adapter):
    binary: str = ""
    component_id = "unknown"
    display_name = "未知组件"
    version_args: tuple[str, ...] = ("--version",)

    def __init__(self, note: str = _PENDING_NOTE) -> None:
        self.note = note

    def _version(self, binary_path: str | None) -> str | None:
        if not binary_path:
            return None
        result = run([binary_path, *self.version_args], timeout=6)
        if result.ok:
            text = (result.stdout or result.stderr).strip().splitlines()
            if text:
                return text[0][:200]
        return None

    def probe(self) -> ProbeResult:
        path = which(self.binary)
        if not path:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="not_installed",
                error_message=f"未检测到 {self.binary}",
                details={"binary": None, "integration": "not_implemented"},
            )
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            version=self._version(path),
            service_status=SERVICE_UNKNOWN,
            health_status=HEALTH_UNKNOWN,
            capabilities=[],
            error_code="integration_pending",
            error_message=self.note,
            details={"binary": path, "integration": "not_implemented"},
        )


class SystemAdapter(Adapter):
    component_id = "system"
    display_name = "systemd / journald 系统能力"

    def probe(self) -> ProbeResult:
        systemd = os.path.isdir("/run/systemd/system")
        journalctl = which("journalctl")
        installed = systemd or bool(journalctl)
        if not installed:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="not_installed",
                error_message="当前环境未检测到 systemd/journald（容器内通常不可用）",
                details={"systemd": False, "journalctl": None},
            )
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            service_status=SERVICE_RUNNING if systemd else SERVICE_UNKNOWN,
            health_status=HEALTH_UNKNOWN,
            capabilities=[],
            error_code="integration_pending",
            error_message="系统能力已探测，日志/审计集成将在后续阶段交付",
            details={
                "systemd": systemd,
                "journalctl": journalctl,
                "integration": "not_implemented",
            },
        )


class DockerAdapter(Adapter):
    component_id = "docker"
    display_name = "Docker 容器运行时"

    SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")

    def __init__(self, config: ContainersConfig) -> None:
        self.config = config

    def probe(self) -> ProbeResult:
        binary = which("docker")
        socket_path = next((p for p in self.SOCKETS if os.path.exists(p)), None)
        socket_accessible = bool(
            socket_path and os.access(socket_path, os.R_OK | os.W_OK)
        )
        details: dict[str, Any] = {
            "binary": binary,
            "socket": socket_path,
            "socket_accessible": socket_accessible,
            "monitoring_enabled": self.config.enabled,
            "integration": "inventory" if self.config.enabled else "monitor_disabled",
            "checked_at": now_iso(),
        }

        version = None
        api_error: DockerApiError | None = None
        if self.config.enabled:
            try:
                client = DockerApiClient(
                    self.config.api_url, timeout=self.config.timeout_seconds
                )
                api_version = client.version()
                version = str(api_version.get("Version") or "")[:100] or None
                details["api_version"] = str(api_version.get("ApiVersion") or "")[:40]
                details["server_version"] = version
                details["api_reachable"] = True
                details["api_endpoint_kind"] = (
                    "unix_socket" if self.config.api_url.startswith("unix://") else "proxy"
                )
            except DockerApiError as exc:
                api_error = exc
                details["api_reachable"] = False
                details["api_endpoint_kind"] = (
                    "unix_socket" if self.config.api_url.startswith("unix://") else "proxy"
                )
        else:
            details["api_reachable"] = False

        if not binary and not socket_path and not (self.config.enabled and version):
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="not_installed",
                error_message="未检测到 Docker 客户端、Socket 或可访问的只读 API 代理",
                details=details,
            )

        if version:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=True,
                version=version,
                service_status=SERVICE_RUNNING,
                health_status=HEALTH_OK,
                capabilities=["container_inventory", "configuration_checks"],
                error_code=None,
                error_message=(
                    "已连接只读 Docker API，可读取容器清单；"
                    f"API 版本 {details.get('api_version') or '未知'}"
                ),
                details=details,
            )

        if binary:
            result = run([binary, "--version"], timeout=5)
            if result.ok and not version:
                version = (result.stdout or result.stderr).strip()[:200]

        health = HEALTH_UNKNOWN
        error_code = "monitor_disabled"
        error_message = "已探测到 Docker；容器监控未启用（默认不向 Web 进程挂载 Docker Socket）"
        service_status = SERVICE_UNKNOWN
        if self.config.enabled and api_error:
            service_status = SERVICE_UNKNOWN
            if api_error.code == "permission_denied":
                health = HEALTH_PERMISSION_DENIED
                error_code = "permission_denied"
                error_message = "容器监控无权访问 Docker API；不会误报为已启用"
            elif api_error.code in {"unavailable", "timeout"}:
                health = HEALTH_DEGRADED
                error_code = "api_unreachable"
                error_message = "容器监控已启用，但无法连接只读 Docker API 代理"
            else:
                health = HEALTH_DEGRADED
                error_code = "api_error"
                error_message = f"只读 Docker API 异常: {api_error.message}"[:500]
        elif binary:
            info = run([binary, "info", "--format", "{{.ServerVersion}}"], timeout=6)
            if info.ok:
                service_status = SERVICE_RUNNING
                details["server_version"] = info.stdout.strip()[:100]
                health = HEALTH_UNKNOWN
                error_code = "monitor_disabled"
                error_message = "Docker 守护进程可访问，但容器监控未启用"
            else:
                service_status = SERVICE_STOPPED
                if "permission denied" in info.tail().lower():
                    health = HEALTH_PERMISSION_DENIED
                    error_code = "permission_denied"
                    error_message = "无权访问 Docker Socket（当前进程未被授权）"
                else:
                    health = HEALTH_DEGRADED
                    error_code = "daemon_unreachable"
                    error_message = "Docker 客户端存在，但无法连接容器运行时"
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            version=version,
            service_status=service_status,
            health_status=health,
            capabilities=[],
            error_code=error_code,
            error_message=error_message,
            details=details,
        )


class ContainerdAdapter(Adapter):
    component_id = "containerd"
    display_name = "Containerd 容器运行时"

    SOCKETS = (
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
    )

    def probe(self) -> ProbeResult:
        binary = which("containerd")
        ctr = which("ctr")
        socket_path = next((p for p in self.SOCKETS if os.path.exists(p)), None)
        details = {
            "binary": binary,
            "ctr": ctr,
            "socket": socket_path,
            "socket_accessible": bool(
                socket_path and os.access(socket_path, os.R_OK | os.W_OK)
            ),
            "inventory": "not_implemented",
            "checked_at": now_iso(),
        }
        if not binary and not ctr and not socket_path:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="not_installed",
                error_message="未检测到 Containerd",
                details=details,
            )
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            service_status=SERVICE_RUNNING if socket_path else SERVICE_UNKNOWN,
            health_status=HEALTH_UNKNOWN,
            error_code="inventory_not_supported",
            error_message=(
                "已探测到 Containerd；本阶段容器清单仅通过 Docker Engine API 采集，"
                "未接入 Containerd 清单，不会伪造结果"
            ),
            details=details,
        )


def default_adapters(
    lynis_adapter: Adapter | None = None,
    *,
    containers_config: ContainersConfig | None = None,
    falco_adapter: Adapter | None = None,
    yara_adapter: Adapter | None = None,
    wazuh_adapter: Adapter | None = None,
) -> list[Adapter]:
    adapters: list[Adapter] = [
        lynis_adapter or LynisAdapter(),
        falco_adapter or FalcoAdapter(),
    ]
    if yara_adapter is not None:
        adapters.append(yara_adapter)
    if wazuh_adapter is not None:
        adapters.append(wazuh_adapter)
    else:
        adapters.append(WazuhAdapter(WazuhConfig()))
    adapters.extend(
        [
            DockerAdapter(containers_config or ContainersConfig()),
            ContainerdAdapter(),
            SystemAdapter(),
        ]
    )
    return adapters
