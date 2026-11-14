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

_PENDING_NOTE = "Installation detected, but this stage only provides component probing; functional integration arrives in a later stage and is not considered active protection"


class ProbeOnlyAdapter(Adapter):
    binary: str = ""
    component_id = "unknown"
    display_name = "Unknown Component"
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
                error_message=f"{self.binary} not detected",
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
    display_name = "systemd / journald System Capabilities"

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
                error_message="systemd/journald not detected in this environment (usually unavailable in containers)",
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
            error_message="System capabilities detected; logging/audit integration arrives in a later stage",
            details={
                "systemd": systemd,
                "journalctl": journalctl,
                "integration": "not_implemented",
            },
        )


class DockerAdapter(Adapter):
    component_id = "docker"
    display_name = "Docker Container Runtime"

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
                error_message="Docker client, socket, or reachable read-only API proxy not detected",
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
                    "Connected to the read-only Docker API; container inventory is available; "
                    f"API version {details.get('api_version') or 'unknown'}"
                ),
                details=details,
            )

        if binary:
            result = run([binary, "--version"], timeout=5)
            if result.ok and not version:
                version = (result.stdout or result.stderr).strip()[:200]

        health = HEALTH_UNKNOWN
        error_code = "monitor_disabled"
        error_message = "Docker detected; container monitoring is disabled (the Docker socket is not mounted into the web process by default)"
        service_status = SERVICE_UNKNOWN
        if self.config.enabled and api_error:
            service_status = SERVICE_UNKNOWN
            if api_error.code == "permission_denied":
                health = HEALTH_PERMISSION_DENIED
                error_code = "permission_denied"
                error_message = "Container monitoring cannot access the Docker API; it is not falsely reported as enabled"
            elif api_error.code in {"unavailable", "timeout"}:
                health = HEALTH_DEGRADED
                error_code = "api_unreachable"
                error_message = "Container monitoring is enabled but cannot reach the read-only Docker API proxy"
            else:
                health = HEALTH_DEGRADED
                error_code = "api_error"
                error_message = f"read-only Docker API error: {api_error.message}"[:500]
        elif binary:
            info = run([binary, "info", "--format", "{{.ServerVersion}}"], timeout=6)
            if info.ok:
                service_status = SERVICE_RUNNING
                details["server_version"] = info.stdout.strip()[:100]
                health = HEALTH_UNKNOWN
                error_code = "monitor_disabled"
                error_message = "Docker daemon is reachable but container monitoring is disabled"
            else:
                service_status = SERVICE_STOPPED
                if "permission denied" in info.tail().lower():
                    health = HEALTH_PERMISSION_DENIED
                    error_code = "permission_denied"
                    error_message = "Permission denied accessing the Docker socket (the current process is not authorized)"
                else:
                    health = HEALTH_DEGRADED
                    error_code = "daemon_unreachable"
                    error_message = "Docker client exists but cannot reach the container runtime"
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
    display_name = "Containerd Container Runtime"

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
                error_message="Containerd not detected",
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
                "Containerd detected; at this stage container inventory is collected only through the Docker Engine API, "
                "Containerd inventory is not integrated, and results are not fabricated"
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
