"""Optional Wazuh Agent probe and local alert-ingestion support.

lsec is not a Wazuh Manager. This adapter only observes a locally installed
Agent and, when explicitly enabled, reads new lines from the local
``alerts.json``. It never claims Wazuh Manager capability, never contacts a
manager, and never exposes registration keys.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from ..common.config import WazuhConfig
from ..common.executor import run, which
from ..common.timeutil import now_iso
from .base import (
    HEALTH_DEGRADED,
    HEALTH_UNAVAILABLE,
    HEALTH_UNKNOWN,
    SERVICE_NOT_INSTALLED,
    SERVICE_RUNNING,
    SERVICE_STOPPED,
    SERVICE_UNKNOWN,
    Adapter,
    ProbeResult,
)

_VERSION_RE = re.compile(r"(?:WAZUH_VERSION|VERSION)\s*[=:]\s*\"?v?([0-9][0-9A-Za-z.\-_]*)")
_ADDRESS_RE = re.compile(
    r"<client\b.*?<server\b.*?<address>(.*?)</address>", re.IGNORECASE | re.DOTALL
)
_PORT_RE = re.compile(
    r"<client\b.*?<server\b.*?<port>(.*?)</port>", re.IGNORECASE | re.DOTALL
)


def _read_text(path: str, limit: int = 262144) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return ""
    try:
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _regular_file(path: str) -> tuple[bool, int]:
    try:
        st = os.lstat(path)
    except OSError:
        return False, 0
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return False, 0
    return True, st.st_size


class WazuhAdapter(Adapter):
    component_id = "wazuh"
    display_name = "Wazuh Agent（可选，仅本地）"

    def __init__(self, config: WazuhConfig) -> None:
        self.config = config

    # ------------------------------------------------------------- probing
    def _version(self, control: str | None) -> str | None:
        if not control:
            return None
        result = run([control, "info"], timeout=8, max_output=16384)
        if not result.ok:
            return None
        match = _VERSION_RE.search(result.stdout or result.stderr or "")
        return match.group(1)[:80] if match else None

    def _service_state(self, control: str | None) -> tuple[str, str | None]:
        if not control:
            return SERVICE_UNKNOWN, None
        result = run([control, "status"], timeout=8, max_output=32768)
        text = f"{result.stdout}\n{result.stderr}".lower()
        if "not running" in text or "stopped" in text:
            return SERVICE_STOPPED, text.strip()[:500] or None
        if "is running" in text:
            return SERVICE_RUNNING, None
        if result.ok:
            return SERVICE_UNKNOWN, (text.strip()[:500] or None)
        return SERVICE_UNKNOWN, (result.tail(500) or "无法读取 Agent 服务状态")

    def _manager_config(self) -> dict[str, Any]:
        conf_path = str(Path(self.config.install_dir) / "etc" / "ossec.conf")
        text = _read_text(conf_path)
        if not text:
            return {
                "config_path": conf_path,
                "config_present": False,
                "manager_configured": False,
                "address": None,
                "port": None,
            }
        address_match = _ADDRESS_RE.search(text)
        port_match = _PORT_RE.search(text)
        address = address_match.group(1).strip()[:255] if address_match else ""
        port = port_match.group(1).strip()[:10] if port_match else ""
        return {
            "config_path": conf_path,
            "config_present": True,
            "manager_configured": bool(address),
            "address": address or None,
            "port": port or None,
        }

    def probe(self) -> ProbeResult:
        agent = which(self.config.agent_bin)
        control = which(self.config.control_bin)
        install_dir = Path(self.config.install_dir)
        install_present = install_dir.is_dir()
        manager = self._manager_config()
        keys_path = str(install_dir / "etc" / "client.keys")
        keys_present, keys_size = _regular_file(keys_path)
        keys_mode = None
        if keys_present:
            try:
                keys_mode = stat.S_IMODE(os.lstat(keys_path).st_mode)
            except OSError:
                keys_mode = None
        alerts_present, alerts_size = _regular_file(self.config.alerts_path)
        service_status, service_detail = self._service_state(control)
        details: dict[str, Any] = {
            "binary": agent,
            "control": control,
            "install_dir": str(install_dir),
            "install_present": install_present,
            "enabled": bool(self.config.enabled),
            "ingest_enabled": bool(self.config.ingest_enabled),
            "manager": manager,
            "registration_present": bool(keys_present and keys_size > 0),
            "registration_key_mode": oct(keys_mode) if keys_mode is not None else None,
            "alerts_path": self.config.alerts_path,
            "alerts_present": alerts_present,
            "alerts_size": alerts_size,
            "service_detail": service_detail,
            "connection_verified": False,
            "scope": "local_agent_only",
            "note": (
                "仅读取本地 Wazuh Agent 状态与本地告警文件；"
                "lsec 不是 Wazuh Manager，不验证也不声称 Manager 连接能力"
            ),
            "checked_at": now_iso(),
        }

        if not self.config.enabled:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=bool(agent or install_present),
                version=self._version(control),
                service_status=SERVICE_UNKNOWN,
                health_status=HEALTH_UNAVAILABLE,
                capabilities=[],
                error_code="disabled",
                error_message="Wazuh 集成为可选项，已在配置中禁用",
                details=details,
            )

        if not agent and not install_present:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                capabilities=[],
                error_code="not_installed",
                error_message=(
                    "未检测到本地 Wazuh Agent；lsec 不提供 Wazuh Manager 功能，"
                    "也不会自动安装 Agent"
                ),
                details=details,
            )

        if not manager["config_present"]:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=True,
                version=self._version(control),
                service_status=service_status,
                health_status=HEALTH_DEGRADED,
                capabilities=[],
                error_code="config_missing",
                error_message="已检测到 Wazuh Agent，但未找到本地 ossec.conf，无法确认注册配置",
                details=details,
            )

        if not manager["manager_configured"]:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=True,
                version=self._version(control),
                service_status=service_status,
                health_status=HEALTH_DEGRADED,
                capabilities=[],
                error_code="manager_not_configured",
                error_message="本地 Agent 未配置 Manager 地址；不会产生可用的 Wazuh 告警",
                details=details,
            )

        if service_status == SERVICE_STOPPED:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=True,
                version=self._version(control),
                service_status=SERVICE_STOPPED,
                health_status=HEALTH_DEGRADED,
                capabilities=[],
                error_code="agent_not_running",
                error_message="Wazuh Agent 已配置但服务未运行；不会产生新的本地告警",
                details=details,
            )

        capabilities = ["local_agent_status"]
        if self.config.ingest_enabled:
            capabilities.append("local_alert_ingest")
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            version=self._version(control),
            service_status=service_status,
            health_status=HEALTH_UNKNOWN,
            capabilities=capabilities,
            error_code="manager_connection_unverified",
            error_message=(
                "本地 Wazuh Agent 已安装；本客户端无法验证其 Manager 连接状态，"
                "只提供本地状态与可选告警接入，不声称完整 Wazuh 能力"
            ),
            details=details,
        )

    def install_plan(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "installable_from_ui": False,
            "package_source": "Wazuh 官方仓库（由管理员在宿主机安装并注册 Agent）",
            "privileges": "安装与注册需要宿主机 root；lsec 不会自动执行",
            "dependencies": ["wazuh-agent", "由管理员提供的 Manager 地址与注册密钥"],
            "steps": [
                "在宿主机按 Wazuh 官方文档安装 Agent",
                "向管理员获取注册信息并使用 agent-auth 注册；密钥不得写入 lsec 日志",
                "确认 wazuh-control status 显示 Agent 运行且 Manager 连接正常",
                "如需本地告警接入，将 alerts.json 路径和 ingest_enabled 写入配置",
            ],
            "notes": [
                "lsec 不是 Wazuh Manager，不管理其他 Agent，也不提供 Manager API",
                "只读取本地 alerts.json 的新增行，默认从文件末尾开始，不导入历史告警",
                "告警不会触发自动隔离、删除或容器操作",
            ],
        }
