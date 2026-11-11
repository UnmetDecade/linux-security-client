"""Falco capability detection and install planning.

Falco needs host kernel and privilege support that a normal container does not
have. This adapter therefore never claims Falco is protecting the host just
because the binary exists. It reports the observed kernel/eBPF prerequisites,
distinguishes missing privileges from missing support, and offers a read-only
install plan for the host administrator.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable

from ..common.executor import run, which
from .base import (
    HEALTH_DEGRADED,
    HEALTH_INCOMPATIBLE,
    HEALTH_PERMISSION_DENIED,
    HEALTH_UNAVAILABLE,
    HEALTH_UNKNOWN,
    SERVICE_NOT_INSTALLED,
    SERVICE_UNKNOWN,
    Adapter,
    ProbeResult,
)

_KERNEL_RE = re.compile(r"^(\d+)\.(\d+)")

# Bit positions in Linux CapEff.
_CAP_BITS = {
    "CAP_SYS_ADMIN": 21,
    "CAP_SYS_MODULE": 16,
    "CAP_SYS_PTRACE": 19,
    "CAP_SYS_RESOURCE": 24,
    "CAP_BPF": 39,
    "CAP_PERFMON": 38,
}


def _read_text(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit).strip()
    except OSError:
        return ""


def _caps_from_status(text: str) -> dict[str, bool | None]:
    caps: dict[str, bool | None] = {name: None for name in _CAP_BITS}
    for line in text.splitlines():
        if not line.startswith("CapEff:"):
            continue
        try:
            value = int(line.split(":", 1)[1].strip(), 16)
        except (IndexError, ValueError):
            return caps
        for name, bit in _CAP_BITS.items():
            caps[name] = bool(value & (1 << bit))
        return caps
    return caps


def probe_environment() -> dict[str, Any]:
    release = os.uname().release if hasattr(os, "uname") else ""
    caps = _caps_from_status(_read_text("/proc/self/status"))
    disabled = _read_text("/proc/sys/kernel/unprivileged_bpf_disabled", 20)
    return {
        "kernel_release": release,
        "btf_available": os.path.exists("/sys/kernel/btf/vmlinux"),
        "bpf_filesystem": os.path.isdir("/sys/fs/bpf"),
        "tracefs": os.path.isdir("/sys/kernel/tracing"),
        "capabilities": caps,
        "unprivileged_bpf_disabled": disabled or "unknown",
    }


def evaluate_capability(environment: dict[str, Any]) -> dict[str, Any]:
    """Evaluate kernel/eBPF prerequisites without claiming Falco is running."""
    release = str(environment.get("kernel_release") or "")
    match = _KERNEL_RE.match(release)
    major = int(match.group(1)) if match else None
    minor = int(match.group(2)) if match else None
    modern_kernel = bool(
        major is not None and minor is not None and (major, minor) >= (5, 8)
    )
    legacy_kernel = bool(
        major is not None and minor is not None and (major, minor) >= (4, 14)
    )
    btf = bool(environment.get("btf_available"))
    caps = environment.get("capabilities") or {}
    sys_admin = caps.get("CAP_SYS_ADMIN") is True
    bpf = caps.get("CAP_BPF") is True
    perfmon = caps.get("CAP_PERFMON") is True
    privileged = sys_admin or (bpf and perfmon)

    if major is None:
        state = "unknown"
        reason = "无法读取内核版本，不能判断 eBPF 兼容性"
    elif not legacy_kernel:
        state = "unsupported"
        reason = f"内核 {release} 低于 Falco eBPF 的最低要求 4.14"
    elif modern_kernel and btf and privileged:
        state = "compatible"
        reason = (
            f"内核 {release} 支持现代 eBPF，BTF 存在，当前进程具备所需 capability；"
            "但 Falco 是否已在宿主侧运行仍需单独确认"
        )
    elif not privileged:
        state = "requires_privileges"
        reason = (
            "缺少 CAP_SYS_ADMIN，或缺少 CAP_BPF + CAP_PERFMON；"
            "Falco 驱动无法在当前权限下加载"
        )
    elif modern_kernel and not btf:
        state = "requires_setup"
        reason = (
            f"内核 {release} 支持现代 eBPF，但未检测到 /sys/kernel/btf/vmlinux；"
            "需要使用带 BTF 的内核或安装匹配的内核头文件"
        )
    else:
        state = "requires_setup"
        reason = (
            f"内核 {release} 不满足现代 eBPF 的 5.8+ 建议；"
            "可能只能使用 legacy eBPF/内核模块，需要匹配的内核头文件"
        )

    return {
        "state": state,
        "reason": reason,
        "kernel_release": release or None,
        "kernel_major_minor": f"{major}.{minor}" if major is not None else None,
        "modern_ebpf_kernel": modern_kernel,
        "legacy_ebpf_kernel": legacy_kernel,
        "btf_available": btf,
        "bpf_filesystem": bool(environment.get("bpf_filesystem")),
        "tracefs": bool(environment.get("tracefs")),
        "cap_sys_admin": sys_admin,
        "cap_bpf": bpf,
        "cap_perfmon": perfmon,
        "has_driver_privileges": privileged,
        "unprivileged_bpf_disabled": str(
            environment.get("unprivileged_bpf_disabled") or "unknown"
        )[:20],
        "running_verified": False,
    }


class FalcoAdapter(Adapter):
    component_id = "falco"
    display_name = "Falco 运行时安全"

    def __init__(
        self,
        binary: str = "falco",
        *,
        enabled: bool = True,
        ingest_enabled: bool = False,
        environment_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self.binary = binary
        self.enabled = enabled
        self.ingest_enabled = ingest_enabled
        self.environment_provider = environment_provider or probe_environment

    def _version(self, binary_path: str | None) -> str | None:
        if not binary_path:
            return None
        result = run([binary_path, "--version"], timeout=8)
        if result.ok:
            lines = (result.stdout or result.stderr).strip().splitlines()
            if lines:
                return lines[0][:200]
        return None

    def probe(self) -> ProbeResult:
        path = which(self.binary)
        try:
            capability = evaluate_capability(self.environment_provider())
        except Exception as exc:
            capability = {
                "state": "unknown",
                "reason": f"无法读取内核/eBPF 环境: {exc}"[:500],
                "running_verified": False,
            }
        details: dict[str, Any] = {
            "binary": path,
            "enabled": self.enabled,
            "ingest_enabled": self.ingest_enabled,
            "capability": capability,
            "integration": "event_ingest",
            "running_verified": False,
        }

        if not self.enabled:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=bool(path),
                version=self._version(path),
                service_status=SERVICE_UNKNOWN,
                health_status=HEALTH_UNKNOWN,
                error_code="disabled",
                error_message="Falco 集成已通过配置禁用",
                details=details,
            )

        if not path:
            details["install_plan_available"] = True
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="not_installed",
                error_message=(
                    "未检测到 Falco；可查看安装计划，但客户端不会自动安装或加载内核驱动"
                ),
                details=details,
            )

        state = capability.get("state")
        if state == "unsupported":
            health = HEALTH_INCOMPATIBLE
            error_code = "kernel_incompatible"
        elif state == "requires_privileges":
            health = HEALTH_PERMISSION_DENIED
            error_code = "permission_denied"
        elif state in {"requires_setup", "unknown"}:
            health = HEALTH_DEGRADED
            error_code = "capability_not_ready"
        elif state == "compatible":
            # The binary and prerequisites are present, but the process is
            # host-side; lsec cannot verify it is running or loading rules.
            health = HEALTH_UNKNOWN
            error_code = "running_not_verified"
        else:  # pragma: no cover - defensive
            health = HEALTH_UNKNOWN
            error_code = "running_not_verified"

        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            version=self._version(path),
            service_status=SERVICE_UNKNOWN,
            health_status=health,
            capabilities=["runtime_events"],
            error_code=error_code,
            error_message=str(capability.get("reason") or "")[:500],
            details=details,
        )

    def install_plan(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "installable_from_ui": False,
            "risk": "Falco 需要宿主机内核能力和特权驱动；不能由 Web UI 静默安装或加载",
            "steps": [
                {
                    "title": "确认内核与 eBPF 支持",
                    "detail": "在宿主机检查 uname -r、/sys/kernel/btf/vmlinux 和 /sys/fs/bpf。现代 eBPF 建议 5.8+ 内核与 BTF。",
                },
                {
                    "title": "从受信来源安装 Falco",
                    "detail": "使用发行版包管理器或 Falco 官方签名仓库，固定版本并校验签名；不要使用来源不明的二进制。",
                },
                {
                    "title": "由管理员加载驱动",
                    "detail": "Falco 需要 CAP_SYS_ADMIN 或 CAP_BPF + CAP_PERFMON；加载驱动是宿主机特权操作，必须单独授权。",
                },
                {
                    "title": "配置 JSON 告警输出",
                    "detail": "让 Falco 输出 JSON，并转发到 lsec 的 POST /api/v1/integrations/falco；使用独立 Falco 接入令牌，不要复用管理员令牌。",
                },
                {
                    "title": "验证事件接收",
                    "detail": "触发一条非生产测试规则，确认事件进入统一事件中心并带有容器关联信息；若内核不兼容，界面会明确显示不支持。",
                },
            ],
            "notes": [
                "lsec 不安装、不启动、不加载 Falco 驱动，也不自动修改宿主机内核配置。",
                "Falco 不应运行在 lsec 容器内；Falco 需要宿主级权限，容器化运行会破坏最小权限边界。",
                "仅安装二进制不等于正在防护；运行状态由宿主侧管理员确认。",
            ],
        }
