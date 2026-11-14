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
        reason = "cannot read kernel version; cannot determine eBPF compatibility"
    elif not legacy_kernel:
        state = "unsupported"
        reason = f"kernel {release} is below the Falco eBPF minimum of 4.14"
    elif modern_kernel and btf and privileged:
        state = "compatible"
        reason = (
            f"kernel {release} supports modern eBPF, BTF is present, and the current process has the required capabilities; "
            "however, whether Falco itself is running on the host must still be verified separately"
        )
    elif not privileged:
        state = "requires_privileges"
        reason = (
            "CAP_SYS_ADMIN is missing, or CAP_BPF + CAP_PERFMON are missing; "
            "the Falco driver cannot be loaded with the current privileges"
        )
    elif modern_kernel and not btf:
        state = "requires_setup"
        reason = (
            f"kernel {release} supports modern eBPF, but /sys/kernel/btf/vmlinux was not detected; "
            "use a kernel with BTF or install matching kernel headers"
        )
    else:
        state = "requires_setup"
        reason = (
            f"kernel {release} does not meet the recommended 5.8+ for modern eBPF; "
            "only legacy eBPF/kernel modules may be available, and matching kernel headers are required"
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
    display_name = "Falco Runtime Security"

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
                "reason": f"cannot read kernel/eBPF environment: {exc}"[:500],
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
                error_message="Falco integration is disabled by configuration",
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
                    "Falco not detected; an install plan is available, but the client never installs it or loads kernel drivers automatically"
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
            "risk": "Falco requires host kernel capabilities and a privileged driver; it cannot be silently installed or loaded from the web UI",
            "steps": [
                {
                    "title": "Confirm kernel and eBPF support",
                    "detail": "On the host, check uname -r, /sys/kernel/btf/vmlinux and /sys/fs/bpf. Modern eBPF recommends a 5.8+ kernel with BTF.",
                },
                {
                    "title": "Install Falco from a trusted source",
                    "detail": "Use the distribution package manager or the official signed Falco repository, pin the version and verify signatures; do not use binaries of unknown origin.",
                },
                {
                    "title": "Load the driver as an administrator",
                    "detail": "Falco requires CAP_SYS_ADMIN or CAP_BPF + CAP_PERFMON; loading the driver is a privileged host operation and must be authorized separately.",
                },
                {
                    "title": "Configure JSON alert output",
                    "detail": "Configure Falco to emit JSON and forward it to lsec's POST /api/v1/integrations/falco; use a dedicated Falco integration token, not an administrator token.",
                },
                {
                    "title": "Verify event ingestion",
                    "detail": "Trigger a non-production test rule and confirm the event reaches the unified event center with container correlation; if the kernel is incompatible, the UI clearly reports it as unsupported.",
                },
            ],
            "notes": [
                "lsec does not install or start Falco, does not load the Falco driver, and does not modify host kernel configuration automatically.",
                "Falco should not run inside the lsec container; it needs host-level privileges, and containerized operation would break the least-privilege boundary.",
                "Having the binary installed does not mean protection is active; host-side administrators must confirm the running state.",
            ],
        }
