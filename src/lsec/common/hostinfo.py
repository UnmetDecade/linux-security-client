"""Best-effort host facts. Values are reported as observed, never guessed."""

from __future__ import annotations

import os
import platform
import socket
from typing import Any


def _read(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit).strip()
    except OSError:
        return ""


def _os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    for line in _read("/etc/os-release").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
    return data


def container_info() -> dict[str, Any]:
    """Detect whether we run inside a container. Informational only."""
    inside = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
    cgroup = _read("/proc/1/cgroup")
    runtime = None
    if "docker" in cgroup:
        runtime = "docker"
    elif "kubepods" in cgroup:
        runtime = "kubernetes"
    elif "lxc" in cgroup:
        runtime = "lxc"
    if not inside and runtime is None:
        return {"containerized": False, "runtime": None}
    return {"containerized": True, "runtime": runtime or "unknown"}


def host_info() -> dict[str, Any]:
    release = _os_release()
    return {
        "hostname": socket.gethostname(),
        "os": release.get("PRETTY_NAME") or platform.platform(),
        "os_id": release.get("ID"),
        "os_version": release.get("VERSION_ID"),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "pid": os.getpid(),
        "uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "container": container_info(),
    }
