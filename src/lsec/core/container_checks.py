"""Deterministic container configuration risk checks.

The evaluator is read-only and only uses data returned by the Docker API. A
missing or malformed inspection is reported as "not evaluated"; it is never
treated as a clean result.
"""

from __future__ import annotations

import os
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
MAX_FINDINGS = 100
MAX_MOUNTS = 100
MAX_CAPS = 100
MAX_PORTS = 100

# (read-write severity, read-only severity)
_SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/", "critical", "high"),
    ("/proc", "critical", "high"),
    ("/sys", "critical", "high"),
    ("/dev", "critical", "high"),
    ("/etc", "high", "medium"),
    ("/root", "high", "medium"),
    ("/home", "high", "medium"),
    ("/var/run", "high", "medium"),
    ("/run", "high", "medium"),
    ("/var/lib/docker", "high", "medium"),
    ("/var/lib/containerd", "high", "medium"),
    ("/boot", "high", "medium"),
    ("/usr", "high", "medium"),
    ("/lib", "high", "medium"),
    ("/lib64", "high", "medium"),
    ("/bin", "high", "medium"),
    ("/sbin", "high", "medium"),
)

_BROAD_CAPS = {
    "ALL": "critical",
    "SYS_ADMIN": "critical",
    "SYS_MODULE": "critical",
    "SYS_RAWIO": "high",
    "SYS_PTRACE": "high",
    "BPF": "high",
    "PERFMON": "high",
    "DAC_READ_SEARCH": "high",
    "DAC_OVERRIDE": "medium",
    "NET_ADMIN": "medium",
    "NET_RAW": "medium",
    "SETUID": "medium",
    "SETGID": "medium",
    "SYS_CHROOT": "medium",
    "MKNOD": "medium",
}

_RECOMMENDATIONS = {
    "privileged": "Remove privileged mode; grant only the specific capabilities needed.",
    "host-network": "Use a bridge network or explicit port mappings instead of sharing the host network namespace.",
    "host-pid": "Remove the host PID namespace; observe processes from inside the container instead.",
    "host-ipc": "Remove the host IPC namespace unless there is a clear inter-process communication requirement.",
    "host-user": "Avoid the host user namespace; enable a dedicated user namespace for the container.",
    "docker-socket": "Do not mount the Docker Socket into workload containers; if read-only queries are truly needed, use a controlled GET-only proxy.",
    "sensitive-mount": "Remove unnecessary host directory mounts; mount only the minimum required paths and prefer read-only.",
    "cap-add": "Remove unnecessary capabilities; use cap_drop: [ALL] and add only what is needed.",
    "seccomp-unconfined": "Enable the default seccomp profile; do not set it to unconfined.",
    "apparmor-unconfined": "Enable the default AppArmor profile; do not set it to unconfined.",
    "selinux-disabled": "Enable SELinux label isolation (label=disable turns isolation off).",
    "host-device": "Do not pass host devices through to containers unless it is a clear hardware-access use case.",
}


def _severity_rank(value: str) -> int:
    try:
        return SEVERITY_ORDER.index(value)
    except ValueError:
        return len(SEVERITY_ORDER)


def max_severity(values: list[str]) -> str:
    if not values:
        return "none"
    return min(values, key=_severity_rank)


def _as_list(value: Any, limit: int = MAX_CAPS) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value[:limit]:
        if isinstance(item, str) and item:
            result.append(item[:300])
        elif isinstance(item, dict):
            # Devices and similar objects are represented by their host path.
            path = item.get("PathOnHost") or item.get("Source") or item.get("Name")
            if isinstance(path, str) and path:
                result.append(path[:300])
    return result


def _bounded(value: Any, limit: int = 300) -> str:
    if not isinstance(value, str):
        return ""
    return value[:limit]


def _path_matches(source: str, root: str) -> bool:
    if root == "/":
        return source.startswith("/")
    return source == root or source.startswith(root.rstrip("/") + "/")


def _sensitive_severity(source: str, writable: bool) -> tuple[str, str] | None:
    normalized = os.path.normpath(source)
    # Match the most specific root first so /etc/ssh is not reported as "/".
    for root, rw_severity, ro_severity in sorted(
        _SENSITIVE_PATHS, key=lambda item: len(item[0]), reverse=True
    ):
        if _path_matches(normalized, root):
            return (rw_severity if writable else ro_severity), root
    return None


def _mount_is_socket(source: str) -> bool:
    normalized = os.path.normpath(source)
    return normalized.endswith("/docker.sock") or normalized.endswith(
        "/containerd.sock"
    )


def _parse_binds(binds: Any) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    if not isinstance(binds, list):
        return mounts
    for raw in binds[:MAX_MOUNTS]:
        if not isinstance(raw, str):
            continue
        parts = raw.split(":")
        if len(parts) < 2:
            continue
        source, destination = parts[0], parts[1]
        options = parts[2] if len(parts) > 2 else ""
        if not source.startswith("/"):
            continue
        mounts.append(
            {
                "type": "bind",
                "source": source[:4096],
                "destination": destination[:4096],
                "read_only": "ro" in options.split(","),
                "propagation": "",
                "inferred_from": "HostConfig.Binds",
            }
        )
    return mounts


def _normalize_mounts(host_config: dict[str, Any], inspect: dict[str, Any]) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    raw_mounts = inspect.get("Mounts")
    if isinstance(raw_mounts, list):
        for item in raw_mounts[:MAX_MOUNTS]:
            if not isinstance(item, dict):
                continue
            source = _bounded(item.get("Source"), 4096)
            destination = _bounded(item.get("Destination"), 4096)
            if not source and not destination:
                continue
            mounts.append(
                {
                    "type": _bounded(item.get("Type"), 40) or "unknown",
                    "source": source,
                    "destination": destination,
                    "read_only": not bool(item.get("RW", False)),
                    "propagation": _bounded(item.get("Propagation"), 40),
                    "inferred_from": "Mounts",
                }
            )
    if not mounts:
        mounts = _parse_binds(host_config.get("Binds"))
    return mounts[:MAX_MOUNTS]


def _normalize_ports(network_settings: Any) -> list[dict[str, Any]]:
    if not isinstance(network_settings, dict):
        return []
    ports = network_settings.get("Ports")
    if not isinstance(ports, dict):
        return []
    result: list[dict[str, Any]] = []
    for container_port, bindings in list(ports.items())[:MAX_PORTS]:
        key = _bounded(container_port, 100)
        if not isinstance(bindings, list) or not bindings:
            result.append({"container": key, "host_ip": None, "host_port": None})
            continue
        for binding in bindings[:20]:
            if not isinstance(binding, dict):
                continue
            result.append(
                {
                    "container": key,
                    "host_ip": _bounded(binding.get("HostIp"), 100) or None,
                    "host_port": _bounded(binding.get("HostPort"), 20) or None,
                }
            )
    return result[:MAX_PORTS]


def _add_finding(
    findings: list[dict[str, Any]],
    *,
    key: str,
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    evidence: dict[str, Any],
) -> None:
    if len(findings) >= MAX_FINDINGS:
        return
    if any(item["key"] == key for item in findings):
        return
    findings.append(
        {
            "key": key[:300],
            "rule_id": rule_id[:120],
            "title": title[:300],
            "severity": severity,
            "description": description[:2000],
            "recommendation": _RECOMMENDATIONS.get(rule_id, "Verify the configuration and adjust it according to least privilege."),
            "evidence": evidence,
        }
    )


def evaluate_container(inspect: dict[str, Any], list_item: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate one inspected container.

    Returns a bounded, UI-ready summary. ``evaluated`` is false when the
    inspection lacks the fields needed for a trustworthy conclusion.
    """
    list_item = list_item or {}
    container_id = _bounded(inspect.get("Id"), 128) or _bounded(list_item.get("Id"), 128)
    name = _bounded(inspect.get("Name"), 300).lstrip("/")
    if not name:
        names = list_item.get("Names")
        if isinstance(names, list) and names and isinstance(names[0], str):
            name = names[0].lstrip("/")[:300]
    config = inspect.get("Config")
    host_config = inspect.get("HostConfig")
    state = inspect.get("State")
    evaluated = isinstance(config, dict) and isinstance(host_config, dict) and isinstance(state, dict)
    findings: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "container_id": container_id,
        "name": name or container_id[:12],
        "image": _bounded((config or {}).get("Image"), 500)
        or _bounded(list_item.get("Image"), 500),
        "image_id": _bounded(inspect.get("Image"), 200),
        "state": _bounded((state or {}).get("Status"), 40)
        or _bounded(list_item.get("State"), 40),
        "status_text": _bounded(list_item.get("Status"), 300),
        "created_at": _bounded(inspect.get("Created"), 80),
        "started_at": _bounded((state or {}).get("StartedAt"), 80),
        "finished_at": _bounded((state or {}).get("FinishedAt"), 80),
        "pid": (state or {}).get("Pid") if isinstance((state or {}).get("Pid"), int) else None,
        "restart_count": (state or {}).get("RestartCount")
        if isinstance((state or {}).get("RestartCount"), int)
        else None,
        "oom_killed": bool((state or {}).get("OOMKilled", False)),
        "user": _bounded((config or {}).get("User"), 100) or "root",
        "user_is_root": not _bounded((config or {}).get("User"), 100),
        "privileged": bool((host_config or {}).get("Privileged", False)),
        "network_mode": _bounded((host_config or {}).get("NetworkMode"), 100)
        or "default",
        "pid_mode": _bounded((host_config or {}).get("PidMode"), 100) or "",
        "ipc_mode": _bounded((host_config or {}).get("IpcMode"), 100) or "",
        "userns_mode": _bounded((host_config or {}).get("UsernsMode"), 100) or "",
        "cap_add": [cap[:100] for cap in _as_list((host_config or {}).get("CapAdd"))],
        "cap_drop": [cap[:100] for cap in _as_list((host_config or {}).get("CapDrop"))],
        "security_opt": [
            item[:200] for item in _as_list((host_config or {}).get("SecurityOpt"))
        ],
        "read_only_rootfs": bool((host_config or {}).get("ReadonlyRootfs", False)),
        "restart_policy": _bounded(
            ((host_config or {}).get("RestartPolicy") or {}).get("Name")
            if isinstance((host_config or {}).get("RestartPolicy"), dict)
            else "",
            60,
        ),
        "devices": [item[:300] for item in _as_list((host_config or {}).get("Devices"))],
        "mounts": _normalize_mounts(host_config or {}, inspect),
        "ports": _normalize_ports(inspect.get("NetworkSettings")),
        "findings": findings,
        "risk_level": "unknown" if not evaluated else "none",
        "risk_count": 0,
        "evaluated": evaluated,
        "evaluation_error": None,
    }

    if not evaluated:
        missing = [
            key
            for key, value in (
                ("Config", config),
                ("HostConfig", host_config),
                ("State", state),
            )
            if not isinstance(value, dict)
        ]
        result["evaluation_error"] = (
            "Docker details are missing fields: " + ", ".join(missing) + "; cannot produce a risk conclusion"
        )
        return result

    if result["privileged"]:
        _add_finding(
            findings,
            key="CONTAINER-PRIVILEGED",
            rule_id="privileged",
            title=f"Container runs in privileged mode: {result['name']}",
            severity="critical",
            description="A privileged container has all host capabilities and default isolation disabled; gaining control of the container is almost equivalent to host root.",
            evidence={"privileged": True},
        )

    if result["network_mode"] == "host":
        _add_finding(
            findings,
            key="CONTAINER-HOST-NETWORK",
            rule_id="host-network",
            title=f"Container shares the host network: {result['name']}",
            severity="high",
            description="Host network mode makes the container use the host network namespace directly, bypassing port isolation and allowing access to host network services.",
            evidence={"network_mode": result["network_mode"]},
        )
    if result["pid_mode"] == "host":
        _add_finding(
            findings,
            key="CONTAINER-HOST-PID",
            rule_id="host-pid",
            title=f"Container shares the host PID namespace: {result['name']}",
            severity="high",
            description="Host PID mode lets the container see and even affect host processes (depending on capabilities).",
            evidence={"pid_mode": result["pid_mode"]},
        )
    if result["ipc_mode"] == "host":
        _add_finding(
            findings,
            key="CONTAINER-HOST-IPC",
            rule_id="host-ipc",
            title=f"Container shares the host IPC namespace: {result['name']}",
            severity="medium",
            description="Host IPC mode lets the container access host inter-process communication resources.",
            evidence={"ipc_mode": result["ipc_mode"]},
        )
    if result["userns_mode"] == "host":
        _add_finding(
            findings,
            key="CONTAINER-HOST-USERNS",
            rule_id="host-user",
            title=f"Container shares the host user namespace: {result['name']}",
            severity="medium",
            description="The host user namespace weakens UID isolation inside the container.",
            evidence={"userns_mode": result["userns_mode"]},
        )

    for mount in result["mounts"]:
        source = mount["source"]
        destination = mount["destination"]
        if source and _mount_is_socket(source):
            _add_finding(
                findings,
                key=f"CONTAINER-DOCKER-SOCKET:{source}:{destination}",
                rule_id="docker-socket",
                title=f"Container mounts the container runtime socket: {result['name']}",
                severity="critical",
                description="Mounting docker.sock/containerd.sock lets the container control the host container runtime directly; even with a read-only mount, socket read/write semantics are not restricted by file mount options.",
                evidence={
                    "source": source,
                    "destination": destination,
                    "read_only": mount["read_only"],
                },
            )
            continue
        if mount["type"] != "bind" or not source.startswith("/"):
            continue
        matched = _sensitive_severity(source, not mount["read_only"])
        if not matched:
            continue
        severity, root = matched
        _add_finding(
            findings,
            key=f"CONTAINER-SENSITIVE-MOUNT:{source}:{destination}",
            rule_id="sensitive-mount",
            title=f"Container mounts a sensitive host directory: {source}",
            severity=severity,
            description=f"Container mounts host path {source} at {destination} ({'read-write' if not mount['read_only'] else 'read-only'}), which may expose or allow modification of host data.",
            evidence={
                "source": source,
                "destination": destination,
                "read_only": mount["read_only"],
                "matched_root": root,
            },
        )

    caps = [cap.upper().removeprefix("CAP_") for cap in result["cap_add"]]
    risky_caps = [cap for cap in caps if cap in _BROAD_CAPS]
    if risky_caps and not result["privileged"]:
        severity = max_severity([_BROAD_CAPS[cap] for cap in risky_caps])
        _add_finding(
            findings,
            key="CONTAINER-BROAD-CAPABILITIES",
            rule_id="cap-add",
            title=f"Container adds overly broad capabilities: {result['name']}",
            severity=severity,
            description="Explicitly added capabilities expand the range of privileged operations the container can perform.",
            evidence={"cap_add": risky_caps[:MAX_CAPS]},
        )

    security_opts = [opt.lower().replace(" ", "") for opt in result["security_opt"]]
    if any(opt in {"seccomp=unconfined", "seccomp:unconfined"} for opt in security_opts) and not result["privileged"]:
        _add_finding(
            findings,
            key="CONTAINER-SECCOMP-UNCONFINED",
            rule_id="seccomp-unconfined",
            title=f"Container disables seccomp: {result['name']}",
            severity="high",
            description="seccomp=unconfined disables system call filtering and significantly expands the kernel attack surface.",
            evidence={"security_opt": result["security_opt"]},
        )
    if any(opt in {"apparmor=unconfined", "apparmor:unconfined"} for opt in security_opts) and not result["privileged"]:
        _add_finding(
            findings,
            key="CONTAINER-APPARMOR-UNCONFINED",
            rule_id="apparmor-unconfined",
            title=f"Container disables AppArmor: {result['name']}",
            severity="medium",
            description="apparmor=unconfined disables the mandatory access control profile.",
            evidence={"security_opt": result["security_opt"]},
        )
    if any(opt in {"label=disable", "label:disable"} for opt in security_opts):
        _add_finding(
            findings,
            key="CONTAINER-SELINUX-DISABLED",
            rule_id="selinux-disabled",
            title=f"Container disables SELinux labels: {result['name']}",
            severity="medium",
            description="label=disable turns off SELinux label isolation, letting the container bypass host policy.",
            evidence={"security_opt": result["security_opt"]},
        )

    if result["devices"]:
        _add_finding(
            findings,
            key="CONTAINER-HOST-DEVICES",
            rule_id="host-device",
            title=f"Container passes through host devices: {result['name']}",
            severity="high",
            description="Passing through host devices may allow the container to access disks, GPUs or other hardware directly.",
            evidence={"devices": result["devices"][:20]},
        )

    result["risk_level"] = max_severity([item["severity"] for item in findings])
    result["risk_count"] = len(findings)
    return result
