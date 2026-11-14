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
    "Container inventory comes from the Docker Engine API; only the container runtime connected to that API is visible. "
    "Containerd is currently only probed for installation and socket presence; container inventory is not collected."
)
LIMITATIONS = [
    "Container monitoring reads through a read-only Docker API proxy; the Web process does not mount the Docker Socket directly.",
    "Only running containers generate configuration risk events; configuration of stopped containers is still shown in the inventory.",
    "This client never stops, restarts, deletes or modifies any container automatically.",
    "Configuration checks are heuristic rules and are not equivalent to vulnerability scanning or runtime behavior detection.",
    "Falco events are written to the unified event center through a separate integration token; when Falco is not installed, runtime alerts are never fabricated.",
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
            "container monitoring is not enabled"
            if not config.enabled
            else "initial container inventory has not been collected yet",
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
            raise not_found("container monitoring is not enabled; there is no container inventory")
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
            raise conflict("container ID prefix is not unique; provide a longer ID")
        raise not_found("container not found")

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
                log.exception("container monitoring refresh error")
            if self._stop.wait(max(15, self.config.refresh_seconds)):
                break

    # --------------------------------------------------------------- refresh
    def refresh(self) -> dict[str, Any]:
        if not self.config.enabled:
            with self._lock:
                self._snapshot = self._empty_snapshot(
                    "disabled", "container monitoring is not enabled"
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
                    note += f"; details for {len(inspect_errors)} containers could not be read, so risk conclusions are incomplete"
                if truncated:
                    state = "degraded"
                    note += (
                        f"; container count exceeds the limit of {self.config.max_containers}; the inventory was truncated"
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
                    "container inventory refresh complete total=%s running=%s risky=%s state=%s",
                    summary["total"],
                    summary["running"],
                    summary["risky"],
                    state,
                )
                return self.snapshot()
            except DockerApiError as exc:
                return self._record_failure(previous, exc.code, exc.message)
            except Exception as exc:  # a broken monitor must not crash the daemon
                log.exception("container monitoring failed")
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
                    f"container monitoring failed: {message}"
                    + ("; the data below is from the last successful collection and is marked stale" if has_old else "")
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
        log.warning("container monitoring unavailable state=%s code=%s error=%s", state, code, message)
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
                        "evaluation_error": f"failed to read container details: {exc.message[:300]}",
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
            f"read {summary['total']} containers, {summary['running']} running; "
            f"{summary['risky']} have configuration risks"
        )
        if summary["unknown"]:
            note += f", {summary['unknown']} could not be evaluated"
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
                        title=str(finding.get("title") or "container configuration risk"),
                        description=(
                            f"Container {container.get('name')} (image {container.get('image')}, "
                            f"state {container.get('state')}) has a configuration risk: "
                            f"{finding.get('description')} "
                            "This client will not stop or modify the container automatically."
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
                            str(finding.get("recommendation") or "verify the container configuration"),
                            "do not stop production containers before confirming the impact",
                            "keep the container and image information as remediation evidence",
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
                        "failed to write container risk event container=%s rule=%s",
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
