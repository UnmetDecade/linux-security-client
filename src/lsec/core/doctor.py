"""``lsec doctor`` style environment self-check."""

from __future__ import annotations

import os
import shutil
import stat
from typing import Any

from ..common.config import Config, is_loopback
from ..common.hostinfo import host_info
from ..common.timeutil import now_iso
from ..storage import components as component_store
from ..storage.db import Database
from .components import ComponentManager


def _check(
    check_id: str, title: str, status: str, detail: str, remediation: str | None = None
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "detail": detail,
        "remediation": remediation,
    }


def _mode(path: str) -> int | None:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


class DoctorService:
    def __init__(
        self,
        db: Database,
        config: Config,
        components: ComponentManager,
        containers: Any | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.components = components
        self.containers = containers

    def run(self, *, probe_components: bool = True) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        checks.append(
            _check(
                "config",
                "Configuration file",
                "ok" if self.config.config_loaded else "info",
                f"loaded {self.config.config_path}"
                if self.config.config_loaded
                else f"{self.config.config_path} not found; using the built-in default configuration",
            )
        )

        data_mode = _mode(str(self.config.data_dir))
        if data_mode is None:
            checks.append(
                _check("data_dir", "Data directory", "fail", "the data directory is not accessible", "check mounts and permissions")
            )
        elif data_mode & 0o007:
            checks.append(
                _check(
                    "data_dir",
                    "Data directory permissions",
                    "warn",
                    f"data directory permissions are {oct(data_mode)}; other users can access it",
                    "tighten data directory permissions to 0700/0750",
                )
            )
        else:
            checks.append(
                _check("data_dir", "Data directory permissions", "ok", f"permissions {oct(data_mode)}")
            )

        secrets = self.config.secrets_dir
        secret_files = list(secrets.glob("*.token")) if secrets.exists() else []
        if not secret_files:
            checks.append(
                _check("secrets", "Access tokens", "warn", "no token files found", "restart the daemon to generate tokens")
            )
        else:
            bad = []
            for path in secret_files:
                mode = _mode(str(path))
                if mode is None or mode & 0o077:
                    bad.append(f"{path.name}={oct(mode) if mode is not None else '?'}")
            checks.append(
                _check(
                    "secrets",
                    "Access token permissions",
                    "fail" if bad else "ok",
                    "the following tokens have overly broad permissions: " + ", ".join(bad) if bad else "token files are readable only by their owner",
                    "chmod 600 <data dir>/secrets/*.token" if bad else None,
                )
            )

        ok, detail = self.db.integrity_check()
        checks.append(
            _check(
                "database",
                "SQLite integrity",
                "ok" if ok else "fail",
                detail,
                "restore the database from a backup" if not ok else None,
            )
        )
        try:
            usage = shutil.disk_usage(str(self.config.data_dir))
            free_gb = usage.free / (1024**3)
            checks.append(
                _check(
                    "disk",
                    "Disk space",
                    "warn" if free_gb < 1 else "ok",
                    f"data partition has {free_gb:.1f} GB free",
                    "clean up the evidence store, quarantine or logs" if free_gb < 1 else None,
                )
            )
        except OSError as exc:
            checks.append(_check("disk", "Disk space", "warn", f"cannot read disk space: {exc}"))

        if probe_components:
            try:
                self.components.probe_all()
            except Exception as exc:  # pragma: no cover
                checks.append(_check("components", "Component probing", "fail", f"probe failed: {exc}"))
        clamav = component_store.get_component(self.db, "clamav")
        if not clamav:
            checks.append(_check("clamav", "ClamAV", "warn", "no ClamAV status record"))
        elif not clamav["installed"]:
            checks.append(
                _check(
                    "clamav",
                    "ClamAV installation",
                    "fail",
                    "ClamAV is not installed; virus scanning is unavailable",
                    "redeploy with the official image that includes ClamAV",
                )
            )
        elif clamav["service_status"] != "running":
            checks.append(
                _check(
                    "clamav",
                    "ClamAV service",
                    "fail",
                    "clamd is not running",
                    "start ClamAV in component management, or check the clamd logs",
                )
            )
        else:
            db_info = (clamav.get("details") or {}).get("database", {})
            if not db_info.get("present"):
                checks.append(
                    _check(
                        "clamav_db",
                        "Virus database",
                        "fail",
                        "no virus database file found",
                        "run a virus database update (freshclam)",
                    )
                )
            else:
                health = "ok" if clamav["health_status"] == "ok" else "warn"
                checks.append(
                    _check(
                        "clamav_db",
                        "Virus database",
                        health,
                        clamav.get("error_message")
                        or f"updated at {db_info.get('updated_at')}, about {db_info.get('age_hours')} hours ago",
                        "run a virus database update" if health != "ok" else None,
                    )
                )

        if not self.config.yara.enabled:
            checks.append(
                _check(
                    "yara",
                    "YARA rule scanning",
                    "info",
                    "disabled in the configuration",
                )
            )
        else:
            yara = component_store.get_component(self.db, "yara")
            if not yara or not yara.get("installed"):
                checks.append(
                    _check(
                        "yara",
                        "YARA installation",
                        "fail",
                        "YARA is not installed; rule scanning is unavailable",
                        "install yara and openssl from the distribution's official repositories",
                    )
                )
            else:
                details = yara.get("details") or {}
                active_count = int(details.get("active_count") or 0)
                signature = details.get("signature") or {}
                notes: list[str] = []
                if active_count <= 0:
                    status = "warn"
                    notes.append("no active rule packs; rule scanning is unavailable")
                elif yara.get("health_status") == "ok":
                    status = "ok"
                    notes.append(f"{active_count} rule packs active")
                else:
                    status = "warn"
                    notes.append(
                        yara.get("error_message") or "YARA health status is abnormal"
                    )
                if self.config.yara.require_signature and not signature.get(
                    "public_key_present"
                ):
                    if status == "ok":
                        status = "warn"
                    notes.append("signature enforcement is enabled but the trusted public key is missing; new rule packs cannot be installed")
                checks.append(
                    _check(
                        "yara",
                        "YARA rule scanning",
                        status,
                        "; ".join(notes)[:300],
                        "install and activate a signature-verified rule pack"
                        if status != "ok"
                        else None,
                    )
                )

        if not self.config.wazuh.enabled:
            checks.append(
                _check(
                    "wazuh",
                    "Wazuh Agent (optional)",
                    "info",
                    "not enabled; this client does not claim Wazuh manager capability",
                )
            )
        else:
            wazuh = component_store.get_component(self.db, "wazuh")
            if not wazuh or not wazuh.get("installed"):
                checks.append(
                    _check(
                        "wazuh",
                        "Wazuh Agent (optional)",
                        "warn",
                        "Wazuh integration is enabled, but no local Agent was detected; "
                        "no Agent/Manager means no Wazuh events are provided",
                        "install and register a Wazuh Agent, or disable wazuh.enabled",
                    )
                )
            else:
                checks.append(
                    _check(
                        "wazuh",
                        "Wazuh Agent (optional)",
                        "warn" if wazuh.get("health_status") != "ok" else "ok",
                        (wazuh.get("error_message") or wazuh.get("health_status") or "unknown")[
                            :300
                        ],
                    )
                )

        if not is_loopback(self.config.server.bind) and not (
            self.config.server.tls_cert and self.config.server.tls_key
        ):
            checks.append(
                _check(
                    "tls",
                    "Remote access encryption",
                    "fail" if not self.config.server.allow_insecure_remote else "warn",
                    "the service is bound to a non-loopback address and TLS is not enabled",
                    "enable TLS or bind to 127.0.0.1 behind a reverse proxy",
                )
            )
        else:
            checks.append(
                _check(
                    "tls",
                    "Listening address",
                    "ok",
                    f"listening on {self.config.server.bind}:{self.config.server.port}"
                    + (", TLS enabled" if self.config.server.tls_cert else ""),
                )
            )

        info = host_info()
        checks.append(
            _check(
                "runtime",
                "Runtime environment",
                "info",
                f"kernel {info['kernel']}, containerized: {info['container']['containerized']}, "
                f"container runtime: {info['container']['runtime'] or 'unknown'}",
            )
        )

        if not self.config.containers.enabled:
            checks.append(
                _check(
                    "containers",
                    "Container monitoring",
                    "info",
                    "not enabled; the Docker Socket is not mounted into the Web process by default. "
                    "When enabling, use a read-only Docker API proxy",
                )
            )
        elif self.containers:
            snapshot = self.containers.snapshot()
            state = snapshot.get("state")
            if state in {"monitored", "degraded"}:
                summary = snapshot.get("summary") or {}
                checks.append(
                    _check(
                        "containers",
                        "Container monitoring",
                        "warn" if state == "degraded" else "ok",
                        f"{snapshot.get('note') or state}; "
                        f"containers {summary.get('total', 0)}, "
                        f"risks {summary.get('risky', 0)}",
                        "check the Docker API proxy and container detail read permissions"
                        if state == "degraded"
                        else None,
                    )
                )
            else:
                checks.append(
                    _check(
                        "containers",
                        "Container monitoring",
                        "warn" if state == "initializing" else "fail",
                        snapshot.get("note") or f"state {state}",
                        "check the Docker API proxy, network connectivity and socket permissions",
                    )
                )

        falco = component_store.get_component(self.db, "falco")
        if falco:
            checks.append(
                _check(
                    "falco",
                    "Falco runtime detection",
                    "info"
                    if falco.get("error_code") == "not_installed"
                    else "warn"
                    if falco.get("health_status") != "ok"
                    else "ok",
                    (falco.get("error_message") or falco.get("health_status") or "unknown")[:300],
                    "view the Falco install plan; if the kernel/eBPF is unsupported, the UI says so explicitly"
                    if falco.get("error_code") not in {"integration_pending"}
                    else None,
                )
            )

        summary = {"ok": 0, "warn": 0, "fail": 0, "info": 0}
        for check in checks:
            summary[check["status"]] = summary.get(check["status"], 0) + 1
        return {
            "checks": checks,
            "summary": {**summary, "total": len(checks)},
            "generated_at": now_iso(),
        }
