"""Versioned TOML configuration with strict validation.

The configuration file is optional; defaults are safe for the container image.
Unknown keys are rejected so typos never silently weaken the product.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = "/etc/lsec/lsec.toml"
DEFAULT_DATA_DIR = "/data"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ServerConfig:
    bind: str = "127.0.0.1"
    port: int = 8080
    tls_cert: str = ""
    tls_key: str = ""
    session_ttl_hours: int = 12
    allow_insecure_remote: bool = False
    max_body_bytes: int = 1_048_576
    login_attempts_per_minute: int = 10


@dataclass(frozen=True)
class StorageConfig:
    data_dir: str = DEFAULT_DATA_DIR
    evidence_max_mb: int = 512
    quarantine_max_mb: int = 2048
    event_retention_days: int = 90
    event_dedup_window_hours: int = 24


@dataclass(frozen=True)
class ScanConfig:
    allowed_roots: tuple[str, ...] = ("/scan",)
    quick_scan_paths: tuple[str, ...] = ("/tmp", "/var/tmp", "/scan")
    skip_paths: tuple[str, ...] = (
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/var/lib/docker",
        "/var/lib/containerd",
        "/var/lib/clamav",
        "/data",
    )
    max_file_size_mb: int = 200
    file_timeout_seconds: int = 60
    max_parallel_tasks: int = 1
    max_errors_recorded: int = 100


@dataclass(frozen=True)
class ResponseConfig:
    quarantine_roots: tuple[str, ...] = ("/scan", "/tmp", "/var/tmp")
    default_mode: str = "suggest"  # alert | suggest | auto
    auto_quarantine_enabled: bool = False


@dataclass(frozen=True)
class ClamAVConfig:
    socket_path: str = "/run/clamav/clamd.ctl"
    clamd_bin: str = "clamd"
    freshclam_bin: str = "freshclam"
    clamscan_bin: str = "clamscan"
    sigtool_bin: str = "sigtool"
    database_dir: str = "/var/lib/clamav"
    config_path: str = "/data/clamav/clamd.conf"
    socket_timeout_seconds: int = 60
    update_interval_hours: int = 24
    freshclam_enabled: bool = True
    auto_start: bool = False
    startup_update: bool = True


@dataclass(frozen=True)
class AuditConfig:
    lynis_bin: str = "lynis"
    lynis_enabled: bool = True
    lynis_timeout_seconds: int = 300
    stale_after_hours: int = 168
    max_findings: int = 200


@dataclass(frozen=True)
class ContainersConfig:
    """Read-only Docker Engine API inventory.

    ``api_url`` should point at a GET-only read-only proxy, never directly at
    the Docker socket from the Web process. An empty URL disables monitoring.
    """

    enabled: bool = False
    api_url: str = "http://docker-proxy:2375"
    timeout_seconds: int = 8
    refresh_seconds: int = 60
    max_containers: int = 200
    include_stopped: bool = True


@dataclass(frozen=True)
class FalcoConfig:
    binary: str = "falco"
    enabled: bool = True
    ingest_enabled: bool = False
    max_event_bytes: int = 32768


@dataclass(frozen=True)
class YaraConfig:
    """YARA rule scanning and signed rule-pack management.

    Rule packs are never downloaded by the daemon. An administrator places a
    pack in ``inbox_dir`` and explicitly installs it. Signature verification is
    required by default; an unverified pack is never silently activated.
    """

    binary: str = "yara"
    yarac_binary: str = "yarac"
    enabled: bool = True
    rules_dir: str = "/data/yara"
    inbox_dir: str = "/data/yara/inbox"
    public_key: str = "/data/yara/trusted.pem"
    require_signature: bool = True
    max_pack_mb: int = 20
    max_rule_files: int = 200
    scan_batch_files: int = 200
    scan_timeout_seconds: int = 120


@dataclass(frozen=True)
class WazuhConfig:
    """Optional read-only Wazuh Agent status and local alert ingestion."""

    enabled: bool = False
    agent_bin: str = "wazuh-agentd"
    control_bin: str = "wazuh-control"
    install_dir: str = "/var/ossec"
    alerts_path: str = "/var/ossec/logs/alerts/alerts.json"
    ingest_enabled: bool = False
    poll_seconds: int = 30
    max_event_bytes: int = 32768
    max_read_bytes: int = 1048576
    state_dir: str = "/data/wazuh"


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file: str = "/data/logs/lsec.log"
    max_bytes: int = 10_485_760
    backups: int = 5


@dataclass(frozen=True)
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    clamav: ClamAVConfig = field(default_factory=ClamAVConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    containers: ContainersConfig = field(default_factory=ContainersConfig)
    falco: FalcoConfig = field(default_factory=FalcoConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    config_path: str = DEFAULT_CONFIG_PATH
    config_loaded: bool = False

    @property
    def data_dir(self) -> Path:
        return Path(self.storage.data_dir)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "lsec.db"

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def clamav_work_dir(self) -> Path:
        return self.data_dir / "clamav"

    @property
    def falco_token_path(self) -> Path:
        return self.secrets_dir / "falco.token"

    @property
    def yara_dir(self) -> Path:
        return Path(self.yara.rules_dir)

    @property
    def yara_inbox(self) -> Path:
        return Path(self.yara.inbox_dir)

    @property
    def wazuh_state_dir(self) -> Path:
        return Path(self.wazuh.state_dir)

    def with_overrides(
        self,
        *,
        data_dir: str | None = None,
        bind: str | None = None,
        port: int | None = None,
        log_level: str | None = None,
    ) -> "Config":
        cfg = self
        if data_dir:
            cfg = replace(cfg, storage=replace(cfg.storage, data_dir=data_dir))
        if bind:
            cfg = replace(cfg, server=replace(cfg.server, bind=bind))
        if port is not None:
            cfg = replace(cfg, server=replace(cfg.server, port=port))
        if log_level:
            cfg = replace(cfg, logging=replace(cfg.logging, level=log_level.upper()))
        return cfg


_ALLOWED_SECTIONS: dict[str, set[str]] = {
    "server": {
        "bind",
        "port",
        "tls_cert",
        "tls_key",
        "session_ttl_hours",
        "allow_insecure_remote",
        "max_body_bytes",
        "login_attempts_per_minute",
    },
    "storage": {
        "data_dir",
        "evidence_max_mb",
        "quarantine_max_mb",
        "event_retention_days",
        "event_dedup_window_hours",
    },
    "scan": {
        "allowed_roots",
        "quick_scan_paths",
        "skip_paths",
        "max_file_size_mb",
        "file_timeout_seconds",
        "max_parallel_tasks",
        "max_errors_recorded",
    },
    "response": {"quarantine_roots", "default_mode", "auto_quarantine_enabled"},
    "clamav": {
        "socket_path",
        "clamd_bin",
        "freshclam_bin",
        "clamscan_bin",
        "sigtool_bin",
        "database_dir",
        "config_path",
        "socket_timeout_seconds",
        "update_interval_hours",
        "freshclam_enabled",
        "auto_start",
        "startup_update",
    },
    "audit": {
        "lynis_bin",
        "lynis_enabled",
        "lynis_timeout_seconds",
        "stale_after_hours",
        "max_findings",
    },
    "containers": {
        "enabled",
        "api_url",
        "timeout_seconds",
        "refresh_seconds",
        "max_containers",
        "include_stopped",
    },
    "falco": {"binary", "enabled", "ingest_enabled", "max_event_bytes"},
    "yara": {
        "binary",
        "yarac_binary",
        "enabled",
        "rules_dir",
        "inbox_dir",
        "public_key",
        "require_signature",
        "max_pack_mb",
        "max_rule_files",
        "scan_batch_files",
        "scan_timeout_seconds",
    },
    "wazuh": {
        "enabled",
        "agent_bin",
        "control_bin",
        "install_dir",
        "alerts_path",
        "ingest_enabled",
        "poll_seconds",
        "max_event_bytes",
        "max_read_bytes",
        "state_dir",
    },
    "logging": {"level", "file", "max_bytes", "backups"},
}


def _check_type(section: str, key: str, value: Any, expected: type) -> None:
    if expected is int and (isinstance(value, bool) or not isinstance(value, int)):
        raise ConfigError(f"[{section}].{key} must be an integer")
    if expected is bool and not isinstance(value, bool):
        raise ConfigError(f"[{section}].{key} must be a boolean")
    if expected is str and not isinstance(value, str):
        raise ConfigError(f"[{section}].{key} must be a string")
    if expected is list and not isinstance(value, list):
        raise ConfigError(f"[{section}].{key} must be an array")


def _str_tuple(section: str, key: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) and not isinstance(value, list):
        raise ConfigError(f"[{section}].{key} must be a string array")
    items = [value] if isinstance(value, str) else value
    if not items or not all(isinstance(item, str) and item for item in items):
        raise ConfigError(f"[{section}].{key} must not be empty and may only contain strings")
    for item in items:
        if not item.startswith("/"):
            raise ConfigError(f"[{section}].{key} paths must be absolute: {item}")
    return tuple(items)


def load_config(path: str | None = None) -> Config:
    """Load and validate configuration. Missing file means defaults."""
    config_path = path or os.environ.get("LSEC_CONFIG", DEFAULT_CONFIG_PATH)
    raw: dict[str, Any] = {}
    loaded = False
    p = Path(config_path)
    if p.exists():
        try:
            with p.open("rb") as fh:
                raw = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read configuration {config_path}: {exc}") from exc
        loaded = True

    for section, values in raw.items():
        if section not in _ALLOWED_SECTIONS:
            raise ConfigError(f"unknown configuration section: [{section}]")
        if not isinstance(values, dict):
            raise ConfigError(f"[{section}] must be a table")
        for key in values:
            if key not in _ALLOWED_SECTIONS[section]:
                raise ConfigError(f"unknown configuration key: [{section}].{key}")

    server = ServerConfig(**raw.get("server", {}))
    storage = StorageConfig(**raw.get("storage", {}))
    scan_raw = dict(raw.get("scan", {}))
    for key in ("allowed_roots", "quick_scan_paths", "skip_paths"):
        if key in scan_raw:
            scan_raw[key] = _str_tuple("scan", key, scan_raw[key])
    scan = ScanConfig(**scan_raw)
    response_raw = dict(raw.get("response", {}))
    if "quarantine_roots" in response_raw:
        response_raw["quarantine_roots"] = _str_tuple(
            "response", "quarantine_roots", response_raw["quarantine_roots"]
        )
    response = ResponseConfig(**response_raw)
    clamav = ClamAVConfig(**raw.get("clamav", {}))
    audit = AuditConfig(**raw.get("audit", {}))
    containers = ContainersConfig(**raw.get("containers", {}))
    falco = FalcoConfig(**raw.get("falco", {}))
    yara = YaraConfig(**raw.get("yara", {}))
    wazuh = WazuhConfig(**raw.get("wazuh", {}))
    logging_cfg = LoggingConfig(**raw.get("logging", {}))

    # Type checks (dataclasses do not enforce them).
    for name, value, typ in (
        ("server.bind", server.bind, str),
        ("server.port", server.port, int),
        ("server.session_ttl_hours", server.session_ttl_hours, int),
        ("server.allow_insecure_remote", server.allow_insecure_remote, bool),
        ("storage.evidence_max_mb", storage.evidence_max_mb, int),
        ("storage.quarantine_max_mb", storage.quarantine_max_mb, int),
        ("scan.max_file_size_mb", scan.max_file_size_mb, int),
        ("scan.file_timeout_seconds", scan.file_timeout_seconds, int),
        ("scan.max_parallel_tasks", scan.max_parallel_tasks, int),
        ("response.default_mode", response.default_mode, str),
        ("response.auto_quarantine_enabled", response.auto_quarantine_enabled, bool),
        ("clamav.update_interval_hours", clamav.update_interval_hours, int),
        ("clamav.freshclam_enabled", clamav.freshclam_enabled, bool),
        ("audit.lynis_bin", audit.lynis_bin, str),
        ("audit.lynis_enabled", audit.lynis_enabled, bool),
        ("audit.lynis_timeout_seconds", audit.lynis_timeout_seconds, int),
        ("audit.stale_after_hours", audit.stale_after_hours, int),
        ("audit.max_findings", audit.max_findings, int),
        ("containers.enabled", containers.enabled, bool),
        ("containers.api_url", containers.api_url, str),
        ("containers.timeout_seconds", containers.timeout_seconds, int),
        ("containers.refresh_seconds", containers.refresh_seconds, int),
        ("containers.max_containers", containers.max_containers, int),
        ("containers.include_stopped", containers.include_stopped, bool),
        ("falco.binary", falco.binary, str),
        ("falco.enabled", falco.enabled, bool),
        ("falco.ingest_enabled", falco.ingest_enabled, bool),
        ("falco.max_event_bytes", falco.max_event_bytes, int),
        ("yara.binary", yara.binary, str),
        ("yara.yarac_binary", yara.yarac_binary, str),
        ("yara.enabled", yara.enabled, bool),
        ("yara.rules_dir", yara.rules_dir, str),
        ("yara.inbox_dir", yara.inbox_dir, str),
        ("yara.public_key", yara.public_key, str),
        ("yara.require_signature", yara.require_signature, bool),
        ("yara.max_pack_mb", yara.max_pack_mb, int),
        ("yara.max_rule_files", yara.max_rule_files, int),
        ("yara.scan_batch_files", yara.scan_batch_files, int),
        ("yara.scan_timeout_seconds", yara.scan_timeout_seconds, int),
        ("wazuh.enabled", wazuh.enabled, bool),
        ("wazuh.agent_bin", wazuh.agent_bin, str),
        ("wazuh.control_bin", wazuh.control_bin, str),
        ("wazuh.install_dir", wazuh.install_dir, str),
        ("wazuh.alerts_path", wazuh.alerts_path, str),
        ("wazuh.ingest_enabled", wazuh.ingest_enabled, bool),
        ("wazuh.poll_seconds", wazuh.poll_seconds, int),
        ("wazuh.max_event_bytes", wazuh.max_event_bytes, int),
        ("wazuh.max_read_bytes", wazuh.max_read_bytes, int),
        ("wazuh.state_dir", wazuh.state_dir, str),
        ("logging.level", logging_cfg.level, str),
    ):
        section, key = name.split(".", 1)
        table = {
            "server": server,
            "storage": storage,
            "scan": scan,
            "response": response,
            "clamav": clamav,
            "audit": audit,
            "containers": containers,
            "falco": falco,
            "yara": yara,
            "wazuh": wazuh,
            "logging": logging_cfg,
        }[section]
        _check_type(section, key, getattr(table, key), typ)

    if not 1 <= server.port <= 65535:
        raise ConfigError("server.port must be between 1 and 65535")
    if not 1 <= scan.max_parallel_tasks <= 4:
        raise ConfigError("scan.max_parallel_tasks must be between 1 and 4")
    if not 10 <= audit.lynis_timeout_seconds <= 1800:
        raise ConfigError("audit.lynis_timeout_seconds must be between 10 and 1800")
    if not 1 <= audit.stale_after_hours <= 8760:
        raise ConfigError("audit.stale_after_hours must be between 1 and 8760")
    if not 1 <= audit.max_findings <= 500:
        raise ConfigError("audit.max_findings must be between 1 and 500")
    if containers.enabled:
        if not containers.api_url:
            raise ConfigError("containers.api_url is required when containers.enabled is true")
        if not (
            containers.api_url.startswith("unix://")
            or containers.api_url.startswith("http://")
        ):
            raise ConfigError("containers.api_url supports only unix:// or http:// addresses")
        if containers.api_url.startswith("unix://") and not containers.api_url[len("unix://"):].startswith("/"):
            raise ConfigError("the Unix socket path in containers.api_url must be absolute")
        if containers.api_url.startswith("http://"):
            from urllib.parse import urlsplit

            parsed = urlsplit(containers.api_url)
            if not parsed.hostname or parsed.username or parsed.password or parsed.query:
                raise ConfigError("invalid HTTP address in containers.api_url")
    if not 2 <= containers.timeout_seconds <= 30:
        raise ConfigError("containers.timeout_seconds must be between 2 and 30")
    if not 15 <= containers.refresh_seconds <= 3600:
        raise ConfigError("containers.refresh_seconds must be between 15 and 3600")
    if not 1 <= containers.max_containers <= 1000:
        raise ConfigError("containers.max_containers must be between 1 and 1000")
    if not 4096 <= falco.max_event_bytes <= 262144:
        raise ConfigError("falco.max_event_bytes must be between 4096 and 262144")
    if not 1 <= yara.max_pack_mb <= 200:
        raise ConfigError("yara.max_pack_mb must be between 1 and 200")
    if not 1 <= yara.max_rule_files <= 1000:
        raise ConfigError("yara.max_rule_files must be between 1 and 1000")
    if not 1 <= yara.scan_batch_files <= 500:
        raise ConfigError("yara.scan_batch_files must be between 1 and 500")
    if not 10 <= yara.scan_timeout_seconds <= 1800:
        raise ConfigError("yara.scan_timeout_seconds must be between 10 and 1800")
    for name in ("rules_dir", "inbox_dir"):
        if not str(getattr(yara, name)).startswith("/"):
            raise ConfigError(f"yara.{name} must be an absolute path")
    if yara.public_key and not yara.public_key.startswith("/"):
        raise ConfigError("yara.public_key must be empty or an absolute path")
    yara_root = os.path.normpath(yara.rules_dir)
    inbox = os.path.normpath(yara.inbox_dir)
    if os.path.commonpath([yara_root, inbox]) != yara_root:
        raise ConfigError("yara.inbox_dir must be inside yara.rules_dir")
    if not 5 <= wazuh.poll_seconds <= 3600:
        raise ConfigError("wazuh.poll_seconds must be between 5 and 3600")
    if not 4096 <= wazuh.max_event_bytes <= 262144:
        raise ConfigError("wazuh.max_event_bytes must be between 4096 and 262144")
    if not 65536 <= wazuh.max_read_bytes <= 16 * 1024 * 1024:
        raise ConfigError("wazuh.max_read_bytes must be between 65536 and 16777216")
    for name in ("install_dir", "alerts_path", "state_dir"):
        if not str(getattr(wazuh, name)).startswith("/"):
            raise ConfigError(f"wazuh.{name} must be an absolute path")
    if wazuh.ingest_enabled and not wazuh.enabled:
        raise ConfigError("wazuh.enabled must also be enabled when wazuh.ingest_enabled is true")
    if response.default_mode not in {"alert", "suggest", "auto"}:
        raise ConfigError("response.default_mode must be one of alert/suggest/auto")
    if bool(server.tls_cert) != bool(server.tls_key):
        raise ConfigError("server.tls_cert and server.tls_key must be configured together")
    if not storage.data_dir.startswith("/"):
        raise ConfigError("storage.data_dir must be an absolute path")

    cfg = Config(
        server=server,
        storage=storage,
        scan=scan,
        response=response,
        clamav=clamav,
        audit=audit,
        containers=containers,
        falco=falco,
        yara=yara,
        wazuh=wazuh,
        logging=logging_cfg,
        config_path=config_path,
        config_loaded=loaded,
    )

    # Environment overrides (container-friendly).
    cfg = cfg.with_overrides(
        data_dir=os.environ.get("LSEC_DATA_DIR") or None,
        bind=os.environ.get("LSEC_BIND") or None,
        port=int(os.environ["LSEC_PORT"]) if os.environ.get("LSEC_PORT") else None,
        log_level=os.environ.get("LSEC_LOG_LEVEL") or None,
    )
    if os.environ.get("LSEC_ALLOW_INSECURE_REMOTE", "").lower() in {"1", "true", "yes"}:
        cfg = replace(
            cfg, server=replace(cfg.server, allow_insecure_remote=True)
        )
    if os.environ.get("LSEC_CONTAINERS_ENABLED", "").lower() in {"1", "true", "yes"}:
        cfg = replace(cfg, containers=replace(cfg.containers, enabled=True))
    if os.environ.get("LSEC_CONTAINERS_API_URL"):
        cfg = replace(
            cfg,
            containers=replace(
                cfg.containers, api_url=os.environ["LSEC_CONTAINERS_API_URL"]
            ),
        )
    if os.environ.get("LSEC_FALCO_INGEST_ENABLED", "").lower() in {"1", "true", "yes"}:
        cfg = replace(cfg, falco=replace(cfg.falco, ingest_enabled=True))
    if os.environ.get("LSEC_YARA_ENABLED", "").lower() in {"1", "true", "yes"}:
        cfg = replace(cfg, yara=replace(cfg.yara, enabled=True))
    elif os.environ.get("LSEC_YARA_ENABLED", "").lower() in {"0", "false", "no"}:
        cfg = replace(cfg, yara=replace(cfg.yara, enabled=False))
    if os.environ.get("LSEC_YARA_PUBLIC_KEY"):
        cfg = replace(
            cfg, yara=replace(cfg.yara, public_key=os.environ["LSEC_YARA_PUBLIC_KEY"])
        )
    if os.environ.get("LSEC_YARA_REQUIRE_SIGNATURE", "").lower() in {"0", "false", "no"}:
        cfg = replace(cfg, yara=replace(cfg.yara, require_signature=False))
    if os.environ.get("LSEC_WAZUH_ENABLED", "").lower() in {"1", "true", "yes"}:
        cfg = replace(cfg, wazuh=replace(cfg.wazuh, enabled=True))
    if os.environ.get("LSEC_WAZUH_INGEST_ENABLED", "").lower() in {"1", "true", "yes"}:
        cfg = replace(
            cfg, wazuh=replace(cfg.wazuh, enabled=True, ingest_enabled=True)
        )
    if os.environ.get("LSEC_WAZUH_ALERTS_PATH"):
        cfg = replace(
            cfg, wazuh=replace(cfg.wazuh, alerts_path=os.environ["LSEC_WAZUH_ALERTS_PATH"])
        )
    return cfg


def is_loopback(bind: str) -> bool:
    return bind in {"127.0.0.1", "::1", "localhost"}
