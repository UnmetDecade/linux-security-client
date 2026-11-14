"""Security daemon entry point (``python -m lsec.daemon``)."""

from __future__ import annotations

import argparse
import fcntl
import os
import signal
import sys
import threading
from pathlib import Path

from . import __version__
from .adapters.clamav import ClamAVAdapter
from .adapters.falco import FalcoAdapter
from .adapters.lynis import LynisAdapter
from .adapters.misc import default_adapters
from .adapters.wazuh import WazuhAdapter
from .adapters.yara import YaraAdapter
from .api.auth import AuthService, ensure_falco_token, ensure_tokens
from .api.server import Application, create_server
from .common.config import Config, ConfigError, is_loopback, load_config
from .common.hostinfo import host_info
from .common.logging import get_logger, setup_logging
from .common.paths import ensure_dir
from .core.audit import AuditService
from .core.components import ComponentManager
from .core.containers import ContainerService
from .core.doctor import DoctorService
from .core.events import EventService
from .core.evidence import EvidenceStore
from .core.maintenance import MaintenanceService
from .core.quarantine import QuarantineService
from .core.scans import ScanManager
from .core.status import StatusService
from .core.updates import UpdateManager
from .core.wazuh import WazuhAlertIngester
from .core.yara import YaraRulePackService
from .storage import settings as settings_store
from .storage.db import Database

log = get_logger("daemon")


class SingleInstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.fsync(fd)
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="lsec-daemon", description="Linux unified security client daemon")
    parser.add_argument("--config", default=os.environ.get("LSEC_CONFIG"), help="path to the TOML configuration file")
    parser.add_argument("--data-dir", help="data directory (overrides the configuration)")
    parser.add_argument("--bind", help="listen address (overrides the configuration)")
    parser.add_argument("--port", type=int, help="listen port (overrides the configuration)")
    parser.add_argument("--log-level", help="log level")
    parser.add_argument("--version", action="version", version=f"lsec {__version__}")
    return parser.parse_args(argv)


def _prepare_directories(config: Config) -> None:
    ensure_dir(config.data_dir, 0o750)
    ensure_dir(config.secrets_dir, 0o700)
    ensure_dir(config.evidence_dir, 0o700)
    ensure_dir(config.quarantine_dir, 0o700)
    ensure_dir(config.logs_dir, 0o750)
    ensure_dir(config.clamav_work_dir, 0o750)
    for directory in (config.evidence_dir, config.quarantine_dir, config.secrets_dir):
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass


def build_app(config: Config) -> tuple[Application, dict[str, object]]:
    db = Database(config.db_path)
    db.initialize()

    settings_store.ensure_defaults(
        db,
        {
            "response_mode": config.response.default_mode
            if config.response.default_mode in {"alert", "suggest"}
            else "suggest",
            "auto_quarantine_enabled": False,
            "scheduled_scan": {
                "enabled": False,
                "type": "quick",
                "interval_hours": 24,
                "last_run_at": None,
            },
        },
    )

    tokens = ensure_tokens(config.secrets_dir)
    falco_token = ensure_falco_token(
        config.secrets_dir, config.falco.ingest_enabled
    )
    auth = AuthService(
        db,
        tokens,
        config.server.session_ttl_hours,
        falco_token=falco_token,
    )

    clamav = ClamAVAdapter(config.clamav, config.scan, config.data_dir)
    lynis = LynisAdapter(config.audit.lynis_bin, enabled=config.audit.lynis_enabled)
    falco = FalcoAdapter(
        config.falco.binary,
        enabled=config.falco.enabled,
        ingest_enabled=config.falco.ingest_enabled,
    )
    yara_rules = YaraRulePackService(config.yara)
    yara = YaraAdapter(config.yara, config.scan, yara_rules)
    wazuh = WazuhAdapter(config.wazuh)
    adapters = [
        clamav,
        *default_adapters(
            lynis,
            containers_config=config.containers,
            falco_adapter=falco,
            yara_adapter=yara,
            wazuh_adapter=wazuh,
        ),
    ]
    components = ComponentManager(db, adapters)
    events = EventService(
        db,
        host_provider=host_info,
        dedup_window_hours=config.storage.event_dedup_window_hours,
    )
    evidence = EvidenceStore(config.evidence_dir, config.storage.evidence_max_mb)
    quarantine = QuarantineService(db, config)
    audits = AuditService(db, config, events, evidence, lynis)
    containers = ContainerService(config.containers, events)
    status = StatusService(db, config, events, audits, containers)
    doctor = DoctorService(db, config, components, containers)
    updates = UpdateManager(db, config, components)
    scans = ScanManager(db, config, components, events, evidence)
    wazuh_ingest = WazuhAlertIngester(config.wazuh, events)

    return Application(
        config=config,
        db=db,
        auth=auth,
        components=components,
        events=events,
        scans=scans,
        quarantine=quarantine,
        audits=audits,
        containers=containers,
        status=status,
        doctor=doctor,
        updates=updates,
        yara=yara_rules,
        wazuh=wazuh,
        wazuh_ingest=wazuh_ingest,
    ), {
        "db": db,
        "components": components,
        "events": events,
        "evidence": evidence,
        "scans": scans,
        "audits": audits,
        "updates": updates,
        "containers": containers,
        "maintenance": MaintenanceService(db, config, events, evidence),
        "clamav": clamav,
        "lynis": lynis,
        "falco": falco,
        "yara": yara,
        "yara_rules": yara_rules,
        "wazuh": wazuh,
        "wazuh_ingest": wazuh_ingest,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config = load_config(args.config)
        config = config.with_overrides(
            data_dir=args.data_dir,
            bind=args.bind,
            port=args.port,
            log_level=args.log_level,
        )
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    if (
        not is_loopback(config.server.bind)
        and not config.server.tls_cert
        and not config.server.allow_insecure_remote
    ):
        print(
            "refusing to start: bound to a non-loopback address but TLS is not enabled. "
            "Configure server.tls_cert/tls_key, or set LSEC_ALLOW_INSECURE_REMOTE=1 (not recommended).",
            file=sys.stderr,
        )
        return 2

    _prepare_directories(config)
    setup_logging(
        config.logging.level,
        config.logging.file,
        config.logging.max_bytes,
        config.logging.backups,
    )

    lock = SingleInstanceLock(config.data_dir / "daemon.lock")
    if not lock.acquire():
        print("another lsec daemon is already running (daemon.lock is held)", file=sys.stderr)
        return 3

    try:
        app, services = build_app(config)
    except Exception as exc:
        log.exception("initialization failed")
        print(f"initialization failed: {exc}", file=sys.stderr)
        lock.release()
        return 1

    components = services["components"]
    try:
        components.probe_all()
    except Exception:
        log.exception("component probe failed at startup")

    scans: ScanManager = services["scans"]
    audits: AuditService = services["audits"]
    containers: ContainerService = services["containers"]
    updates: UpdateManager = services["updates"]
    maintenance: MaintenanceService = services["maintenance"]
    wazuh_ingest: WazuhAlertIngester = services["wazuh_ingest"]
    clamav = services["clamav"]

    scans.start()
    audits.start()
    containers.start()
    updates.start()
    maintenance.start()
    wazuh_ingest.start()

    def _auto_start() -> None:
        if not config.clamav.auto_start:
            return
        try:
            clamav.start()
            log.info("ClamAV started automatically per configuration")
        except Exception as exc:
            log.warning("ClamAV automatic start failed: %s", exc)
        try:
            components.probe("clamav")
        except Exception:
            pass

    threading.Thread(target=_auto_start, name="clamav-autostart", daemon=True).start()

    server = create_server(app)
    scheme = "https" if config.server.tls_cert else "http"
    log.info(
        "lsec daemon started version=%s bind=%s port=%s data_dir=%s",
        __version__,
        config.server.bind,
        config.server.port,
        config.data_dir,
    )
    log.info("Web management UI: %s://%s:%s/", scheme, config.server.bind, config.server.port)
    log.info(
        "access token files: %s (do not share tokens through chat or logs)",
        config.secrets_dir,
    )

    def _handle_signal(signum: int, _frame: object) -> None:
        log.info("received signal %s; preparing to stop", signum)
        threading.Thread(target=server.shutdown, name="shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        server.serve_forever(poll_interval=0.5)
    except Exception:
        log.exception("HTTP server exited unexpectedly")
    finally:
        log.info("stopping background services")
        scans.stop()
        audits.stop()
        containers.stop()
        updates.stop()
        maintenance.stop()
        wazuh_ingest.stop()
        server.server_close()
        lock.release()
        log.info("daemon stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
