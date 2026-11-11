"""Virus signature update scheduling for ClamAV (freshclam)."""

from __future__ import annotations

import threading
import time
from typing import Any

from ..common.config import Config
from ..common.errors import LsecError, conflict
from ..common.logging import get_logger
from ..storage import audit as audit_store
from ..storage import components as component_store
from ..storage.db import Database
from .components import ComponentManager

log = get_logger("core.updates")


class UpdateManager:
    def __init__(self, db: Database, config: Config, components: ComponentManager) -> None:
        self.db = db
        self.config = config
        self.components = components
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="update-manager", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _loop(self) -> None:
        if self.config.clamav.startup_update:
            # Give the API and component probes a moment to settle.
            if self._stop.wait(timeout=15):
                return
            self._maybe_update()
        while not self._stop.wait(timeout=1800):
            self._maybe_update()

    def _due(self) -> bool:
        probe = component_store.get_component(self.db, "clamav")
        if not probe or not probe.get("installed"):
            return False
        database = (probe.get("details") or {}).get("database") or {}
        if not database.get("present"):
            return True
        age = database.get("age_hours")
        if age is None:
            return True
        return age >= max(1, self.config.clamav.update_interval_hours)

    def _maybe_update(self) -> None:
        if not self.config.clamav.freshclam_enabled:
            return
        try:
            self.components.probe("clamav")
        except Exception:
            log.exception("更新前探测 ClamAV 失败")
        if not self._due():
            return
        try:
            self.run_update(actor="system", request_id=None, client=None)
        except LsecError as exc:
            log.warning("自动更新病毒库失败: %s", exc.message)
        except Exception:
            log.exception("自动更新病毒库异常")

    def run_update(
        self, *, actor: str, request_id: str | None, client: str | None
    ) -> dict[str, Any]:
        if not self.config.clamav.freshclam_enabled:
            raise conflict("病毒库自动更新已禁用")
        if not self._lock.acquire(blocking=False):
            raise conflict("已有病毒库更新正在执行")
        try:
            log.info("开始更新病毒库")
            outcome = self.components.update("clamav")
            try:
                probe = self.components.probe("clamav")
                if (
                    outcome.get("ok")
                    and self.config.clamav.auto_start
                    and probe.get("service_status") != "running"
                ):
                    log.info("病毒库就绪，按配置启动 ClamAV")
                    self.components.start("clamav")
            except Exception:
                log.exception("更新后探测/启动 ClamAV 失败")
            verification = outcome.get("signature_verification") or {}
            if verification.get("checked") and not verification.get("ok"):
                log.warning("病毒库更新后数字签名校验未通过")
            audit_store.record(
                self.db,
                action="component.update",
                actor=actor,
                client=client,
                request_id=request_id,
                target="clamav",
                result="success" if outcome.get("ok") else "failure",
                error=None if outcome.get("ok") else (outcome.get("output_tail") or "")[:1000],
                after_state={
                    "database": outcome.get("database"),
                    "exit_code": outcome.get("exit_code"),
                    "signature_verification": outcome.get(
                        "signature_verification"
                    ),
                },
                confirmed=False,
            )
            return outcome
        except BaseException as exc:
            try:
                audit_store.record(
                    self.db,
                    action="component.update",
                    actor=actor,
                    client=client,
                    request_id=request_id,
                    target="clamav",
                    result="failure",
                    error=str(exc)[:1000],
                )
            except Exception:
                log.exception("写入更新审计失败")
            raise
        finally:
            self._lock.release()
