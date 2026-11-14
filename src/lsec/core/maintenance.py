"""Periodic cleanup: sessions, resolved event retention, evidence quota and logs."""

from __future__ import annotations

import threading
import time

from ..common.config import Config
from ..common.logging import get_logger
from ..storage import sessions as session_store
from ..storage.db import Database
from .events import EventService
from .evidence import EvidenceStore

log = get_logger("core.maintenance")


class MaintenanceService:
    def __init__(
        self,
        db: Database,
        config: Config,
        events: EventService,
        evidence: EvidenceStore,
    ) -> None:
        self.db = db
        self.config = config
        self.events = events
        self.evidence = evidence
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="maintenance", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _loop(self) -> None:
        self.run_once()
        while not self._stop.wait(timeout=6 * 3600):
            self.run_once()

    def run_once(self) -> None:
        try:
            removed_sessions = session_store.prune_expired(self.db)
            removed_events = self.events.prune(self.config.storage.event_retention_days)
            removed_files = self.evidence.prune()
            if any((removed_sessions, removed_events, removed_files)):
                log.info(
                    "maintenance complete sessions=%s events=%s evidence=%s",
                    removed_sessions,
                    removed_events,
                    removed_files,
                )
        except Exception:
            log.exception("periodic maintenance failed")
