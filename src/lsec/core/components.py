"""Component registry and health probing."""

from __future__ import annotations

from typing import Any

from ..adapters.base import Adapter, ProbeResult
from ..common.errors import not_found
from ..common.logging import get_logger
from ..storage import components as component_store
from ..storage.db import Database

log = get_logger("core.components")


class ComponentManager:
    def __init__(self, db: Database, adapters: list[Adapter]) -> None:
        self.db = db
        self.adapters: dict[str, Adapter] = {a.component_id: a for a in adapters}

    def get_adapter(self, component_id: str) -> Adapter:
        adapter = self.adapters.get(component_id)
        if not adapter:
            raise not_found(f"未知组件: {component_id}")
        return adapter

    def probe(self, component_id: str) -> dict[str, Any]:
        adapter = self.get_adapter(component_id)
        result = adapter.probe()
        return component_store.upsert_component(self.db, result.to_dict())

    def probe_all(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for component_id in sorted(self.adapters):
            try:
                results.append(self.probe(component_id))
            except Exception as exc:  # a broken adapter must not take down the daemon
                log.exception("组件探测失败 component=%s", component_id)
                adapter = self.adapters[component_id]
                failed = ProbeResult(
                    component_id=component_id,
                    display_name=adapter.display_name,
                    installed=False,
                    health_status="check_failed",
                    error_code="probe_failed",
                    error_message=f"探测失败: {exc}",
                )
                results.append(component_store.upsert_component(self.db, failed.to_dict()))
        return results

    def list(self) -> list[dict[str, Any]]:
        return component_store.list_components(self.db)

    def start(self, component_id: str) -> dict[str, Any]:
        adapter = self.get_adapter(component_id)
        result = adapter.start()
        return component_store.upsert_component(self.db, result.to_dict())

    def stop(self, component_id: str) -> dict[str, Any]:
        adapter = self.get_adapter(component_id)
        result = adapter.stop()
        return component_store.upsert_component(self.db, result.to_dict())

    def update(self, component_id: str) -> dict[str, Any]:
        adapter = self.get_adapter(component_id)
        outcome = adapter.update()
        component_store.mark_update(self.db, component_id)
        return outcome

    def install_plan(self, component_id: str) -> dict[str, Any]:
        return self.get_adapter(component_id).install_plan()

    def required_component_status(self) -> dict[str, Any] | None:
        return component_store.get_component(self.db, "clamav")
