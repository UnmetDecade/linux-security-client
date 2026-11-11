"""Scan task queue, worker threads, progress and scheduled scans."""

from __future__ import annotations

import os
import threading
import time
from datetime import timedelta
from typing import Any

from ..adapters.base import Detection, ScanOutcome, TaskContext
from ..common.config import Config
from ..common.errors import LsecError, ErrorCode, conflict, invalid, not_found
from ..common.logging import get_logger
from ..common.paths import ensure_within_roots, validate_path_text
from ..common.timeutil import now_iso, parse_iso, to_iso, utcnow
from ..storage import scans as scan_store
from ..storage import settings as settings_store
from ..storage.db import Database
from .components import ComponentManager
from .evidence import EvidenceStore
from .events import EventService

log = get_logger("core.scans")

SUPPORTED_ENGINES = ("clamav", "yara")
MAX_QUEUED_TASKS = 50


class ScanManager:
    def __init__(
        self,
        db: Database,
        config: Config,
        components: ComponentManager,
        events: EventService,
        evidence: EvidenceStore,
        *,
        actor: str = "system",
    ) -> None:
        self.db = db
        self.config = config
        self.components = components
        self.events = events
        self.evidence = evidence
        self.actor = actor
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._workers: list[threading.Thread] = []
        self._scheduler: threading.Thread | None = None
        self._events: dict[str, threading.Event] = {}
        self._events_lock = threading.Lock()

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        recovered = scan_store.recover_interrupted(self.db)
        if recovered:
            log.warning("发现 %s 个中断任务，已标记为失败", recovered)
        for index in range(self.config.scan.max_parallel_tasks):
            worker = threading.Thread(
                target=self._worker_loop, name=f"scan-worker-{index}", daemon=True
            )
            worker.start()
            self._workers.append(worker)
        self._scheduler = threading.Thread(
            target=self._scheduler_loop, name="scan-scheduler", daemon=True
        )
        self._scheduler.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._events_lock:
            events = list(self._events.values())
        for event in events:
            event.set()
        for worker in self._workers:
            worker.join(timeout=5)
        if self._scheduler:
            self._scheduler.join(timeout=2)

    # --------------------------------------------------------------- create
    def create_task(
        self,
        *,
        task_type: str,
        targets: list[str] | None,
        engines: list[str] | None,
        actor: str,
    ) -> dict[str, Any]:
        if task_type not in scan_store.SUPPORTED_TASK_TYPES:
            raise invalid(
                f"任务类型 {task_type} 尚未实现",
                {"supported": list(scan_store.SUPPORTED_TASK_TYPES)},
            )
        default_engine = "yara" if task_type == "yara" else "clamav"
        selected = engines or [default_engine]
        if not isinstance(selected, list) or not selected:
            raise invalid("必须选择一个扫描引擎")
        if not all(isinstance(engine, str) for engine in selected):
            raise invalid("引擎名称必须是字符串")
        # Deduplicate while preserving the caller's order.
        selected = list(dict.fromkeys(selected))
        unknown = [engine for engine in selected if engine not in SUPPORTED_ENGINES]
        if unknown:
            raise invalid(
                "所选引擎当前不可用",
                {"unknown": unknown, "supported": list(SUPPORTED_ENGINES)},
            )
        if task_type == "yara" and selected != ["yara"]:
            raise invalid("YARA 规则扫描任务只能选择 YARA 引擎")
        resolved = self._resolve_targets(task_type, targets or [])
        for engine in selected:
            self._require_engine_ready(engine)
        queued_row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM scan_tasks WHERE status = 'queued'"
        )
        if int(queued_row["n"] if queued_row else 0) >= MAX_QUEUED_TASKS:
            raise conflict("扫描队列已满，请稍后再试")
        task = scan_store.create_task(
            self.db,
            task_type=task_type,
            targets=resolved,
            engines=selected,
            actor=actor,
        )
        self._wake.set()
        return task

    def _require_engine_ready(self, engine: str) -> None:
        probe = self.components.probe(engine)
        if engine == "clamav":
            if not probe.get("installed"):
                raise LsecError(
                    ErrorCode.COMPONENT_UNAVAILABLE,
                    "ClamAV 未安装，无法创建扫描任务",
                    {"component": "clamav"},
                )
            if probe.get("service_status") != "running":
                raise LsecError(
                    ErrorCode.COMPONENT_UNAVAILABLE,
                    "ClamAV 服务未运行，无法创建扫描任务",
                    {"component": "clamav", "health": probe.get("health_status")},
                )
            return
        if engine == "yara":
            if not probe.get("installed"):
                raise LsecError(
                    ErrorCode.COMPONENT_UNAVAILABLE,
                    "YARA 未安装，无法创建规则扫描任务",
                    {"component": "yara"},
                )
            if probe.get("error_code") or probe.get("health_status") == "unavailable":
                raise LsecError(
                    ErrorCode.COMPONENT_UNAVAILABLE,
                    probe.get("error_message")
                    or "YARA 规则包不可用，无法创建扫描任务",
                    {
                        "component": "yara",
                        "error_code": probe.get("error_code"),
                        "health": probe.get("health_status"),
                    },
                )
            return
        raise invalid(f"未知扫描引擎: {engine}")

    def _resolve_targets(self, task_type: str, requested: list[str]) -> list[str]:
        if task_type == "quick":
            targets = [
                path for path in self.config.scan.quick_scan_paths if os.path.exists(path)
            ]
            if not targets:
                raise invalid("快速扫描目标均不存在，请检查配置 scan.quick_scan_paths")
            return targets
        if task_type == "full":
            return ["/"]
        if task_type in {"custom", "yara"}:
            if not requested:
                label = "YARA 规则扫描" if task_type == "yara" else "自定义扫描"
                raise invalid(f"{label}必须提供至少一个目标路径")
            cleaned: list[str] = []
            for path in requested:
                validate_path_text(path, field="扫描路径")
                if not os.path.exists(path):
                    raise invalid(f"扫描目标不存在: {path}")
                ensure_within_roots(
                    path, self.config.scan.allowed_roots, field="扫描路径"
                )
                cleaned.append(path)
            return cleaned
        raise invalid("不支持的任务类型")

    def cancel(self, task_id: str) -> dict[str, Any]:
        task = scan_store.request_cancel(self.db, task_id)
        with self._events_lock:
            event = self._events.get(task_id)
        if event:
            event.set()
        return task

    def get(self, task_id: str) -> dict[str, Any]:
        return scan_store.get_task(self.db, task_id)

    def list(self, **params: Any) -> tuple[list[dict[str, Any]], int]:
        return scan_store.list_tasks(self.db, **params)

    def active(self) -> dict[str, Any] | None:
        return scan_store.latest_active(self.db)

    # --------------------------------------------------------------- worker
    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            task = scan_store.next_queued(self.db)
            if not task:
                self._wake.wait(timeout=1.0)
                self._wake.clear()
                continue
            if not scan_store.mark_running(self.db, task["task_id"]):
                continue
            cancel_event = threading.Event()
            with self._events_lock:
                self._events[task["task_id"]] = cancel_event
            try:
                self._run_task(task, cancel_event)
            finally:
                with self._events_lock:
                    self._events.pop(task["task_id"], None)

    def _run_task(self, task: dict[str, Any], cancel_event: threading.Event) -> None:
        task_id = task["task_id"]
        engines = task.get("selected_engines") or ["clamav"]
        detections_report: list[dict[str, Any]] = []
        started = time.monotonic()
        total_files = 0
        total_detections = 0
        total_errors = 0
        all_error_details: list[dict[str, Any]] = []
        engine_summaries: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        cancelled = False

        for index, engine in enumerate(engines):
            if cancel_event.is_set():
                cancelled = True
                break
            engine_started = time.monotonic()

            def progress(
                scanned: int,
                total: int,
                detections: int,
                errors: int,
                pct: float | None,
                *,
                engine_index: int = index,
                engine_name: str = engine,
            ) -> None:
                overall = None
                if pct is not None:
                    overall = (
                        engine_index + min(100.0, max(0.0, pct)) / 100.0
                    ) / len(engines) * 100.0
                try:
                    scan_store.update_progress(
                        self.db,
                        task_id,
                        files_scanned=total_files + scanned,
                        detections=total_detections + detections,
                        errors=total_errors + errors,
                        progress=round(overall, 1) if overall is not None else None,
                    )
                except Exception:  # progress must never abort a scan
                    log.exception(
                        "更新任务进度失败 task=%s engine=%s", task_id, engine_name
                    )

            def on_detection(
                detection: Detection, *, engine_name: str = engine
            ) -> None:
                if engine_name == "yara":
                    event = self.events.ingest_yara_detection(
                        detection, task_id=task_id, task_type=task["task_type"]
                    )
                else:
                    event = self.events.ingest_clamav_detection(
                        detection, task_id=task_id, task_type=task["task_type"]
                    )
                if len(detections_report) < 500:
                    detections_report.append(
                        {
                            "path": detection.path,
                            "detection_name": detection.detection_name,
                            "severity": event["severity"],
                            "sha256": detection.sha256,
                            "event_id": event["event_id"],
                            "engine": engine_name,
                        }
                    )

            context = TaskContext(
                task_id=task_id,
                cancel_event=cancel_event,
                progress=progress,
                on_detection=on_detection,
            )
            try:
                adapter = self.components.get_adapter(engine)
                outcome: ScanOutcome = adapter.run_task(task, context)
            except LsecError as exc:
                failures.append(
                    {"engine": engine, "error": exc.message, "code": exc.code.value}
                )
                all_error_details.append(
                    {
                        "engine": engine,
                        "error": exc.message,
                        "code": exc.code.value,
                    }
                )
                total_errors += 1
                engine_summaries.append(
                    {
                        "engine": engine,
                        "status": "failed",
                        "error": exc.message,
                        "duration_seconds": round(
                            time.monotonic() - engine_started, 1
                        ),
                    }
                )
                log.warning(
                    "扫描引擎失败 task=%s engine=%s: %s", task_id, engine, exc.message
                )
                continue
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("扫描引擎异常 task=%s engine=%s", task_id, engine)
                failures.append({"engine": engine, "error": f"内部错误: {exc}"})
                all_error_details.append(
                    {"engine": engine, "error": f"内部错误: {exc}"}
                )
                total_errors += 1
                engine_summaries.append(
                    {
                        "engine": engine,
                        "status": "failed",
                        "error": f"内部错误: {exc}",
                        "duration_seconds": round(
                            time.monotonic() - engine_started, 1
                        ),
                    }
                )
                continue

            total_files += outcome.files_scanned
            total_detections += outcome.detections
            total_errors += outcome.errors
            all_error_details.extend(outcome.error_details)
            cancelled = cancelled or outcome.cancelled or cancel_event.is_set()
            engine_summaries.append(
                {
                    "engine": engine,
                    "status": "cancelled" if outcome.cancelled else "completed",
                    "files_scanned": outcome.files_scanned,
                    "detections": outcome.detections,
                    "errors": outcome.errors,
                    "duration_seconds": round(time.monotonic() - engine_started, 1),
                    "summary": outcome.summary,
                }
            )

        if len(failures) == len(engines):
            scan_store.finish(
                self.db,
                task_id,
                status="failed",
                summary={
                    "engines": engines,
                    "engine_results": engine_summaries,
                    "error_code": failures[0].get("code") if failures else None,
                },
                errors=all_error_details[:100],
                files_scanned=total_files,
                detections=total_detections,
                error_count=max(1, total_errors),
                progress=task.get("progress"),
            )
            log.warning("扫描任务失败 task=%s: %s", task_id, failures[0]["error"])
            return

        if cancelled:
            status = "cancelled"
        elif failures or total_errors > 0:
            status = "partial"
        else:
            status = "succeeded"

        max_total = max(
            [
                int(item.get("summary", {}).get("total_files") or 0)
                for item in engine_summaries
            ]
            or [0]
        )
        summary = {
            "engines": engines,
            "engine_results": engine_summaries,
            "detections_sample": detections_report,
            "detections_total": total_detections,
            "errors_total": total_errors,
            "files_scanned_total": total_files,
            "total_files": max_total,
            "duration_seconds": round(time.monotonic() - started, 1),
        }
        try:
            report_path = self.evidence.write_scan_report(
                task_id,
                {
                    "task": {
                        "task_id": task_id,
                        "task_type": task["task_type"],
                        "target_paths": task["target_paths"],
                        "engines": engines,
                    },
                    "status": status,
                    "summary": summary,
                    "detections": detections_report,
                    "errors": all_error_details[:100],
                },
            )
            if report_path:
                summary["evidence_path"] = report_path
        except OSError as exc:
            log.warning("写入扫描证据失败 task=%s: %s", task_id, exc)

        scan_store.finish(
            self.db,
            task_id,
            status=status,
            summary=summary,
            errors=all_error_details[:100],
            files_scanned=total_files,
            detections=total_detections,
            error_count=total_errors,
            progress=None if cancelled else (100.0 if max_total else None),
        )
        log.info(
            "扫描任务结束 task=%s status=%s engines=%s files=%s detections=%s errors=%s",
            task_id,
            status,
            ",".join(engines),
            total_files,
            total_detections,
            total_errors,
        )

    # ------------------------------------------------------------ scheduling
    def _scheduler_loop(self) -> None:
        while not self._stop.wait(timeout=30):
            try:
                self._maybe_schedule()
            except Exception:
                log.exception("定时扫描调度失败")

    def _maybe_schedule(self) -> None:
        schedule = settings_store.get(self.db, "scheduled_scan", {}) or {}
        if not isinstance(schedule, dict) or not schedule.get("enabled"):
            return
        interval = int(schedule.get("interval_hours", 24))
        last_run = schedule.get("last_run_at")
        due = True
        if last_run:
            try:
                due = utcnow() - parse_iso(last_run) >= timedelta(hours=interval)
            except ValueError:
                due = True
        if not due:
            return
        if scan_store.latest_active(self.db):
            return
        scan_type = schedule.get("type", "quick")
        if scan_type not in {"quick", "full"}:
            scan_type = "quick"
        try:
            task = self.create_task(
                task_type=scan_type, targets=None, engines=["clamav"], actor="scheduler"
            )
        except LsecError as exc:
            log.warning("定时扫描创建失败: %s", exc.message)
            return
        schedule = dict(schedule)
        schedule["last_run_at"] = now_iso()
        settings_store.set_value(self.db, "scheduled_scan", schedule)
        log.info("已创建定时扫描任务 task=%s", task["task_id"])
