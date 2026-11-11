"""Host audit orchestration.

The service runs one audit at a time in a background worker. Built-in checks
are always read-only. Lynis is optional and its raw output is preserved next
to the parsed report. Findings become unified security events; checks that
could not execute are recorded as errors and never as findings.
"""

from __future__ import annotations

import hashlib
import queue
import threading
import time
from typing import Any

from ..adapters.lynis import LynisAdapter, LynisOutcome, warning_severity
from ..common.config import Config
from ..common.errors import conflict
from ..common.hostinfo import host_info
from ..common.logging import get_logger
from ..storage import audit as audit_store
from ..storage import audits as audit_run_store
from ..storage.db import Database
from .events import EventService
from .evidence import EvidenceStore
from .hostchecks import (
    ERROR,
    FINDING,
    CheckResult,
    collect_system_info,
    run_builtin_checks,
)

log = get_logger("core.audit")

MAX_INGESTED_FINDINGS = 500


class AuditService:
    def __init__(
        self,
        db: Database,
        config: Config,
        events: EventService,
        evidence: EvidenceStore,
        lynis: LynisAdapter,
        *,
        check_runner=run_builtin_checks,
    ) -> None:
        self.db = db
        self.config = config
        self.events = events
        self.evidence = evidence
        self.lynis = lynis
        self.check_runner = check_runner
        self._queue: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._create_lock = threading.Lock()

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        recovered = audit_run_store.recover_interrupted(self.db)
        if recovered:
            log.warning("发现 %s 个中断体检，已标记为失败", recovered)
        self._thread = threading.Thread(
            target=self._worker_loop, name="host-audit", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._queue.put("")
        if self._thread:
            self._thread.join(timeout=5)

    # --------------------------------------------------------------- create
    def create(self, actor: str) -> dict[str, Any]:
        with self._create_lock:
            if audit_run_store.latest_active(self.db):
                raise conflict("已有主机体检正在运行，请等待完成")
            scope = "container" if host_info().get("container", {}).get("containerized") else "host"
            run = audit_run_store.create_run(
                self.db, scope=scope, requested_by=actor
            )
        self._queue.put(run["audit_id"])
        return run

    # ----------------------------------------------------------------- query
    def get(self, audit_id: str) -> dict[str, Any]:
        return audit_run_store.get_run(self.db, audit_id)

    def list(self, *, limit: int = 20, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        return audit_run_store.list_runs(self.db, limit=limit, offset=offset)

    def latest(self) -> dict[str, Any] | None:
        return audit_run_store.latest_finished(self.db)

    def latest_active(self) -> dict[str, Any] | None:
        return audit_run_store.latest_active(self.db)

    # ---------------------------------------------------------------- worker
    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                audit_id = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            if not audit_id or self._stop.is_set():
                continue
            try:
                self._execute(audit_id)
            except Exception:
                log.exception("主机体检异常 audit=%s", audit_id)
                try:
                    audit_run_store.finish_run(
                        self.db,
                        audit_id,
                        status="failed",
                        summary={"error": "体检执行发生内部异常"},
                        checks_total=0,
                        findings_count=0,
                        errors_count=1,
                        severity_counts={},
                        error="体检执行发生内部异常",
                    )
                    audit_store.record(
                        self.db,
                        action="audit.complete",
                        actor="system",
                        target=audit_id,
                        result="failure",
                        error="内部异常",
                        confirmed=True,
                    )
                except Exception:
                    log.exception("写入体检失败状态失败 audit=%s", audit_id)

    def _execute(self, audit_id: str) -> None:
        if not audit_run_store.mark_running(self.db, audit_id):
            return
        run = audit_run_store.get_run(self.db, audit_id)
        started = time.monotonic()
        containerized = bool(host_info().get("container", {}).get("containerized"))
        if containerized:
            scope_note = (
                "检查范围为容器可见的文件系统、网络命名空间和内核参数；"
                "未挂载的宿主机路径与宿主网络不在范围内"
            )
        else:
            scope_note = "检查范围为当前主机文件系统和网络命名空间"
        limitations = [
            "所有检查均为只读，不会修改系统配置、账户、服务或内核参数",
            "Lynis 的 suggestion 条目保存在报告中，不逐条生成安全事件以减少噪声",
            "检查失败（权限/文件缺失）与风险发现分开记录，不会把失败当成风险",
        ]
        system_info = collect_system_info()

        builtin = self.check_runner()
        lynis_outcome: LynisOutcome | None = None
        lynis_findings: list[CheckResult] = []
        try:
            lynis_outcome = self.lynis.run_audit(
                self.evidence.audit_directory(audit_id),
                timeout=self.config.audit.lynis_timeout_seconds,
            )
            lynis_findings = self._lynis_results(lynis_outcome)
        except Exception as exc:
            log.exception("Lynis 执行异常 audit=%s", audit_id)
            lynis_outcome = LynisOutcome(
                available=False,
                enabled=self.config.audit.lynis_enabled,
                error=f"Lynis 执行异常: {exc}",
            )

        results: list[CheckResult] = [*builtin, *lynis_findings]
        if lynis_outcome and lynis_outcome.available and lynis_outcome.error:
            results.append(
                CheckResult(
                    check_id="LYNIS-RUN",
                    category="system",
                    title="Lynis 执行未完整完成",
                    status=ERROR,
                    detail=lynis_outcome.error,
                    source="lynis",
                    target={"type": "host"},
                )
            )
        findings = [item for item in results if item.status == FINDING]
        check_errors = [item for item in results if item.status == ERROR]
        severity_counts = {
            severity: sum(1 for item in findings if item.severity == severity)
            for severity in ("critical", "high", "medium", "low", "info")
        }

        event_errors: list[str] = []
        ingested = 0
        for item in findings:
            if ingested >= min(self.config.audit.max_findings, MAX_INGESTED_FINDINGS):
                break
            try:
                self.events.ingest_finding(
                    source=item.source,
                    category=item.category
                    if item.category
                    in {
                        "malware",
                        "intrusion",
                        "runtime",
                        "integrity",
                        "vulnerability",
                        "configuration",
                    }
                    else "configuration",
                    severity=item.severity or "medium",
                    title=item.title,
                    description=item.detail
                    + (f" 建议: {item.remediation}" if item.remediation else ""),
                    check_id=item.check_id,
                    target=item.target,
                    evidence={
                        **item.evidence,
                        "audit_id": audit_id,
                        "remediation": item.remediation,
                    },
                    recommended_actions=[item.remediation] if item.remediation else [],
                    dedup_hint=item.dedup_hint or item.title,
                    source_ref={
                        "source": item.source,
                        "audit_id": audit_id,
                        "check_id": item.check_id,
                    },
                )
                ingested += 1
            except Exception as exc:
                log.exception("写入审计事件失败 audit=%s check=%s", audit_id, item.check_id)
                event_errors.append(f"{item.check_id}: {exc}")

        errors_count = len(check_errors) + len(event_errors)
        status = "partial" if errors_count else "succeeded"
        summary = {
            "scope_note": scope_note,
            "limitations": limitations,
            "system_info": system_info,
            "checks": [item.to_dict() for item in results],
            "counts": {
                "checks": len(results),
                "findings": len(findings),
                "errors": len(check_errors),
                "skipped": sum(1 for item in results if item.status == "skipped"),
                "passed": sum(1 for item in results if item.status == "pass"),
                "events_ingested": ingested,
                "event_errors": len(event_errors),
            },
            "event_errors": event_errors[:50],
            "lynis": lynis_outcome.to_dict() if lynis_outcome else {
                "available": False,
                "enabled": self.config.audit.lynis_enabled,
                "error": "Lynis 未执行",
            },
            "duration_seconds": round(time.monotonic() - started, 1),
        }
        evidence_path: str | None = None
        evidence_error: str | None = None
        try:
            evidence_path = self.evidence.write_audit_report(audit_id, summary)
        except OSError as exc:
            evidence_error = f"写入体检证据失败: {exc}"
            status = "failed"
            errors_count += 1
            summary["evidence_error"] = evidence_error

        audit_run_store.finish_run(
            self.db,
            audit_id,
            status=status,
            summary=summary,
            checks_total=len(results),
            findings_count=len(findings),
            errors_count=errors_count,
            severity_counts=severity_counts,
            hardening_index=lynis_outcome.hardening_index if lynis_outcome else None,
            lynis_available=bool(lynis_outcome and lynis_outcome.available),
            lynis_version=lynis_outcome.version if lynis_outcome else None,
            evidence_path=evidence_path,
            error=evidence_error,
        )
        audit_store.record(
            self.db,
            action="audit.complete",
            actor=run.get("requested_by") or "system",
            target=audit_id,
            after_state={
                "status": status,
                "findings": len(findings),
                "errors": errors_count,
                "checks": len(results),
            },
            result="success" if status != "failed" else "failure",
            error=evidence_error,
            confirmed=True,
        )
        log.info(
            "主机体检结束 audit=%s status=%s checks=%s findings=%s errors=%s",
            audit_id,
            status,
            len(results),
            len(findings),
            errors_count,
        )

    def _lynis_results(self, outcome: LynisOutcome) -> list[CheckResult]:
        if not outcome.available:
            return []
        results: list[CheckResult] = []
        for warning in outcome.warnings:
            test_id = warning.get("test_id") or "LYNIS"
            text = warning.get("text") or "Lynis 警告"
            target = warning.get("target") or ""
            remediation = warning.get("remediation") or None
            digest = hashlib.sha256(
                f"{test_id}|{target}|{text}".encode("utf-8", errors="replace")
            ).hexdigest()[:12]
            results.append(
                CheckResult(
                    check_id=test_id,
                    category="configuration",
                    title=f"Lynis 警告: {text[:160]}",
                    status=FINDING,
                    severity=warning_severity(test_id, text),
                    detail=text + (f"（目标: {target}）" if target else ""),
                    remediation=remediation,
                    source="lynis",
                    target={
                        "type": "config" if target.startswith("/") else "host",
                        "path": target if target.startswith("/") else None,
                        "name": target or None,
                    },
                    evidence={
                        "test_id": test_id,
                        "target": target,
                        "remediation": remediation,
                    },
                    dedup_hint=f"lynis:{test_id}:{digest}",
                )
            )
        return results
