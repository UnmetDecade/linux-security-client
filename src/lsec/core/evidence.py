"""Bounded evidence store for scan reports and detection context."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from ..common.logging import get_logger
from ..common.timeutil import now_iso

log = get_logger("core.evidence")

MAX_REPORT_BYTES = 1024 * 1024


class EvidenceStore:
    def __init__(self, root: Path, max_mb: int = 512) -> None:
        self.root = Path(root)
        self.max_bytes = max(0, max_mb) * 1024 * 1024
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def audit_directory(self, audit_id: str) -> Path:
        directory = self.root / "audits" / audit_id
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        return directory

    def write_audit_report(self, audit_id: str, payload: dict[str, Any]) -> str | None:
        directory = self.audit_directory(audit_id)
        data = json.dumps(
            {"generated_at": now_iso(), **payload}, ensure_ascii=False, default=str
        ).encode("utf-8")
        if len(data) > MAX_REPORT_BYTES:
            data = json.dumps(
                {
                    "generated_at": now_iso(),
                    "truncated": True,
                    "note": "the audit report exceeds 1MB and was truncated; see the raw Lynis report and database summary",
                    "audit_id": audit_id,
                },
                ensure_ascii=False,
            ).encode("utf-8")
        path = directory / "report.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return str(path)

    def write_scan_report(self, task_id: str, payload: dict[str, Any]) -> str | None:
        directory = self.root / "scans"
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        data = json.dumps(
            {"generated_at": now_iso(), **payload}, ensure_ascii=False, default=str
        ).encode("utf-8")
        if len(data) > MAX_REPORT_BYTES:
            data = json.dumps(
                {
                    "generated_at": now_iso(),
                    "truncated": True,
                    "note": "the report exceeds 1MB and was truncated",
                    "task_id": task_id,
                },
                ensure_ascii=False,
            ).encode("utf-8")
        path = directory / f"{task_id}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        self.prune()
        return str(path)

    def usage_bytes(self) -> int:
        total = 0
        for dirpath, _dirs, files in os.walk(self.root):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(dirpath, name))
                except OSError:
                    continue
        return total

    def prune(self, retention_days: int = 90) -> int:
        """Remove old evidence, then evict oldest files until under quota."""
        if not self.root.exists():
            return 0
        removed = 0
        cutoff = time.time() - retention_days * 86400
        entries: list[tuple[float, int, str]] = []
        for dirpath, _dirs, files in os.walk(self.root):
            for name in files:
                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if st.st_mtime < cutoff:
                    try:
                        os.unlink(path)
                        removed += 1
                    except OSError:
                        pass
                else:
                    entries.append((st.st_mtime, st.st_size, path))
        total = sum(size for _mtime, size, _path in entries)
        if self.max_bytes and total > self.max_bytes:
            for _mtime, size, path in sorted(entries):
                try:
                    os.unlink(path)
                    removed += 1
                    total -= size
                except OSError:
                    continue
                if total <= self.max_bytes:
                    break
        if removed:
            log.info("evidence store cleanup complete; removed %s files", removed)
        return removed
