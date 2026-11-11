"""Optional local Wazuh ``alerts.json`` ingestion.

The ingester reads only newly appended lines from the configured local alert
file. It never contacts a Wazuh Manager and never claims manager capability.
State is persisted (inode + byte offset) so a daemon restart does not replay the
whole file. A crash between inserting events and persisting the offset can
replay a small batch; the unified event dedup key prevents duplicate events
(occurrences may increment).
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any

from ..common.config import WazuhConfig
from ..common.errors import ErrorCode, LsecError
from ..common.logging import get_logger
from ..common.paths import ensure_dir
from ..common.timeutil import now_iso
from .events import EventService

log = get_logger("core.wazuh")


class WazuhAlertIngester:
    def __init__(self, config: WazuhConfig, events: EventService) -> None:
        self.config = config
        self.events = events
        self.state_dir = Path(config.state_dir)
        self.state_path = self.state_dir / "state.json"
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self._status: dict[str, Any] = {
            "schema_version": 1,
            "enabled": bool(config.enabled),
            "ingest_enabled": bool(config.ingest_enabled),
            "running": False,
            "alerts_path": config.alerts_path,
            "file_present": False,
            "file_size": 0,
            "offset": 0,
            "alerts_seen": 0,
            "events_total": 0,
            "parse_errors": 0,
            "rejected": 0,
            "last_event_at": None,
            "last_poll_at": None,
            "last_error": None,
            "state_error": None,
            "started_at": None,
            "started_at_end": False,
            "note": (
                "仅接入本地 Wazuh Agent alerts.json 的新增行；"
                "不是 Wazuh Manager，也不验证 Manager 连接"
            ),
        }
        if self.active:
            ensure_dir(self.state_dir, 0o700)

    @property
    def active(self) -> bool:
        return bool(self.config.enabled and self.config.ingest_enabled)

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if not self.active:
            return
        with self._lock:
            if self._running:
                return
            self._running = True
            self._status["running"] = True
            self._status["started_at"] = now_iso()
        self._thread = threading.Thread(
            target=self._loop, name="wazuh-alert-ingest", daemon=True
        )
        self._thread.start()
        log.info("Wazuh 本地告警接入已启动 path=%s", self.config.alerts_path)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        with self._lock:
            self._running = False
            self._status["running"] = False
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # ingestion must not kill the daemon
                log.exception("Wazuh 告警接入异常")
                with self._lock:
                    self._status["last_error"] = str(exc)[:500]
            self._stop.wait(self.config.poll_seconds)

    # --------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        with self._lock:
            snapshot = dict(self._status)
        try:
            st = os.lstat(self.config.alerts_path)
            present = stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)
            size = st.st_size if present else 0
        except OSError:
            present = False
            size = 0
        snapshot.update(
            {
                "file_present": present,
                "file_size": size,
                "poll_seconds": self.config.poll_seconds,
                "max_event_bytes": self.config.max_event_bytes,
                "max_read_bytes": self.config.max_read_bytes,
                "scope": "local_agent_alert_file",
            }
        )
        if not self.config.enabled:
            snapshot["note"] = "Wazuh 集成未启用（可选）"
        elif not self.config.ingest_enabled:
            snapshot["note"] = "Wazuh 本地告警接入未启用；仅可查看 Agent 状态"
        elif not self._running:
            snapshot["note"] = "Wazuh 本地告警接入未运行"
        return snapshot

    # ----------------------------------------------------------------- tick
    def tick(self) -> dict[str, Any]:
        """Perform one read-only ingestion pass (also used by tests)."""
        with self._lock:
            self._status["last_poll_at"] = now_iso()
        if not self.active:
            return self.status()

        try:
            state, fresh = self._load_state()
        except LsecError as exc:
            with self._lock:
                self._status["state_error"] = exc.message
            return self.status()

        try:
            fd = os.open(
                self.config.alerts_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            with self._lock:
                self._status["file_present"] = False
                self._status["last_error"] = f"无法打开本地 Wazuh 告警文件: {exc}"[:500]
            return self.status()

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                with self._lock:
                    self._status["last_error"] = "Wazuh 告警路径不是普通文件"
                return self.status()
            inode = int(st.st_ino)
            size = int(st.st_size)
            if fresh:
                # Do not import an unbounded backlog on first enablement.
                state = {
                    "schema_version": 1,
                    "alerts_path": self.config.alerts_path,
                    "inode": inode,
                    "offset": size,
                    "initialized_at": now_iso(),
                }
                self._save_state(state)
                with self._lock:
                    self._status["started_at_end"] = True
                    self._status["offset"] = size
                return self.status()

            offset = int(state.get("offset") or 0)
            original_offset = offset
            state_inode = state.get("inode")
            if state_inode not in (None, inode) or size < offset:
                # Rotation/truncation: restart from the beginning of the new file.
                offset = 0
                state["inode"] = inode
                state["rotated_at"] = now_iso()
                state["skip_until_newline"] = False

            os.lseek(fd, offset, os.SEEK_SET)
            data = os.read(fd, self.config.max_read_bytes)
            new_offset = offset
            lines: list[bytes] = []
            skipped_line = 0
            skip = bool(state.get("skip_until_newline"))
            if data and skip:
                # Finish discarding an oversized line started in a previous pass.
                newline_at = data.find(b"\n")
                if newline_at < 0:
                    new_offset = offset + len(data)
                    data = b""
                else:
                    new_offset = offset + newline_at + 1
                    data = data[newline_at + 1 :]
                    skip = False
            if data and not skip:
                newline_at = data.rfind(b"\n")
                if newline_at >= 0:
                    lines = data[: newline_at + 1].splitlines()
                    new_offset += newline_at + 1
                elif len(data) >= self.config.max_read_bytes:
                    # A single line larger than the read budget: discard this
                    # chunk and keep skipping until the newline appears, so a
                    # truncated fragment is never parsed as a whole alert.
                    new_offset += len(data)
                    skip = True
                    skipped_line = 1
            state["skip_until_newline"] = skip
            if skipped_line:
                with self._lock:
                    self._status["rejected"] += 1
                    self._status["last_error"] = "Wazuh 告警单行超过读取上限，已跳过"

            events_total = 0
            seen = 0
            parse_errors = 0
            rejected = 0
            last_event_at = None
            for raw_line in lines:
                line = raw_line.strip()
                if not line:
                    continue
                seen += 1
                if len(line) > self.config.max_event_bytes:
                    rejected += 1
                    continue
                try:
                    alert = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    parse_errors += 1
                    with self._lock:
                        self._status["last_error"] = (
                            f"Wazuh 告警 JSON 解析失败: {exc}"[:300]
                        )
                    continue
                try:
                    event = self.events.ingest_wazuh_alert(
                        alert, max_event_bytes=self.config.max_event_bytes
                    )
                except LsecError as exc:
                    rejected += 1
                    with self._lock:
                        self._status["last_error"] = exc.message[:500]
                    continue
                except Exception as exc:  # pragma: no cover - defensive
                    rejected += 1
                    with self._lock:
                        self._status["last_error"] = f"告警归一化失败: {exc}"[:500]
                    continue
                events_total += 1
                last_event_at = event.get("last_seen_at") or event.get("created_at")

            state["alerts_path"] = self.config.alerts_path
            state["inode"] = inode
            state["offset"] = new_offset
            state["updated_at"] = now_iso()
            if new_offset != original_offset or state_inode != inode:
                try:
                    self._save_state(state)
                except LsecError as exc:
                    with self._lock:
                        self._status["state_error"] = exc.message
                    return self.status()

            with self._lock:
                self._status.update(
                    {
                        "file_present": True,
                        "file_size": size,
                        "offset": new_offset,
                        "alerts_seen": self._status["alerts_seen"] + seen,
                        "events_total": self._status["events_total"] + events_total,
                        "parse_errors": self._status["parse_errors"] + parse_errors,
                        "rejected": self._status["rejected"] + rejected,
                        "state_error": None,
                    }
                )
                if last_event_at:
                    self._status["last_event_at"] = last_event_at
            return self.status()
        except OSError as exc:
            with self._lock:
                self._status["last_error"] = f"读取 Wazuh 告警失败: {exc}"[:500]
            return self.status()
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    # --------------------------------------------------------------- state
    def _load_state(self) -> tuple[dict[str, Any], bool]:
        if not self.state_path.exists():
            return {}, True
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LsecError(
                ErrorCode.INTERNAL,
                "Wazuh 接入状态文件损坏，为避免重复/漏读已暂停接入",
                {"path": str(self.state_path), "detail": str(exc)[:300]},
            ) from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("offset"), int):
            raise LsecError(
                ErrorCode.INTERNAL,
                "Wazuh 接入状态文件格式无效，已暂停接入",
                {"path": str(self.state_path)},
            )
        if raw.get("alerts_path") not in (None, self.config.alerts_path):
            # The configured file changed; start from its current end.
            return {}, True
        return raw, False

    def _save_state(self, state: dict[str, Any]) -> None:
        ensure_dir(self.state_dir, 0o700)
        fd, temporary = tempfile.mkstemp(
            prefix=".wazuh-state-", suffix=".json", dir=str(self.state_dir)
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        except OSError as exc:
            raise LsecError(
                ErrorCode.INTERNAL,
                "无法保存 Wazuh 接入状态",
                {"path": str(self.state_path), "detail": str(exc)[:300]},
            ) from exc
        finally:
            try:
                os.unlink(temporary)
            except OSError:
                pass
