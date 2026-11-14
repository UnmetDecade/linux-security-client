"""ClamAV adapter.

Integrates with clamd over its documented Unix-socket protocol using "z"
(NUL) framing (zPING, zVERSION, zSCAN, zSHUTDOWN) instead of parsing human-
oriented terminal output. freshclam handles signature updates. The daemon
process is managed as a child process.
"""

from __future__ import annotations

import glob
import hashlib
import os
import re
import socket
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..common.config import ClamAVConfig, ScanConfig
from ..common.errors import component_unavailable, conflict, invalid
from ..common.executor import run, which
from ..common.logging import get_logger
from ..common.paths import is_skipped_dir
from ..common.timeutil import age_hours, now_iso, to_iso
from .base import (
    HEALTH_CHECK_FAILED,
    HEALTH_DEGRADED,
    HEALTH_OK,
    HEALTH_PERMISSION_DENIED,
    HEALTH_UNAVAILABLE,
    SERVICE_NOT_INSTALLED,
    SERVICE_RUNNING,
    SERVICE_STOPPED,
    Adapter,
    Detection,
    ProbeResult,
    ScanOutcome,
    TaskContext,
)

log = get_logger("adapter.clamav")

MAX_RESPONSE_BYTES = 1_048_576


class ClamdError(Exception):
    pass


class ClamdClient:
    """Minimal, defensive clamd protocol client (null-terminated responses)."""

    def __init__(self, socket_path: str, default_timeout: float = 60) -> None:
        self.socket_path = socket_path
        self.default_timeout = default_timeout

    def command(self, command: str, timeout: float | None = None) -> str:
        if "\n" in command or "\r" in command or "\x00" in command:
            raise ValueError("clamd command must not contain control characters")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout if timeout is not None else self.default_timeout)
        try:
            sock.connect(self.socket_path)
            # Use the documented "z" framing: NUL-terminated command, NUL-
            # terminated reply. Sending "zSCAN path\\n" is not a valid framed
            # command ("z" selects NUL as the terminator) and clamd will report
            # COMMAND READ TIMED OUT for it.
            sock.sendall(b"z" + command.encode("utf-8") + b"\x00")
            chunks: list[bytes] = []
            size = 0
            while True:
                data = sock.recv(8192)
                if not data:
                    break
                end = data.find(b"\x00")
                if end >= 0:
                    chunks.append(data[:end])
                    break
                chunks.append(data)
                size += len(data)
                if size > MAX_RESPONSE_BYTES:
                    raise ClamdError("clamd response exceeds the size limit")
            if not chunks:
                raise ClamdError("no response from clamd")
            return b"".join(chunks).decode("utf-8", errors="replace").strip()
        except (OSError, socket.timeout) as exc:
            raise ClamdError(str(exc)) from exc
        finally:
            sock.close()

    def ping(self) -> bool:
        try:
            return self.command("PING", timeout=3).strip() == "PONG"
        except ClamdError:
            return False

    def version(self) -> str:
        return self.command("VERSION", timeout=5)

    def scan(self, path: str, timeout: float) -> str:
        return self.command(f"SCAN {path}", timeout=timeout)

    def shutdown(self) -> str:
        return self.command("SHUTDOWN", timeout=5)


def _db_snapshot(database_dir: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    newest: float | None = None
    for pattern in ("*.cvd", "*.cld"):
        for path in glob.glob(os.path.join(database_dir, pattern)):
            try:
                st = os.stat(path)
            except OSError:
                continue
            files.append(
                {
                    "name": os.path.basename(path),
                    "size": st.st_size,
                    "modified_at": to_iso(datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)),
                }
            )
            newest = st.st_mtime if newest is None else max(newest, st.st_mtime)
    updated_at = (
        to_iso(datetime.fromtimestamp(newest, tz=timezone.utc)) if newest else None
    )
    return {
        "directory": database_dir,
        "files": files,
        "updated_at": updated_at,
        "age_hours": age_hours(updated_at),
        "present": bool(files),
    }


def _sha256(path: str) -> tuple[str | None, str | None]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        return None, str(exc)
    try:
        size = os.fstat(fd).st_size
        if size > 1024 * 1024 * 1024:
            return None, "file too large; skipping hash computation"
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest(), None
    except OSError as exc:
        return None, str(exc)


class ClamAVAdapter(Adapter):
    component_id = "clamav"
    display_name = "ClamAV Antivirus Engine"

    def __init__(self, config: ClamAVConfig, scan_config: ScanConfig, data_dir: Path) -> None:
        self.config = config
        self.scan_config = scan_config
        self.data_dir = Path(data_dir)
        self.client = ClamdClient(
            config.socket_path, default_timeout=config.socket_timeout_seconds
        )
        self._process: subprocess.Popen[bytes] | None = None

    # ------------------------------------------------------------------ probe
    def probe(self) -> ProbeResult:
        clamd_bin = which(self.config.clamd_bin)
        freshclam_bin = which(self.config.freshclam_bin)
        clamscan_bin = which(self.config.clamscan_bin)
        installed = any((clamd_bin, freshclam_bin, clamscan_bin))
        details: dict[str, Any] = {
            "binaries": {
                "clamd": clamd_bin,
                "freshclam": freshclam_bin,
                "clamscan": clamscan_bin,
            },
            "socket": self.config.socket_path,
            "database": _db_snapshot(self.config.database_dir),
            "real_time_protection": {
                "supported": False,
                "state": "unsupported",
                "reason": "ClamAV On-Access is not enabled in container deployments (requires fanotify/kernel support; real-time protection is not provided at this stage)",
            },
        }
        if not installed:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="not_installed",
                error_message="ClamAV executables not detected",
                details=details,
            )

        version = None
        daemon_version = None
        service_status = SERVICE_STOPPED
        running = self.client.ping()
        if running:
            service_status = SERVICE_RUNNING
            try:
                daemon_version = self.client.version()
            except ClamdError:
                daemon_version = None
        if clamscan_bin:
            result = run([clamscan_bin, "--version"], timeout=5)
            if result.ok:
                version = result.stdout.strip() or None
        if not version and daemon_version:
            version = daemon_version

        db = details["database"]
        health = HEALTH_OK
        error_code = None
        error_message = None
        if not running:
            health = HEALTH_DEGRADED
            error_code = "service_stopped"
            error_message = "ClamAV is installed but clamd is not running; on-demand scanning is unavailable"
        elif not db["present"]:
            health = HEALTH_DEGRADED
            error_code = "database_missing"
            error_message = "clamd is running but no signature database was found; scans will fail"
        elif (
            db["age_hours"] is not None
            and db["age_hours"] > max(48, self.config.update_interval_hours * 2)
        ):
            health = HEALTH_DEGRADED
            error_code = "database_outdated"
            error_message = (
                f"signature database has not been updated for {db['age_hours']:.1f} hours; check freshclam updates"
            )

        if daemon_version:
            details["clamd_version"] = daemon_version
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            version=version,
            service_status=service_status,
            health_status=health,
            capabilities=["on_demand_scan", "signature_update"],
            error_code=error_code,
            error_message=error_message,
            details=details,
        )

    # ------------------------------------------------------------- lifecycle
    def _write_clamd_config(self) -> None:
        conf = Path(self.config.config_path)
        conf.parent.mkdir(parents=True, exist_ok=True)
        socket_dir = Path(self.config.socket_path).parent
        socket_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.data_dir / "logs" / "clamd.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(
            [
                "Foreground yes",
                f"LocalSocket {self.config.socket_path}",
                "LocalSocketMode 0660",
                f"DatabaseDirectory {self.config.database_dir}",
                f"LogFile {log_file}",
                "LogTime yes",
                "MaxThreads 2",
                "MaxConnectionQueueLength 16",
                "StreamMaxLength 100M",
                "ScanArchive yes",
                "SelfCheck 3600",
                "",
            ]
        )
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        try:
            os.chmod(conf, 0o600)
        except OSError:
            pass

    def start(self) -> ProbeResult:
        clamd_bin = which(self.config.clamd_bin)
        if not clamd_bin:
            raise component_unavailable("clamd is not installed; cannot start ClamAV")
        if self.client.ping():
            return self.probe()
        if not _db_snapshot(self.config.database_dir)["present"]:
            raise component_unavailable(
                "no signature database found; refusing to start the scan engine; update signatures first",
                {"database_dir": self.config.database_dir},
            )
        self._write_clamd_config()
        log_path = self.data_dir / "logs" / "clamd-boot.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(log_path, "ab")
        try:
            self._process = subprocess.Popen(
                [clamd_bin, "-c", self.config.config_path],
                stdout=handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            handle.close()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.client.ping():
                return self.probe()
            if self._process.poll() is not None:
                tail = ""
                try:
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
                except OSError:
                    pass
                raise component_unavailable(
                    "clamd exited immediately after starting", {"exit_code": self._process.returncode, "log_tail": tail}
                )
            time.sleep(0.5)
        raise component_unavailable("clamd startup timed out (45 seconds)")

    def stop(self) -> ProbeResult:
        if not self.client.ping():
            raise conflict("clamd is not running")
        try:
            self.client.shutdown()
        except ClamdError as exc:
            log.warning("clamd SHUTDOWN failed: %s", exc)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not self.client.ping():
                return self.probe()
            time.sleep(0.5)
        if self._process and self._process.poll() is None:
            self._process.terminate()
        raise component_unavailable("clamd did not stop within 20 seconds")

    # ---------------------------------------------------------------- update
    def update(self) -> dict[str, Any]:
        freshclam = which(self.config.freshclam_bin)
        if not freshclam:
            raise component_unavailable("freshclam is not installed; cannot update signatures")
        started = time.monotonic()
        result = run(
            [
                freshclam,
                "--datadir",
                self.config.database_dir,
                "--stdout",
            ],
            timeout=900,
            max_output=128 * 1024,
        )
        snapshot = _db_snapshot(self.config.database_dir)
        verification = self.verify_database_signatures()
        return {
            "ok": result.ok,
            "exit_code": result.returncode,
            "timed_out": result.timed_out,
            "duration_seconds": round(time.monotonic() - started, 1),
            "output_tail": result.tail(1600),
            "database": snapshot,
            "signature_verification": verification,
        }

    def verify_database_signatures(self) -> dict[str, Any]:
        """Verify the ClamAV CVD digital signature with ``sigtool --info``.

        freshclam already verifies signatures while downloading; this check
        re-verifies the files currently on disk. ``.cld`` (unpacked) databases
        carry no CVD signature, so they are reported as not applicable rather
        than silently treated as verified.
        """
        sigtool = which(self.config.sigtool_bin)
        snapshot = _db_snapshot(self.config.database_dir)
        cvd_names = sorted(
            item["name"] for item in snapshot["files"] if item["name"].endswith(".cvd")
        )
        if not sigtool:
            return {
                "checked": False,
                "ok": None,
                "reason": "sigtool is not installed; signature database digital signature was not verified",
                "files": [],
            }
        if not cvd_names:
            return {
                "checked": False,
                "ok": None,
                "reason": "no .cvd signature database found; the .cld directory format carries no CVD digital signature",
                "files": [],
            }
        results: list[dict[str, Any]] = []
        for name in cvd_names:
            path = os.path.join(self.config.database_dir, name)
            outcome = run(
                [sigtool, f"--info={path}"], timeout=60, max_output=32768
            )
            text = f"{outcome.stdout}\n{outcome.stderr}"
            verified = bool(
                outcome.ok and re.search(r"verification ok", text, re.IGNORECASE)
            )
            results.append(
                {
                    "name": name,
                    "verified": verified,
                    "exit_code": outcome.returncode,
                    "output_tail": outcome.tail(500),
                }
            )
        return {
            "checked": True,
            "ok": all(item["verified"] for item in results),
            "sigtool": sigtool,
            "files": results,
        }

    # ------------------------------------------------------------------ scan
    def _iter_files(
        self, targets: list[str], errors: list[dict[str, Any]], skipped: dict[str, int]
    ) -> Iterator[tuple[str, int]]:
        for target in targets:
            if os.path.islink(target):
                skipped["symlink_targets"] += 1
                continue
            if os.path.isfile(target):
                try:
                    st = os.lstat(target)
                except OSError as exc:
                    errors.append({"path": target, "error": exc.strerror})
                    continue
                if stat.S_ISREG(st.st_mode):
                    yield target, st.st_size
                else:
                    skipped["non_regular"] += 1
                continue
            if not os.path.isdir(target):
                errors.append({"path": target, "error": "target does not exist or is not a directory/regular file"})
                continue

            def on_error(exc: OSError) -> None:
                errors.append({"path": getattr(exc, "filename", target), "error": exc.strerror})

            for root, dirs, files in os.walk(target, topdown=True, onerror=on_error, followlinks=False):
                dirs[:] = [
                    d
                    for d in dirs
                    if not is_skipped_dir(os.path.join(root, d), self.scan_config.skip_paths)
                    and not is_skipped_dir(
                        os.path.join(root, d),
                        (str(self.data_dir / "quarantine"), str(self.data_dir / "evidence")),
                    )
                ]
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        st = os.lstat(path)
                    except OSError as exc:
                        errors.append({"path": path, "error": exc.strerror})
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        skipped["symlinks"] += 1
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        skipped["non_regular"] += 1
                        continue
                    yield path, st.st_size

    def run_task(self, task: dict[str, Any], context: TaskContext) -> ScanOutcome:
        if not self.client.ping():
            raise component_unavailable(
                "clamd is not running; cannot perform the scan", {"component": self.component_id}
            )
        if not _db_snapshot(self.config.database_dir)["present"]:
            raise component_unavailable("no signature database found; cannot perform the scan")
        targets = [str(t) for t in task.get("target_paths", [])]
        if not targets:
            raise invalid("scan targets are empty")

        max_bytes = self.scan_config.max_file_size_mb * 1024 * 1024
        errors: list[dict[str, Any]] = []
        max_errors = self.scan_config.max_errors_recorded
        skipped = {"large_files": 0, "symlinks": 0, "non_regular": 0, "symlink_targets": 0}
        files_scanned = 0
        detections = 0
        started = time.monotonic()

        # Count first so progress is real. If a walk fails, the count is partial
        # and progress is reported as null instead of inventing a percentage.
        total = 0
        counting_errors: list[dict[str, Any]] = []
        count_skipped = {"large_files": 0, "symlinks": 0, "non_regular": 0, "symlink_targets": 0}
        for _path, size in self._iter_files(targets, counting_errors, count_skipped):
            if 0 <= size <= max_bytes:
                total += 1
        if counting_errors:
            total = 0
            errors.extend(counting_errors[:max_errors])

        last_report = 0.0
        for path, size in self._iter_files(targets, errors, skipped):
            if context.cancel_event.is_set():
                return ScanOutcome(
                    files_scanned=files_scanned,
                    detections=detections,
                    errors=len(errors),
                    summary={
                        "cancelled": True,
                        "targets": targets,
                        "total_files": total or None,
                        "skipped": skipped,
                        "duration_seconds": round(time.monotonic() - started, 1),
                    },
                    error_details=errors[:max_errors],
                    cancelled=True,
                )
            if size > max_bytes:
                skipped["large_files"] += 1
                continue
            try:
                response = self.client.scan(path, timeout=self.scan_config.file_timeout_seconds)
            except ClamdError as exc:
                if len(errors) < max_errors:
                    errors.append({"path": path, "error": f"clamd: {exc}"})
                continue
            if response.endswith(" OK"):
                files_scanned += 1
            elif response.endswith(" FOUND"):
                detection_name = _parse_detection_name(response)
                sha256, hash_error = _sha256(path)
                detection = Detection(
                    path=path,
                    detection_name=detection_name,
                    size=size,
                    sha256=sha256,
                    details={
                        "raw_response": response[:1000],
                        "hash_error": hash_error,
                        "engine": "clamav",
                    },
                )
                detections += 1
                files_scanned += 1
                try:
                    context.on_detection(detection)
                except Exception as exc:  # event persistence must not abort scanning
                    log.exception("failed to record detection event")
                    if len(errors) < max_errors:
                        errors.append({"path": path, "error": f"failed to record event: {exc}"})
            else:
                if len(errors) < max_errors:
                    errors.append({"path": path, "error": response[:500] or "clamd returned an empty response"})

            now = time.monotonic()
            if now - last_report >= 1.0:
                progress = (files_scanned / total * 100.0) if total else None
                context.progress(files_scanned, total, detections, len(errors), progress)
                last_report = now

        progress = (files_scanned / total * 100.0) if total else None
        context.progress(files_scanned, total, detections, len(errors), progress)
        return ScanOutcome(
            files_scanned=files_scanned,
            detections=detections,
            errors=len(errors),
            summary={
                "targets": targets,
                "total_files": total or None,
                "skipped": skipped,
                "duration_seconds": round(time.monotonic() - started, 1),
            },
            error_details=errors[:max_errors],
        )


def _parse_detection_name(response: str) -> str:
    text = response.strip()
    if " FOUND" in text:
        text = text.rsplit(" FOUND", 1)[0]
    if ": " in text:
        return text.rsplit(": ", 1)[1].strip() or "Unknown"
    return text or "Unknown"
