"""Safe external command execution.

Only argv arrays are accepted. No shell is ever used. Every command has a
timeout, output caps and process-group cleanup so a hung tool cannot take the
daemon down or exhaust memory.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass

DEFAULT_MAX_OUTPUT = 256 * 1024


@dataclass(frozen=True)
class ExecResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def tail(self, limit: int = 400) -> str:
        text = (self.stderr or self.stdout).strip()
        return text[-limit:]


def which(binary: str) -> str | None:
    if os.path.sep in binary:
        return binary if os.path.isfile(binary) and os.access(binary, os.X_OK) else None
    return shutil.which(binary)


def run(
    argv: list[str] | tuple[str, ...],
    *,
    timeout: float = 30,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    max_output: int = DEFAULT_MAX_OUTPUT,
    stdin_data: bytes | None = None,
) -> ExecResult:
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv must be a non-empty list")
    if not all(isinstance(arg, str) for arg in argv):
        raise ValueError("argv entries must be strings")
    if any("\x00" in arg for arg in argv):
        raise ValueError("argv entries must not contain NUL")

    started = time.monotonic()
    child_env = dict(os.environ)
    if env:
        child_env.update(env)
    input_data = stdin_data

    proc = subprocess.Popen(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        cwd=cwd,
        env=child_env,
        start_new_session=True,
        close_fds=True,
    )
    timed_out = False
    try:
        out_b, err_b = proc.communicate(input=input_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        try:
            out_b, err_b = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            out_b, err_b = b"", b""
    duration = round(time.monotonic() - started, 3)
    return ExecResult(
        argv=tuple(argv),
        returncode=None if timed_out else proc.returncode,
        stdout=_decode(out_b, max_output),
        stderr=_decode(err_b, max_output),
        timed_out=timed_out,
        duration_seconds=duration,
    )


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):  # pragma: no cover
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def _decode(data: bytes | None, max_output: int) -> str:
    if not data:
        return ""
    truncated = False
    if len(data) > max_output:
        data = data[:max_output]
        truncated = True
    text = data.decode("utf-8", errors="replace")
    if truncated:
        text += "\n...[输出已截断]"
    return text
