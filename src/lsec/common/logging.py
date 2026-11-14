"""Structured application logging with rotation.

Secrets are never logged. Callers must not interpolate tokens, file contents
or credential material into log messages.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_CONFIGURED = False


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("component", "request_id", "action", "task_id", "event_id"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backups: int = 5,
) -> None:
    global _CONFIGURED
    root = logging.getLogger("lsec")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    if _CONFIGURED:
        return
    formatter = JsonFormatter()

    stderr = logging.StreamHandler(sys.stderr)
    stderr.setFormatter(formatter)
    root.addHandler(stderr)

    if log_file:
        try:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError as exc:  # pragma: no cover - environment dependent
            root.warning("cannot open log file %s: %s", log_file, exc)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"lsec.{name}")
