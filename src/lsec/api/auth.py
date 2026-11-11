"""Authentication, sessions, roles and CSRF for the HTTP API."""

from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from ..common.errors import ErrorCode, LsecError, forbidden, unauthorized
from ..storage import sessions as session_store
from ..storage.db import Database

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLE_INTEGRATION = "integration"
COOKIE_NAME = "lsec_session"


def _write_secret(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (value + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _replace_secret(path: Path, value: str) -> None:
    """Atomically replace a token file with a 0600 file."""
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        if temporary.exists():
            temporary.unlink()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (value + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def ensure_tokens(secrets_dir: Path) -> dict[str, str]:
    """Create/read admin & viewer tokens. Values are never logged."""
    secrets_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(secrets_dir, 0o700)
    except OSError:
        pass
    tokens: dict[str, str] = {}
    for role, env_name in (
        (ROLE_ADMIN, "LSEC_ADMIN_TOKEN"),
        (ROLE_VIEWER, "LSEC_VIEWER_TOKEN"),
    ):
        path = secrets_dir / f"{role}.token"
        env_value = os.environ.get(env_name)
        if env_value:
            if len(env_value) < 16:
                raise ValueError(f"{env_name} 长度必须至少 16 个字符")
            value = env_value
            # Keep the on-disk token in sync so the CLI can find the same
            # credential the daemon is using. Never log either value.
            try:
                existing = path.read_text(encoding="utf-8").strip()
            except OSError:
                existing = None
            if existing != value:
                _replace_secret(path, value)
        elif path.exists():
            value = path.read_text(encoding="utf-8").strip()
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        else:
            value = secrets.token_urlsafe(32)
            _write_secret(path, value)
        if not value:
            raise ValueError(f"空令牌文件: {path}")
        tokens[role] = value
    return tokens


def ensure_falco_token(secrets_dir: Path, enabled: bool) -> str | None:
    """Create/read the dedicated Falco integration token.

    This token can only post to the Falco ingestion endpoint. It is not part of
    the admin/viewer token map, so it cannot read status or perform any other
    operation.
    """
    if not enabled:
        return None
    secrets_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(secrets_dir, 0o700)
    except OSError:
        pass
    path = secrets_dir / "falco.token"
    env_value = os.environ.get("LSEC_FALCO_TOKEN")
    if env_value:
        if len(env_value) < 16:
            raise ValueError("LSEC_FALCO_TOKEN 长度必须至少 16 个字符")
        value = env_value
        try:
            existing = path.read_text(encoding="utf-8").strip()
        except OSError:
            existing = None
        if existing != value:
            _replace_secret(path, value)
    elif path.exists():
        value = path.read_text(encoding="utf-8").strip()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    else:
        value = secrets.token_urlsafe(32)
        _write_secret(path, value)
    if not value:
        raise ValueError(f"空令牌文件: {path}")
    return value


class LoginRateLimiter:
    def __init__(self, attempts_per_minute: int = 10) -> None:
        self.limit = max(1, attempts_per_minute)
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            while bucket and now - bucket[0] > 60:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True


class AuthService:
    def __init__(
        self,
        db: Database,
        tokens: dict[str, str],
        ttl_hours: int,
        *,
        falco_token: str | None = None,
    ) -> None:
        self.db = db
        self.tokens = tokens
        self.ttl_hours = ttl_hours
        self.falco_token = falco_token
        self.rate_limiter = LoginRateLimiter()
        self.integration_rate_limiter = LoginRateLimiter(240)

    def token_role(self, token: str) -> str | None:
        if not token:
            return None
        candidate = token.encode("utf-8")
        matched: str | None = None
        for role, expected in self.tokens.items():
            if hmac.compare_digest(candidate, expected.encode("utf-8")):
                matched = role
        return matched

    def falco_token_valid(self, token: str) -> bool:
        if not self.falco_token or not token:
            return False
        return hmac.compare_digest(
            token.encode("utf-8"), self.falco_token.encode("utf-8")
        )

    def login(
        self, token: str, remote_addr: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        if not self.rate_limiter.check(remote_addr):
            raise LsecError(
                ErrorCode.RATE_LIMITED,
                "登录尝试过于频繁，请稍后再试",
                http_status=429,
            )
        role = self.token_role(token)
        if not role:
            return None, None
        session = session_store.create(
            self.db, role=role, ttl_hours=self.ttl_hours, remote_addr=remote_addr
        )
        return session, role

    def session(
        self, session_id: str | None
    ) -> dict[str, Any] | None:
        if not session_id:
            return None
        return session_store.get_valid(self.db, session_id)

    def logout(self, session_id: str | None) -> None:
        if session_id:
            session_store.delete(self.db, session_id)


def require_admin(role: str) -> None:
    if role != ROLE_ADMIN:
        raise forbidden("该操作需要管理员权限")


def csrf_valid(session: dict[str, Any], supplied: str | None) -> bool:
    if not supplied:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), session["csrf_token"].encode("utf-8"))
