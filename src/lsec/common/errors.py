"""Typed error model shared by daemon, API and CLI."""

from __future__ import annotations

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    INVALID_ARGUMENT = "invalid_argument"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    COMPONENT_UNAVAILABLE = "component_unavailable"
    TASK_FAILED = "task_failed"
    NOT_IMPLEMENTED = "not_implemented"
    INTERNAL = "internal_error"


HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_ARGUMENT: 400,
    ErrorCode.UNAUTHORIZED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.COMPONENT_UNAVAILABLE: 503,
    ErrorCode.TASK_FAILED: 500,
    ErrorCode.NOT_IMPLEMENTED: 501,
    ErrorCode.INTERNAL: 500,
}


class LsecError(Exception):
    """An expected, user-facing failure with a stable code."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        details: Any = None,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details
        self.http_status = http_status or HTTP_STATUS.get(code, 500)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.details is not None:
            payload["details"] = self.details
        return payload


def invalid(message: str, details: Any = None) -> LsecError:
    return LsecError(ErrorCode.INVALID_ARGUMENT, message, details)


def not_found(message: str) -> LsecError:
    return LsecError(ErrorCode.NOT_FOUND, message)


def conflict(message: str, details: Any = None) -> LsecError:
    return LsecError(ErrorCode.CONFLICT, message, details)


def unauthorized(message: str = "Login or a valid access token is required") -> LsecError:
    return LsecError(ErrorCode.UNAUTHORIZED, message)


def forbidden(message: str) -> LsecError:
    return LsecError(ErrorCode.FORBIDDEN, message)


def component_unavailable(message: str, details: Any = None) -> LsecError:
    return LsecError(ErrorCode.COMPONENT_UNAVAILABLE, message, details)


def not_implemented(message: str) -> LsecError:
    return LsecError(ErrorCode.NOT_IMPLEMENTED, message)
