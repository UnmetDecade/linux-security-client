"""Path validation shared by scans, quarantine and report generation.

Rules:
- Paths must be absolute, non-empty and free of NUL/newline characters.
- Symlinks are rejected for destructive operations; scans never follow them.
- Callers that act on user supplied paths must pass an allow-list of roots.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import invalid

MAX_PATH_LENGTH = 4096


def validate_path_text(path: object, *, field: str = "path") -> str:
    if not isinstance(path, str) or not path:
        raise invalid(f"{field} must be a non-empty string")
    if len(path) > MAX_PATH_LENGTH:
        raise invalid(f"{field} exceeds the maximum length {MAX_PATH_LENGTH}")
    if "\x00" in path or "\n" in path or "\r" in path:
        raise invalid(f"{field} contains illegal characters")
    if not os.path.isabs(path):
        raise invalid(f"{field} must be an absolute path: {path}")
    return path


def canonical(path: str, *, must_exist: bool = True) -> str:
    """Resolve a path, following symlinks, and require existence by default."""
    validate_path_text(path)
    real = os.path.realpath(path)
    if must_exist and not os.path.exists(real):
        raise invalid(f"path does not exist: {path}")
    return real


def is_within(path: str, root: str) -> bool:
    try:
        real_path = os.path.realpath(path)
        real_root = os.path.realpath(root)
    except OSError:
        return False
    if real_path == real_root:
        return True
    try:
        return os.path.commonpath([real_path, real_root]) == real_root
    except ValueError:
        return False


def ensure_within_roots(path: str, roots: tuple[str, ...] | list[str], *, field: str = "path") -> str:
    validate_path_text(path, field=field)
    if not any(is_within(path, root) for root in roots):
        raise invalid(
            f"{field} is outside the allowed roots",
            {"path": path, "allowed_roots": list(roots)},
        )
    return path


def require_regular_file(path: str, *, field: str = "path") -> os.stat_result:
    """Reject directories, symlinks, devices and FIFOs."""
    validate_path_text(path, field=field)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise invalid(f"cannot access {field}: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise invalid(f"{field} is a symlink; refusing operation: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise invalid(f"{field} is not a regular file: {path}")
    return st


def require_directory(path: str, *, field: str = "path") -> None:
    validate_path_text(path, field=field)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise invalid(f"cannot access {field}: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise invalid(f"{field} is not a regular directory: {path}")


def ensure_dir(path: Path, mode: int = 0o750) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def is_skipped_dir(path: str, skip_paths: tuple[str, ...] | list[str]) -> bool:
    for skip in skip_paths:
        if is_within(path, skip):
            return True
    return False
