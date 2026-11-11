"""Quarantine and restore operations (privileged, audited, never silent)."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from ..common.config import Config
from ..common.errors import conflict, invalid, not_found
from ..common.ids import new_id
from ..common.logging import get_logger
from ..common.paths import ensure_within_roots, require_regular_file, validate_path_text
from ..storage import audit as audit_store
from ..storage import quarantine as quarantine_store
from ..storage.db import Database

log = get_logger("core.quarantine")

CHUNK = 1024 * 1024


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, CHUNK)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


class QuarantineService:
    def __init__(self, db: Database, config: Config) -> None:
        self.db = db
        self.config = config
        self.root = config.quarantine_dir
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _audit(self, **kwargs: Any) -> None:
        try:
            audit_store.record(self.db, **kwargs)
        except Exception:  # pragma: no cover - audit must not mask the main result
            log.exception("写入审计记录失败")

    def quarantine(
        self,
        *,
        path: str,
        actor: str,
        request_id: str,
        client: str | None,
        confirmed: bool,
        event_id: str | None = None,
        engine: str | None = None,
        detection_name: str | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise invalid("隔离操作需要明确确认")
        validate_path_text(path)
        st = require_regular_file(path)
        real_path = os.path.realpath(path)
        ensure_within_roots(
            real_path, self.config.response.quarantine_roots, field="隔离路径"
        )
        size = st.st_size
        used = quarantine_store.total_size(self.db)
        if used + size > self.config.storage.quarantine_max_mb * 1024 * 1024:
            raise conflict("隔离区容量已达上限，请先清理")

        item_id = new_id()
        stored_name = f"{item_id}.bin"
        stored_path = self.root / stored_name
        source_fd = -1
        try:
            source_fd = os.open(real_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            fst = os.fstat(source_fd)
            if not stat.S_ISREG(fst.st_mode):
                raise invalid("隔离源不是普通文件")
            sha256 = _hash_fd(source_fd)
            dest_fd = os.open(
                stored_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.lseek(source_fd, 0, os.SEEK_SET)
                while True:
                    chunk = os.read(source_fd, CHUNK)
                    if not chunk:
                        break
                    os.write(dest_fd, chunk)
                os.fsync(dest_fd)
            finally:
                os.close(dest_fd)
            os.chmod(stored_path, 0o600)
            verify_fd = os.open(stored_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                stored_hash = _hash_fd(verify_fd)
            finally:
                os.close(verify_fd)
            if stored_hash != sha256:
                raise conflict("隔离文件校验失败，原文件未移动")

            # Ensure the path still points at the file we hashed before unlinking.
            current = os.lstat(real_path)
            if (current.st_dev, current.st_ino) != (fst.st_dev, fst.st_ino):
                raise conflict("文件在隔离过程中被替换，操作已中止")
            os.unlink(real_path)
        except BaseException:
            try:
                if stored_path.exists():
                    os.unlink(stored_path)
            except OSError:
                pass
            raise
        finally:
            if source_fd >= 0:
                os.close(source_fd)

        try:
            item = quarantine_store.add_item(
                self.db,
                original_path=real_path,
                stored_name=stored_name,
                sha256=sha256,
                size=size,
                actor=actor,
                engine=engine,
                detection_name=detection_name,
                event_id=event_id,
            )
        except BaseException:
            try:
                os.unlink(stored_path)
            except OSError:
                pass
            raise
        self._audit(
            action="quarantine.create",
            actor=actor,
            client=client,
            request_id=request_id,
            target=real_path,
            before_state={"exists": True, "size": size, "sha256": sha256},
            after_state={"item_id": item_id, "status": "quarantined"},
            confirmed=True,
            result="success",
        )
        log.info("文件已隔离 item=%s path=%s", item_id, real_path)
        return item

    def restore(
        self,
        *,
        item_id: str,
        actor: str,
        request_id: str,
        client: str | None,
        confirmed: bool,
    ) -> dict[str, Any]:
        if not confirmed:
            raise invalid("恢复操作需要明确确认")
        item = quarantine_store.get_item(self.db, item_id)
        if item["status"] != "quarantined":
            raise conflict(f"隔离项状态为 {item['status']}，无法恢复")
        stored_path = self.root / item["stored_name"]
        try:
            st = require_regular_file(str(stored_path), field="隔离存储文件")
        except Exception:
            quarantine_store.mark_missing(self.db, item_id, "隔离存储文件缺失")
            self._audit(
                action="quarantine.restore",
                actor=actor,
                client=client,
                request_id=request_id,
                target=item["original_path"],
                result="failure",
                error="隔离存储文件缺失",
                confirmed=True,
            )
            raise conflict("隔离存储文件缺失，无法恢复") from None
        original = item["original_path"]
        validate_path_text(original)
        ensure_within_roots(
            original, self.config.response.quarantine_roots, field="恢复路径"
        )
        parent = os.path.dirname(original) or "/"
        if not os.path.isdir(parent):
            raise invalid(f"原始目录不存在: {parent}")
        if os.path.lexists(original):
            raise conflict("原始路径已被占用，拒绝覆盖现有文件")

        src_fd = os.open(str(stored_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            src_hash = _hash_fd(src_fd)
            if src_hash != item["sha256"]:
                raise conflict("隔离文件哈希不匹配，拒绝恢复")
            dst_fd = os.open(
                original,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.lseek(src_fd, 0, os.SEEK_SET)
                while True:
                    chunk = os.read(src_fd, CHUNK)
                    if not chunk:
                        break
                    os.write(dst_fd, chunk)
                os.fsync(dst_fd)
            finally:
                os.close(dst_fd)
            verify_fd = os.open(original, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                restored_hash = _hash_fd(verify_fd)
            finally:
                os.close(verify_fd)
            if restored_hash != item["sha256"]:
                os.unlink(original)
                raise conflict("恢复后哈希校验失败，已删除目标文件")
            os.unlink(stored_path)
        finally:
            os.close(src_fd)

        updated = quarantine_store.mark_restored(self.db, item_id)
        self._audit(
            action="quarantine.restore",
            actor=actor,
            client=client,
            request_id=request_id,
            target=original,
            before_state={"status": "quarantined", "sha256": item["sha256"]},
            after_state={"status": "restored"},
            confirmed=True,
            result="success",
        )
        log.info("隔离文件已恢复 item=%s path=%s", item_id, original)
        return updated

    def delete(
        self,
        *,
        item_id: str,
        actor: str,
        request_id: str,
        client: str | None,
        confirmed: bool,
    ) -> dict[str, Any]:
        if not confirmed:
            raise invalid("删除隔离文件需要明确确认")
        item = quarantine_store.get_item(self.db, item_id)
        if item["status"] != "quarantined":
            raise conflict(f"隔离项状态为 {item['status']}，无法删除")
        stored_path = self.root / item["stored_name"]
        if not stored_path.exists():
            quarantine_store.mark_missing(self.db, item_id, "隔离存储文件缺失")
            self._audit(
                action="quarantine.delete",
                actor=actor,
                client=client,
                request_id=request_id,
                target=item["original_path"],
                result="failure",
                error="隔离存储文件缺失",
                confirmed=True,
            )
            raise conflict("隔离存储文件缺失，无法删除")
        os.unlink(stored_path)
        updated = quarantine_store.mark_deleted(self.db, item_id)
        self._audit(
            action="quarantine.delete",
            actor=actor,
            client=client,
            request_id=request_id,
            target=item["original_path"],
            before_state={"status": "quarantined", "sha256": item["sha256"]},
            after_state={"status": "deleted"},
            confirmed=True,
            result="success",
        )
        log.info("隔离文件已删除 item=%s", item_id)
        return updated

    def get(self, item_id: str) -> dict[str, Any]:
        item = quarantine_store.get_item(self.db, item_id)
        stored = self.root / item["stored_name"]
        item["file_exists"] = stored.exists()
        item["stored_path"] = str(stored)
        return item

    def list(self, **params: Any) -> tuple[list[dict[str, Any]], int]:
        return quarantine_store.list_items(self.db, **params)
