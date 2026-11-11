"""YARA rule-pack validation, version management and signature verification.

Design notes
------------
* The daemon never downloads rule packs. An administrator places a pack in the
  configured inbox and explicitly installs it.
* A pack is a zip archive or directory containing ``manifest.json``, an
  optional ``manifest.sig`` detached signature, and the rule files listed in
  the manifest. Every listed rule file is pinned by SHA-256.
* Signature verification is required by default. Verification uses the
  configured OpenSSL public key; a missing/invalid signature is rejected before
  anything is activated.
* The rules are compiled with ``yarac`` before installation. A pack that does
  not compile is rejected and never becomes active.
* Versions are stored separately. Activation only switches the active version
  pointer; the previous version remains on disk for rollback.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from ..common.config import YaraConfig
from ..common.errors import (
    ErrorCode,
    LsecError,
    component_unavailable,
    conflict,
    invalid,
    not_found,
)
from ..common.executor import run, which
from ..common.ids import new_id
from ..common.logging import get_logger
from ..common.paths import ensure_dir, is_within, require_directory, require_regular_file
from ..common.timeutil import now_iso

log = get_logger("core.yara")

PACK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RULE_NAME_RE = re.compile(r"(?m)^\s*(?:private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
ALLOWED_SUFFIXES = (".yar", ".yara")
MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
MAX_FILES = 500
MAX_SINGLE_FILE = 10 * 1024 * 1024


class YaraRulePackService:
    def __init__(self, config: YaraConfig) -> None:
        self.config = config
        self.root = Path(config.rules_dir)
        self.inbox = Path(config.inbox_dir)
        self.packs_root = self.root / "packs"
        self.staging_root = self.root / "staging"
        self.state_path = self.root / "state.json"
        self._lock = threading.RLock()
        self._prepare()

    # ------------------------------------------------------------- lifecycle
    def _prepare(self) -> None:
        ensure_dir(self.root, 0o750)
        ensure_dir(self.inbox, 0o750)
        ensure_dir(self.packs_root, 0o750)
        ensure_dir(self.staging_root, 0o700)

    # ---------------------------------------------------------------- state
    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"schema_version": 1, "active": {}}
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LsecError(
                ErrorCode.INTERNAL,
                f"YARA 状态文件损坏: {exc}",
                {"path": str(self.state_path)},
            ) from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("active"), dict):
            raise LsecError(
                ErrorCode.INTERNAL,
                "YARA 状态文件格式无效",
                {"path": str(self.state_path)},
            )
        active: dict[str, str] = {}
        for pack_id, version in raw["active"].items():
            if (
                isinstance(pack_id, str)
                and PACK_ID_RE.match(pack_id)
                and isinstance(version, str)
                and VERSION_RE.match(version)
            ):
                active[pack_id] = version
        return {"schema_version": 1, "active": active}

    def _save_state(self, state: dict[str, Any]) -> None:
        ensure_dir(self.root, 0o750)
        fd, temporary = tempfile.mkstemp(
            prefix=".state-", suffix=".json", dir=str(self.root)
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            try:
                os.unlink(temporary)
            except OSError:
                pass

    # -------------------------------------------------------------- listing
    def list_packs(self) -> list[dict[str, Any]]:
        with self._lock:
            state = self._load_state()
            active = state["active"]
            packs: list[dict[str, Any]] = []
            if not self.packs_root.exists():
                return packs
            for pack_dir in sorted(self.packs_root.iterdir()):
                if not pack_dir.is_dir() or not PACK_ID_RE.match(pack_dir.name):
                    continue
                versions: list[dict[str, Any]] = []
                for version_dir in sorted(pack_dir.iterdir()):
                    if (
                        not version_dir.is_dir()
                        or not VERSION_RE.match(version_dir.name)
                    ):
                        continue
                    record = self._read_installed(pack_dir.name, version_dir)
                    if record:
                        versions.append(record)
                if versions:
                    for record in versions:
                        record["active"] = (
                            active.get(pack_dir.name) == record["version"]
                        )
                    packs.append(
                        {
                            "pack_id": pack_dir.name,
                            "name": versions[-1].get("name") or pack_dir.name,
                            "active_version": active.get(pack_dir.name),
                            "versions": versions,
                        }
                    )
            return packs

    def _read_installed(
        self, pack_id: str, version_dir: Path
    ) -> dict[str, Any] | None:
        try:
            manifest = json.loads(
                (version_dir / MANIFEST).read_text(encoding="utf-8")
            )
            install = json.loads(
                (version_dir / "install.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(manifest, dict) or not isinstance(install, dict):
            return None
        if manifest.get("pack_id") != pack_id or manifest.get("version") != version_dir.name:
            return None
        rules = manifest.get("rules") if isinstance(manifest.get("rules"), list) else []
        return {
            "pack_id": pack_id,
            "version": version_dir.name,
            "name": str(manifest.get("name") or pack_id)[:120],
            "description": str(manifest.get("description") or "")[:1000],
            "created_at": manifest.get("created_at"),
            "rule_files": [str(item.get("path"))[:300] for item in rules if isinstance(item, dict)],
            "rules_count": int(install.get("rules_count") or 0),
            "installed_at": install.get("installed_at"),
            "signature_verified": bool(install.get("signature_verified")),
            "signature_key_fingerprint": install.get("signature_key_fingerprint"),
            "source_name": install.get("source_name"),
            "manifest_sha256": install.get("manifest_sha256"),
            "active": False,
        }

    # -------------------------------------------------------------- install
    def install(
        self,
        source_path: str,
        *,
        activate: bool,
    ) -> dict[str, Any]:
        with self._lock:
            source = self._validated_source(source_path)
            source_name = os.path.basename(source)
            staging = self.staging_root / new_id()
            ensure_dir(staging, 0o700)
            try:
                if source.is_dir():
                    self._copy_directory(source, staging)
                else:
                    self._extract_zip(source, staging)
                manifest_raw, manifest = self._load_manifest(staging)
                pack_id = manifest["pack_id"]
                version = manifest["version"]
                rule_entries = manifest["rules"]
                self._verify_files_present(staging, rule_entries)
                self._verify_hashes(staging, rule_entries)
                signature_verified, key_fingerprint = self._verify_signature(
                    staging, manifest_raw
                )
                rules_count = self._compile(staging, rule_entries)
                destination = self.packs_root / pack_id / version
                if destination.exists():
                    raise conflict(
                        "该规则包版本已安装，拒绝覆盖",
                        {"pack_id": pack_id, "version": version},
                    )
                record = {
                    "schema_version": 1,
                    "installed_at": now_iso(),
                    "source_name": source_name[:300],
                    "signature_verified": signature_verified,
                    "signature_key_fingerprint": key_fingerprint,
                    "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                    "rules_count": rules_count,
                }
                self._write_private_json(staging / "install.json", record)
                ensure_dir(destination.parent, 0o750)
                os.replace(staging, destination)
                self._harden_tree(destination)
                if activate:
                    state = self._load_state()
                    state["active"][pack_id] = version
                    self._save_state(state)
                log.info(
                    "YARA 规则包已安装 pack=%s version=%s signature=%s",
                    pack_id,
                    version,
                    signature_verified,
                )
                return {
                    "pack_id": pack_id,
                    "version": version,
                    "name": manifest["name"],
                    "rules_count": rules_count,
                    "signature_verified": signature_verified,
                    "activated": bool(activate),
                    "path": str(destination),
                }
            except Exception:
                shutil.rmtree(staging, ignore_errors=True)
                raise

    def _validated_source(self, source_path: str) -> Path:
        if not isinstance(source_path, str) or not source_path:
            raise invalid("必须提供规则包路径")
        if "\x00" in source_path or "\n" in source_path or "\r" in source_path:
            raise invalid("规则包路径包含非法字符")
        if not os.path.isabs(source_path):
            raise invalid("规则包路径必须是绝对路径")
        if not is_within(source_path, str(self.inbox)):
            raise invalid(
                "规则包必须位于受控的 inbox 目录内",
                {"inbox": str(self.inbox)},
            )
        if not os.path.exists(source_path):
            raise invalid(f"规则包路径不存在: {source_path}")
        if os.path.islink(source_path):
            raise invalid("规则包路径不能是符号链接")
        source = Path(source_path)
        if source.is_dir():
            require_directory(str(source), field="规则包目录")
            return source
        require_regular_file(str(source), field="规则包文件")
        if source.suffix.lower() != ".zip":
            raise invalid("规则包文件必须是 .zip 或目录")
        if source.stat().st_size > self.config.max_pack_mb * 1024 * 1024:
            raise invalid("规则包文件超过大小限制")
        return source

    def _extract_zip(self, source: Path, staging: Path) -> None:
        try:
            archive = zipfile.ZipFile(source)
        except (OSError, zipfile.BadZipFile) as exc:
            raise invalid(f"无法读取规则包: {exc}") from exc
        with archive:
            members = archive.infolist()
            if len(members) > MAX_FILES:
                raise invalid("规则包文件数量超过限制")
            total = 0
            for info in members:
                relative = self._safe_relative(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise invalid(f"规则包包含符号链接，拒绝安装: {info.filename}")
                if info.is_dir():
                    ensure_dir(staging / relative, 0o700)
                    continue
                if info.file_size > MAX_SINGLE_FILE:
                    raise invalid(f"规则包内单个文件过大: {info.filename}")
                total += info.file_size
                if total > self.config.max_pack_mb * 1024 * 1024:
                    raise invalid("规则包解压后超过大小限制")
                destination = staging / relative
                ensure_dir(destination.parent, 0o700)
                self._write_bytes(destination, archive.read(info))

    def _copy_directory(self, source: Path, staging: Path) -> None:
        seen = 0
        total = 0
        for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
            for dirname in list(dirnames):
                candidate = Path(dirpath) / dirname
                if candidate.is_symlink():
                    raise invalid(f"规则包目录包含符号链接，拒绝安装: {candidate}")
            for filename in filenames:
                candidate = Path(dirpath) / filename
                relative = candidate.relative_to(source)
                if candidate.is_symlink():
                    raise invalid(f"规则包目录包含符号链接，拒绝安装: {candidate}")
                st = candidate.lstat()
                if not stat.S_ISREG(st.st_mode):
                    raise invalid(f"规则包目录包含非普通文件: {candidate}")
                seen += 1
                if seen > MAX_FILES:
                    raise invalid("规则包文件数量超过限制")
                if st.st_size > MAX_SINGLE_FILE:
                    raise invalid(f"规则包内单个文件过大: {relative}")
                total += st.st_size
                if total > self.config.max_pack_mb * 1024 * 1024:
                    raise invalid("规则包超过大小限制")
                destination = staging / self._safe_relative(str(relative))
                ensure_dir(destination.parent, 0o700)
                self._write_bytes(destination, candidate.read_bytes())

    @staticmethod
    def _safe_relative(name: str) -> Path:
        if not name or "\x00" in name or "\\" in name:
            raise invalid(f"规则包内路径非法: {name!r}")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or ":" in name:
            raise invalid(f"规则包内路径越界: {name}")
        parts = [part for part in pure.parts if part not in {"", "."}]
        if not parts:
            raise invalid("规则包内存在空路径")
        return Path(*parts)

    @staticmethod
    def _write_bytes(destination: Path, data: bytes) -> None:
        fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    def _load_manifest(self, staging: Path) -> tuple[bytes, dict[str, Any]]:
        path = staging / MANIFEST
        require_regular_file(str(path), field="manifest.json")
        raw = path.read_bytes()
        if len(raw) > 64 * 1024:
            raise invalid("manifest.json 超过 64KB")
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise invalid(f"manifest.json 不是合法 JSON: {exc}") from exc
        if not isinstance(manifest, dict):
            raise invalid("manifest.json 必须是对象")
        if manifest.get("schema_version") != 1:
            raise invalid("不支持的 manifest schema_version")
        pack_id = manifest.get("pack_id")
        version = manifest.get("version")
        name = manifest.get("name")
        if not isinstance(pack_id, str) or not PACK_ID_RE.match(pack_id):
            raise invalid("manifest.pack_id 格式无效")
        if not isinstance(version, str) or not VERSION_RE.match(version):
            raise invalid("manifest.version 格式无效")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise invalid("manifest.name 必须为 1-120 字符")
        rules = manifest.get("rules")
        if not isinstance(rules, list) or not rules:
            raise invalid("manifest.rules 不能为空")
        if len(rules) > self.config.max_rule_files:
            raise invalid("manifest.rules 数量超过配置上限")
        normalised: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in rules:
            if not isinstance(item, dict):
                raise invalid("manifest.rules 条目必须是对象")
            rule_path = item.get("path")
            digest = item.get("sha256")
            if not isinstance(rule_path, str):
                raise invalid("manifest.rules[].path 必须是字符串")
            relative = self._safe_relative(rule_path)
            text = relative.as_posix()
            if not text.endswith(ALLOWED_SUFFIXES):
                raise invalid(f"规则文件必须使用 .yar/.yara: {text}")
            if text in seen:
                raise invalid(f"manifest 中规则路径重复: {text}")
            seen.add(text)
            if not isinstance(digest, str) or not SHA256_RE.match(digest):
                raise invalid(f"规则文件 sha256 无效: {text}")
            normalised.append({"path": text, "sha256": digest})
        manifest["rules"] = normalised
        return raw, manifest

    def _verify_files_present(
        self, staging: Path, entries: list[dict[str, str]]
    ) -> None:
        allowed = {MANIFEST, SIGNATURE} | {item["path"] for item in entries}
        for dirpath, _dirnames, filenames in os.walk(staging):
            for filename in filenames:
                relative = (Path(dirpath) / filename).relative_to(staging).as_posix()
                if relative not in allowed:
                    raise invalid(f"规则包包含未在 manifest 中声明的文件: {relative}")

    def _verify_hashes(self, staging: Path, entries: list[dict[str, str]]) -> None:
        for item in entries:
            path = staging / item["path"]
            require_regular_file(str(path), field=item["path"])
            digest = hashlib.sha256()
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    digest.update(chunk)
            if digest.hexdigest() != item["sha256"]:
                raise invalid(f"规则文件哈希校验失败: {item['path']}")

    def _verify_signature(
        self, staging: Path, manifest_raw: bytes
    ) -> tuple[bool, str | None]:
        key_path = self.config.public_key
        signature = staging / SIGNATURE
        if not key_path:
            if self.config.require_signature:
                raise invalid("未配置 YARA 可信公钥，拒绝安装未验证规则包")
            return False, None
        if not os.path.isfile(key_path) or os.path.islink(key_path):
            raise invalid(
                "YARA 可信公钥不存在或不是普通文件",
                {"public_key": key_path},
            )
        if not signature.exists():
            raise invalid("规则包缺少 manifest.sig 签名文件")
        require_regular_file(str(signature), field="manifest.sig")
        openssl = which("openssl")
        if not openssl:
            raise component_unavailable("未找到 openssl，无法校验规则包签名")
        result = run(
            [
                openssl,
                "dgst",
                "-sha256",
                "-verify",
                key_path,
                "-signature",
                str(signature),
                str(staging / MANIFEST),
            ],
            timeout=10,
            max_output=8192,
        )
        if not result.ok:
            raise invalid(
                "规则包签名校验失败",
                {"detail": result.tail(500)},
            )
        try:
            key_bytes = Path(key_path).read_bytes()
        except OSError as exc:
            raise invalid(f"无法读取 YARA 可信公钥: {exc}") from exc
        fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
        return True, fingerprint

    def _compile(self, staging: Path, entries: list[dict[str, str]]) -> int:
        yarac = which(self.config.yarac_binary)
        if not yarac:
            raise component_unavailable("未找到 yarac，无法校验 YARA 规则")
        rule_files = [str(staging / item["path"]) for item in entries]
        compiled = staging / ".compile-check"
        try:
            result = run(
                [yarac, *rule_files, str(compiled)],
                timeout=self.config.scan_timeout_seconds,
                max_output=16384,
            )
            if not result.ok or not compiled.exists():
                raise invalid(
                    "YARA 规则编译失败，规则包拒绝加载",
                    {"detail": result.tail(1200) or "yarac 未生成编译结果"},
                )
        finally:
            try:
                compiled.unlink()
            except OSError:
                pass
        # Count declarations for operator display. This is informational only;
        # yarac is the authority on whether the pack compiles.
        names: list[str] = []
        for item in entries:
            try:
                text = (staging / item["path"]).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
            names.extend(RULE_NAME_RE.findall(text))
        return len(names)

    # ------------------------------------------------------------- activate
    def activate(self, pack_id: str, version: str) -> dict[str, Any]:
        self._validate_ref(pack_id, version)
        with self._lock:
            path = self.packs_root / pack_id / version
            if not path.is_dir() or not (path / MANIFEST).is_file():
                raise not_found("规则包版本不存在")
            state = self._load_state()
            state["active"][pack_id] = version
            self._save_state(state)
        log.info("YARA 规则包已激活 pack=%s version=%s", pack_id, version)
        return {
            "pack_id": pack_id,
            "version": version,
            "active_version": version,
        }

    def delete(self, pack_id: str, version: str) -> dict[str, Any]:
        self._validate_ref(pack_id, version)
        with self._lock:
            state = self._load_state()
            if state["active"].get(pack_id) == version:
                raise conflict("不能删除当前激活的规则包版本，请先激活其他版本")
            path = self.packs_root / pack_id / version
            if not path.is_dir():
                raise not_found("规则包版本不存在")
            shutil.rmtree(path)
            try:
                path.parent.rmdir()
            except OSError:
                pass
        log.info("YARA 规则包版本已删除 pack=%s version=%s", pack_id, version)
        return {"pack_id": pack_id, "version": version, "deleted": True}

    @staticmethod
    def _validate_ref(pack_id: str, version: str) -> None:
        if not isinstance(pack_id, str) or not PACK_ID_RE.match(pack_id):
            raise invalid("规则包 ID 格式无效")
        if not isinstance(version, str) or not VERSION_RE.match(version):
            raise invalid("规则包版本格式无效")

    # ---------------------------------------------------------------- scans
    def active_rule_sets(self) -> list[dict[str, Any]]:
        """Return active packs with absolute rule-file paths.

        A missing/corrupt active version is reported instead of being silently
        ignored, so the UI and scan result can distinguish "no rules" from
        "rules configured but unavailable".
        """
        with self._lock:
            state = self._load_state()
            active = state["active"]
            result: list[dict[str, Any]] = []
            for pack_id, version in sorted(active.items()):
                base = self.packs_root / pack_id / version
                manifest_path = base / MANIFEST
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    entries = manifest.get("rules")
                    if not isinstance(entries, list):
                        raise ValueError("rules missing")
                    files: list[Path] = []
                    for item in entries:
                        relative = self._safe_relative(str(item.get("path")))
                        path = base / relative
                        if not path.is_file() or path.is_symlink():
                            raise ValueError(f"missing rule file {relative}")
                        files.append(path)
                    result.append(
                        {
                            "pack_id": pack_id,
                            "version": version,
                            "name": str(manifest.get("name") or pack_id),
                            "rule_files": files,
                            "rules_count": len(files),
                        }
                    )
                except (OSError, ValueError, json.JSONDecodeError, LsecError) as exc:
                    result.append(
                        {
                            "pack_id": pack_id,
                            "version": version,
                            "name": pack_id,
                            "rule_files": [],
                            "error": str(exc)[:300],
                        }
                    )
            return result

    def scan_snapshot(self) -> dict[str, Any]:
        try:
            packs = self.list_packs()
            state_error = None
        except LsecError as exc:
            packs = []
            state_error = exc.message
        active = []
        for pack in packs:
            for version in pack["versions"]:
                if version.get("active"):
                    active.append(
                        {
                            "pack_id": pack["pack_id"],
                            "version": version["version"],
                            "name": version["name"],
                            "rules_count": version["rules_count"],
                            "signature_verified": version["signature_verified"],
                        }
                    )
        key_exists = bool(
            self.config.public_key
            and os.path.isfile(self.config.public_key)
            and not os.path.islink(self.config.public_key)
        )
        return {
            "enabled": bool(self.config.enabled),
            "rules_dir": str(self.root),
            "inbox_dir": str(self.inbox),
            "packs_count": len(packs),
            "active_count": len(active),
            "active": active,
            "packs": packs,
            "signature": {
                "required": bool(self.config.require_signature),
                "public_key": self.config.public_key or None,
                "public_key_present": key_exists,
            },
            "state_error": state_error,
            "limits": {
                "max_pack_mb": self.config.max_pack_mb,
                "max_rule_files": self.config.max_rule_files,
            },
        }

    # ------------------------------------------------------------- internals
    @staticmethod
    def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())

    @staticmethod
    def _harden_tree(root: Path) -> None:
        for dirpath, _dirnames, filenames in os.walk(root):
            try:
                os.chmod(dirpath, 0o750)
            except OSError:
                pass
            for filename in filenames:
                try:
                    os.chmod(os.path.join(dirpath, filename), 0o600)
                except OSError:
                    pass
