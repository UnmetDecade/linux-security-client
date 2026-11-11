"""YARA adapter: rule-pack status and on-demand rule scanning.

The adapter never downloads rules and never treats "installed" as protection.
Only rule packs that passed manifest, hash, signature and ``yarac`` validation
are used. Scanning is read-only.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable

from ..common.config import ScanConfig, YaraConfig
from ..common.errors import component_unavailable
from ..common.executor import run, which
from ..common.logging import get_logger
from ..common.paths import is_skipped_dir
from ..common.timeutil import now_iso
from ..core.yara import YaraRulePackService
from .base import (
    HEALTH_DEGRADED,
    HEALTH_OK,
    HEALTH_UNAVAILABLE,
    SERVICE_NOT_INSTALLED,
    SERVICE_STOPPED,
    SERVICE_UNKNOWN,
    Adapter,
    Detection,
    ProbeResult,
    ScanOutcome,
    TaskContext,
)

log = get_logger("adapters.yara")

# YARA prints ``rule_name [tag1,tag2] target`` when -g is used. Rule names are
# identifiers; the target may contain spaces, so split only where the grammar
# allows it.
MATCH_RE = re.compile(
    r"^(?P<rule>[A-Za-z_][A-Za-z0-9_]*)(?: \[(?P<tags>[^\]]*)\])? (?P<target>\S.*)$"
)
SEVERITY_TAGS = {
    "critical": "critical",
    "severity_critical": "critical",
    "high": "high",
    "severity_high": "high",
    "medium": "medium",
    "severity_medium": "medium",
    "low": "low",
    "severity_low": "low",
    "info": "info",
    "informational": "info",
    "test": "medium",
    "eicar": "medium",
}


def severity_for_tags(tags: Iterable[str]) -> str:
    normalised = {str(tag).strip().lower() for tag in tags if tag}
    for tag in (
        "critical",
        "severity_critical",
        "high",
        "severity_high",
        "medium",
        "severity_medium",
        "test",
        "eicar",
        "low",
        "severity_low",
        "info",
        "informational",
    ):
        if tag in normalised:
            return SEVERITY_TAGS[tag]
    return "high"


def parse_yara_output(output: str) -> list[tuple[str, list[str], str]]:
    matches: list[tuple[str, list[str], str]] = []
    for line in (output or "").splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        found = MATCH_RE.match(line)
        if not found:
            continue
        tags = [
            item.strip()
            for item in (found.group("tags") or "").split(",")
            if item.strip()
        ]
        matches.append((found.group("rule"), tags, found.group("target")))
    return matches


def _hash_file(path: str, limit: int) -> tuple[str | None, int]:
    """Hash a matched file without following symlinks (TOCTOU hardening)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None, 0
    try:
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                return None, st.st_size if stat.S_ISREG(st.st_mode) else 0
            digest = hashlib.sha256()
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest(), st.st_size
    except OSError:
        return None, 0


class YaraAdapter(Adapter):
    component_id = "yara"
    display_name = "YARA 规则检测"

    def __init__(
        self,
        config: YaraConfig,
        scan_config: ScanConfig,
        rules: YaraRulePackService,
    ) -> None:
        self.config = config
        self.scan_config = scan_config
        self.rules = rules

    # ---------------------------------------------------------------- probe
    def _version(self, binary: str | None) -> str | None:
        if not binary:
            return None
        result = run([binary, "--version"], timeout=6, max_output=4096)
        if result.ok:
            text = (result.stdout or result.stderr).strip().splitlines()
            if text:
                return text[0][:120]
        return None

    def probe(self) -> ProbeResult:
        binary = which(self.config.binary)
        yarac = which(self.config.yarac_binary)
        version = self._version(binary)
        yarac_version = self._version(yarac)
        snapshot = self.rules.scan_snapshot()
        details: dict[str, Any] = {
            "binary": binary,
            "version": version,
            "yarac": yarac,
            "yarac_version": yarac_version,
            "enabled": bool(self.config.enabled),
            "integration": "rule_scan" if self.config.enabled else "disabled",
            "rules_dir": snapshot.get("rules_dir"),
            "inbox_dir": snapshot.get("inbox_dir"),
            "packs_count": snapshot.get("packs_count", 0),
            "active_count": snapshot.get("active_count", 0),
            "active": snapshot.get("active", []),
            "signature": snapshot.get("signature"),
            "state_error": snapshot.get("state_error"),
            "checked_at": now_iso(),
        }
        if not self.config.enabled:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=bool(binary),
                version=version,
                service_status=SERVICE_UNKNOWN,
                health_status=HEALTH_UNAVAILABLE,
                capabilities=[],
                error_code="disabled",
                error_message="YARA 已在配置中禁用；不会执行规则扫描",
                details=details,
            )
        if not binary:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                capabilities=[],
                error_code="not_installed",
                error_message="未检测到 YARA 二进制，无法执行规则扫描",
                details=details,
            )
        if not yarac:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=True,
                version=version,
                service_status=SERVICE_STOPPED,
                health_status=HEALTH_DEGRADED,
                capabilities=["rule_scan"],
                error_code="yarac_missing",
                error_message="YARA 已安装，但缺少 yarac，无法校验和加载规则包",
                details=details,
            )
        if details["state_error"]:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=True,
                version=version,
                service_status=SERVICE_STOPPED,
                health_status=HEALTH_DEGRADED,
                capabilities=["rule_scan"],
                error_code="rules_state_error",
                error_message=str(details["state_error"])[:300],
                details=details,
            )
        if not snapshot.get("active_count"):
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=True,
                version=version,
                service_status=SERVICE_STOPPED,
                health_status=HEALTH_DEGRADED,
                capabilities=["rule_pack_management"],
                error_code="no_active_packs",
                error_message="YARA 已安装，但没有已激活的规则包，规则扫描不可用",
                details=details,
            )
        key_ready = bool((snapshot.get("signature") or {}).get("public_key_present"))
        warning = None
        if self.config.require_signature and not key_ready:
            warning = "规则包签名校验已启用，但可信公钥尚未配置；新规则包无法安装"
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            version=version,
            service_status=SERVICE_UNKNOWN,
            health_status=HEALTH_OK,
            capabilities=[
                "rule_scan",
                "rule_pack_management",
                "signature_verification",
            ],
            error_code=None,
            error_message=warning,
            details=details,
        )

    def install_plan(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "installable_from_ui": False,
            "package_source": "发行版官方仓库（Debian/Ubuntu: yara）",
            "privileges": "规则扫描本身不需要 root；安装软件包需要系统包管理器权限",
            "dependencies": ["python3（客户端）", "yara", "yarac（通常随 yara 提供）", "openssl（签名校验）"],
            "steps": [
                "在宿主或镜像中通过官方仓库安装 yara 与 openssl",
                "将经过签名和哈希校验的规则包放入 YARA inbox 目录",
                "在 Web/CLI 中显式安装并激活规则包",
            ],
            "notes": [
                "本客户端不会自动下载或加载未验证规则包",
                "YARA 是规则匹配引擎，命中不等同于已确认恶意软件",
                "不会自动隔离或删除命中文件",
            ],
        }

    # -------------------------------------------------------------- scanning
    def run_task(self, task: dict[str, Any], context: TaskContext) -> ScanOutcome:
        if not self.config.enabled:
            raise component_unavailable("YARA 已在配置中禁用")
        packs = self.rules.active_rule_sets()
        usable = [pack for pack in packs if not pack.get("error") and pack.get("rule_files")]
        pack_errors = [
            {
                "pack_id": pack.get("pack_id"),
                "version": pack.get("version"),
                "error": pack.get("error"),
            }
            for pack in packs
            if pack.get("error") or not pack.get("rule_files")
        ]
        if not usable:
            raise component_unavailable(
                "没有可用的 YARA 规则包，请先安装并激活经过校验的规则包",
                {"packs": pack_errors},
            )
        yara = which(self.config.binary)
        yarac = which(self.config.yarac_binary)
        if not yara or not yarac:
            raise component_unavailable("YARA 或 yarac 不可用，无法执行规则扫描")

        files, skipped = self._enumerate_targets(task.get("target_paths") or [])
        outcome = ScanOutcome()
        outcome.error_details.extend(pack_errors)
        outcome.errors += len(pack_errors)
        outcome.files_scanned = 0
        outcome.summary.update(
            {
                "engine": "yara",
                "packs_total": len(packs),
                "packs_usable": len(usable),
                "packs_scanned": 0,
                "candidate_files": len(files),
                "skipped": skipped,
                "files_scanned_semantics": "files submitted to YARA",
                "note": (
                    "YARA CLI 不提供文件级进度或扫描总数；进度按已提交给 YARA 的文件数计算，"
                    "files_scanned 表示实际提交给 YARA 的文件数。"
                ),
            }
        )
        if not files:
            outcome.summary["total_files"] = 0
            outcome.summary["packs_scanned"] = len(usable)
            return outcome

        total_units = len(files) * len(usable)
        processed_units = 0
        file_set = set(files)
        attempted: set[str] = set()
        seen: set[tuple[str, str, str]] = set()
        successful_packs = 0
        temporary_root = Path(tempfile.mkdtemp(prefix="lsec-yara-", dir="/tmp"))
        try:
            os.chmod(temporary_root, 0o700)
            for pack in usable:
                if context.cancel_event.is_set():
                    outcome.cancelled = True
                    break
                compiled = temporary_root / f"{pack['pack_id']}-{pack['version']}.rules"
                compiled_ok, compile_error = self._compile_pack(
                    yarac, pack, compiled
                )
                if not compiled_ok:
                    outcome.errors += 1
                    outcome.error_details.append(
                        {
                            "pack_id": pack["pack_id"],
                            "version": pack["version"],
                            "error": compile_error,
                        }
                    )
                    processed_units += len(files)
                    continue
                successful_packs += 1
                for batch in self._batches(files):
                    if context.cancel_event.is_set():
                        outcome.cancelled = True
                        break
                    attempted.update(batch)
                    matches, parse_error = self._scan_batch(
                        yara, compiled, batch, context, temporary_root
                    )
                    if parse_error:
                        outcome.errors += 1
                        outcome.error_details.append(
                            {
                                "pack_id": pack["pack_id"],
                                "version": pack["version"],
                                "error": parse_error,
                            }
                        )
                    processed_units += len(batch)
                    for rule, tags, target in matches:
                        if target not in file_set:
                            outcome.errors += 1
                            outcome.error_details.append(
                                {
                                    "pack_id": pack["pack_id"],
                                    "error": "YARA 返回了不在扫描范围内的目标，已忽略",
                                }
                            )
                            continue
                        key = (str(pack["pack_id"]), rule, target)
                        if key in seen:
                            continue
                        seen.add(key)
                        sha256, size = _hash_file(
                            target, self.scan_config.max_file_size_mb * 1024 * 1024
                        )
                        detection = Detection(
                            path=target,
                            detection_name=rule[:300],
                            size=size,
                            sha256=sha256,
                            details={
                                "engine": "yara",
                                "pack_id": pack["pack_id"],
                                "pack_version": pack["version"],
                                "rule": rule[:300],
                                "tags": tags[:30],
                                "severity": severity_for_tags(tags),
                            },
                        )
                        context.on_detection(detection)
                    outcome.detections = len(seen)
                    context.progress(
                        len(attempted),
                        len(files),
                        outcome.detections,
                        outcome.errors,
                        min(100.0, processed_units / total_units * 100.0),
                    )
                try:
                    compiled.unlink()
                except OSError:
                    pass
                if outcome.cancelled:
                    break
        finally:
            shutil.rmtree(temporary_root, ignore_errors=True)

        outcome.files_scanned = len(attempted)
        outcome.summary["packs_scanned"] = successful_packs
        outcome.summary["total_files"] = len(files)
        if successful_packs == 0 and not outcome.cancelled:
            raise component_unavailable(
                "所有 YARA 规则包均执行失败，未产生可信扫描结果",
                {"errors": outcome.error_details[:5]},
            )
        return outcome

    def _batches(self, files: list[str]) -> Iterable[list[str]]:
        """Bound both argv entry count and total argv bytes.

        Linux limits a single argv+env block (typically ~2 MB). Long paths can
        exceed it well before ``scan_batch_files`` is reached, so leave ample
        headroom for the compiled-rules path and environment.
        """
        limit = 128 * 1024
        batch: list[str] = []
        size = 0
        for path in files:
            path_size = len(os.fsencode(path)) + 1
            if batch and (
                len(batch) >= self.config.scan_batch_files
                or size + path_size > limit
            ):
                yield batch
                batch = []
                size = 0
            batch.append(path)
            size += path_size
        if batch:
            yield batch

    def _compile_pack(
        self, yarac: str, pack: dict[str, Any], destination: Path
    ) -> tuple[bool, str | None]:
        result = run(
            [yarac, *[str(path) for path in pack["rule_files"]], str(destination)],
            timeout=self.config.scan_timeout_seconds,
            max_output=16384,
        )
        if result.ok and destination.is_file():
            try:
                os.chmod(destination, 0o600)
            except OSError:
                pass
            return True, None
        return False, (result.tail(1200) or "yarac 未生成编译结果")[:1500]

    def _scan_batch(
        self,
        yara: str,
        compiled: Path,
        batch: list[str],
        context: TaskContext,
        workdir: Path,
    ) -> tuple[list[tuple[str, list[str], str]], str | None]:
        if context.cancel_event.is_set():
            return [], None
        # YARA accepts exactly one target argument (FILE/DIR/PID). Passing
        # several files makes it treat all but the last as rules files, which
        # fails with compiled rules ("can't accept multiple rules files...").
        # --scan-list is the supported way to scan a bounded file list.
        fd, list_name = tempfile.mkstemp(
            prefix="batch-", suffix=".list", dir=workdir
        )
        list_path = Path(list_name)
        try:
            with os.fdopen(fd, "wb") as fh:
                for path in batch:
                    fh.write(os.fsencode(path) + b"\n")
            # -C tells YARA that the rule argument is the compiled output of
            # yarac. Without it YARA parses the binary as source and fails with
            # a "non-ascii character" syntax error.
            result = run(
                [
                    yara,
                    "-w",
                    "-g",
                    "-C",
                    str(compiled),
                    "--scan-list",
                    str(list_path),
                ],
                timeout=self.config.scan_timeout_seconds,
                max_output=2 * 1024 * 1024,
            )
        finally:
            try:
                list_path.unlink()
            except OSError:
                pass
        matches = parse_yara_output(result.stdout)
        if result.timed_out:
            return matches, f"YARA 批次超时（{self.config.scan_timeout_seconds}s）"
        if result.returncode != 0:
            return matches, f"YARA 返回 {result.returncode}: {result.tail(800)}"
        return matches, None

    def _enumerate_targets(
        self, targets: list[str]
    ) -> tuple[list[str], dict[str, int]]:
        max_bytes = self.scan_config.max_file_size_mb * 1024 * 1024
        files: list[str] = []
        seen: set[str] = set()
        skipped = {
            "missing": 0,
            "symlink": 0,
            "special": 0,
            "too_large": 0,
            "skip_path": 0,
            "unreadable": 0,
            "unsupported_name": 0,
        }

        def consider(path: str) -> None:
            if path in seen:
                return
            # YARA -g prints one match per line and has no escaping. Newlines
            # (and leading/trailing whitespace) in a filename would make the
            # result ambiguous, so such files are skipped explicitly instead of
            # being silently mis-parsed.
            if (
                path != path.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in path)
            ):
                skipped["unsupported_name"] += 1
                return
            try:
                st = os.lstat(path)
            except OSError:
                skipped["missing"] += 1
                return
            if stat.S_ISLNK(st.st_mode):
                skipped["symlink"] += 1
                return
            if not stat.S_ISREG(st.st_mode):
                skipped["special"] += 1
                return
            if st.st_size > max_bytes:
                skipped["too_large"] += 1
                return
            if not os.access(path, os.R_OK):
                skipped["unreadable"] += 1
                return
            seen.add(path)
            files.append(path)

        for target in targets:
            if not isinstance(target, str) or not target:
                continue
            if is_skipped_dir(target, self.scan_config.skip_paths):
                skipped["skip_path"] += 1
                continue
            try:
                st = os.lstat(target)
            except OSError:
                skipped["missing"] += 1
                continue
            if stat.S_ISLNK(st.st_mode):
                skipped["symlink"] += 1
                continue
            if stat.S_ISREG(st.st_mode):
                consider(target)
                continue
            if not stat.S_ISDIR(st.st_mode):
                skipped["special"] += 1
                continue
            for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
                kept: list[str] = []
                for dirname in sorted(dirnames):
                    candidate = os.path.join(dirpath, dirname)
                    if (
                        os.path.islink(candidate)
                        or is_skipped_dir(candidate, self.scan_config.skip_paths)
                    ):
                        skipped["symlink" if os.path.islink(candidate) else "skip_path"] += 1
                        continue
                    kept.append(dirname)
                dirnames[:] = kept
                for filename in sorted(filenames):
                    consider(os.path.join(dirpath, filename))
        files.sort()
        return files, skipped
