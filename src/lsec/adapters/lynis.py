"""Lynis adapter.

Lynis is executed as a read-only system audit. The adapter runs only documented
CLI flags, writes its native log and data report into the audit evidence
directory, and parses the bounded report keys that the product consumes.

No Lynis command can change system configuration. The adapter never sends
Lynis suggestions to a shell, and it does not treat an audit warning as proof
that a host is compromised.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..common.executor import run, which
from ..common.logging import get_logger
from .base import (
    HEALTH_DEGRADED,
    HEALTH_OK,
    HEALTH_UNAVAILABLE,
    SERVICE_NOT_INSTALLED,
    SERVICE_UNKNOWN,
    Adapter,
    ProbeResult,
)

log = get_logger("adapter.lynis")

MAX_REPORT_BYTES = 1024 * 1024
_MAX_WARNINGS = 200
_MAX_SUGGESTIONS = 300
_MAX_TEXT = 1000
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TEST_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]*-\d+$")


@dataclass
class LynisOutcome:
    available: bool
    enabled: bool
    version: str | None = None
    returncode: int | None = None
    timed_out: bool = False
    duration_seconds: float = 0.0
    report_path: str | None = None
    log_path: str | None = None
    hardening_index: int | None = None
    tests_done: int | None = None
    warnings: list[dict[str, str]] = field(default_factory=list)
    suggestions: list[dict[str, str]] = field(default_factory=list)
    report_text: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "enabled": self.enabled,
            "version": self.version,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "duration_seconds": self.duration_seconds,
            "report_path": self.report_path,
            "log_path": self.log_path,
            "hardening_index": self.hardening_index,
            "tests_done": self.tests_done,
            "warnings": self.warnings,
            "suggestions": self.suggestions,
            "error": self.error,
        }


def _clean(value: str) -> str:
    return _ANSI_RE.sub("", value).strip()[:_MAX_TEXT]


def _parse_entry(raw: str, *, max_items: int) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line.startswith("warning[]=") and not line.startswith("suggestion[]="):
            continue
        value = line.split("=", 1)[1]
        parts = value.split("|", 3)
        test_id = _clean(parts[0]) if parts else ""
        text = _clean(parts[1]) if len(parts) > 1 else ""
        target = _clean(parts[2]) if len(parts) > 2 else ""
        remediation = (
            _clean(parts[3]).rstrip("|").strip() if len(parts) > 3 else ""
        )
        if test_id in {"-", ""}:
            test_id = "LYNIS"
        if target in {"-", ""}:
            target = ""
        if remediation in {"-", ""}:
            remediation = ""
        items.append(
            {
                "test_id": test_id if _TEST_ID_RE.match(test_id) else "LYNIS",
                "text": text or value[:_MAX_TEXT],
                "target": target,
                "remediation": remediation,
            }
        )
        if len(items) >= max_items:
            break
    return items


def parse_report(text: str) -> dict[str, Any]:
    """Parse the stable key/value subset of lynis-report.dat.

    Unrelated keys are ignored, so a Lynis version that adds fields does not
    break the product. Missing values stay None rather than being guessed.
    """
    warnings = _parse_entry(
        "\n".join(
            line
            for line in text.splitlines()
            if line.startswith("warning[]=")
        ),
        max_items=_MAX_WARNINGS,
    )
    suggestions = _parse_entry(
        "\n".join(
            line
            for line in text.splitlines()
            if line.startswith("suggestion[]=")
        ),
        max_items=_MAX_SUGGESTIONS,
    )
    values: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("#") or "=" not in line or line.endswith("[]="):
            continue
        key, value = line.split("=", 1)
        if key in {
            "hardening_index",
            "lynis_tests_done",
            "lynis_version",
            "report_datetime_end",
        }:
            values[key] = value.strip()
    hardening: int | None = None
    try:
        hardening = int(values["hardening_index"])
    except (KeyError, ValueError):
        pass
    tests_done: int | None = None
    try:
        tests_done = int(values["lynis_tests_done"])
    except (KeyError, ValueError):
        pass
    return {
        "lynis_version": values.get("lynis_version"),
        "hardening_index": hardening,
        "tests_done": tests_done,
        "report_datetime_end": values.get("report_datetime_end"),
        "warnings": warnings,
        "suggestions": suggestions,
    }


def warning_severity(test_id: str, text: str) -> str:
    """Deterministic severity for a Lynis warning.

    Lynis warnings are not all equivalent. Keyword rules are documented and
    intentionally conservative; they never upgrade an ordinary warning above
    high without supporting text.
    """
    lowered = f"{test_id} {text}".lower()
    if any(
        token in lowered
        for token in ("vulnerab", "rootkit", "malware", "compromise", "exploit")
    ):
        return "high"
    if any(
        token in lowered
        for token in ("firewall", "authentication", "password", "permission", "ssh")
    ):
        return "medium"
    return "medium"


class LynisAdapter(Adapter):
    component_id = "lynis"
    display_name = "Lynis 系统安全审计"

    def __init__(self, binary: str = "lynis", *, enabled: bool = True) -> None:
        self.binary = binary
        self.enabled = enabled

    def _binary(self) -> str | None:
        if not self.enabled:
            return None
        return which(self.binary)

    def _version(self, binary_path: str) -> str | None:
        result = run([binary_path, "--version"], timeout=6)
        if result.ok:
            lines = (result.stdout or result.stderr).strip().splitlines()
            if lines:
                return lines[0][:120]
        return None

    def probe(self) -> ProbeResult:
        if not self.enabled:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="disabled",
                error_message="Lynis 集成已在配置中禁用；仅运行内置只读检查",
                details={"binary": None, "integration": "disabled"},
            )
        path = self._binary()
        if not path:
            return ProbeResult(
                component_id=self.component_id,
                display_name=self.display_name,
                installed=False,
                service_status=SERVICE_NOT_INSTALLED,
                health_status=HEALTH_UNAVAILABLE,
                error_code="not_installed",
                error_message="未检测到 lynis；主机体检仍会运行内置检查",
                details={"binary": None, "integration": "builtin_only"},
            )
        version = self._version(path)
        return ProbeResult(
            component_id=self.component_id,
            display_name=self.display_name,
            installed=True,
            version=version,
            service_status=SERVICE_UNKNOWN,
            health_status=HEALTH_OK if version else HEALTH_DEGRADED,
            capabilities=["host_audit"],
            error_code=None if version else "version_unknown",
            error_message=None if version else "lynis 已安装，但无法读取版本",
            details={
                "binary": path,
                "integration": "read_only_audit",
                "mode": "audit system --quick",
            },
        )

    def install_plan(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "installable_from_ui": False,
            "source": "发行版软件包，例如 Debian/Ubuntu 的 lynis 包",
            "requires_root": True,
            "note": "不会在运行期自动安装或执行远程脚本；请在镜像或主机上通过受控包管理器安装",
        }

    def run_audit(self, workdir: Path, timeout: int) -> LynisOutcome:
        if not self.enabled:
            return LynisOutcome(
                available=False, enabled=False, error="Lynis 集成已在配置中禁用"
            )
        binary = self._binary()
        if not binary:
            return LynisOutcome(
                available=False, enabled=True, error=f"未检测到 {self.binary}"
            )
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(workdir, 0o700)
        except OSError:
            pass
        report_path = workdir / "lynis-report.dat"
        log_path = workdir / "lynis.log"
        result = run(
            [
                binary,
                "audit",
                "system",
                "--quick",
                "--no-colors",
                "--quiet",
                "--logfile",
                str(log_path),
                "--report-file",
                str(report_path),
            ],
            timeout=timeout,
            max_output=512 * 1024,
        )
        for path in (report_path, log_path):
            try:
                if path.exists():
                    os.chmod(path, 0o600)
            except OSError:
                pass
        report_text = ""
        if report_path.exists():
            try:
                size = report_path.stat().st_size
                with report_path.open("rb") as fh:
                    report_text = fh.read(MAX_REPORT_BYTES).decode(
                        "utf-8", errors="replace"
                    )
                if size > MAX_REPORT_BYTES:
                    report_text += "\n...[报告已截断]"
            except OSError as exc:
                log.warning("读取 Lynis 报告失败: %s", exc)
        parsed = parse_report(report_text)
        outcome = LynisOutcome(
            available=True,
            enabled=True,
            version=parsed.get("lynis_version"),
            returncode=result.returncode,
            timed_out=result.timed_out,
            duration_seconds=result.duration_seconds,
            report_path=str(report_path) if report_path.exists() else None,
            log_path=str(log_path) if log_path.exists() else None,
            hardening_index=parsed.get("hardening_index"),
            tests_done=parsed.get("tests_done"),
            warnings=parsed.get("warnings", []),
            suggestions=parsed.get("suggestions", []),
            report_text=report_text,
        )
        if result.timed_out:
            outcome.error = f"Lynis 执行超时（{timeout} 秒），结果可能不完整"
        elif not report_text:
            outcome.error = f"Lynis 未生成报告: {result.tail(300) or '无输出'}"
        elif result.returncode not in (0, None):
            outcome.error = f"Lynis 退出码 {result.returncode}: {result.tail(300)}"
        return outcome
