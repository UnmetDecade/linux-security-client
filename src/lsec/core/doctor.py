"""``lsec doctor`` style environment self-check."""

from __future__ import annotations

import os
import shutil
import stat
from typing import Any

from ..common.config import Config, is_loopback
from ..common.hostinfo import host_info
from ..common.timeutil import now_iso
from ..storage import components as component_store
from ..storage.db import Database
from .components import ComponentManager


def _check(
    check_id: str, title: str, status: str, detail: str, remediation: str | None = None
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "detail": detail,
        "remediation": remediation,
    }


def _mode(path: str) -> int | None:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


class DoctorService:
    def __init__(
        self,
        db: Database,
        config: Config,
        components: ComponentManager,
        containers: Any | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.components = components
        self.containers = containers

    def run(self, *, probe_components: bool = True) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        checks.append(
            _check(
                "config",
                "配置文件",
                "ok" if self.config.config_loaded else "info",
                f"已加载 {self.config.config_path}"
                if self.config.config_loaded
                else f"未找到 {self.config.config_path}，正在使用内置默认配置",
            )
        )

        data_mode = _mode(str(self.config.data_dir))
        if data_mode is None:
            checks.append(
                _check("data_dir", "数据目录", "fail", "数据目录不可访问", "检查挂载与权限")
            )
        elif data_mode & 0o007:
            checks.append(
                _check(
                    "data_dir",
                    "数据目录权限",
                    "warn",
                    f"数据目录权限为 {oct(data_mode)}，其他用户可访问",
                    "将数据目录权限收紧为 0700/0750",
                )
            )
        else:
            checks.append(
                _check("data_dir", "数据目录权限", "ok", f"权限 {oct(data_mode)}")
            )

        secrets = self.config.secrets_dir
        secret_files = list(secrets.glob("*.token")) if secrets.exists() else []
        if not secret_files:
            checks.append(
                _check("secrets", "访问令牌", "warn", "未找到令牌文件", "重启守护进程以生成令牌")
            )
        else:
            bad = []
            for path in secret_files:
                mode = _mode(str(path))
                if mode is None or mode & 0o077:
                    bad.append(f"{path.name}={oct(mode) if mode is not None else '?'}")
            checks.append(
                _check(
                    "secrets",
                    "访问令牌权限",
                    "fail" if bad else "ok",
                    "以下令牌权限过宽: " + ", ".join(bad) if bad else "令牌文件仅所有者可读",
                    "chmod 600 数据目录/secrets/*.token" if bad else None,
                )
            )

        ok, detail = self.db.integrity_check()
        checks.append(
            _check(
                "database",
                "SQLite 完整性",
                "ok" if ok else "fail",
                detail,
                "从备份恢复数据库" if not ok else None,
            )
        )
        try:
            usage = shutil.disk_usage(str(self.config.data_dir))
            free_gb = usage.free / (1024**3)
            checks.append(
                _check(
                    "disk",
                    "磁盘空间",
                    "warn" if free_gb < 1 else "ok",
                    f"数据分区剩余 {free_gb:.1f} GB",
                    "清理证据库、隔离区或日志" if free_gb < 1 else None,
                )
            )
        except OSError as exc:
            checks.append(_check("disk", "磁盘空间", "warn", f"无法读取磁盘空间: {exc}"))

        if probe_components:
            try:
                self.components.probe_all()
            except Exception as exc:  # pragma: no cover
                checks.append(_check("components", "组件探测", "fail", f"探测失败: {exc}"))
        clamav = component_store.get_component(self.db, "clamav")
        if not clamav:
            checks.append(_check("clamav", "ClamAV", "warn", "没有 ClamAV 状态记录"))
        elif not clamav["installed"]:
            checks.append(
                _check(
                    "clamav",
                    "ClamAV 安装",
                    "fail",
                    "未安装 ClamAV，病毒扫描不可用",
                    "使用包含 ClamAV 的官方镜像重新部署",
                )
            )
        elif clamav["service_status"] != "running":
            checks.append(
                _check(
                    "clamav",
                    "ClamAV 服务",
                    "fail",
                    "clamd 未运行",
                    "在组件管理中启动 ClamAV，或检查 clamd 日志",
                )
            )
        else:
            db_info = (clamav.get("details") or {}).get("database", {})
            if not db_info.get("present"):
                checks.append(
                    _check(
                        "clamav_db",
                        "病毒库",
                        "fail",
                        "未找到病毒库文件",
                        "执行病毒库更新（freshclam）",
                    )
                )
            else:
                health = "ok" if clamav["health_status"] == "ok" else "warn"
                checks.append(
                    _check(
                        "clamav_db",
                        "病毒库",
                        health,
                        clamav.get("error_message")
                        or f"更新于 {db_info.get('updated_at')}，约 {db_info.get('age_hours')} 小时前",
                        "执行病毒库更新" if health != "ok" else None,
                    )
                )

        if not self.config.yara.enabled:
            checks.append(
                _check(
                    "yara",
                    "YARA 规则扫描",
                    "info",
                    "已在配置中禁用",
                )
            )
        else:
            yara = component_store.get_component(self.db, "yara")
            if not yara or not yara.get("installed"):
                checks.append(
                    _check(
                        "yara",
                        "YARA 安装",
                        "fail",
                        "未安装 YARA，规则扫描不可用",
                        "通过发行版官方仓库安装 yara 与 openssl",
                    )
                )
            else:
                details = yara.get("details") or {}
                active_count = int(details.get("active_count") or 0)
                signature = details.get("signature") or {}
                notes: list[str] = []
                if active_count <= 0:
                    status = "warn"
                    notes.append("没有已激活的规则包，规则扫描不可用")
                elif yara.get("health_status") == "ok":
                    status = "ok"
                    notes.append(f"已激活 {active_count} 个规则包")
                else:
                    status = "warn"
                    notes.append(
                        yara.get("error_message") or "YARA 健康状态异常"
                    )
                if self.config.yara.require_signature and not signature.get(
                    "public_key_present"
                ):
                    if status == "ok":
                        status = "warn"
                    notes.append("签名强制已启用但可信公钥缺失，新规则包无法安装")
                checks.append(
                    _check(
                        "yara",
                        "YARA 规则扫描",
                        status,
                        "；".join(notes)[:300],
                        "安装并激活经过签名校验的规则包"
                        if status != "ok"
                        else None,
                    )
                )

        if not self.config.wazuh.enabled:
            checks.append(
                _check(
                    "wazuh",
                    "Wazuh Agent（可选）",
                    "info",
                    "未启用；本客户端不会声称具备 Wazuh 管理端能力",
                )
            )
        else:
            wazuh = component_store.get_component(self.db, "wazuh")
            if not wazuh or not wazuh.get("installed"):
                checks.append(
                    _check(
                        "wazuh",
                        "Wazuh Agent（可选）",
                        "warn",
                        "已启用 Wazuh 集成，但未检测到本地 Agent；"
                        "没有 Agent/Manager 时不提供 Wazuh 事件",
                        "安装并注册 Wazuh Agent，或关闭 wazuh.enabled",
                    )
                )
            else:
                checks.append(
                    _check(
                        "wazuh",
                        "Wazuh Agent（可选）",
                        "warn" if wazuh.get("health_status") != "ok" else "ok",
                        (wazuh.get("error_message") or wazuh.get("health_status") or "未知")[
                            :300
                        ],
                    )
                )

        if not is_loopback(self.config.server.bind) and not (
            self.config.server.tls_cert and self.config.server.tls_key
        ):
            checks.append(
                _check(
                    "tls",
                    "远程访问加密",
                    "fail" if not self.config.server.allow_insecure_remote else "warn",
                    "服务绑定到非回环地址且未启用 TLS",
                    "启用 TLS 或改为 127.0.0.1 并前置反向代理",
                )
            )
        else:
            checks.append(
                _check(
                    "tls",
                    "监听地址",
                    "ok",
                    f"监听 {self.config.server.bind}:{self.config.server.port}"
                    + ("，已启用 TLS" if self.config.server.tls_cert else ""),
                )
            )

        info = host_info()
        checks.append(
            _check(
                "runtime",
                "运行环境",
                "info",
                f"内核 {info['kernel']}，容器运行: {info['container']['containerized']}，"
                f"容器类型: {info['container']['runtime'] or '未知'}",
            )
        )

        if not self.config.containers.enabled:
            checks.append(
                _check(
                    "containers",
                    "容器监控",
                    "info",
                    "未启用；默认不向 Web 进程挂载 Docker Socket。"
                    "启用时请使用只读 Docker API 代理",
                )
            )
        elif self.containers:
            snapshot = self.containers.snapshot()
            state = snapshot.get("state")
            if state in {"monitored", "degraded"}:
                summary = snapshot.get("summary") or {}
                checks.append(
                    _check(
                        "containers",
                        "容器监控",
                        "warn" if state == "degraded" else "ok",
                        f"{snapshot.get('note') or state}；"
                        f"容器 {summary.get('total', 0)}，"
                        f"风险 {summary.get('risky', 0)}",
                        "检查 Docker API 代理与容器详情读取权限"
                        if state == "degraded"
                        else None,
                    )
                )
            else:
                checks.append(
                    _check(
                        "containers",
                        "容器监控",
                        "warn" if state == "initializing" else "fail",
                        snapshot.get("note") or f"状态 {state}",
                        "检查 Docker API 代理、网络连通性与 Socket 权限",
                    )
                )

        falco = component_store.get_component(self.db, "falco")
        if falco:
            checks.append(
                _check(
                    "falco",
                    "Falco 运行时检测",
                    "info"
                    if falco.get("error_code") == "not_installed"
                    else "warn"
                    if falco.get("health_status") != "ok"
                    else "ok",
                    (falco.get("error_message") or falco.get("health_status") or "未知")[:300],
                    "查看 Falco 安装计划；若内核/eBPF 不支持，界面会明确提示"
                    if falco.get("error_code") not in {"integration_pending"}
                    else None,
                )
            )

        summary = {"ok": 0, "warn": 0, "fail": 0, "info": 0}
        for check in checks:
            summary[check["status"]] = summary.get(check["status"], 0) + 1
        return {
            "checks": checks,
            "summary": {**summary, "total": len(checks)},
            "generated_at": now_iso(),
        }
