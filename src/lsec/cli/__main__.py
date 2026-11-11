"""``lsec`` CLI - a thin, non-privileged client of the daemon HTTP API.

The CLI never executes privileged operations itself; it authenticates to the
daemon with a token and receives the same authorization checks as the Web UI.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .. import __version__

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_UNAUTHORIZED = 3
EXIT_COMPONENT = 4
EXIT_TASK_FAILED = 5
EXIT_NOT_FOUND = 6
EXIT_CONFLICT = 7
EXIT_RATE_LIMITED = 8

ERROR_EXIT = {
    "invalid_argument": EXIT_USAGE,
    "unauthorized": EXIT_UNAUTHORIZED,
    "forbidden": EXIT_UNAUTHORIZED,
    "not_found": EXIT_NOT_FOUND,
    "conflict": EXIT_CONFLICT,
    "rate_limited": EXIT_RATE_LIMITED,
    "component_unavailable": EXIT_COMPONENT,
    "not_implemented": EXIT_COMPONENT,
    "task_failed": EXIT_TASK_FAILED,
    "internal_error": EXIT_INTERNAL,
}


class ApiError(Exception):
    def __init__(self, code: str, message: str, status: int, details: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details

    @property
    def exit_code(self) -> int:
        return ERROR_EXIT.get(self.code, EXIT_INTERNAL)


class Client:
    def __init__(self, server: str, token: str | None, *, timeout: float = 30) -> None:
        self.server = server.rstrip("/")
        self.token = token
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        url = f"{self.server}{path}"
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        context = None
        if url.startswith("https://"):
            context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout, context=context) as response:
                raw = response.read()
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8"))
                error = payload.get("error", {})
                raise ApiError(
                    error.get("code", "internal_error"),
                    error.get("message", f"HTTP {exc.code}"),
                    exc.code,
                    error.get("details"),
                ) from None
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ApiError("internal_error", f"HTTP {exc.code}", exc.code) from None
        except urllib.error.URLError as exc:
            raise ApiError(
                "internal_error",
                f"无法连接守护进程 {self.server}: {exc.reason}",
                0,
            ) from None
        except json.JSONDecodeError:
            raise ApiError("internal_error", "守护进程返回了非 JSON 响应", 0) from None

    def request_raw(self, method: str, path: str, *, timeout: float | None = None) -> tuple[bytes, str]:
        """Fetch non-JSON content (e.g. CSV export)."""
        url = f"{self.server}{path}"
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers, method=method)
        context = ssl.create_default_context() if url.startswith("https://") else None
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout, context=context) as response:
                return response.read(), response.headers.get("Content-Type", "application/octet-stream")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                error = json.loads(raw.decode("utf-8")).get("error", {})
                raise ApiError(
                    error.get("code", "internal_error"),
                    error.get("message", f"HTTP {exc.code}"),
                    exc.code,
                ) from None
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ApiError("internal_error", f"HTTP {exc.code}", exc.code) from None
        except urllib.error.URLError as exc:
            raise ApiError("internal_error", f"无法连接守护进程 {self.server}: {exc.reason}", 0) from None


def resolve_token(args: argparse.Namespace) -> str | None:
    if args.token:
        return args.token
    env = os.environ.get("LSEC_TOKEN")
    if env:
        return env
    candidates = []
    if args.token_file:
        candidates.append(Path(args.token_file))
    if os.environ.get("LSEC_TOKEN_FILE"):
        candidates.append(Path(os.environ["LSEC_TOKEN_FILE"]))
    candidates.append(Path("/data/secrets/admin.token"))
    candidates.append(Path.home() / ".config" / "lsec" / "token")
    for path in candidates:
        try:
            if path.is_file():
                value = path.read_text(encoding="utf-8").strip()
                if value:
                    return value
        except OSError:
            continue
    return None


# ------------------------------------------------------------------ output
def _print_table(headers: list[str], rows: list[list[Any]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    fmt = "  ".join(f"{{:<{width}}}" for width in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * width for width in widths]))
    for row in rows:
        print(fmt.format(*[str(cell) for cell in row]))


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _severity_label(value: str) -> str:
    return {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    }.get(value, value)


def _status_label(value: str) -> str:
    return {
        "queued": "排队中",
        "running": "扫描中",
        "cancel_requested": "正在取消",
        "cancelled": "已取消",
        "succeeded": "已完成",
        "failed": "失败",
        "partial": "部分完成",
        "new": "新事件",
        "acknowledged": "已确认",
        "investigating": "调查中",
        "resolved": "已解决",
        "ignored": "已忽略",
        "quarantined": "已隔离",
        "restored": "已恢复",
        "deleted": "已删除",
        "missing": "文件缺失",
    }.get(value, value)


def _event_target_label(target: Any) -> str:
    if not isinstance(target, dict) or not target:
        return "-"
    path = target.get("path")
    if path:
        return str(path)
    name = target.get("name")
    container_id = target.get("container_id")
    if name and container_id:
        return f"{name} ({str(container_id)[:12]})"
    if name:
        return str(name)
    if container_id:
        return str(container_id)[:12]
    pid = target.get("pid")
    if pid is not None:
        return f"pid {pid}"
    target_type = target.get("type")
    return str(target_type) if target_type else "-"


def _human_bytes(size: Any) -> str:
    try:
        value = float(size)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "-"


# ---------------------------------------------------------------- commands
def cmd_status(client: Client, args: argparse.Namespace) -> int:
    payload = client.request("GET", "/api/v1/status")
    if args.json:
        _print_json(payload)
        return EXIT_OK
    status = payload["status"]
    print(f"总体状态: {status['overall_label']} ({status['overall']})")
    print(f"说明: {status['summary']}")
    protection = status["protection"]
    print(f"按需扫描: {protection['on_demand']['state']} - {protection['on_demand']['reason']}")
    print(f"实时防护: {protection['real_time']['state']} - {protection['real_time']['reason']}")
    db = protection["virus_database"]
    print(f"病毒库: {db['state']}  更新于 {db.get('updated_at') or '未知'}  约 {db.get('age_hours', '?')} 小时前")
    events = status["events"]
    print(
        f"未处理事件: 严重 {events['critical']} / 高危 {events['high']} / "
        f"中危 {events['medium']} / 低危 {events['low']}"
    )
    last = status.get("last_scan")
    if last:
        print(
            f"最近扫描: {last['task_type']} {_status_label(last['status'])} "
            f"文件 {last['files_scanned']} 检测 {last['detections_count']} 错误 {last['errors_count']}"
        )
    else:
        print("最近扫描: 无")
    baseline = status.get("host_baseline") or {}
    if baseline:
        print(f"主机体检: {baseline.get('state')} - {baseline.get('note')}")
    containers = status.get("containers") or {}
    if containers:
        print(
            f"容器监控: {containers.get('state')} - {containers.get('note')}"
        )
    if status.get("reasons"):
        print("需要关注:")
        for reason in status["reasons"]:
            print(f"  - {reason}")
    print(f"生成时间: {status['generated_at']}")
    return EXIT_OK


def cmd_components(client: Client, args: argparse.Namespace) -> int:
    if args.action == "list":
        payload = client.request("GET", "/api/v1/components")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        rows = [
            [
                c["component_id"],
                c["display_name"],
                "是" if c["installed"] else "否",
                c.get("version") or "-",
                c.get("service_status", "-"),
                c.get("health_status", "-"),
                (c.get("error_message") or "")[:40],
            ]
            for c in payload["components"]
        ]
        _print_table(["组件", "名称", "已安装", "版本", "服务", "健康", "说明"], rows)
        return EXIT_OK
    if args.action == "probe":
        payload = client.request("POST", "/api/v1/components/probe", {})
        _print_json(payload) if args.json else print("组件探测完成")
        return EXIT_OK
    if args.action == "install-plan":
        payload = client.request("GET", f"/api/v1/components/{args.component}/install-plan")
        _print_json(payload)
        return EXIT_OK
    if args.action == "update":
        payload = client.request("POST", f"/api/v1/components/{args.component}/update", {}, timeout=900)
        if args.json:
            _print_json(payload)
        else:
            outcome = payload["update"]
            print(f"更新{'成功' if outcome.get('ok') else '失败'}，退出码 {outcome.get('exit_code')}")
            print(outcome.get("output_tail") or "")
        return EXIT_OK if payload["update"].get("ok") else EXIT_COMPONENT
    if args.action in {"start", "stop"}:
        payload = client.request(
            "POST", f"/api/v1/components/{args.component}/{args.action}", {}
        )
        if args.json:
            _print_json(payload)
        else:
            component = payload["component"]
            print(f"{component['display_name']}: {component['health_status']}")
        return EXIT_OK
    raise ApiError("invalid_argument", "未知组件操作", 400)


def cmd_scan(client: Client, args: argparse.Namespace) -> int:
    if args.action == "quick":
        task_type, paths = "quick", []
    elif args.action == "full":
        task_type, paths = "full", []
    elif args.action == "path":
        if not args.paths:
            raise ApiError("invalid_argument", "scan path 需要至少一个路径", 400)
        task_type, paths = "custom", args.paths
    else:
        raise ApiError("invalid_argument", "未知扫描类型", 400)
    engines = args.engine or ["clamav"]
    payload = client.request(
        "POST",
        "/api/v1/scans",
        {"type": task_type, "paths": paths, "engines": engines},
    )
    task = payload["task"]
    if args.json:
        _print_json(payload)
    else:
        print(f"扫描任务已创建: {task['task_id']}")
        print(f"类型: {task['task_type']}  状态: {_status_label(task['status'])}")
    if args.wait:
        return _wait_task(client, task["task_id"], args.json)
    return EXIT_OK


def _wait_task(client: Client, task_id: str, as_json: bool) -> int:
    last_line = ""
    while True:
        payload = client.request("GET", f"/api/v1/scans/{task_id}")
        task = payload["task"]
        if as_json:
            _print_json(payload)
        else:
            progress = task.get("progress")
            line = (
                f"状态: {_status_label(task['status'])}  文件: {task['files_scanned']}  "
                f"检测: {task['detections_count']}  错误: {task['errors_count']}  "
                f"进度: {progress if progress is not None else '未知'}"
            )
            if line != last_line:
                print(line, flush=True)
                last_line = line
        if task["status"] in {"succeeded", "failed", "partial", "cancelled"}:
            if not as_json:
                summary = task.get("result_summary") or {}
                print(f"任务结束: {_status_label(task['status'])}")
                if summary.get("evidence_path"):
                    print(f"证据报告: {summary['evidence_path']}")
            return {
                "succeeded": EXIT_OK,
                "partial": EXIT_OK,
                "cancelled": EXIT_OK,
                "failed": EXIT_TASK_FAILED,
            }[task["status"]]
        time.sleep(2)


def cmd_task(client: Client, args: argparse.Namespace) -> int:
    if args.action == "list":
        params = f"?limit={args.limit}"
        if args.status:
            params += f"&status={args.status}"
        payload = client.request("GET", f"/api/v1/scans{params}")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        rows = [
            [
                t["task_id"],
                t["task_type"],
                _status_label(t["status"]),
                t.get("progress") if t.get("progress") is not None else "-",
                t["files_scanned"],
                t["detections_count"],
                t["errors_count"],
                t["created_at"],
            ]
            for t in payload["tasks"]
        ]
        _print_table(["任务ID", "类型", "状态", "进度%", "文件", "检测", "错误", "创建时间"], rows)
        return EXIT_OK
    if args.action == "show":
        payload = client.request("GET", f"/api/v1/scans/{args.task_id}")
        if args.json:
            _print_json(payload)
        else:
            task = payload["task"]
            print(f"任务: {task['task_id']}")
            print(f"类型: {task['task_type']}  状态: {_status_label(task['status'])}")
            print(f"目标: {', '.join(task['target_paths'])}")
            print(f"文件: {task['files_scanned']}  检测: {task['detections_count']}  错误: {task['errors_count']}")
            print(f"创建: {task['created_at']}  开始: {task.get('started_at')}  结束: {task.get('finished_at')}")
            summary = task.get("result_summary") or {}
            if summary.get("evidence_path"):
                print(f"证据: {summary['evidence_path']}")
            errors = task.get("error_details") or []
            if errors:
                print("错误样例:")
                for error in errors[:10]:
                    print(f"  - {error.get('path', '')}: {error.get('error', '')}")
        return EXIT_OK
    if args.action == "cancel":
        payload = client.request("POST", f"/api/v1/scans/{args.task_id}/cancel", {})
        _print_json(payload) if args.json else print(f"任务状态: {_status_label(payload['task']['status'])}")
        return EXIT_OK
    raise ApiError("invalid_argument", "未知任务操作", 400)


def cmd_events(client: Client, args: argparse.Namespace) -> int:
    if args.action == "list":
        params = [f"limit={args.limit}"]
        for key in ("severity", "source", "category", "status", "q"):
            value = getattr(args, key, None)
            if value:
                params.append(f"{key}={urllib.parse.quote(str(value))}")
        payload = client.request("GET", f"/api/v1/events?{'&'.join(params)}")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        rows = [
            [
                e["last_seen_at"],
                _severity_label(e["severity"]),
                _status_label(e["status"]),
                e["source"],
                e["title"][:50],
                _event_target_label(e.get("target")),
                e["occurrences"],
            ]
            for e in payload["events"]
        ]
        _print_table(["最近发生", "级别", "状态", "来源", "标题", "目标", "次数"], rows)
        print(f"共 {payload['total']} 条")
        return EXIT_OK
    if args.action == "show":
        payload = client.request("GET", f"/api/v1/events/{args.event_id}")
        if args.json:
            _print_json(payload)
        else:
            event = payload["event"]
            print(f"事件: {event['event_id']}")
            print(f"标题: {event['title']}")
            print(f"级别: {_severity_label(event['severity'])}  状态: {_status_label(event['status'])}  来源: {event['source']}")
            print(f"首次: {event['first_seen_at']}  最近: {event['last_seen_at']}  次数: {event['occurrences']}")
            print(f"目标: {_event_target_label(event.get('target'))}")
            print(f"说明: {event['description']}")
            evidence = event.get("evidence") or {}
            if evidence.get("detection_name"):
                print(f"检测名: {evidence['detection_name']}")
            if evidence.get("sha256"):
                print(f"SHA256: {evidence['sha256']}")
            actions = event.get("recommended_actions") or []
            if actions:
                print("建议:")
                for action in actions:
                    print(f"  - {action}")
        return EXIT_OK
    if args.action == "export":
        params = [f"format={args.format}"]
        for key in ("severity", "source", "category", "status", "q"):
            value = getattr(args, key, None)
            if value:
                params.append(f"{key}={urllib.parse.quote(str(value))}")
        path = f"/api/v1/events/export?{'&'.join(params)}"
        if args.format == "csv":
            data, _content_type = client.request_raw("GET", path)
            if args.output:
                Path(args.output).write_bytes(data)
                print(f"已导出到 {args.output}")
            else:
                sys.stdout.buffer.write(data)
            return EXIT_OK
        payload = client.request("GET", path)
        if args.output:
            Path(args.output).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            print(f"已导出到 {args.output}")
        else:
            _print_json(payload)
        return EXIT_OK
    raise ApiError("invalid_argument", "未知事件操作", 400)


def cmd_quarantine(client: Client, args: argparse.Namespace) -> int:
    if args.action == "list":
        params = f"limit={args.limit}"
        if args.status:
            params += f"&status={urllib.parse.quote(args.status)}"
        payload = client.request("GET", f"/api/v1/quarantine?{params}")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        rows = [
            [
                item["item_id"],
                item["original_path"][:60],
                _human_bytes(item["size"]),
                item.get("detection_name") or "-",
                _status_label(item["status"]),
                item["detected_at"],
            ]
            for item in payload["items"]
        ]
        _print_table(["ID", "原路径", "大小", "检测名", "状态", "隔离时间"], rows)
        print(f"共 {payload['total']} 条")
        return EXIT_OK
    if args.action == "inspect":
        payload = client.request("GET", f"/api/v1/quarantine/{args.item_id}")
        _print_json(payload)
        return EXIT_OK
    if args.action == "add":
        if not args.confirm:
            raise ApiError(
                "invalid_argument",
                "隔离文件需要显式 --confirm 以完成二次确认",
                400,
            )
        payload = client.request(
            "POST",
            "/api/v1/quarantine",
            {
                "path": args.path,
                "confirm": True,
                "detection_name": args.detection_name,
                "event_id": args.event_id,
                "engine": "clamav",
            },
        )
        if args.json:
            _print_json(payload)
        else:
            item = payload["item"]
            print(f"文件已隔离: {item['item_id']}  {item['original_path']}")
            print(f"SHA256: {item['sha256']}")
        return EXIT_OK
    if args.action in {"restore", "delete"}:
        if not args.confirm:
            raise ApiError(
                "invalid_argument",
                f"{args.action} 需要显式 --confirm 以完成二次确认",
                400,
            )
        payload = client.request(
            "POST",
            f"/api/v1/quarantine/{args.item_id}/{args.action}",
            {"confirm": True},
        )
        if args.json:
            _print_json(payload)
        else:
            print(f"隔离项状态: {_status_label(payload['item']['status'])}")
        return EXIT_OK
    raise ApiError("invalid_argument", "未知隔离区操作", 400)


AUDIT_TERMINAL = {"succeeded", "partial", "failed"}


def _print_audit(audit: dict) -> None:
    summary = audit.get("result_summary") or {}
    counts = summary.get("counts") or {}
    print(f"体检: {audit['audit_id']}")
    print(f"状态: {audit['status']}  范围: {audit.get('scope') or '-'}")
    print(f"创建: {audit.get('created_at')}  开始: {audit.get('started_at')}  结束: {audit.get('finished_at')}")
    print(
        f"检查: {audit.get('checks_total', 0)}  发现: {audit.get('findings_count', 0)}  "
        f"未能执行: {audit.get('errors_count', 0)}"
    )
    if counts:
        print(
            f"通过: {counts.get('passed', 0)}  跳过: {counts.get('skipped', 0)}  "
            f"已生成事件: {counts.get('events_ingested', 0)}"
        )
    severity = audit.get("severity_counts") or {}
    if severity:
        print(
            "风险级别: 严重 {critical} / 高危 {high} / 中危 {medium} / 低危 {low}".format(
                critical=severity.get("critical", 0),
                high=severity.get("high", 0),
                medium=severity.get("medium", 0),
                low=severity.get("low", 0),
            )
        )
    if audit.get("hardening_index") is not None:
        print(f"Lynis 加固指数: {audit['hardening_index']}")
    if audit.get("lynis_available"):
        print(f"Lynis: 可用  版本 {audit.get('lynis_version') or '未知'}")
    else:
        print("Lynis: 不可用（仅内置检查结果）")
    if audit.get("error"):
        print(f"错误: {audit['error']}")
    if summary.get("scope_note"):
        print(f"范围说明: {summary['scope_note']}")

    findings = [c for c in summary.get("checks", []) if c.get("status") == "finding"]
    if findings:
        print("风险发现:")
        for check in findings[:30]:
            print(
                f"  - [{check.get('severity')}] {check.get('check_id')} "
                f"{check.get('title')}"
            )
        if len(findings) > 30:
            print(f"  ... 另有 {len(findings) - 30} 项，详见证据报告")
    errors = [c for c in summary.get("checks", []) if c.get("status") == "error"]
    if errors:
        print("未能执行的检查:")
        for check in errors[:20]:
            print(f"  - {check.get('check_id')}: {check.get('detail')}")
    if audit.get("evidence_path"):
        print(f"证据报告: {audit['evidence_path']}")
    for note in summary.get("limitations", []):
        print(f"限制: {note}")


def _wait_audit(client: Client, audit_id: str, as_json: bool) -> int:
    last_status = ""
    while True:
        payload = client.request("GET", f"/api/v1/audits/{audit_id}")
        audit = payload["audit"]
        if as_json:
            _print_json(payload)
        elif audit["status"] != last_status:
            print(f"状态: {audit['status']}", flush=True)
            last_status = audit["status"]
        if audit["status"] in AUDIT_TERMINAL:
            if not as_json:
                _print_audit(audit)
            return EXIT_OK if audit["status"] in {"succeeded", "partial"} else EXIT_TASK_FAILED
        time.sleep(1)


def cmd_audit(client: Client, args: argparse.Namespace) -> int:
    if args.action == "list":
        payload = client.request("GET", f"/api/v1/audit?limit={args.limit}")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        rows = [
            [
                record["created_at"],
                record["action"],
                record["actor"],
                record.get("target") or "-",
                record["result"],
                (record.get("error") or "")[:40],
            ]
            for record in payload["records"]
        ]
        _print_table(["时间", "操作", "操作者", "目标", "结果", "错误"], rows)
        return EXIT_OK
    if args.action == "history":
        payload = client.request("GET", f"/api/v1/audits?limit={args.limit}")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        rows = [
            [
                audit["audit_id"],
                audit["status"],
                audit.get("scope") or "-",
                audit.get("checks_total", 0),
                audit.get("findings_count", 0),
                audit.get("errors_count", 0),
                audit.get("hardening_index") if audit.get("hardening_index") is not None else "-",
                audit.get("created_at"),
            ]
            for audit in payload["audits"]
        ]
        _print_table(
            ["体检ID", "状态", "范围", "检查", "发现", "错误", "加固指数", "创建时间"],
            rows,
        )
        return EXIT_OK
    if args.action == "run":
        payload = client.request("POST", "/api/v1/audits", {})
        audit = payload["audit"]
        if args.json and not args.wait:
            _print_json(payload)
        elif not args.json:
            print(f"体检任务已创建: {audit['audit_id']}")
            print(f"状态: {audit['status']}  范围: {audit.get('scope') or '-'}")
        if args.wait:
            return _wait_audit(client, audit["audit_id"], args.json)
        return EXIT_OK
    if args.action == "report":
        audit_id = args.audit_id
        if not audit_id:
            payload = client.request("GET", "/api/v1/audits?limit=20")
            finished = [
                item for item in payload["audits"]
                if item["status"] in AUDIT_TERMINAL
            ]
            if not finished:
                raise ApiError("not_found", "尚无已完成的主机体检记录", 404)
            audit_id = finished[0]["audit_id"]
        payload = client.request("GET", f"/api/v1/audits/{audit_id}")
        if args.json:
            _print_json(payload)
        else:
            _print_audit(payload["audit"])
        return EXIT_OK
    raise ApiError("invalid_argument", "未知体检操作", 400)


def _container_uptime(started_at: Any) -> str:
    if not started_at:
        return "-"
    try:
        from datetime import datetime, timezone

        text = str(started_at).replace("Z", "+00:00")
        started = datetime.fromisoformat(text)
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        seconds = max(
            0, int((datetime.now(timezone.utc) - started).total_seconds())
        )
    except (ValueError, TypeError):
        return "-"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def cmd_containers(client: Client, args: argparse.Namespace) -> int:
    if args.action == "list":
        payload = client.request("GET", "/api/v1/containers")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        snapshot = payload["containers"]
        print(f"容器监控: {snapshot.get('state')} - {snapshot.get('note')}")
        engine = snapshot.get("engine") or {}
        if engine:
            print(
                f"运行时: {engine.get('runtime')} {engine.get('server_version') or ''} "
                f"API {engine.get('api_version') or '-'}"
            )
        summary = snapshot.get("summary") or {}
        print(
            f"容器: 总数 {summary.get('total', 0)} / 运行中 {summary.get('running', 0)} / "
            f"风险 {summary.get('risky', 0)} / 无法评估 {summary.get('unknown', 0)}"
        )
        rows = [
            [
                str(item.get("container_id") or "")[:12],
                item.get("name") or "-",
                item.get("image") or "-",
                item.get("state") or "-",
                _container_uptime(item.get("started_at"))
                if item.get("state") == "running"
                else "-",
                _severity_label(item.get("risk_level") or "unknown")
                if item.get("risk_level") != "none"
                else "无",
                item.get("risk_count", 0),
            ]
            for item in snapshot.get("containers") or []
        ]
        if rows:
            _print_table(
                ["ID", "名称", "镜像", "状态", "运行时长", "风险", "发现数"],
                rows,
            )
        else:
            print("没有容器数据")
        return EXIT_OK
    if args.action == "refresh":
        payload = client.request("POST", "/api/v1/containers/refresh", {})
        if args.json:
            _print_json(payload)
        else:
            snapshot = payload["containers"]
            print(f"刷新完成: {snapshot.get('state')} - {snapshot.get('note')}")
        return (
            EXIT_OK
            if payload["containers"].get("state") in {"monitored", "degraded"}
            else EXIT_COMPONENT
        )
    if args.action == "inspect":
        _need(args, "container_id")
        payload = client.request("GET", f"/api/v1/containers/{args.container_id}")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        container = payload["container"]
        print(f"容器: {container.get('name')} ({container.get('container_id')})")
        print(f"镜像: {container.get('image') or '-'}")
        print(f"状态: {container.get('state') or '-'}  用户: {container.get('user')}")
        print(
            f"特权: {'是' if container.get('privileged') else '否'}  "
            f"网络: {container.get('network_mode')}  PID: {container.get('pid_mode') or '-'}"
        )
        print(f"风险等级: {_severity_label(container.get('risk_level') or 'unknown')}")
        if not container.get("evaluated"):
            print(f"无法评估: {container.get('evaluation_error')}")
        if container.get("mounts"):
            print("挂载:")
            for mount in container["mounts"]:
                mode = "ro" if mount.get("read_only") else "rw"
                print(
                    f"  - {mount.get('source') or '-'} -> {mount.get('destination')} ({mode})"
                )
        findings = container.get("findings") or []
        if findings:
            print("配置风险:")
            for finding in findings:
                print(
                    f"  - [{_severity_label(finding.get('severity'))}] "
                    f"{finding.get('title')}"
                )
                print(f"    {finding.get('recommendation')}")
        else:
            print("配置风险: 无" if container.get("evaluated") else "配置风险: 未知")
        return EXIT_OK
    raise ApiError("invalid_argument", "未知容器操作", 400)


def cmd_falco(client: Client, args: argparse.Namespace) -> int:
    if args.action == "status":
        payload = client.request("GET", "/api/v1/falco")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        falco = payload["falco"]
        component = falco.get("component") or {}
        capability = (component.get("details") or {}).get("capability") or {}
        print(
            f"Falco: 已安装 {'是' if component.get('installed') else '否'}  "
            f"版本 {component.get('version') or '-'}  健康 {component.get('health_status')}"
        )
        print(f"说明: {component.get('error_message') or '-'}")
        print(
            f"内核/eBPF: {capability.get('state', 'unknown')} - "
            f"{capability.get('reason', '无结果')}"
        )
        print(
            f"内核 {capability.get('kernel_release') or '-'}  "
            f"BTF {capability.get('btf_available')}  "
            f"CAP_SYS_ADMIN {capability.get('cap_sys_admin')}"
        )
        ingest = falco.get("event_ingest") or {}
        print(
            f"事件接入: {'已启用' if ingest.get('enabled') else '未启用'}  "
            f"事件数 {ingest.get('events_total', 0)}"
        )
        return EXIT_OK
    if args.action == "install-plan":
        payload = client.request("GET", "/api/v1/components/falco/install-plan")
        plan = payload["plan"]
        if args.json:
            _print_json(plan)
            return EXIT_OK
        print(f"Falco 安装计划（不会自动执行）: {plan.get('risk') or ''}")
        for index, step in enumerate(plan.get("steps") or [], 1):
            print(f"{index}. {step.get('title')}")
            print(f"   {step.get('detail')}")
        for note in plan.get("notes") or []:
            print(f"注意: {note}")
        return EXIT_OK
    raise ApiError("invalid_argument", "未知 Falco 操作", 400)


def cmd_yara(client: Client, args: argparse.Namespace) -> int:
    if args.action == "status":
        payload = client.request("GET", "/api/v1/yara")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        yara = payload["yara"]
        component = yara.get("component") or {}
        rules = yara.get("rules") or {}
        print(
            f"YARA: 已安装 {'是' if component.get('installed') else '否'}  "
            f"版本 {component.get('version') or '-'}  健康 {component.get('health_status')}"
        )
        print(f"扫描就绪: {'是' if yara.get('scan_ready') else '否'}")
        print(f"说明: {component.get('error_message') or '-'}")
        print(
            f"规则包: {rules.get('packs_count', 0)} 个  已激活: "
            f"{rules.get('active_count', 0)} 个"
        )
        signature = rules.get("signature") or {}
        print(
            f"签名校验: {'必需' if signature.get('required') else '未强制'}  "
            f"公钥: {'已配置' if signature.get('public_key_present') else '缺失'}"
        )
        for item in rules.get("active") or []:
            print(
                f"  - {item['pack_id']}@{item['version']}  "
                f"规则 {item['rules_count']}  签名 {'已验证' if item['signature_verified'] else '未验证'}"
            )
        if rules.get("state_error"):
            print(f"规则状态错误: {rules['state_error']}")
        return EXIT_OK
    if args.action == "packs":
        payload = client.request("GET", "/api/v1/yara/packs")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        rows = []
        for pack in payload["packs"]:
            for version in pack["versions"]:
                rows.append(
                    [
                        pack["pack_id"],
                        version["version"],
                        version.get("name") or "-",
                        version["rules_count"],
                        "是" if version.get("active") else "否",
                        "已验证" if version.get("signature_verified") else "未验证",
                        version.get("installed_at") or "-",
                    ]
                )
        _print_table(
            ["规则包", "版本", "名称", "规则数", "激活", "签名", "安装时间"], rows
        )
        print(f"投递目录: {payload.get('inbox_dir')}")
        return EXIT_OK
    if args.action == "install":
        payload = client.request(
            "POST",
            "/api/v1/yara/packs",
            {
                "path": args.target,
                "activate": args.activate,
                "confirm": bool(args.confirm),
            },
            timeout=300,
        )
        if args.json:
            _print_json(payload)
            return EXIT_OK
        pack = payload["pack"]
        print(
            f"规则包已安装: {pack['pack_id']}@{pack['version']}  "
            f"规则 {pack['rules_count']}  签名 "
            f"{'已验证' if pack['signature_verified'] else '未验证'}  "
            f"激活 {'是' if pack['activated'] else '否'}"
        )
        return EXIT_OK
    if args.action in {"activate", "delete"}:
        method = "POST" if args.action == "activate" else "DELETE"
        suffix = "/activate" if args.action == "activate" else ""
        payload = client.request(
            method,
            f"/api/v1/yara/packs/{args.target}/{args.version}{suffix}",
            {"confirm": bool(args.confirm)},
        )
        if args.json:
            _print_json(payload)
        elif args.action == "activate":
            print(f"已激活规则包: {args.target}@{args.version}")
        else:
            print(f"已删除规则包版本: {args.target}@{args.version}")
        return EXIT_OK
    if args.action == "scan":
        paths = [path for path in [args.target, *args.paths] if path]
        if not paths:
            raise ApiError("invalid_argument", "yara scan 需要至少一个扫描路径", 400)
        payload = client.request(
            "POST",
            "/api/v1/scans",
            {"type": "yara", "paths": paths, "engines": ["yara"]},
        )
        task = payload["task"]
        if args.json:
            _print_json(payload)
        else:
            print(f"YARA 规则扫描任务已创建: {task['task_id']}")
        if args.wait:
            return _wait_task(client, task["task_id"], args.json)
        return EXIT_OK
    raise ApiError("invalid_argument", "未知 YARA 操作", 400)


def cmd_wazuh(client: Client, args: argparse.Namespace) -> int:
    if args.action == "status":
        payload = client.request("GET", "/api/v1/wazuh")
        if args.json:
            _print_json(payload)
            return EXIT_OK
        wazuh = payload["wazuh"]
        component = wazuh.get("component") or {}
        details = component.get("details") or {}
        manager = details.get("manager") or {}
        ingest = wazuh.get("ingest") or {}
        print(
            f"Wazuh: 已安装 {'是' if component.get('installed') else '否'}  "
            f"版本 {component.get('version') or '-'}  健康 {component.get('health_status')}"
        )
        print(f"能力状态: {wazuh.get('state')}（仅本地 Agent，不是 Manager）")
        print(f"说明: {component.get('error_message') or '-'}")
        print(
            f"Manager 配置: {'是' if manager.get('manager_configured') else '否'}  "
            f"地址 {manager.get('address') or '-'}:{manager.get('port') or '-'}  "
            f"连接验证: 否"
        )
        print(
            f"本地注册信息: {'存在' if details.get('registration_present') else '缺失或不可读'}  "
            f"告警文件: {'存在' if details.get('alerts_present') else '不存在'}"
        )
        print(
            f"本地告警接入: {'已启用' if ingest.get('ingest_enabled') else '未启用'}  "
            f"运行 {'是' if ingest.get('running') else '否'}  "
            f"事件数 {ingest.get('events_total', 0)}  解析错误 {ingest.get('parse_errors', 0)}"
        )
        print(f"接入说明: {ingest.get('note') or '-'}")
        return EXIT_OK
    if args.action == "install-plan":
        payload = client.request("GET", "/api/v1/wazuh/install-plan")
        plan = payload["plan"]
        if args.json:
            _print_json(plan)
            return EXIT_OK
        print("Wazuh Agent 安装计划（不会自动执行）:")
        for index, step in enumerate(plan.get("steps") or [], 1):
            print(f"{index}. {step}")
        for note in plan.get("notes") or []:
            print(f"注意: {note}")
        return EXIT_OK
    raise ApiError("invalid_argument", "未知 Wazuh 操作", 400)


def cmd_doctor(client: Client, args: argparse.Namespace) -> int:
    payload = client.request("GET", "/api/v1/doctor", timeout=120)
    if args.json:
        _print_json(payload)
        return EXIT_OK
    report = payload["report"]
    for check in report["checks"]:
        marker = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]", "info": "[INFO]"}.get(check["status"], "[????]")
        print(f"{marker} {check['title']}: {check['detail']}")
        if check.get("remediation"):
            print(f"       建议: {check['remediation']}")
    summary = report["summary"]
    print(
        f"检查完成: 通过 {summary['ok']}，警告 {summary['warn']}，"
        f"失败 {summary['fail']}，信息 {summary['info']}"
    )
    return EXIT_OK if summary["fail"] == 0 else EXIT_COMPONENT


def cmd_version(client: Client, args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {"client_version": __version__}
    if client.token:
        try:
            payload.update(client.request("GET", "/api/v1/version", timeout=5))
        except ApiError as exc:
            payload["server_error"] = exc.message
    if args.json:
        _print_json(payload)
    else:
        print(f"lsec 客户端: {__version__}")
        if payload.get("daemon_version"):
            print(f"lsec 守护进程: {payload['daemon_version']}  API {payload.get('api_version')}")
        elif payload.get("server_error"):
            print(f"守护进程: 不可达（{payload['server_error']}）")
        else:
            print("守护进程: 未提供令牌，跳过查询")
    return EXIT_OK


def cmd_health(client: Client, args: argparse.Namespace) -> int:
    payload = client.request("GET", "/api/v1/health", timeout=5)
    _print_json(payload) if args.json else print(f"守护进程存活，版本 {payload.get('version')}")
    return EXIT_OK


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lsec", description="Linux 统一安全防护客户端 CLI")
    parser.add_argument("--server", default=os.environ.get("LSEC_SERVER", "http://127.0.0.1:8080"))
    parser.add_argument("--token", help="管理员/只读访问令牌（也可用 LSEC_TOKEN）")
    parser.add_argument("--token-file", help="令牌文件路径")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--version", action="version", version=f"lsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="查看总体安全状态")
    sub.add_parser("health", help="检查守护进程存活")
    sub.add_parser("version", help="查看客户端/守护进程版本")
    sub.add_parser("doctor", help="运行环境自检")

    components = sub.add_parser("components", help="组件管理")
    components.add_argument("action", choices=["list", "probe", "start", "stop", "update", "install-plan"])
    components.add_argument("component", nargs="?", help="组件 ID，例如 clamav")

    scan = sub.add_parser("scan", help="创建扫描任务")
    scan.add_argument("action", choices=["quick", "full", "path"])
    scan.add_argument("paths", nargs="*", help="自定义扫描路径")
    scan.add_argument(
        "--engine",
        action="append",
        choices=["clamav", "yara"],
        help="扫描引擎，可重复；默认 clamav",
    )
    scan.add_argument("--wait", action="store_true", help="等待扫描完成并显示进度")

    task = sub.add_parser("task", help="扫描任务")
    task.add_argument("action", choices=["list", "show", "cancel"])
    task.add_argument("task_id", nargs="?")
    task.add_argument("--status")
    task.add_argument("--limit", type=int, default=50)

    events = sub.add_parser("events", help="安全事件")
    events.add_argument("action", choices=["list", "show", "export"])
    events.add_argument("event_id", nargs="?")
    events.add_argument("--severity")
    events.add_argument("--source")
    events.add_argument("--category")
    events.add_argument("--status")
    events.add_argument("--q")
    events.add_argument("--limit", type=int, default=50)
    events.add_argument("--format", choices=["json", "csv"], default="json")
    events.add_argument("--output", help="导出文件路径")

    quarantine = sub.add_parser("quarantine", help="隔离区")
    quarantine.add_argument("action", choices=["list", "add", "inspect", "restore", "delete"])
    quarantine.add_argument("item_id", nargs="?")
    quarantine.add_argument("--path", help="add 操作要隔离的文件路径")
    quarantine.add_argument("--detection-name", help="add 操作的检测名")
    quarantine.add_argument("--event-id", help="add 操作关联的事件 ID")
    quarantine.add_argument("--status", help="list 操作按状态过滤")
    quarantine.add_argument("--limit", type=int, default=100)
    quarantine.add_argument("--confirm", action="store_true")

    audit = sub.add_parser("audit", help="操作审计 / 主机体检")
    audit.add_argument("action", choices=["list", "run", "report", "history"])
    audit.add_argument("audit_id", nargs="?", help="report 操作的体检 ID；省略时使用最近一次")
    audit.add_argument("--wait", action="store_true", help="run 操作等待体检完成")
    audit.add_argument("--limit", type=int, default=100)

    containers = sub.add_parser("containers", help="容器清单与配置风险")
    containers.add_argument("action", choices=["list", "inspect", "refresh"])
    containers.add_argument("container_id", nargs="?", help="容器的完整 ID、唯一前缀或名称")

    falco = sub.add_parser("falco", help="Falco 能力检测与安装计划")
    falco.add_argument("action", choices=["status", "install-plan"])

    wazuh = sub.add_parser("wazuh", help="可选的本地 Wazuh Agent 状态")
    wazuh.add_argument("action", choices=["status", "install-plan"])

    yara = sub.add_parser("yara", help="YARA 规则包管理与规则扫描")
    yara.add_argument(
        "action", choices=["status", "packs", "install", "activate", "delete", "scan"]
    )
    yara.add_argument(
        "target",
        nargs="?",
        help="install: 规则包路径；activate/delete: 规则包 ID；scan: 首个扫描路径",
    )
    yara.add_argument("version", nargs="?", help="activate/delete 的规则包版本")
    yara.add_argument("paths", nargs="*", help="scan 的其余扫描路径")
    yara.add_argument(
        "--no-activate",
        dest="activate",
        action="store_false",
        help="install 后不激活（默认安装后激活）",
    )
    yara.set_defaults(activate=True)
    yara.add_argument("--confirm", action="store_true", help="确认安装/激活/删除")
    yara.add_argument("--wait", action="store_true", help="scan 操作等待任务完成")
    return parser


def _need(args: argparse.Namespace, name: str) -> None:
    if not getattr(args, name, None):
        raise ApiError("invalid_argument", f"缺少参数 {name}", 400)


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    token = resolve_token(args)
    client = Client(args.server, token)
    try:
        if args.command == "status":
            return cmd_status(client, args)
        if args.command == "health":
            return cmd_health(client, args)
        if args.command == "version":
            return cmd_version(client, args)
        if args.command == "doctor":
            return cmd_doctor(client, args)
        if args.command == "components":
            if args.action in {"start", "stop", "update", "install-plan"}:
                _need(args, "component")
            return cmd_components(client, args)
        if args.command == "scan":
            return cmd_scan(client, args)
        if args.command == "task":
            if args.action in {"show", "cancel"}:
                _need(args, "task_id")
            return cmd_task(client, args)
        if args.command == "events":
            if args.action == "show":
                _need(args, "event_id")
            return cmd_events(client, args)
        if args.command == "quarantine":
            if args.action in {"inspect", "restore", "delete"}:
                _need(args, "item_id")
            if args.action == "add":
                _need(args, "path")
            return cmd_quarantine(client, args)
        if args.command == "audit":
            return cmd_audit(client, args)
        if args.command == "containers":
            return cmd_containers(client, args)
        if args.command == "falco":
            return cmd_falco(client, args)
        if args.command == "wazuh":
            return cmd_wazuh(client, args)
        if args.command == "yara":
            if args.action in {"install", "activate", "delete", "scan"}:
                _need(args, "target")
            if args.action in {"activate", "delete"}:
                _need(args, "version")
            if args.action in {"install", "activate", "delete"} and not args.confirm:
                raise ApiError(
                    "invalid_argument",
                    "安装/激活/删除 YARA 规则包需要显式 --confirm 二次确认",
                    400,
                )
            return cmd_yara(client, args)
        parser.error("未知命令")
        return EXIT_USAGE
    except ApiError as exc:
        if args.json:
            _print_json({"ok": False, "error": {"code": exc.code, "message": exc.message, "details": exc.details}})
        else:
            print(f"错误 [{exc.code}]: {exc.message}", file=sys.stderr)
            if exc.details:
                print(json.dumps(exc.details, ensure_ascii=False, indent=2), file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(run())
