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
                f"cannot connect to the daemon {self.server}: {exc.reason}",
                0,
            ) from None
        except json.JSONDecodeError:
            raise ApiError("internal_error", "the daemon returned a non-JSON response", 0) from None

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
            raise ApiError("internal_error", f"cannot connect to the daemon {self.server}: {exc.reason}", 0) from None


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
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }.get(value, value)


def _status_label(value: str) -> str:
    return {
        "queued": "Queued",
        "running": "Running",
        "cancel_requested": "Cancelling",
        "cancelled": "Cancelled",
        "succeeded": "Succeeded",
        "failed": "Failed",
        "partial": "Partially completed",
        "new": "New event",
        "acknowledged": "Acknowledged",
        "investigating": "Investigating",
        "resolved": "Resolved",
        "ignored": "Ignored",
        "quarantined": "Quarantined",
        "restored": "Restored",
        "deleted": "Deleted",
        "missing": "File missing",
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
    print(f"Overall status: {status['overall_label']} ({status['overall']})")
    print(f"Summary: {status['summary']}")
    protection = status["protection"]
    print(f"On-demand scan: {protection['on_demand']['state']} - {protection['on_demand']['reason']}")
    print(f"Real-time protection: {protection['real_time']['state']} - {protection['real_time']['reason']}")
    db = protection["virus_database"]
    print(f"Virus database: {db['state']}  updated at {db.get('updated_at') or 'unknown'}  about {db.get('age_hours', '?')} hours ago")
    events = status["events"]
    print(
        f"Unhandled events: critical {events['critical']} / high {events['high']} / "
        f"medium {events['medium']} / low {events['low']}"
    )
    last = status.get("last_scan")
    if last:
        print(
            f"Last scan: {last['task_type']} {_status_label(last['status'])} "
            f"files {last['files_scanned']} detections {last['detections_count']} errors {last['errors_count']}"
        )
    else:
        print("Last scan: none")
    baseline = status.get("host_baseline") or {}
    if baseline:
        print(f"Host audit: {baseline.get('state')} - {baseline.get('note')}")
    containers = status.get("containers") or {}
    if containers:
        print(
            f"Container monitoring: {containers.get('state')} - {containers.get('note')}"
        )
    if status.get("reasons"):
        print("Needs attention:")
        for reason in status["reasons"]:
            print(f"  - {reason}")
    print(f"Generated at: {status['generated_at']}")
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
                "yes" if c["installed"] else "no",
                c.get("version") or "-",
                c.get("service_status", "-"),
                c.get("health_status", "-"),
                (c.get("error_message") or "")[:40],
            ]
            for c in payload["components"]
        ]
        _print_table(["Component", "Name", "Installed", "Version", "Service", "Health", "Notes"], rows)
        return EXIT_OK
    if args.action == "probe":
        payload = client.request("POST", "/api/v1/components/probe", {})
        _print_json(payload) if args.json else print("Component probe completed")
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
            print(f"Update {'succeeded' if outcome.get('ok') else 'failed'}, exit code {outcome.get('exit_code')}")
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
    raise ApiError("invalid_argument", "unknown component action", 400)


def cmd_scan(client: Client, args: argparse.Namespace) -> int:
    if args.action == "quick":
        task_type, paths = "quick", []
    elif args.action == "full":
        task_type, paths = "full", []
    elif args.action == "path":
        if not args.paths:
            raise ApiError("invalid_argument", "scan path requires at least one path", 400)
        task_type, paths = "custom", args.paths
    else:
        raise ApiError("invalid_argument", "unknown scan type", 400)
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
        print(f"Scan task created: {task['task_id']}")
        print(f"Type: {task['task_type']}  Status: {_status_label(task['status'])}")
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
                f"Status: {_status_label(task['status'])}  Files: {task['files_scanned']}  "
                f"Detections: {task['detections_count']}  Errors: {task['errors_count']}  "
                f"Progress: {progress if progress is not None else 'unknown'}"
            )
            if line != last_line:
                print(line, flush=True)
                last_line = line
        if task["status"] in {"succeeded", "failed", "partial", "cancelled"}:
            if not as_json:
                summary = task.get("result_summary") or {}
                print(f"Task finished: {_status_label(task['status'])}")
                if summary.get("evidence_path"):
                    print(f"Evidence report: {summary['evidence_path']}")
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
        _print_table(["Task ID", "Type", "Status", "Progress %", "Files", "Detections", "Errors", "Created"], rows)
        return EXIT_OK
    if args.action == "show":
        payload = client.request("GET", f"/api/v1/scans/{args.task_id}")
        if args.json:
            _print_json(payload)
        else:
            task = payload["task"]
            print(f"Task: {task['task_id']}")
            print(f"Type: {task['task_type']}  Status: {_status_label(task['status'])}")
            print(f"Targets: {', '.join(task['target_paths'])}")
            print(f"Files: {task['files_scanned']}  Detections: {task['detections_count']}  Errors: {task['errors_count']}")
            print(f"Created: {task['created_at']}  Started: {task.get('started_at')}  Finished: {task.get('finished_at')}")
            summary = task.get("result_summary") or {}
            if summary.get("evidence_path"):
                print(f"Evidence: {summary['evidence_path']}")
            errors = task.get("error_details") or []
            if errors:
                print("Error samples:")
                for error in errors[:10]:
                    print(f"  - {error.get('path', '')}: {error.get('error', '')}")
        return EXIT_OK
    if args.action == "cancel":
        payload = client.request("POST", f"/api/v1/scans/{args.task_id}/cancel", {})
        _print_json(payload) if args.json else print(f"Task status: {_status_label(payload['task']['status'])}")
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown task action", 400)


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
        _print_table(["Last seen", "Severity", "Status", "Source", "Title", "Target", "Count"], rows)
        print(f"{payload['total']} total")
        return EXIT_OK
    if args.action == "show":
        payload = client.request("GET", f"/api/v1/events/{args.event_id}")
        if args.json:
            _print_json(payload)
        else:
            event = payload["event"]
            print(f"Event: {event['event_id']}")
            print(f"Title: {event['title']}")
            print(f"Severity: {_severity_label(event['severity'])}  Status: {_status_label(event['status'])}  Source: {event['source']}")
            print(f"First seen: {event['first_seen_at']}  Last seen: {event['last_seen_at']}  Count: {event['occurrences']}")
            print(f"Target: {_event_target_label(event.get('target'))}")
            print(f"Description: {event['description']}")
            evidence = event.get("evidence") or {}
            if evidence.get("detection_name"):
                print(f"Detection name: {evidence['detection_name']}")
            if evidence.get("sha256"):
                print(f"SHA256: {evidence['sha256']}")
            actions = event.get("recommended_actions") or []
            if actions:
                print("Recommendations:")
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
                print(f"Exported to {args.output}")
            else:
                sys.stdout.buffer.write(data)
            return EXIT_OK
        payload = client.request("GET", path)
        if args.output:
            Path(args.output).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            print(f"Exported to {args.output}")
        else:
            _print_json(payload)
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown event action", 400)


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
        _print_table(["ID", "Original path", "Size", "Detection", "Status", "Quarantined at"], rows)
        print(f"{payload['total']} total")
        return EXIT_OK
    if args.action == "inspect":
        payload = client.request("GET", f"/api/v1/quarantine/{args.item_id}")
        _print_json(payload)
        return EXIT_OK
    if args.action == "add":
        if not args.confirm:
            raise ApiError(
                "invalid_argument",
                "quarantining a file requires an explicit --confirm to complete the second confirmation",
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
            print(f"File quarantined: {item['item_id']}  {item['original_path']}")
            print(f"SHA256: {item['sha256']}")
        return EXIT_OK
    if args.action in {"restore", "delete"}:
        if not args.confirm:
            raise ApiError(
                "invalid_argument",
                f"{args.action} requires an explicit --confirm to complete the second confirmation",
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
            print(f"Quarantine item status: {_status_label(payload['item']['status'])}")
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown quarantine action", 400)


AUDIT_TERMINAL = {"succeeded", "partial", "failed"}


def _print_audit(audit: dict) -> None:
    summary = audit.get("result_summary") or {}
    counts = summary.get("counts") or {}
    print(f"Audit: {audit['audit_id']}")
    print(f"Status: {audit['status']}  Scope: {audit.get('scope') or '-'}")
    print(f"Created: {audit.get('created_at')}  Started: {audit.get('started_at')}  Finished: {audit.get('finished_at')}")
    print(
        f"Checks: {audit.get('checks_total', 0)}  Findings: {audit.get('findings_count', 0)}  "
        f"Not executed: {audit.get('errors_count', 0)}"
    )
    if counts:
        print(
            f"Passed: {counts.get('passed', 0)}  Skipped: {counts.get('skipped', 0)}  "
            f"Events generated: {counts.get('events_ingested', 0)}"
        )
    severity = audit.get("severity_counts") or {}
    if severity:
        print(
            "Risk levels: critical {critical} / high {high} / medium {medium} / low {low}".format(
                critical=severity.get("critical", 0),
                high=severity.get("high", 0),
                medium=severity.get("medium", 0),
                low=severity.get("low", 0),
            )
        )
    if audit.get("hardening_index") is not None:
        print(f"Lynis hardening index: {audit['hardening_index']}")
    if audit.get("lynis_available"):
        print(f"Lynis: available  version {audit.get('lynis_version') or 'unknown'}")
    else:
        print("Lynis: unavailable (built-in check results only)")
    if audit.get("error"):
        print(f"Error: {audit['error']}")
    if summary.get("scope_note"):
        print(f"Scope note: {summary['scope_note']}")

    findings = [c for c in summary.get("checks", []) if c.get("status") == "finding"]
    if findings:
        print("Risk findings:")
        for check in findings[:30]:
            print(
                f"  - [{check.get('severity')}] {check.get('check_id')} "
                f"{check.get('title')}"
            )
        if len(findings) > 30:
            print(f"  ... {len(findings) - 30} more; see the evidence report for details")
    errors = [c for c in summary.get("checks", []) if c.get("status") == "error"]
    if errors:
        print("Checks that could not run:")
        for check in errors[:20]:
            print(f"  - {check.get('check_id')}: {check.get('detail')}")
    if audit.get("evidence_path"):
        print(f"Evidence report: {audit['evidence_path']}")
    for note in summary.get("limitations", []):
        print(f"Limitation: {note}")


def _wait_audit(client: Client, audit_id: str, as_json: bool) -> int:
    last_status = ""
    while True:
        payload = client.request("GET", f"/api/v1/audits/{audit_id}")
        audit = payload["audit"]
        if as_json:
            _print_json(payload)
        elif audit["status"] != last_status:
            print(f"Status: {audit['status']}", flush=True)
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
        _print_table(["Time", "Action", "Actor", "Target", "Result", "Error"], rows)
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
            ["Audit ID", "Status", "Scope", "Checks", "Findings", "Errors", "Hardening index", "Created"],
            rows,
        )
        return EXIT_OK
    if args.action == "run":
        payload = client.request("POST", "/api/v1/audits", {})
        audit = payload["audit"]
        if args.json and not args.wait:
            _print_json(payload)
        elif not args.json:
            print(f"Audit task created: {audit['audit_id']}")
            print(f"Status: {audit['status']}  Scope: {audit.get('scope') or '-'}")
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
                raise ApiError("not_found", "there are no completed host audit records yet", 404)
            audit_id = finished[0]["audit_id"]
        payload = client.request("GET", f"/api/v1/audits/{audit_id}")
        if args.json:
            _print_json(payload)
        else:
            _print_audit(payload["audit"])
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown audit action", 400)


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
        print(f"Container monitoring: {snapshot.get('state')} - {snapshot.get('note')}")
        engine = snapshot.get("engine") or {}
        if engine:
            print(
                f"Runtime: {engine.get('runtime')} {engine.get('server_version') or ''} "
                f"API {engine.get('api_version') or '-'}"
            )
        summary = snapshot.get("summary") or {}
        print(
            f"Containers: total {summary.get('total', 0)} / running {summary.get('running', 0)} / "
            f"risky {summary.get('risky', 0)} / not evaluated {summary.get('unknown', 0)}"
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
                else "none",
                item.get("risk_count", 0),
            ]
            for item in snapshot.get("containers") or []
        ]
        if rows:
            _print_table(
                ["ID", "Name", "Image", "State", "Uptime", "Risk", "Findings"],
                rows,
            )
        else:
            print("No container data")
        return EXIT_OK
    if args.action == "refresh":
        payload = client.request("POST", "/api/v1/containers/refresh", {})
        if args.json:
            _print_json(payload)
        else:
            snapshot = payload["containers"]
            print(f"Refresh completed: {snapshot.get('state')} - {snapshot.get('note')}")
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
        print(f"Container: {container.get('name')} ({container.get('container_id')})")
        print(f"Image: {container.get('image') or '-'}")
        print(f"State: {container.get('state') or '-'}  User: {container.get('user')}")
        print(
            f"Privileged: {'yes' if container.get('privileged') else 'no'}  "
            f"Network: {container.get('network_mode')}  PID: {container.get('pid_mode') or '-'}"
        )
        print(f"Risk level: {_severity_label(container.get('risk_level') or 'unknown')}")
        if not container.get("evaluated"):
            print(f"Not evaluated: {container.get('evaluation_error')}")
        if container.get("mounts"):
            print("Mounts:")
            for mount in container["mounts"]:
                mode = "ro" if mount.get("read_only") else "rw"
                print(
                    f"  - {mount.get('source') or '-'} -> {mount.get('destination')} ({mode})"
                )
        findings = container.get("findings") or []
        if findings:
            print("Configuration risks:")
            for finding in findings:
                print(
                    f"  - [{_severity_label(finding.get('severity'))}] "
                    f"{finding.get('title')}"
                )
                print(f"    {finding.get('recommendation')}")
        else:
            print("Configuration risks: none" if container.get("evaluated") else "Configuration risks: unknown")
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown container action", 400)


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
            f"Falco: installed {'yes' if component.get('installed') else 'no'}  "
            f"version {component.get('version') or '-'}  health {component.get('health_status')}"
        )
        print(f"Notes: {component.get('error_message') or '-'}")
        print(
            f"Kernel/eBPF: {capability.get('state', 'unknown')} - "
            f"{capability.get('reason', 'no result')}"
        )
        print(
            f"Kernel {capability.get('kernel_release') or '-'}  "
            f"BTF {capability.get('btf_available')}  "
            f"CAP_SYS_ADMIN {capability.get('cap_sys_admin')}"
        )
        ingest = falco.get("event_ingest") or {}
        print(
            f"Event ingestion: {'enabled' if ingest.get('enabled') else 'disabled'}  "
            f"events {ingest.get('events_total', 0)}"
        )
        return EXIT_OK
    if args.action == "install-plan":
        payload = client.request("GET", "/api/v1/components/falco/install-plan")
        plan = payload["plan"]
        if args.json:
            _print_json(plan)
            return EXIT_OK
        print(f"Falco install plan (not executed automatically): {plan.get('risk') or ''}")
        for index, step in enumerate(plan.get("steps") or [], 1):
            print(f"{index}. {step.get('title')}")
            print(f"   {step.get('detail')}")
        for note in plan.get("notes") or []:
            print(f"Note: {note}")
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown Falco action", 400)


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
            f"YARA: installed {'yes' if component.get('installed') else 'no'}  "
            f"version {component.get('version') or '-'}  health {component.get('health_status')}"
        )
        print(f"Scan ready: {'yes' if yara.get('scan_ready') else 'no'}")
        print(f"Notes: {component.get('error_message') or '-'}")
        print(
            f"Rule packs: {rules.get('packs_count', 0)}  active: "
            f"{rules.get('active_count', 0)}"
        )
        signature = rules.get("signature") or {}
        print(
            f"Signature check: {'required' if signature.get('required') else 'not enforced'}  "
            f"public key: {'configured' if signature.get('public_key_present') else 'missing'}"
        )
        for item in rules.get("active") or []:
            print(
                f"  - {item['pack_id']}@{item['version']}  "
                f"rules {item['rules_count']}  signature {'verified' if item['signature_verified'] else 'unverified'}"
            )
        if rules.get("state_error"):
            print(f"Rule state error: {rules['state_error']}")
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
                        "yes" if version.get("active") else "no",
                        "verified" if version.get("signature_verified") else "unverified",
                        version.get("installed_at") or "-",
                    ]
                )
        _print_table(
            ["Rule pack", "Version", "Name", "Rules", "Active", "Signature", "Installed"], rows
        )
        print(f"Inbox directory: {payload.get('inbox_dir')}")
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
            f"Rule pack installed: {pack['pack_id']}@{pack['version']}  "
            f"rules {pack['rules_count']}  signature "
            f"{'verified' if pack['signature_verified'] else 'unverified'}  "
            f"activated {'yes' if pack['activated'] else 'no'}"
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
            print(f"Rule pack activated: {args.target}@{args.version}")
        else:
            print(f"Rule pack version deleted: {args.target}@{args.version}")
        return EXIT_OK
    if args.action == "scan":
        paths = [path for path in [args.target, *args.paths] if path]
        if not paths:
            raise ApiError("invalid_argument", "yara scan requires at least one scan path", 400)
        payload = client.request(
            "POST",
            "/api/v1/scans",
            {"type": "yara", "paths": paths, "engines": ["yara"]},
        )
        task = payload["task"]
        if args.json:
            _print_json(payload)
        else:
            print(f"YARA rule scan task created: {task['task_id']}")
        if args.wait:
            return _wait_task(client, task["task_id"], args.json)
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown YARA action", 400)


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
            f"Wazuh: installed {'yes' if component.get('installed') else 'no'}  "
            f"version {component.get('version') or '-'}  health {component.get('health_status')}"
        )
        print(f"Capability status: {wazuh.get('state')} (local Agent only, not a Manager)")
        print(f"Notes: {component.get('error_message') or '-'}")
        print(
            f"Manager configuration: {'yes' if manager.get('manager_configured') else 'no'}  "
            f"address {manager.get('address') or '-'}:{manager.get('port') or '-'}  "
            f"connectivity check: no"
        )
        print(
            f"Local registration: {'present' if details.get('registration_present') else 'missing or unreadable'}  "
            f"alerts file: {'present' if details.get('alerts_present') else 'absent'}"
        )
        print(
            f"Local alert ingestion: {'enabled' if ingest.get('ingest_enabled') else 'disabled'}  "
            f"running {'yes' if ingest.get('running') else 'no'}  "
            f"events {ingest.get('events_total', 0)}  parse errors {ingest.get('parse_errors', 0)}"
        )
        print(f"Ingestion notes: {ingest.get('note') or '-'}")
        return EXIT_OK
    if args.action == "install-plan":
        payload = client.request("GET", "/api/v1/wazuh/install-plan")
        plan = payload["plan"]
        if args.json:
            _print_json(plan)
            return EXIT_OK
        print("Wazuh Agent install plan (not executed automatically):")
        for index, step in enumerate(plan.get("steps") or [], 1):
            print(f"{index}. {step}")
        for note in plan.get("notes") or []:
            print(f"Note: {note}")
        return EXIT_OK
    raise ApiError("invalid_argument", "unknown Wazuh action", 400)


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
            print(f"        Remediation: {check['remediation']}")
    summary = report["summary"]
    print(
        f"Checks complete: {summary['ok']} ok, {summary['warn']} warnings, "
        f"{summary['fail']} failed, {summary['info']} info"
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
        print(f"lsec client: {__version__}")
        if payload.get("daemon_version"):
            print(f"lsec daemon: {payload['daemon_version']}  API {payload.get('api_version')}")
        elif payload.get("server_error"):
            print(f"Daemon: unreachable ({payload['server_error']})")
        else:
            print("Daemon: no token provided; skipping the query")
    return EXIT_OK


def cmd_health(client: Client, args: argparse.Namespace) -> int:
    payload = client.request("GET", "/api/v1/health", timeout=5)
    _print_json(payload) if args.json else print(f"Daemon is alive, version {payload.get('version')}")
    return EXIT_OK


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lsec", description="Linux unified security protection client CLI")
    parser.add_argument("--server", default=os.environ.get("LSEC_SERVER", "http://127.0.0.1:8080"))
    parser.add_argument("--token", help="admin/read-only access token (or use LSEC_TOKEN)")
    parser.add_argument("--token-file", help="path to the token file")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--version", action="version", version=f"lsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show overall security status")
    sub.add_parser("health", help="check whether the daemon is alive")
    sub.add_parser("version", help="show client/daemon versions")
    sub.add_parser("doctor", help="run the environment self-check")

    components = sub.add_parser("components", help="component management")
    components.add_argument("action", choices=["list", "probe", "start", "stop", "update", "install-plan"])
    components.add_argument("component", nargs="?", help="component ID, e.g. clamav")

    scan = sub.add_parser("scan", help="create a scan task")
    scan.add_argument("action", choices=["quick", "full", "path"])
    scan.add_argument("paths", nargs="*", help="custom scan paths")
    scan.add_argument(
        "--engine",
        action="append",
        choices=["clamav", "yara"],
        help="scan engine; repeatable; defaults to clamav",
    )
    scan.add_argument("--wait", action="store_true", help="wait for the scan to finish and show progress")

    task = sub.add_parser("task", help="scan tasks")
    task.add_argument("action", choices=["list", "show", "cancel"])
    task.add_argument("task_id", nargs="?")
    task.add_argument("--status")
    task.add_argument("--limit", type=int, default=50)

    events = sub.add_parser("events", help="security events")
    events.add_argument("action", choices=["list", "show", "export"])
    events.add_argument("event_id", nargs="?")
    events.add_argument("--severity")
    events.add_argument("--source")
    events.add_argument("--category")
    events.add_argument("--status")
    events.add_argument("--q")
    events.add_argument("--limit", type=int, default=50)
    events.add_argument("--format", choices=["json", "csv"], default="json")
    events.add_argument("--output", help="export file path")

    quarantine = sub.add_parser("quarantine", help="quarantine")
    quarantine.add_argument("action", choices=["list", "add", "inspect", "restore", "delete"])
    quarantine.add_argument("item_id", nargs="?")
    quarantine.add_argument("--path", help="path of the file to quarantine for the add action")
    quarantine.add_argument("--detection-name", help="detection name for the add action")
    quarantine.add_argument("--event-id", help="event ID to associate for the add action")
    quarantine.add_argument("--status", help="filter by status for the list action")
    quarantine.add_argument("--limit", type=int, default=100)
    quarantine.add_argument("--confirm", action="store_true")

    audit = sub.add_parser("audit", help="operation audit / host audit")
    audit.add_argument("action", choices=["list", "run", "report", "history"])
    audit.add_argument("audit_id", nargs="?", help="audit ID for the report action; defaults to the most recent one")
    audit.add_argument("--wait", action="store_true", help="wait for the audit to finish for the run action")
    audit.add_argument("--limit", type=int, default=100)

    containers = sub.add_parser("containers", help="container inventory and configuration risks")
    containers.add_argument("action", choices=["list", "inspect", "refresh"])
    containers.add_argument("container_id", nargs="?", help="full container ID, unique prefix, or name")

    falco = sub.add_parser("falco", help="Falco capability check and install plan")
    falco.add_argument("action", choices=["status", "install-plan"])

    wazuh = sub.add_parser("wazuh", help="optional local Wazuh Agent status")
    wazuh.add_argument("action", choices=["status", "install-plan"])

    yara = sub.add_parser("yara", help="YARA rule pack management and rule scans")
    yara.add_argument(
        "action", choices=["status", "packs", "install", "activate", "delete", "scan"]
    )
    yara.add_argument(
        "target",
        nargs="?",
        help="install: rule pack path; activate/delete: rule pack ID; scan: first scan path",
    )
    yara.add_argument("version", nargs="?", help="rule pack version for activate/delete")
    yara.add_argument("paths", nargs="*", help="additional scan paths for scan")
    yara.add_argument(
        "--no-activate",
        dest="activate",
        action="store_false",
        help="do not activate after install (activation is the default)",
    )
    yara.set_defaults(activate=True)
    yara.add_argument("--confirm", action="store_true", help="confirm install/activation/deletion")
    yara.add_argument("--wait", action="store_true", help="wait for the task to finish for the scan action")
    return parser


def _need(args: argparse.Namespace, name: str) -> None:
    if not getattr(args, name, None):
        raise ApiError("invalid_argument", f"missing argument {name}", 400)


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
                    "installing/activating/deleting a YARA rule pack requires an explicit --confirm second confirmation",
                    400,
                )
            return cmd_yara(client, args)
        parser.error("unknown command")
        return EXIT_USAGE
    except ApiError as exc:
        if args.json:
            _print_json({"ok": False, "error": {"code": exc.code, "message": exc.message, "details": exc.details}})
        else:
            print(f"Error [{exc.code}]: {exc.message}", file=sys.stderr)
            if exc.details:
                print(json.dumps(exc.details, ensure_ascii=False, indent=2), file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(run())
