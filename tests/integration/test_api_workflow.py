"""End-to-end API tests with a real daemon, HTTP server and a fake clamd.

The fake clamd is a test double for the documented UNIX-socket protocol only.
It is not shipped in the product and it never fabricates production data.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from lsec.api.server import create_server
from lsec.common.config import (
    AuditConfig,
    ClamAVConfig,
    Config,
    ContainersConfig,
    LoggingConfig,
    ResponseConfig,
    ScanConfig,
    ServerConfig,
    StorageConfig,
    YaraConfig,
)
from lsec.core.containers import ContainerService
from lsec.daemon import build_app
from tests.fake_docker import FakeDockerApi, make_inspect

EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
TERMINAL = {"succeeded", "failed", "partial", "cancelled"}


class FakeClamd:
    """Minimal clamd protocol server using documented NUL ("z") framing."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(path))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.clients: list[threading.Thread] = []

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=3)
        for client in self.clients:
            client.join(timeout=2)
        self.sock.close()
        try:
            self.path.unlink()
        except OSError:
            pass

    def _accept(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            client = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            client.start()
            self.clients.append(client)

    def _handle(self, conn: socket.socket) -> None:
        try:
            with conn:
                data = b""
                while b"\x00" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                raw = data.split(b"\x00", 1)[0]
                if raw.startswith(b"z"):
                    raw = raw[1:]
                command = raw.decode("utf-8", errors="replace").strip()
                if command == "PING":
                    reply = "PONG"
                elif command == "VERSION":
                    reply = "ClamAV 1.4.3/27000/Fri Jan 01 00:00:00 2026"
                elif command.startswith("SCAN "):
                    target = command[len("SCAN "):]
                    if "eicar" in os.path.basename(target).lower():
                        reply = f"{target}: Eicar-Test-Signature FOUND"
                    else:
                        reply = f"{target}: OK"
                elif command == "SHUTDOWN":
                    reply = "SHUTDOWN"
                    self.stop_event.set()
                else:
                    reply = f"UNKNOWN COMMAND: {command}"
                conn.sendall(reply.encode("utf-8") + b"\x00")
        except OSError:
            pass


class ApiClient:
    def __init__(self, port: int) -> None:
        self.port = port
        self.cookie = ""
        self.csrf = ""

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        csrf: str | None = None,
        cookie: str | None = None,
        origin: str | None = None,
        token: str | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        headers: dict[str, str] = {"Accept": "*/*"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        effective_cookie = self.cookie if cookie is None else cookie
        if effective_cookie and not token:
            headers["Cookie"] = effective_cookie
        effective_csrf = self.csrf if csrf is None else csrf
        if effective_csrf and not token:
            headers["X-LSEC-CSRF"] = effective_csrf
        if origin:
            headers["Origin"] = origin
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            data = response.read()
            response_headers = {key: value for key, value in response.getheaders()}
            return response.status, data, response_headers
        finally:
            conn.close()

    def json(self, method: str, path: str, body: dict | None = None, **kwargs) -> tuple[int, dict, dict]:
        status, data, headers = self.request(method, path, body, **kwargs)
        try:
            payload = json.loads(data.decode("utf-8")) if data else {}
        except json.JSONDecodeError:
            payload = {"raw": data.decode("utf-8", errors="replace")}
        return status, payload, headers

    def login(self, token: str) -> dict:
        status, payload, headers = self.json("POST", "/api/v1/auth/login", {"token": token})
        if status != 200:
            raise AssertionError(f"login failed: {status} {payload}")
        set_cookie = headers.get("Set-Cookie", "")
        self.cookie = set_cookie.split(";", 1)[0]
        self.csrf = payload["csrf_token"]
        return payload


class ApiWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scan_dir = root / "scan"
        self.db_dir = root / "clamav-db"
        self.data_dir = root / "data"
        for directory in (self.scan_dir, self.db_dir, self.data_dir, root / "logs"):
            directory.mkdir(parents=True, exist_ok=True)
        (self.db_dir / "main.cvd").write_bytes(b"fake-signature-database")
        self.fake_clamd = FakeClamd(root / "clamd.ctl")
        self.fake_clamd.start()
        self.addCleanup(self.fake_clamd.close)

        config = Config(
            server=ServerConfig(bind="127.0.0.1", port=0, session_ttl_hours=1),
            storage=StorageConfig(data_dir=str(self.data_dir)),
            scan=ScanConfig(
                allowed_roots=(str(self.scan_dir),),
                quick_scan_paths=(str(self.scan_dir),),
                skip_paths=(),
                max_file_size_mb=10,
                max_parallel_tasks=1,
            ),
            response=ResponseConfig(
                quarantine_roots=(str(self.scan_dir),), default_mode="suggest"
            ),
            clamav=ClamAVConfig(
                socket_path=str(root / "clamd.ctl"),
                clamd_bin="/bin/echo",
                freshclam_bin="/bin/true",
                clamscan_bin="/bin/echo",
                database_dir=str(self.db_dir),
                config_path=str(self.data_dir / "clamav" / "clamd.conf"),
                auto_start=False,
                startup_update=False,
            ),
            audit=AuditConfig(lynis_enabled=False),
            yara=YaraConfig(
                enabled=False,
                rules_dir=str(root / "yara"),
                inbox_dir=str(root / "yara" / "inbox"),
                public_key=str(root / "yara" / "trusted.pem"),
                require_signature=False,
            ),
            logging=LoggingConfig(file=str(root / "logs" / "lsec.log")),
            config_path=str(root / "lsec.toml"),
            config_loaded=False,
        )
        self.app, services = build_app(config)
        self.components = services["components"]
        self.scans = services["scans"]
        self.audits = services["audits"]
        self.components.probe_all()
        self.scans.start()
        self.addCleanup(self.scans.stop)
        self.audits.start()
        self.addCleanup(self.audits.stop)

        self.server = create_server(self.app)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)

        self.admin = ApiClient(self.port)
        self.admin.login(self.app.auth.tokens["admin"])
        self.viewer = ApiClient(self.port)
        self.viewer.login(self.app.auth.tokens["viewer"])

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    # ------------------------------------------------------------- helpers
    def create_file(self, name: str, content: str) -> Path:
        path = self.scan_dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def wait_for_task(self, task_id: str, timeout: float = 20.0) -> dict:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            status, payload, _ = self.admin.json("GET", f"/api/v1/scans/{task_id}")
            self.assertEqual(status, 200, payload)
            last = payload["task"]
            if last["status"] in TERMINAL:
                return last
            time.sleep(0.1)
        self.fail(f"task did not finish: {last}")

    def run_quick_scan(self) -> tuple[dict, list[dict]]:
        self.create_file("eicar.txt", EICAR)
        self.create_file("clean.txt", "totally harmless content")
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/scans", {"type": "quick", "engines": ["clamav"]}
        )
        self.assertEqual(status, 201, payload)
        task = self.wait_for_task(payload["task"]["task_id"])
        status, payload, _ = self.admin.json("GET", "/api/v1/events?limit=20")
        self.assertEqual(status, 200, payload)
        return task, payload["events"]

    # --------------------------------------------------------------- tests
    def test_health_and_static_security_headers(self) -> None:
        status, payload, _ = self.admin.json("GET", "/api/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "alive")

        status, body, headers = self.admin.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"lsec", body)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("script-src 'self'", headers.get("Content-Security-Policy", ""))

        status, body, _ = self.admin.request("GET", "/assets/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"use strict", body)

        status, _, _ = self.admin.request("GET", "/assets/../lsec.db")
        self.assertEqual(status, 404)

    def test_authentication_is_required(self) -> None:
        anonymous = ApiClient(self.port)
        status, payload, _ = anonymous.json("GET", "/api/v1/status")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "unauthorized")

        status, payload, _ = anonymous.json(
            "POST", "/api/v1/auth/login", {"token": "not-the-token"}
        )
        self.assertEqual(status, 401)

    def test_viewer_is_read_only(self) -> None:
        status, payload, _ = self.viewer.json("GET", "/api/v1/status")
        self.assertEqual(status, 200)
        self.assertIn(payload["status"]["overall"], {"at_risk", "protection_incomplete", "healthy"})

        status, payload, _ = self.viewer.json(
            "POST", "/api/v1/scans", {"type": "quick", "engines": ["clamav"]}
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "forbidden")

        status, _, _ = self.viewer.request("GET", "/api/v1/logs")
        self.assertEqual(status, 403)

    def test_csrf_and_origin_are_enforced(self) -> None:
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/scans", {"type": "quick", "engines": ["clamav"]}, csrf=""
        )
        self.assertEqual(status, 403)

        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/scans",
            {"type": "quick", "engines": ["clamav"]},
            origin="http://evil.example",
        )
        self.assertEqual(status, 403)

    def test_truthful_status_and_capabilities(self) -> None:
        status, payload, _ = self.admin.json("GET", "/api/v1/status")
        self.assertEqual(status, 200)
        protection = payload["status"]["protection"]
        self.assertEqual(protection["on_demand"]["state"], "ready")
        self.assertEqual(protection["real_time"]["state"], "unsupported")
        self.assertEqual(protection["virus_database"]["state"], "current")
        # Real-time protection is unsupported, so the aggregate must not be "healthy".
        self.assertNotEqual(payload["status"]["overall"], "healthy")
        self.assertIn("real-time protection", " ".join(payload["status"]["reasons"]))

        status, payload, _ = self.admin.json("GET", "/api/v1/capabilities")
        self.assertEqual(payload["capabilities"]["malware_scan"]["state"], "available")
        self.assertEqual(payload["capabilities"]["host_audit"]["state"], "available")
        self.assertFalse(payload["capabilities"]["host_audit"]["lynis"]["enabled"])
        self.assertEqual(
            payload["capabilities"]["container_security"]["state"], "disabled"
        )
        self.assertIn(
            payload["capabilities"]["falco"]["state"],
            {
                "unavailable",
                "unknown",
                "incompatible",
                "requires_privileges",
                "requires_setup",
                "available",
                "disabled",
            },
        )

    def wait_for_audit(self, audit_id: str, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            status, payload, _ = self.admin.json("GET", f"/api/v1/audits/{audit_id}")
            self.assertEqual(status, 200, payload)
            last = payload["audit"]
            if last["status"] in {"succeeded", "partial", "failed"}:
                return last
            time.sleep(0.1)
        self.fail(f"audit did not finish: {last}")

    def test_host_audit_flow_and_permissions(self) -> None:
        status, payload, _ = self.viewer.json("POST", "/api/v1/audits")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "forbidden")

        status, payload, _ = self.admin.json("POST", "/api/v1/audits")
        self.assertEqual(status, 202, payload)
        audit_id = payload["audit"]["audit_id"]
        self.assertEqual(payload["audit"]["status"], "queued")

        audit = self.wait_for_audit(audit_id)
        self.assertIn(audit["status"], {"succeeded", "partial"})
        summary = audit["result_summary"]
        self.assertTrue(summary["scope_note"])
        self.assertTrue(summary["limitations"])
        self.assertFalse(summary["lynis"]["available"])
        checks = summary["checks"]
        self.assertGreater(len(checks), 0)
        self.assertEqual(summary["counts"]["checks"], len(checks))
        for check in checks:
            self.assertIn(check["status"], {"pass", "finding", "error", "skipped"})
            if check["status"] == "finding":
                self.assertIn(
                    check["severity"], {"critical", "high", "medium", "low", "info"}
                )
        self.assertIn("AUTH-UID0", {check["check_id"] for check in checks})
        self.assertTrue(Path(audit["evidence_path"]).is_file())

        # Checks that could not run must be counted as errors, not findings.
        errors = [check for check in checks if check["status"] == "error"]
        self.assertEqual(audit["errors_count"], len(errors) + summary["counts"]["event_errors"])

        status, payload, _ = self.admin.json("GET", "/api/v1/audits?limit=5")
        self.assertEqual(status, 200, payload)
        self.assertIn(audit_id, {item["audit_id"] for item in payload["audits"]})

        status, payload, _ = self.viewer.json("GET", f"/api/v1/audits/{audit_id}")
        self.assertEqual(status, 200, payload)

        status, payload, _ = self.admin.json("GET", "/api/v1/status")
        baseline = payload["status"]["host_baseline"]
        self.assertIn(baseline["state"], {"current", "failed"})
        self.assertEqual(baseline["last_audit"]["audit_id"], audit_id)

        status, payload, _ = self.admin.json("GET", "/api/v1/audit?action=audit.run")
        self.assertEqual(status, 200, payload)
        self.assertIn(audit_id, {item["target"] for item in payload["records"]})

    def test_container_inventory_risk_and_falco_ingest(self) -> None:
        cid = "d" * 64
        api = FakeDockerApi()
        api.set_containers(
            [
                make_inspect(
                    cid,
                    "risky-web",
                    privileged=True,
                    network_mode="host",
                    cap_add=["SYS_ADMIN"],
                    mounts=[
                        {
                            "Type": "bind",
                            "Source": "/var/run/docker.sock",
                            "Destination": "/var/run/docker.sock",
                            "RW": True,
                            "Propagation": "rprivate",
                        }
                    ],
                )
            ]
        )
        api.start()
        self.addCleanup(api.stop)

        service = ContainerService(
            ContainersConfig(
                enabled=True,
                api_url=api.url,
                timeout_seconds=2,
                refresh_seconds=15,
                max_containers=10,
            ),
            self.app.events,
        )
        self.app.containers = service
        self.app.status.containers = service
        snapshot = service.refresh()
        self.assertEqual(snapshot["state"], "monitored")
        self.assertEqual(snapshot["summary"]["risky"], 1)

        status, payload, _ = self.viewer.json("GET", "/api/v1/containers")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["containers"]["summary"]["running"], 1)
        # The API must never receive a mutating Docker request.
        self.assertTrue(all(method == "GET" for method, _ in api.requests))

        status, payload, _ = self.admin.json("GET", f"/api/v1/containers/{cid[:12]}")
        self.assertEqual(status, 200, payload)
        container = payload["container"]
        self.assertEqual(container["name"], "risky-web")
        self.assertTrue(container["privileged"])
        self.assertIn(
            "CONTAINER-PRIVILEGED",
            {finding["key"] for finding in container["findings"]},
        )

        status, payload, _ = self.viewer.json(
            "POST", "/api/v1/containers/refresh"
        )
        self.assertEqual(status, 403)
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/containers/refresh"
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = self.admin.json(
            "POST", f"/api/v1/containers/{cid}/stop"
        )
        self.assertEqual(status, 404)

        status, payload, _ = self.admin.json(
            "GET", "/api/v1/events?source=docker"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["events"]), 3)
        self.assertEqual(
            {item["target"]["container_id"] for item in payload["events"]}, {cid}
        )
        self.assertEqual(
            sorted(item["severity"] for item in payload["events"]),
            ["critical", "critical", "high"],
        )
        rules = {
            (item.get("evidence") or {}).get("rule_id")
            for item in payload["events"]
        }
        self.assertIn("CONTAINER-PRIVILEGED", rules)
        self.assertIn("CONTAINER-HOST-NETWORK", rules)
        self.assertTrue(
            any(str(rule).startswith("CONTAINER-DOCKER-SOCKET:") for rule in rules)
        )

        status, payload, _ = self.admin.json("GET", "/api/v1/status")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"]["containers"]["state"], "monitored")
        self.assertEqual(payload["status"]["containers"]["risky"], 1)

        status, payload, _ = self.admin.json("GET", "/api/v1/capabilities")
        self.assertEqual(
            payload["capabilities"]["container_security"]["state"], "available"
        )

        status, payload, _ = self.admin.json("GET", "/api/v1/audit?action=container.refresh")
        self.assertEqual(status, 200, payload)
        self.assertIn(
            "docker", {item["target"] for item in payload["records"]}
        )

        # Falco ingestion uses a dedicated token, not admin/viewer credentials.
        falco_token = "f" * 48
        self.app.auth.falco_token = falco_token
        falco_event = {
            "uuid": "9a8b7c6d-1111-2222-3333-444455556666",
            "time": "2026-11-10T09:10:00Z",
            "rule": "Unexpected shell in container",
            "priority": "Warning",
            "output": "shell spawned in risky-web",
            "output_fields": {
                "container.id": cid,
                "container.name": "risky-web",
                "container.image.repository": "nginx",
                "proc.name": "bash",
                "proc.pid": 777,
            },
        }
        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/integrations/falco",
            falco_event,
            token=falco_token,
        )
        self.assertEqual(status, 202, payload)
        self.assertTrue(payload["created"])

        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/integrations/falco",
            falco_event,
            token=falco_token,
        )
        self.assertEqual(status, 202, payload)
        self.assertFalse(payload["created"])

        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/integrations/falco",
            falco_event,
            token=self.app.auth.tokens["admin"],
        )
        self.assertEqual(status, 401)

        status, _, _ = self.admin.request(
            "GET", "/api/v1/status", token=falco_token
        )
        self.assertEqual(status, 401)

        status, payload, _ = self.viewer.json("GET", "/api/v1/events?source=falco")
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(payload["events"][0]["occurrences"], 2)
        self.assertEqual(payload["events"][0]["target"]["pid"], 777)

        status, payload, _ = self.viewer.json("GET", "/api/v1/falco")
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["falco"]["event_ingest"]["enabled"])
        self.assertEqual(
            payload["falco"]["event_ingest"]["events_total"], 1
        )

    def test_scan_pipeline_creates_event_and_evidence(self) -> None:
        task, events = self.run_quick_scan()
        self.assertEqual(task["status"], "succeeded")
        self.assertEqual(task["files_scanned"], 2)
        self.assertEqual(task["detections_count"], 1)
        self.assertEqual(task["errors_count"], 0)
        report = Path(task["result_summary"]["evidence_path"])
        self.assertTrue(report.is_file())
        self.assertIn("Eicar-Test-Signature", report.read_text(encoding="utf-8"))

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["source"], "clamav")
        self.assertEqual(event["category"], "malware")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["status"], "new")
        self.assertEqual(event["occurrences"], 1)
        self.assertEqual(event["target"]["path"], str(self.scan_dir / "eicar.txt"))
        self.assertEqual(event["evidence"]["detection_name"], "Eicar-Test-Signature")
        self.assertEqual(len(event["evidence"]["sha256"]), 64)

        # A second scan merges into the open event instead of duplicating it.
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/scans", {"type": "quick", "engines": ["clamav"]}
        )
        self.assertEqual(status, 201)
        self.wait_for_task(payload["task"]["task_id"])
        status, payload, _ = self.admin.json("GET", "/api/v1/events?limit=20")
        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(payload["events"][0]["occurrences"], 2)

    def test_quarantine_restore_delete_flow(self) -> None:
        self.create_file("eicar.txt", EICAR)
        target = self.scan_dir / "eicar.txt"
        original = target.read_text(encoding="utf-8")

        # Missing explicit confirmation is rejected.
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/quarantine", {"path": str(target)}
        )
        self.assertEqual(status, 400)
        self.assertTrue(target.exists())

        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/quarantine",
            {
                "path": str(target),
                "detection_name": "Eicar-Test-Signature",
                "engine": "clamav",
                "confirm": True,
            },
        )
        self.assertEqual(status, 201, payload)
        item = payload["item"]
        item_id = item["item_id"]
        self.assertEqual(item["status"], "quarantined")
        self.assertFalse(target.exists())
        self.assertEqual(len(item["sha256"]), 64)

        status, payload, _ = self.admin.json("GET", f"/api/v1/quarantine/{item_id}")
        self.assertTrue(payload["item"]["file_exists"])

        # Occupied original path must never be overwritten.
        target.write_text("attacker replacement", encoding="utf-8")
        status, payload, _ = self.admin.json(
            "POST",
            f"/api/v1/quarantine/{item_id}/restore",
            {"confirm": True},
        )
        self.assertEqual(status, 409)
        self.assertEqual(target.read_text(encoding="utf-8"), "attacker replacement")
        target.unlink()

        status, payload, _ = self.admin.json(
            "POST",
            f"/api/v1/quarantine/{item_id}/restore",
            {"confirm": True},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(target.read_text(encoding="utf-8"), original)
        self.assertEqual(payload["item"]["status"], "restored")

        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/quarantine",
            {"path": str(target), "confirm": True},
        )
        self.assertEqual(status, 201, payload)
        second_id = payload["item"]["item_id"]
        status, payload, _ = self.admin.json(
            "POST", f"/api/v1/quarantine/{second_id}/delete", {"confirm": True}
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["item"]["status"], "deleted")
        self.assertFalse(target.exists())

        status, payload, _ = self.admin.json("GET", "/api/v1/audit?limit=200")
        actions = {record["action"] for record in payload["records"]}
        self.assertIn("quarantine.create", actions)
        self.assertIn("quarantine.restore", actions)
        self.assertIn("quarantine.delete", actions)

    def test_quarantine_rejects_symlinks_and_outside_paths(self) -> None:
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.scan_dir / "link.txt"
        link.symlink_to(outside)
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/quarantine", {"path": str(link), "confirm": True}
        )
        self.assertEqual(status, 400)
        self.assertTrue(outside.exists())

        status, payload, _ = self.admin.json(
            "POST", "/api/v1/quarantine", {"path": str(outside), "confirm": True}
        )
        self.assertEqual(status, 400)
        self.assertTrue(outside.exists())

    def test_event_status_and_csv_export(self) -> None:
        _task, events = self.run_quick_scan()
        event_id = events[0]["event_id"]
        status, payload, _ = self.admin.json(
            "PATCH",
            f"/api/v1/events/{event_id}",
            {"status": "acknowledged", "note": "triaged"},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["event"]["status"], "acknowledged")
        self.assertEqual(payload["event"]["evidence"]["status_notes"][0]["note"], "triaged")

        status, payload, _ = self.admin.json(
            "PATCH", f"/api/v1/events/{event_id}", {"status": "new"}
        )
        self.assertEqual(status, 400)

        status, body, headers = self.admin.request(
            "GET", "/api/v1/events/export?format=csv"
        )
        self.assertEqual(status, 200)
        text = body.decode("utf-8-sig")
        self.assertIn("event_id", text)
        self.assertIn("Eicar-Test-Signature", text)
        self.assertIn("text/csv", headers.get("Content-Type", ""))

        status, body, headers = self.admin.request(
            "GET", "/api/v1/events/export?format=json"
        )
        exported = json.loads(body.decode("utf-8"))
        self.assertEqual(len(exported["events"]), 1)

    def test_settings_are_validated_and_future_modes_refused(self) -> None:
        status, payload, _ = self.admin.json("GET", "/api/v1/settings")
        self.assertEqual(status, 200)
        self.assertEqual(payload["settings"]["response_mode"], "suggest")
        self.assertFalse(payload["settings"]["auto_quarantine_enabled"])

        status, payload, _ = self.admin.json(
            "PATCH", "/api/v1/settings", {"response_mode": "auto"}
        )
        self.assertEqual(status, 501)
        self.assertEqual(payload["error"]["code"], "not_implemented")

        status, payload, _ = self.admin.json(
            "PATCH",
            "/api/v1/settings",
            {
                "response_mode": "alert",
                "scheduled_scan": {
                    "enabled": True,
                    "type": "quick",
                    "interval_hours": 12,
                },
            },
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["settings"]["response_mode"], "alert")
        self.assertTrue(payload["settings"]["scheduled_scan"]["enabled"])
        self.assertEqual(payload["settings"]["scheduled_scan"]["interval_hours"], 12)

        status, payload, _ = self.viewer.json(
            "PATCH", "/api/v1/settings", {"response_mode": "suggest"}
        )
        self.assertEqual(status, 403)

    def test_doctor_reports_real_environment(self) -> None:
        status, payload, _ = self.admin.json("GET", "/api/v1/doctor")
        self.assertEqual(status, 200)
        checks = {check["id"]: check for check in payload["report"]["checks"]}
        self.assertEqual(checks["database"]["status"], "ok")
        self.assertIn("clamav_db", checks)
        self.assertEqual(checks["clamav_db"]["status"], "ok")
        self.assertGreaterEqual(payload["report"]["summary"]["total"], 5)

    def test_api_rejects_invalid_scan_shapes(self) -> None:
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/scans", {"type": "quick", "paths": "not-a-list"}
        )
        self.assertEqual(status, 400)
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/scans", {"type": "yara"}
        )
        self.assertEqual(status, 400)
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/scans", {"type": "custom", "paths": ["/etc"]}
        )
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
