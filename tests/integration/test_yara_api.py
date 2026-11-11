"""End-to-end YARA rule-pack API, scan and event tests.

Fake ``yara``/``yarac`` binaries stand in for the real engines; the API,
storage, scan queue, event dedup and audit paths are the real daemon code.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path

from lsec.api.server import create_server
from lsec.common.config import (
    AuditConfig,
    ClamAVConfig,
    Config,
    LoggingConfig,
    ResponseConfig,
    ScanConfig,
    ServerConfig,
    StorageConfig,
    YaraConfig,
)
from lsec.daemon import build_app
from tests.integration.test_api_workflow import ApiClient, TERMINAL

FAKE_YARAC = """#!/bin/sh
if [ "$1" = "--version" ]; then echo "4.5.0-fake"; exit 0; fi
last=""
for arg in "$@"; do last="$arg"; done
: > "$last"
exit 0
"""

FAKE_YARA = """#!/bin/sh
if [ "$1" = "--version" ]; then echo "4.5.0-fake"; exit 0; fi
if [ "$3" != "-C" ] || [ "$5" != "--scan-list" ] || [ ! -f "$6" ]; then
  echo "unexpected yara arguments" >&2
  exit 2
fi
while IFS= read -r f; do
  case "$f" in *eicar*) printf 'EICAR_Test_String [eicar,test] %s\\n' "$f" ;; esac
done < "$6"
exit 0
"""


def _write_exec(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


class YaraApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.root = root
        self.scan_dir = root / "scan"
        self.inbox = root / "yara" / "inbox"
        self.scan_dir.mkdir()
        (root / "logs").mkdir()
        tools = root / "tools"
        tools.mkdir()
        self.yarac = _write_exec(tools / "yarac", FAKE_YARAC)
        self.yara = _write_exec(tools / "yara", FAKE_YARA)
        config = Config(
            server=ServerConfig(bind="127.0.0.1", port=0, session_ttl_hours=1),
            storage=StorageConfig(data_dir=str(root / "data")),
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
                socket_path=str(root / "missing-clamd.ctl"),
                clamd_bin="/bin/echo",
                freshclam_bin="/bin/true",
                clamscan_bin="/bin/echo",
                database_dir=str(root / "clamav-db"),
                config_path=str(root / "clamav" / "clamd.conf"),
                auto_start=False,
                startup_update=False,
            ),
            audit=AuditConfig(lynis_enabled=False),
            yara=YaraConfig(
                binary=str(self.yara),
                yarac_binary=str(self.yarac),
                enabled=True,
                rules_dir=str(root / "yara"),
                inbox_dir=str(self.inbox),
                public_key="",
                require_signature=False,
                max_pack_mb=5,
                max_rule_files=20,
            ),
            logging=LoggingConfig(file=str(root / "logs" / "lsec.log")),
            config_path=str(root / "lsec.toml"),
            config_loaded=False,
        )
        self.app, services = build_app(config)
        self.components = services["components"]
        self.scans = services["scans"]
        self.yara_rules = services["yara_rules"]
        self.components.probe_all()
        self.scans.start()
        self.addCleanup(self.scans.stop)

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
    def make_pack(self, version: str = "1.0.0") -> Path:
        rule = b'rule EICAR_Test_String : eicar test {\n  strings:\n    $a = "eicar"\n  condition:\n    $a\n}\n'
        manifest = {
            "schema_version": 1,
            "pack_id": "integration-pack",
            "version": version,
            "name": "Integration Pack",
            "rules": [{"path": "rules/eicar.yar", "sha256": hashlib.sha256(rule).hexdigest()}],
        }
        directory = self.inbox / version
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "pack.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr("rules/eicar.yar", rule)
        return path

    def wait_task(self, task_id: str, timeout: float = 20.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status, payload, _ = self.admin.json("GET", f"/api/v1/scans/{task_id}")
            self.assertEqual(status, 200, payload)
            task = payload["task"]
            if task["status"] in TERMINAL:
                return task
            time.sleep(0.1)
        self.fail(f"task {task_id} did not finish")

    # --------------------------------------------------------------- tests
    def test_viewer_can_read_but_not_install_packs(self) -> None:
        status, payload, _ = self.viewer.json("GET", "/api/v1/yara")
        self.assertEqual(status, 200)
        self.assertIn("yara", payload)
        status, payload, _ = self.viewer.json(
            "POST", "/api/v1/yara/packs", {"path": "/x", "confirm": True}
        )
        self.assertEqual(status, 403, payload)

    def test_install_requires_confirmation(self) -> None:
        pack = self.make_pack()
        status, payload, _ = self.admin.json(
            "POST", "/api/v1/yara/packs", {"path": str(pack)}
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("confirm", payload["error"]["message"])
        self.assertEqual(self.yara_rules.list_packs(), [])

    def test_install_activate_and_delete_versions(self) -> None:
        one = self.make_pack("1.0.0")
        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/yara/packs",
            {"path": str(one), "activate": True, "confirm": True},
        )
        self.assertEqual(status, 201, payload)
        self.assertEqual(payload["pack"]["pack_id"], "integration-pack")
        self.assertTrue(payload["pack"]["activated"])

        status, payload, _ = self.admin.json("GET", "/api/v1/yara/packs")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["packs"]), 1)
        self.assertEqual(payload["packs"][0]["active_version"], "1.0.0")

        two = self.make_pack("2.0.0")
        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/yara/packs",
            {"path": str(two), "activate": False, "confirm": True},
        )
        self.assertEqual(status, 201, payload)

        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/yara/packs/integration-pack/1.0.0/activate",
            {"confirm": True},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["pack"]["active_version"], "1.0.0")

        status, payload, _ = self.admin.json(
            "DELETE", "/api/v1/yara/packs/integration-pack/1.0.0", {"confirm": True}
        )
        self.assertEqual(status, 409, payload)
        status, payload, _ = self.admin.json(
            "DELETE", "/api/v1/yara/packs/integration-pack/2.0.0", {"confirm": True}
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = self.admin.json("GET", "/api/v1/yara/packs")
        versions = payload["packs"][0]["versions"]
        self.assertEqual([item["version"] for item in versions], ["1.0.0"])

        status, audit_payload, _ = self.admin.json(
            "GET", "/api/v1/audit?limit=100"
        )
        self.assertEqual(status, 200, audit_payload)
        actions = {
            row.get("action") for row in audit_payload.get("records", [])
        }
        self.assertIn("yara.pack.install", actions)
        self.assertIn("yara.pack.activate", actions)
        self.assertIn("yara.pack.delete", actions)

    def test_invalid_pack_is_rejected_and_not_listed(self) -> None:
        directory = self.inbox / "bad"
        directory.mkdir()
        path = directory / "bad.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", '{"schema_version": 1}')
        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/yara/packs",
            {"path": str(path), "activate": True, "confirm": True},
        )
        self.assertEqual(status, 400, payload)
        self.assertEqual(self.yara_rules.list_packs(), [])
        self.assertEqual(
            [path for path in (Path(self.yara_rules.staging_root)).iterdir()
             if path.is_dir()],
            [],
        )

    def test_yara_scan_creates_event_and_dedups(self) -> None:
        pack = self.make_pack()
        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/yara/packs",
            {"path": str(pack), "activate": True, "confirm": True},
        )
        self.assertEqual(status, 201, payload)
        target = self.scan_dir / "eicar-sample.txt"
        target.write_text("eicar test file", encoding="utf-8")
        (self.scan_dir / "normal.txt").write_text("clean", encoding="utf-8")

        for _ in range(2):
            status, payload, _ = self.admin.json(
                "POST",
                "/api/v1/scans",
                {"type": "yara", "paths": [str(target)], "engines": ["yara"]},
            )
            self.assertEqual(status, 201, payload)
            task = self.wait_task(payload["task"]["task_id"])
            self.assertEqual(task["status"], "succeeded", task)
            self.assertEqual(task["detections_count"], 1)
            event_ids = [item["event_id"] for item in task["result_summary"]["detections_sample"]]
            first_event = event_ids[0]

        status, payload, _ = self.admin.json("GET", f"/api/v1/events/{first_event}")
        self.assertEqual(status, 200, payload)
        event = payload["event"]
        self.assertEqual(event["source"], "yara")
        self.assertEqual(event["category"], "malware")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["occurrences"], 2)
        self.assertEqual(event["target"].get("path"), str(target))
        self.assertIn("不等同", event["description"])

        status, payload, _ = self.admin.json("GET", "/api/v1/quarantine")
        self.assertEqual(status, 200)
        self.assertEqual(payload.get("items", []), [])

    def test_yara_scan_without_active_pack_is_rejected(self) -> None:
        target = self.scan_dir / "eicar-sample.txt"
        target.write_text("eicar", encoding="utf-8")
        status, payload, _ = self.admin.json(
            "POST",
            "/api/v1/scans",
            {"type": "yara", "paths": [str(target)], "engines": ["yara"]},
        )
        self.assertNotEqual(status, 202)
        self.assertEqual(payload["error"]["code"], "component_unavailable")


if __name__ == "__main__":
    unittest.main()
