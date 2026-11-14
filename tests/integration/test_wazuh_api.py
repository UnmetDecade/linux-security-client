"""Wazuh optional-integration API tests.

The fake control binary and local ``alerts.json`` exercise the real adapter,
ingester, event store and API. Nothing here contacts a Wazuh Manager.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
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
    WazuhConfig,
    YaraConfig,
)
from lsec.daemon import build_app
from tests.integration.test_api_workflow import ApiClient

FAKE_CONTROL = """#!/bin/sh
if [ "$1" = "info" ]; then
  echo 'WAZUH_VERSION="v4.7.0"'
  exit 0
fi
if [ "$1" = "status" ]; then
  echo "wazuh-agentd is running..."
  exit 0
fi
exit 1
"""


def _write_exec(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


def _alert(level: int = 10, description: str = "Multiple authentication failures") -> dict:
    return {
        "timestamp": "2026-11-10T10:00:00.000+0000",
        "rule": {
            "level": level,
            "description": description,
            "id": "5710",
            "groups": ["syslog", "authentication_failed", "sshd"],
        },
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.11"},
        "location": "/var/log/auth.log",
        "data": {"srcip": "203.0.113.7"},
    }


class WazuhApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.root = root
        tools = root / "tools"
        tools.mkdir()
        self.control = _write_exec(tools / "wazuh-control", FAKE_CONTROL)
        self.agent = _write_exec(tools / "wazuh-agentd", "#!/bin/sh\nexit 0\n")
        self.install = root / "ossec"
        (self.install / "etc").mkdir(parents=True)
        (self.install / "etc" / "ossec.conf").write_text(
            "<ossec_config><client><server><address>10.0.0.1</address>"
            "<port>1514</port></server></client></ossec_config>",
            encoding="utf-8",
        )
        (self.install / "etc" / "client.keys").write_text(
            "001 web-01 10.0.0.11 not-a-real-key\n", encoding="utf-8"
        )
        self.alerts = root / "alerts.json"
        self.alerts.write_text("", encoding="utf-8")
        (root / "scan").mkdir()
        (root / "logs").mkdir()

        config = Config(
            server=ServerConfig(bind="127.0.0.1", port=0, session_ttl_hours=1),
            storage=StorageConfig(data_dir=str(root / "data")),
            scan=ScanConfig(
                allowed_roots=(str(root / "scan"),),
                quick_scan_paths=(str(root / "scan"),),
                skip_paths=(),
                max_file_size_mb=10,
                max_parallel_tasks=1,
            ),
            response=ResponseConfig(
                quarantine_roots=(str(root / "scan"),), default_mode="suggest"
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
                enabled=False,
                rules_dir=str(root / "yara"),
                inbox_dir=str(root / "yara" / "inbox"),
                public_key="",
                require_signature=False,
            ),
            wazuh=WazuhConfig(
                enabled=True,
                agent_bin=str(self.agent),
                control_bin=str(self.control),
                install_dir=str(self.install),
                alerts_path=str(self.alerts),
                ingest_enabled=True,
                poll_seconds=1,
                state_dir=str(root / "wazuh-state"),
            ),
            logging=LoggingConfig(file=str(root / "logs" / "lsec.log")),
            config_path=str(root / "lsec.toml"),
            config_loaded=False,
        )
        self.app, services = build_app(config)
        self.components = services["components"]
        self.ingester = services["wazuh_ingest"]
        self.components.probe_all()

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
        self.ingester.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _append(self, *alerts: dict) -> None:
        with self.alerts.open("a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(alert) + "\n")

    # --------------------------------------------------------------- tests
    def test_viewer_can_read_status(self) -> None:
        status, payload, _ = self.viewer.json("GET", "/api/v1/wazuh")
        self.assertEqual(status, 200, payload)
        wazuh = payload["wazuh"]
        self.assertEqual(wazuh["scope"], "local_agent_only")
        self.assertFalse(wazuh["connection_verified"])
        self.assertIn("not a Wazuh Manager", wazuh["note"])
        self.assertEqual(wazuh["component"]["version"], "4.7.0")
        self.assertEqual(wazuh["component"]["service_status"], "running")
        self.assertTrue(wazuh["component"]["details"]["registration_present"])
        self.assertEqual(wazuh["ingest"]["scope"], "local_agent_alert_file")

    def test_capabilities_never_claim_full_wazuh(self) -> None:
        status, payload, _ = self.admin.json("GET", "/api/v1/capabilities")
        self.assertEqual(status, 200)
        wazuh = payload["capabilities"]["wazuh"]
        self.assertEqual(wazuh["state"], "degraded")
        self.assertTrue(wazuh["installed"])
        self.assertFalse(wazuh["connection_verified"])
        self.assertEqual(wazuh["manager"]["address"], "10.0.0.1")
        self.assertEqual(wazuh["ingest"]["ingest_enabled"], True)
        # Credentials/key contents are never exposed.
        serialized = json.dumps(payload)
        self.assertNotIn("not-a-real-key", serialized)

    def test_install_plan_is_manual_and_readable(self) -> None:
        for client in (self.admin, self.viewer):
            status, payload, _ = client.json("GET", "/api/v1/wazuh/install-plan")
            self.assertEqual(status, 200, payload)
            plan = payload["plan"]
            self.assertFalse(plan["installable_from_ui"])
            self.assertTrue(any("not a Wazuh Manager" in note for note in plan["notes"]))

    def test_alert_ingestion_creates_unified_event(self) -> None:
        self.ingester.tick()  # initialize at current EOF
        self._append(_alert())
        status = self.ingester.tick()
        self.assertEqual(status["events_total"], 1)

        status, payload, _ = self.admin.json(
            "GET", "/api/v1/events?source=wazuh"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["events"]), 1)
        event = payload["events"][0]
        self.assertEqual(event["source"], "wazuh")
        self.assertEqual(event["category"], "intrusion")
        self.assertEqual(event["severity"], "high")
        self.assertFalse(
            event["source_refs"][0]["manager_connection_verified"]
        )
        self.assertIn("not a Wazuh Manager", event["description"])

        # No automatic quarantine/delete action is recorded.
        status, qpayload, _ = self.admin.json("GET", "/api/v1/quarantine")
        self.assertEqual(status, 200)
        self.assertEqual(qpayload.get("items", []), [])

    def test_duplicate_alert_merges_occurrences(self) -> None:
        self.ingester.tick()
        self._append(_alert())
        self.ingester.tick()
        self._append(_alert())
        status = self.ingester.tick()
        self.assertEqual(status["events_total"], 2)

        status, payload, _ = self.admin.json("GET", "/api/v1/events?source=wazuh")
        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(payload["events"][0]["occurrences"], 2)
        self.assertGreaterEqual(len(payload["events"][0]["source_refs"]), 2)


if __name__ == "__main__":
    unittest.main()
