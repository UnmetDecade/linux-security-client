"""Wazuh local-agent adapter and alerts.json ingestion tests.

The client is intentionally limited to read-only local observation: it never
contacts a Manager, never reads registration key contents and never claims
manager capability. These tests pin that contract down.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsec.adapters.wazuh import WazuhAdapter
from lsec.common.config import WazuhConfig
from lsec.common.errors import LsecError
from lsec.core.events import (
    EventService,
    wazuh_category,
    wazuh_severity,
)
from lsec.core.wazuh import WazuhAlertIngester
from lsec.storage.db import Database

FAKE_CONTROL_RUNNING = """#!/bin/sh
if [ "$1" = "info" ]; then
  echo 'WAZUH_VERSION="v4.7.0"'
  exit 0
fi
if [ "$1" = "status" ]; then
  echo "wazuh-agentd is running..."
  echo "wazuh-execd is running..."
  exit 0
fi
exit 1
"""

FAKE_CONTROL_STOPPED = """#!/bin/sh
if [ "$1" = "info" ]; then
  echo 'WAZUH_VERSION="v4.7.0"'
  exit 0
fi
if [ "$1" = "status" ]; then
  echo "wazuh-agentd not running..."
  exit 0
fi
exit 1
"""


def _write_exec(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


def _alert(**overrides: object) -> dict:
    alert = {
        "timestamp": "2026-11-10T10:00:00.000+0000",
        "rule": {
            "level": 10,
            "description": "Multiple authentication failures",
            "id": "5710",
            "groups": ["syslog", "authentication_failed", "sshd"],
        },
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.11"},
        "manager": {"name": "wazuh-manager"},
        "location": "/var/log/auth.log",
        "decoder": {"name": "sshd"},
        "data": {"srcip": "203.0.113.7"},
        "full_log": "Failed password for invalid user admin from 203.0.113.7",
    }
    alert.update(overrides)
    return alert


class SeverityMappingTests(unittest.TestCase):
    def test_levels(self) -> None:
        self.assertEqual(wazuh_severity(0), "info")
        self.assertEqual(wazuh_severity(1), "low")
        self.assertEqual(wazuh_severity(3), "low")
        self.assertEqual(wazuh_severity(4), "medium")
        self.assertEqual(wazuh_severity(7), "medium")
        self.assertEqual(wazuh_severity(8), "high")
        self.assertEqual(wazuh_severity(11), "high")
        self.assertEqual(wazuh_severity(12), "critical")
        self.assertEqual(wazuh_severity(15), "critical")

    def test_categories(self) -> None:
        self.assertEqual(wazuh_category({"groups": ["syscheck", "fim"]}), "integrity")
        self.assertEqual(wazuh_category({"groups": ["virus"]}), "malware")
        self.assertEqual(wazuh_category({"groups": ["authentication_success"]}), "intrusion")
        self.assertEqual(wazuh_category({"groups": ["vulnerability-detector"]}), "vulnerability")
        self.assertEqual(wazuh_category({"groups": ["sca"]}), "configuration")
        self.assertEqual(wazuh_category({"groups": []}), "runtime")


class IngestEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "lsec.db")
        self.db.initialize()
        self.events = EventService(
            self.db, host_provider=lambda: {"hostname": "test-host"}
        )

    def test_maps_fields_and_evidence(self) -> None:
        event = self.events.ingest_wazuh_alert(_alert())
        self.assertEqual(event["source"], "wazuh")
        self.assertEqual(event["category"], "intrusion")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["target"]["type"], "network")
        self.assertEqual(event["target"]["name"], "203.0.113.7")
        self.assertFalse(event["source_refs"][0]["manager_connection_verified"])
        self.assertEqual(event["source_refs"][0]["rule_id"], "5710")
        details = event["evidence"]["details"]
        self.assertEqual(details["rule_level"], 10)
        self.assertEqual(details["agent_id"], "001")
        self.assertEqual(details["engine"], "wazuh")
        self.assertEqual(details["scope"], "local_agent_alert_file")
        self.assertIn("不是 Wazuh Manager", event["description"])
        self.assertTrue(any("Manager" in action for action in event["recommended_actions"]))
        self.assertIn("不会自动隔离或删除文件", event["description"])
        self.assertIn("如需处置", event["recommended_actions"][-1])

    def test_syscheck_uses_file_target(self) -> None:
        event = self.events.ingest_wazuh_alert(
            _alert(
                rule={
                    "level": 7,
                    "description": "Integrity checksum changed",
                    "id": "550",
                    "groups": ["ossec", "syscheck"],
                },
                syscheck={"path": "/etc/passwd"},
                data={},
            )
        )
        self.assertEqual(event["category"], "integrity")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["target"]["type"], "file")
        self.assertEqual(event["target"]["path"], "/etc/passwd")

    def test_duplicate_alerts_merge(self) -> None:
        first = self.events.ingest_wazuh_alert(_alert())
        second = self.events.ingest_wazuh_alert(_alert())
        self.assertEqual(first["event_id"], second["event_id"])
        merged = self.events.get(first["event_id"])
        self.assertEqual(merged["occurrences"], 2)

    def test_invalid_payloads_rejected(self) -> None:
        with self.assertRaises(LsecError):
            self.events.ingest_wazuh_alert(["not", "an", "object"])  # type: ignore[arg-type]
        with self.assertRaises(LsecError):
            self.events.ingest_wazuh_alert(_alert(full_log="x" * 40000))

    def test_unknown_level_defaults_to_info(self) -> None:
        event = self.events.ingest_wazuh_alert(_alert(rule={"level": "bad"}))
        self.assertEqual(event["severity"], "info")


class IngesterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.alerts = root / "alerts.json"
        self.alerts.write_text("", encoding="utf-8")
        self.state_dir = root / "state"
        self.db = Database(root / "lsec.db")
        self.db.initialize()
        self.events = EventService(
            self.db, host_provider=lambda: {"hostname": "test-host"}
        )

    def _config(self, **overrides: object) -> WazuhConfig:
        values = {
            "enabled": True,
            "ingest_enabled": True,
            "alerts_path": str(self.alerts),
            "state_dir": str(self.state_dir),
            "poll_seconds": 1,
            "max_event_bytes": 32768,
            "max_read_bytes": 1048576,
        }
        values.update(overrides)
        return WazuhConfig(**values)  # type: ignore[arg-type]

    def _ingester(self, **overrides: object) -> WazuhAlertIngester:
        return WazuhAlertIngester(self._config(**overrides), self.events)

    def _append(self, *alerts: dict) -> None:
        with self.alerts.open("a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(alert) + "\n")

    def test_first_run_starts_at_end(self) -> None:
        self.alerts.write_text(json.dumps(_alert()) + "\n", encoding="utf-8")
        ingester = self._ingester()
        status = ingester.tick()
        self.assertTrue(status["started_at_end"])
        self.assertEqual(status["events_total"], 0)
        self.assertEqual(status["file_size"], self.alerts.stat().st_size)

        self._append(_alert(rule={"level": 5, "description": "second"}))
        status = ingester.tick()
        self.assertEqual(status["events_total"], 1)
        self.assertEqual(status["alerts_seen"], 1)
        self.assertIsNotNone(status["last_event_at"])

    def test_offset_prevents_replay(self) -> None:
        self._ingester().tick()  # initialize empty file at EOF
        self._append(_alert())
        ingester = self._ingester()
        self.assertEqual(ingester.tick()["events_total"], 1)
        # A fresh instance reads the persisted offset and does not replay.
        ingester2 = self._ingester()
        self.assertEqual(ingester2.tick()["events_total"], 0)
        counts = self.events.counts()
        self.assertEqual(counts["total_open"], 1)

    def test_rotation_and_truncation_reset(self) -> None:
        self._ingester().tick()
        self._append(_alert())
        ingester = self._ingester()
        self.assertEqual(ingester.tick()["events_total"], 1)

        # Replace with a new inode (rotation).
        replacement = self.alerts.with_suffix(".tmp")
        replacement.write_text(
            json.dumps(_alert(rule={"level": 12, "description": "rotated"})) + "\n",
            encoding="utf-8",
        )
        os.replace(replacement, self.alerts)
        status = ingester.tick()
        self.assertEqual(status["events_total"], 2)

        # Truncate the same file to zero and write a shorter alert.
        with self.alerts.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(_alert(rule={"level": 4, "description": "trunc"})) + "\n")
        status = ingester.tick()
        self.assertEqual(status["events_total"], 3)

    def test_parse_errors_are_counted_not_fatal(self) -> None:
        self._ingester().tick()
        with self.alerts.open("a", encoding="utf-8") as handle:
            handle.write("{not json}\n")
            handle.write(json.dumps(_alert()) + "\n")
        status = self._ingester().tick()
        self.assertEqual(status["parse_errors"], 1)
        self.assertEqual(status["events_total"], 1)
        self.assertIn("解析失败", status["last_error"])

    def test_oversize_line_skipped_without_partial_alert(self) -> None:
        ingester = self._ingester(max_read_bytes=1024, max_event_bytes=1024)
        ingester.tick()
        huge = json.dumps(_alert(full_log="x" * 4000)) + "\n"
        self._append(_alert())
        with self.alerts.open("a", encoding="utf-8") as handle:
            handle.write(huge)
        status = ingester.tick()
        self.assertEqual(status["events_total"], 1)  # valid preceding line only
        for _ in range(8):
            status = ingester.tick()
        self.assertGreaterEqual(status["rejected"], 1)
        self.assertEqual(status["events_total"], 1)  # fragment never parsed
        # A following valid line is still ingested after the skipped one.
        self._append(_alert(rule={"level": 3, "description": "after skip"}))
        status = ingester.tick()
        self.assertEqual(status["events_total"], 2)

    def test_corrupt_state_pauses_ingestion(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "state.json").write_text("{broken", encoding="utf-8")
        self._append(_alert())
        status = self._ingester().tick()
        self.assertEqual(status["events_total"], 0)
        self.assertIn("状态文件", status["state_error"])

    def test_symlink_alerts_file_rejected(self) -> None:
        real = Path(self.tmp.name) / "real-alerts.json"
        real.write_text(json.dumps(_alert()) + "\n", encoding="utf-8")
        self.alerts.unlink()
        self.alerts.symlink_to(real)
        status = self._ingester().tick()
        self.assertEqual(status["events_total"], 0)
        self.assertFalse(status["file_present"])
        self.assertIn("无法打开", status["last_error"])

    def test_disabled_ingester_does_not_run(self) -> None:
        ingester = self._ingester(enabled=False)
        self.assertFalse(ingester.active)
        self.assertEqual(ingester.tick()["events_total"], 0)
        self.assertIn("未启用", ingester.status()["note"])
        self.assertFalse(self.state_dir.exists())

    def test_ingest_disabled_keeps_state_dir_untouched(self) -> None:
        ingester = self._ingester(ingest_enabled=False)
        self.assertFalse(ingester.active)
        self.assertFalse(self.state_dir.exists())


class AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.install = self.root / "ossec"
        (self.install / "etc").mkdir(parents=True)
        self.control = _write_exec(self.root / "wazuh-control", FAKE_CONTROL_RUNNING)
        self.agent = _write_exec(self.root / "wazuh-agentd", "#!/bin/sh\nexit 0\n")
        self.alerts = self.root / "alerts.json"
        self.alerts.write_text("", encoding="utf-8")

    def _config(self, **overrides: object) -> WazuhConfig:
        values = {
            "enabled": True,
            "agent_bin": str(self.agent),
            "control_bin": str(self.control),
            "install_dir": str(self.install),
            "alerts_path": str(self.alerts),
            "ingest_enabled": False,
            "state_dir": str(self.root / "state"),
        }
        values.update(overrides)
        return WazuhConfig(**values)  # type: ignore[arg-type]

    def _conf(self, address: str = "10.0.0.1", port: str = "1514") -> None:
        (self.install / "etc" / "ossec.conf").write_text(
            f"<ossec_config><client><server><address>{address}</address>"
            f"<port>{port}</port></server></client></ossec_config>",
            encoding="utf-8",
        )

    def test_disabled_reports_unavailable(self) -> None:
        result = WazuhAdapter(self._config(enabled=False)).probe()
        self.assertEqual(result.health_status, "unavailable")
        self.assertEqual(result.error_code, "disabled")
        self.assertEqual(result.capabilities, [])

    def test_not_installed(self) -> None:
        result = WazuhAdapter(
            self._config(agent_bin=str(self.root / "missing"), install_dir=str(self.root / "nope"))
        ).probe()
        self.assertFalse(result.installed)
        self.assertEqual(result.error_code, "not_installed")
        self.assertIn("不提供 Wazuh Manager", result.error_message)

    def test_missing_config_degraded(self) -> None:
        result = WazuhAdapter(self._config()).probe()
        self.assertTrue(result.installed)
        self.assertEqual(result.health_status, "degraded")
        self.assertEqual(result.error_code, "config_missing")

    def test_running_agent_reports_unverified_manager(self) -> None:
        self._conf()
        (self.install / "etc" / "client.keys").write_text(
            "001 web-01 10.0.0.11 abcdef\n", encoding="utf-8"
        )
        result = WazuhAdapter(self._config()).probe()
        self.assertEqual(result.version, "4.7.0")
        self.assertEqual(result.service_status, "running")
        self.assertEqual(result.health_status, "unknown")
        self.assertEqual(result.error_code, "manager_connection_unverified")
        self.assertFalse(result.details["connection_verified"])
        self.assertEqual(result.details["manager"]["address"], "10.0.0.1")
        self.assertEqual(result.details["manager"]["port"], "1514")
        self.assertTrue(result.details["registration_present"])
        self.assertEqual(result.details["scope"], "local_agent_only")
        self.assertEqual(result.capabilities, ["local_agent_status"])

    def test_ingest_capability_only_when_enabled(self) -> None:
        self._conf()
        result = WazuhAdapter(self._config(ingest_enabled=True)).probe()
        self.assertIn("local_alert_ingest", result.capabilities)

    def test_stopped_agent_degraded(self) -> None:
        stopped = _write_exec(self.root / "wazuh-control-stopped", FAKE_CONTROL_STOPPED)
        self._conf()
        result = WazuhAdapter(self._config(control_bin=str(stopped))).probe()
        self.assertEqual(result.service_status, "stopped")
        self.assertEqual(result.health_status, "degraded")
        self.assertEqual(result.error_code, "agent_not_running")

    def test_unconfigured_manager_degraded(self) -> None:
        (self.install / "etc" / "ossec.conf").write_text(
            "<ossec_config><client><server></server></client></ossec_config>",
            encoding="utf-8",
        )
        result = WazuhAdapter(self._config()).probe()
        self.assertEqual(result.error_code, "manager_not_configured")

    def test_symlinked_registration_file_not_read(self) -> None:
        self._conf()
        real = self.root / "keys-real"
        real.write_text("secret-key-content\n", encoding="utf-8")
        (self.install / "etc" / "client.keys").symlink_to(real)
        result = WazuhAdapter(self._config()).probe()
        self.assertFalse(result.details["registration_present"])
        self.assertIsNone(result.details["registration_key_mode"])

    def test_install_plan_is_manual(self) -> None:
        plan = WazuhAdapter(self._config()).install_plan()
        self.assertFalse(plan["installable_from_ui"])
        self.assertTrue(any("不是 Wazuh Manager" in note for note in plan["notes"]))
        self.assertTrue(any("agent-auth" in step for step in plan["steps"]))

    def test_status_parsing_ignores_other_running_daemons(self) -> None:
        mixed = _write_exec(
            self.root / "wazuh-control-mixed",
            "#!/bin/sh\n"
            'if [ "$1" = "info" ]; then echo \'WAZUH_VERSION="v4.7.0"\'; exit 0; fi\n'
            'if [ "$1" = "status" ]; then echo "wazuh-execd is running..."; '
            'echo "wazuh-agentd not running..."; exit 0; fi\nexit 1\n',
        )
        self._conf()
        result = WazuhAdapter(self._config(control_bin=str(mixed))).probe()
        self.assertEqual(result.service_status, "stopped")
        self.assertEqual(result.error_code, "agent_not_running")


if __name__ == "__main__":
    unittest.main()
