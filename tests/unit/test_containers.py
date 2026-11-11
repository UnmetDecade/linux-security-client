"""Container configuration checks and read-only inventory tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lsec.common.config import ContainersConfig
from lsec.core.container_checks import evaluate_container
from lsec.core.containers import ContainerService
from lsec.core.docker_api import DockerApiClient, DockerApiError
from lsec.core.events import EventService
from lsec.storage import events as event_store
from lsec.storage.db import Database
from tests.fake_docker import FakeDockerApi, make_inspect

CID = "a" * 64
CID2 = "b" * 64


class ContainerCheckTests(unittest.TestCase):
    def evaluate(self, **kwargs):
        inspect = make_inspect(CID, "demo", **kwargs)
        return evaluate_container(inspect)

    def test_privileged_and_host_namespaces(self) -> None:
        result = self.evaluate(
            privileged=True, network_mode="host", pid_mode="host", ipc_mode="host"
        )
        self.assertTrue(result["evaluated"])
        self.assertEqual(result["risk_level"], "critical")
        keys = {finding["key"] for finding in result["findings"]}
        self.assertIn("CONTAINER-PRIVILEGED", keys)
        self.assertIn("CONTAINER-HOST-NETWORK", keys)
        self.assertIn("CONTAINER-HOST-PID", keys)
        self.assertIn("CONTAINER-HOST-IPC", keys)

    def test_docker_socket_mount_is_critical_even_read_only(self) -> None:
        result = self.evaluate(
            mounts=[
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "RW": False,
                    "Propagation": "rprivate",
                }
            ]
        )
        self.assertEqual(result["risk_level"], "critical")
        finding = next(
            item for item in result["findings"] if item["rule_id"] == "docker-socket"
        )
        self.assertTrue(finding["evidence"]["read_only"])

    def test_sensitive_mount_uses_most_specific_path(self) -> None:
        result = self.evaluate(
            mounts=[
                {
                    "Type": "bind",
                    "Source": "/etc/ssh",
                    "Destination": "/host-ssh",
                    "RW": True,
                    "Propagation": "rprivate",
                }
            ]
        )
        finding = next(
            item for item in result["findings"] if item["rule_id"] == "sensitive-mount"
        )
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["evidence"]["matched_root"], "/etc")

    def test_host_root_read_only_is_high(self) -> None:
        result = self.evaluate(
            mounts=[
                {
                    "Type": "bind",
                    "Source": "/",
                    "Destination": "/host",
                    "RW": False,
                    "Propagation": "rprivate",
                }
            ]
        )
        finding = next(
            item for item in result["findings"] if item["rule_id"] == "sensitive-mount"
        )
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["evidence"]["matched_root"], "/")

    def test_broad_capabilities_and_unconfined_security(self) -> None:
        result = self.evaluate(
            cap_add=["SYS_ADMIN", "NET_ADMIN"],
            security_opt=["seccomp=unconfined", "apparmor=unconfined"],
        )
        by_rule = {finding["rule_id"]: finding for finding in result["findings"]}
        self.assertEqual(by_rule["cap-add"]["severity"], "critical")
        self.assertEqual(by_rule["seccomp-unconfined"]["severity"], "high")
        self.assertEqual(by_rule["apparmor-unconfined"]["severity"], "medium")

    def test_benign_container_is_not_flagged(self) -> None:
        result = self.evaluate(
            mounts=[
                {
                    "Type": "volume",
                    "Source": "web-data",
                    "Destination": "/data",
                    "RW": True,
                    "Propagation": "",
                }
            ]
        )
        self.assertTrue(result["evaluated"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["risk_level"], "none")

    def test_missing_inspection_fields_is_not_treated_as_safe(self) -> None:
        inspect = make_inspect(CID, "broken")
        inspect.pop("HostConfig")
        result = evaluate_container(inspect)
        self.assertFalse(result["evaluated"])
        self.assertEqual(result["risk_level"], "unknown")
        self.assertIn("HostConfig", result["evaluation_error"])

    def test_env_is_not_retained(self) -> None:
        result = self.evaluate()
        serialized = repr(result)
        self.assertNotIn("must-not-be-collected", serialized)


class DockerApiClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeDockerApi()
        self.api.set_containers([make_inspect(CID, "demo", privileged=True)])
        self.api.start()
        self.addCleanup(self.api.stop)

    def test_reads_version_and_inventory(self) -> None:
        client = DockerApiClient(self.api.url, timeout=2)
        self.assertEqual(client.version()["Version"], "24.0.9")
        self.assertEqual(client.info()["Architecture"], "x86_64")
        self.assertEqual(len(client.list_containers()), 1)
        self.assertEqual(client.inspect_container(CID)["Name"], "/demo")
        self.assertTrue(all(method == "GET" for method, _ in self.api.requests))

    def test_permission_denied_is_distinct(self) -> None:
        self.api.permission_denied = True
        client = DockerApiClient(self.api.url, timeout=2)
        with self.assertRaises(DockerApiError) as caught:
            client.version()
        self.assertEqual(caught.exception.code, "permission_denied")

    def test_rejects_untrusted_ids_and_urls(self) -> None:
        with self.assertRaises(DockerApiError):
            DockerApiClient("https://example.com", timeout=2)
        with self.assertRaises(DockerApiError):
            DockerApiClient("http://user:pass@example.com", timeout=2)
        client = DockerApiClient(self.api.url, timeout=2)
        with self.assertRaises(DockerApiError):
            client.inspect_container("../../etc/passwd")


class ContainerServiceTests(unittest.TestCase):
    def make_service(self, api_url: str) -> tuple[ContainerService, Database]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "lsec.db")
        db.initialize()
        events = EventService(
            db,
            host_provider=lambda: {"hostname": "test-host"},
            dedup_window_hours=24,
        )
        service = ContainerService(
            ContainersConfig(
                enabled=True,
                api_url=api_url,
                timeout_seconds=2,
                refresh_seconds=15,
                max_containers=20,
            ),
            events,
        )
        return service, db

    def test_disabled_monitor_has_no_inventory(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "lsec.db")
        db.initialize()
        service = ContainerService(
            ContainersConfig(enabled=False),
            EventService(db, host_provider=lambda: {}),
        )
        snapshot = service.snapshot()
        self.assertEqual(snapshot["state"], "disabled")
        self.assertEqual(snapshot["containers"], [])

    def test_refresh_ingests_once_then_merges(self) -> None:
        api = FakeDockerApi()
        api.set_containers([make_inspect(CID, "privileged-demo", privileged=True)])
        api.start()
        self.addCleanup(api.stop)
        service, db = self.make_service(api.url)

        first = service.refresh()
        self.assertEqual(first["state"], "monitored")
        self.assertEqual(first["summary"]["total"], 1)
        self.assertEqual(first["summary"]["risky"], 1)
        self.assertEqual(first["ingest"]["created"], 1)
        events, total = event_store.list_events(db, source="docker")
        self.assertEqual(total, 1)
        self.assertEqual(events[0]["severity"], "critical")
        self.assertEqual(events[0]["target"]["container_id"], CID)

        second = service.refresh()
        self.assertEqual(second["ingest"]["created"], 0)
        events, total = event_store.list_events(db, source="docker")
        self.assertEqual(total, 1)
        self.assertEqual(events[0]["occurrences"], 1)

        # The same container remains findable by name and unique ID prefix.
        self.assertEqual(service.get("privileged-demo")["container_id"], CID)
        self.assertEqual(service.get(CID[:12])["container_id"], CID)

    def test_permission_failure_is_reported_without_inventory(self) -> None:
        api = FakeDockerApi()
        api.set_containers([make_inspect(CID, "demo")])
        api.permission_denied = True
        api.start()
        self.addCleanup(api.stop)
        service, _db = self.make_service(api.url)
        snapshot = service.refresh()
        self.assertEqual(snapshot["state"], "permission_denied")
        self.assertEqual(snapshot["containers"], [])
        self.assertIn("权限", snapshot["note"])


if __name__ == "__main__":
    unittest.main()
