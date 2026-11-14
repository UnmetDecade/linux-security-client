"""Falco capability detection, install plan and event normalization tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from lsec.adapters.falco import FalcoAdapter, evaluate_capability
from lsec.api.auth import ensure_falco_token
from lsec.common.errors import LsecError
from lsec.core.falco import normalize_falco_event


def environment(
    release: str = "6.8.0-45-generic",
    *,
    btf: bool = True,
    sys_admin: bool = True,
    bpf: bool = False,
    perfmon: bool = False,
) -> dict:
    return {
        "kernel_release": release,
        "btf_available": btf,
        "bpf_filesystem": True,
        "tracefs": True,
        "capabilities": {
            "CAP_SYS_ADMIN": sys_admin,
            "CAP_BPF": bpf,
            "CAP_PERFMON": perfmon,
            "CAP_SYS_MODULE": False,
            "CAP_SYS_PTRACE": True,
            "CAP_SYS_RESOURCE": True,
        },
        "unprivileged_bpf_disabled": "2",
    }


class CapabilityTests(unittest.TestCase):
    def test_modern_kernel_with_btf_and_privileges_is_compatible(self) -> None:
        result = evaluate_capability(environment())
        self.assertEqual(result["state"], "compatible")
        self.assertTrue(result["modern_ebpf_kernel"])
        self.assertFalse(result["running_verified"])

    def test_bpf_and_perfmon_can_replace_sys_admin(self) -> None:
        result = evaluate_capability(
            environment(sys_admin=False, bpf=True, perfmon=True)
        )
        self.assertEqual(result["state"], "compatible")

    def test_old_kernel_is_explicitly_unsupported(self) -> None:
        result = evaluate_capability(environment("4.4.0-210-generic"))
        self.assertEqual(result["state"], "unsupported")
        self.assertIn("4.14", result["reason"])

    def test_missing_privileges_is_not_reported_as_enabled(self) -> None:
        result = evaluate_capability(
            environment(sys_admin=False, bpf=False, perfmon=False)
        )
        self.assertEqual(result["state"], "requires_privileges")

    def test_missing_btf_requires_setup(self) -> None:
        result = evaluate_capability(environment(btf=False))
        self.assertEqual(result["state"], "requires_setup")

    def test_legacy_kernel_requires_setup(self) -> None:
        result = evaluate_capability(environment("4.19.0", btf=False))
        self.assertEqual(result["state"], "requires_setup")
        self.assertFalse(result["modern_ebpf_kernel"])


class AdapterTests(unittest.TestCase):
    def test_missing_binary_is_reported_as_not_installed(self) -> None:
        adapter = FalcoAdapter(
            "lsec-falco-not-present",
            environment_provider=lambda: environment(),
        )
        result = adapter.probe()
        self.assertFalse(result.installed)
        self.assertEqual(result.error_code, "not_installed")
        self.assertEqual(result.details["capability"]["state"], "compatible")

    def test_incompatible_kernel_is_visible(self) -> None:
        adapter = FalcoAdapter(
            sys.executable,
            environment_provider=lambda: environment("4.4.0"),
        )
        result = adapter.probe()
        self.assertTrue(result.installed)
        self.assertEqual(result.health_status, "incompatible")
        self.assertEqual(result.error_code, "kernel_incompatible")

    def test_install_plan_never_claims_ui_installation(self) -> None:
        plan = FalcoAdapter(sys.executable).install_plan()
        self.assertFalse(plan["installable_from_ui"])
        self.assertGreaterEqual(len(plan["steps"]), 4)
        self.assertTrue(any("does not install" in note for note in plan["notes"]))


class TokenTests(unittest.TestCase):
    def test_disabled_ingest_does_not_create_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(ensure_falco_token(Path(tmp), False))
            self.assertFalse((Path(tmp) / "falco.token").exists())

    def test_token_is_private_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = ensure_falco_token(Path(tmp), True)
            second = ensure_falco_token(Path(tmp), True)
            self.assertTrue(first)
            self.assertEqual(first, second)
            path = Path(tmp) / "falco.token"
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class FalcoEventTests(unittest.TestCase):
    def normalize(self, payload: dict) -> dict:
        return normalize_falco_event(
            payload,
            host_provider=lambda: {"hostname": "test-host"},
            max_event_bytes=32768,
        )

    def payload(self, **overrides) -> dict:
        base = {
            "uuid": "3f8c7e2a-0a0b-4c3d-8e9f-1234567890ab",
            "time": "2026-11-10T09:00:00Z",
            "rule": "Terminal shell in container",
            "priority": "Warning",
            "output": "A shell was spawned in a container (user=root)",
            "hostname": "node-1",
            "output_fields": {
                "container.id": "c" * 64,
                "container.name": "web",
                "container.image.repository": "nginx",
                "container.image.tag": "latest",
                "proc.name": "bash",
                "proc.pid": 1234,
                "proc.cmdline": "bash -c id",
                "evt.type": "execve",
            },
        }
        base.update(overrides)
        return base

    def test_maps_priority_and_container_association(self) -> None:
        event = self.normalize(self.payload())
        self.assertEqual(event["source"], "falco")
        self.assertEqual(event["category"], "runtime")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["target"]["type"], "container")
        self.assertEqual(event["target"]["container_id"], "c" * 64)
        self.assertEqual(event["target"]["name"], "web")
        self.assertEqual(event["target"]["pid"], 1234)
        self.assertEqual(event["evidence"]["container_image"], "nginx:latest")
        self.assertIn("Terminal shell", event["title"])

    def test_priority_mapping_is_deterministic(self) -> None:
        cases = {
            "Emergency": "critical",
            "Critical": "critical",
            "Error": "high",
            "Warning": "medium",
            "Notice": "low",
            "Informational": "info",
            "Debug": "info",
        }
        for priority, expected in cases.items():
            with self.subTest(priority=priority):
                event = self.normalize(self.payload(priority=priority))
                self.assertEqual(event["severity"], expected)

    def test_unknown_priority_is_not_silently_high(self) -> None:
        event = self.normalize(self.payload(priority="custom"))
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["evidence"]["priority"], "custom")

    def test_rejects_missing_content_and_bad_fields(self) -> None:
        with self.assertRaises(LsecError):
            self.normalize({"priority": "Warning"})
        with self.assertRaises(LsecError):
            self.normalize(self.payload(output_fields=["not", "an", "object"]))
        with self.assertRaises(LsecError):
            self.normalize(self.payload(output="x" * 40000))

    def test_invalid_container_id_is_not_used_as_target_id(self) -> None:
        payload = self.payload()
        payload["output_fields"]["container.id"] = "../../etc/passwd"
        event = self.normalize(payload)
        self.assertIsNone(event["target"]["container_id"])
        self.assertEqual(event["target"]["type"], "container")

    def test_dedup_key_is_stable_for_same_rule_and_container(self) -> None:
        first = self.normalize(self.payload())
        second = self.normalize(self.payload(output="different output"))
        self.assertEqual(first["dedup_key"], second["dedup_key"])


if __name__ == "__main__":
    unittest.main()
