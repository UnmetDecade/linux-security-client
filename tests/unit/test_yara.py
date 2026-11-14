"""YARA rule-pack integrity, versioning and scan-adapter tests.

The tests use fake ``yarac``/``yara`` executables for compilation and matching.
Signature tests use the real OpenSSL CLI because verifying our invocation of
OpenSSL (not re-implementing it) is the point. No production data is used.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from lsec.adapters.base import TaskContext
from lsec.adapters.yara import (
    YaraAdapter,
    parse_yara_output,
    severity_for_tags,
)
from lsec.common.config import ScanConfig, YaraConfig
from lsec.common.errors import LsecError
from lsec.core.yara import YaraRulePackService

FAKE_YARAC_OK = """#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "4.5.0-fake"
  exit 0
fi
last=""
for arg in "$@"; do last="$arg"; done
: > "$last"
exit 0
"""

FAKE_YARAC_FAIL = """#!/bin/sh
echo "error: syntax error" >&2
exit 1
"""

# The fake scanner understands just enough of YARA's -g output to exercise the
# adapter's parsing, scope filtering and deduplication.
FAKE_YARA = """#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "4.5.0-fake"
  exit 0
fi
# invocation: yara -w -g -C compiled.rules --scan-list listfile
if [ "$3" != "-C" ]; then
  echo "missing -C for compiled rules" >&2
  exit 2
fi
if [ "$5" != "--scan-list" ] || [ ! -f "$6" ]; then
  echo "missing --scan-list" >&2
  exit 2
fi
while IFS= read -r f; do
  case "$f" in
    *eicar*)
      printf 'EICAR_Test_String [eicar,test] %s\\n' "$f"
      ;;
    *critical*)
      printf 'Critical_Rule [severity_critical] %s\\n' "$f"
      ;;
    *out-of-scope*)
      printf 'Out_Scope [test] /tmp/not-in-scope\\n'
      ;;
  esac
done < "$6"
exit 0
"""


def _write_exec(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class YaraPackTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inbox = self.root / "yara" / "inbox"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.yarac = _write_exec(self.tools / "yarac", FAKE_YARAC_OK)
        self.yara = _write_exec(self.tools / "yara", FAKE_YARA)
        self.config = YaraConfig(
            binary=str(self.yara),
            yarac_binary=str(self.yarac),
            enabled=True,
            rules_dir=str(self.root / "yara"),
            inbox_dir=str(self.inbox),
            public_key="",
            require_signature=False,
            max_pack_mb=5,
            max_rule_files=20,
        )
        self.service = YaraRulePackService(self.config)

    # ------------------------------------------------------------- helpers
    def make_pack(
        self,
        *,
        pack_id: str = "local-test",
        version: str = "1.0.0",
        rule_name: str = "local_test",
        rule_text: str | None = None,
        extra: dict[str, bytes] | None = None,
    ) -> tuple[Path, dict[str, bytes]]:
        rule_data = (
            rule_text
            or f'rule {rule_name} {{\n  strings:\n    $a = "eicar"\n  condition:\n    $a\n}}\n'
        ).encode("utf-8")
        manifest = {
            "schema_version": 1,
            "pack_id": pack_id,
            "version": version,
            "name": f"{pack_id} rules",
            "description": "unit test pack",
            "rules": [{"path": "rules/test.yar", "sha256": _sha256(rule_data)}],
        }
        manifest_raw = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
        files = {
            "manifest.json": manifest_raw,
            "rules/test.yar": rule_data,
        }
        if extra:
            files.update(extra)
        return self._zip_pack(pack_id, version, files), files

    def _zip_pack(
        self, pack_id: str, version: str, files: dict[str, bytes]
    ) -> Path:
        directory = self.inbox / f"{pack_id}-{version}"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "pack.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return path

    def install(self, path: Path, *, activate: bool = True) -> dict:
        return self.service.install(str(path), activate=activate)


class YaraPackInstallTests(YaraPackTestBase):
    def test_install_and_activate(self) -> None:
        path, _ = self.make_pack()
        result = self.install(path)
        self.assertEqual(result["pack_id"], "local-test")
        self.assertEqual(result["version"], "1.0.0")
        self.assertTrue(result["activated"])
        self.assertFalse(result["signature_verified"])

        packs = self.service.list_packs()
        self.assertEqual(len(packs), 1)
        self.assertEqual(packs[0]["active_version"], "1.0.0")
        self.assertEqual(packs[0]["versions"][0]["rules_count"], 1)
        snapshot = self.service.scan_snapshot()
        self.assertEqual(snapshot["active_count"], 1)
        self.assertIsNone(snapshot["state_error"])

    def test_install_without_activation(self) -> None:
        path, _ = self.make_pack()
        result = self.install(path, activate=False)
        self.assertFalse(result["activated"])
        self.assertEqual(self.service.scan_snapshot()["active_count"], 0)

    def test_same_version_is_never_overwritten(self) -> None:
        path, _ = self.make_pack()
        self.install(path)
        again = self.inbox / "again"
        again.mkdir()
        shutil.copy2(path, again / "pack.zip")
        with self.assertRaises(LsecError) as caught:
            self.install(again / "pack.zip")
        self.assertEqual(caught.exception.code.value, "conflict")

    def test_source_must_be_inside_inbox(self) -> None:
        path, _ = self.make_pack()
        outside = self.root / "outside.zip"
        shutil.copy2(path, outside)
        with self.assertRaises(LsecError):
            self.install(outside)

    def test_symlink_source_is_rejected(self) -> None:
        path, _ = self.make_pack()
        link = self.inbox / "link.zip"
        link.symlink_to(path)
        with self.assertRaises(LsecError):
            self.install(link)

    def test_non_zip_file_is_rejected(self) -> None:
        path = self.inbox / "rules.txt"
        path.write_text("not a pack", encoding="utf-8")
        with self.assertRaises(LsecError):
            self.install(path)

    def test_hash_mismatch_is_rejected(self) -> None:
        pack, files = self.make_pack()
        manifest = json.loads(files["manifest.json"])
        rules = manifest["rules"][0]
        manifest["rules"] = [dict(rules, sha256="0" * 64)]
        tampered = self._zip_pack(
            "tampered",
            "1.0.0",
            {
                "manifest.json": json.dumps(manifest).encode(),
                "rules/test.yar": files["rules/test.yar"],
            },
        )
        with self.assertRaises(LsecError):
            self.install(tampered)
        self.assertEqual(self.service.list_packs(), [])

    def test_undeclared_file_is_rejected(self) -> None:
        path, _ = self.make_pack(extra={"rules/extra.yar": b"rule x { condition: true }"})
        with self.assertRaises(LsecError):
            self.install(path)

    def test_path_traversal_is_rejected(self) -> None:
        path, _ = self.make_pack(extra={"../escape.yar": b"rule escape { condition: true }"})
        with self.assertRaises(LsecError):
            self.install(path)

    def test_zip_symlink_entry_is_rejected(self) -> None:
        path = self.inbox / "symlink.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", b"{}")
            info = zipfile.ZipInfo("rules/link.yar")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "/etc/passwd")
        with self.assertRaises(LsecError):
            self.install(path)

    def test_directory_symlink_is_rejected(self) -> None:
        directory = self.inbox / "directory-pack"
        (directory / "rules").mkdir(parents=True)
        (directory / "rules" / "target.yar").write_text(
            "rule target { condition: true }", encoding="utf-8"
        )
        (directory / "rules" / "link.yar").symlink_to(
            directory / "rules" / "target.yar"
        )
        manifest = {
            "schema_version": 1,
            "pack_id": "directory-pack",
            "version": "1.0.0",
            "name": "directory pack",
            "rules": [],
        }
        (directory / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        with self.assertRaises(LsecError):
            self.install(directory)

    def test_compile_failure_is_rejected(self) -> None:
        failing = _write_exec(self.tools / "yarac-fail", FAKE_YARAC_FAIL)
        config = YaraConfig(
            binary=str(self.yara),
            yarac_binary=str(failing),
            enabled=True,
            rules_dir=self.config.rules_dir,
            inbox_dir=self.config.inbox_dir,
            public_key="",
            require_signature=False,
        )
        service = YaraRulePackService(config)
        path, _ = self.make_pack()
        with self.assertRaises(LsecError) as caught:
            service.install(str(path), activate=True)
        self.assertIn("compilation failed", caught.exception.message)
        self.assertEqual(service.list_packs(), [])

    def test_activation_switch_and_delete_rules(self) -> None:
        one, _ = self.make_pack(version="1.0.0", rule_name="one")
        two_dir = self.inbox / "two"
        two_dir.mkdir()
        rule = b"rule two { condition: true }\n"
        manifest = {
            "schema_version": 1,
            "pack_id": "local-test",
            "version": "2.0.0",
            "name": "second",
            "rules": [{"path": "two.yar", "sha256": _sha256(rule)}],
        }
        with zipfile.ZipFile(two_dir / "pack.zip", "w") as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr("two.yar", rule)
        self.install(one)
        self.install(two_dir / "pack.zip")
        self.assertEqual(
            self.service.scan_snapshot()["active"][0]["version"], "2.0.0"
        )
        self.service.activate("local-test", "1.0.0")
        self.assertEqual(
            self.service.scan_snapshot()["active"][0]["version"], "1.0.0"
        )
        with self.assertRaises(LsecError) as caught:
            self.service.delete("local-test", "1.0.0")
        self.assertEqual(caught.exception.code.value, "conflict")
        self.service.delete("local-test", "2.0.0")
        versions = self.service.list_packs()[0]["versions"]
        self.assertEqual([item["version"] for item in versions], ["1.0.0"])

    def test_delete_missing_is_not_found(self) -> None:
        with self.assertRaises(LsecError) as caught:
            self.service.delete("missing", "1.0.0")
        self.assertEqual(caught.exception.code.value, "not_found")

    def test_state_file_corruption_is_reported(self) -> None:
        state = Path(self.config.rules_dir) / "state.json"
        state.write_text("{broken", encoding="utf-8")
        snapshot = self.service.scan_snapshot()
        self.assertIn("corrupt", snapshot["state_error"])
        with self.assertRaises(LsecError):
            self.service.active_rule_sets()


class YaraSignatureTests(YaraPackTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl CLI is required for signature tests")

    def _signed_pack(self, *, corrupt: bool = False) -> tuple[Path, Path]:
        path, files = self.make_pack()
        private = self.inbox / "signing-key.pem"
        public = self.inbox / "trusted.pub"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private),
                "-pubout",
                "-out",
                str(public),
            ],
            check=True,
            capture_output=True,
        )
        signature = self.inbox / "manifest.sig"
        # Sign the manifest bytes that are actually in the archive.
        manifest_path = self.inbox / "manifest-to-sign.json"
        manifest_path.write_bytes(files["manifest.json"])
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private),
                "-out",
                str(signature),
                str(manifest_path),
            ],
            check=True,
            capture_output=True,
        )
        sig_bytes = signature.read_bytes()
        if corrupt:
            sig_bytes = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
        signed_zip = self._zip_pack(
            "signed-pack",
            "1.0.0",
            {
                **files,
                "manifest.sig": sig_bytes,
            },
        )
        return signed_zip, public

    def test_valid_signature_is_verified(self) -> None:
        signed, public = self._signed_pack()
        config = YaraConfig(
            binary=str(self.yara),
            yarac_binary=str(self.yarac),
            enabled=True,
            rules_dir=self.config.rules_dir,
            inbox_dir=self.config.inbox_dir,
            public_key=str(public),
            require_signature=True,
        )
        service = YaraRulePackService(config)
        result = service.install(str(signed), activate=True)
        self.assertTrue(result["signature_verified"])
        record = service.list_packs()[0]["versions"][0]
        self.assertTrue(record["signature_verified"])
        self.assertTrue(record["signature_key_fingerprint"])

    def test_bad_signature_is_rejected(self) -> None:
        signed, public = self._signed_pack(corrupt=True)
        config = YaraConfig(
            binary=str(self.yara),
            yarac_binary=str(self.yarac),
            enabled=True,
            rules_dir=self.config.rules_dir,
            inbox_dir=self.config.inbox_dir,
            public_key=str(public),
            require_signature=True,
        )
        service = YaraRulePackService(config)
        with self.assertRaises(LsecError) as caught:
            service.install(str(signed), activate=True)
        self.assertIn("signature", caught.exception.message)
        self.assertEqual(service.list_packs(), [])

    def test_signature_required_without_key_is_rejected(self) -> None:
        path, _ = self.make_pack()
        config = YaraConfig(
            binary=str(self.yara),
            yarac_binary=str(self.yarac),
            enabled=True,
            rules_dir=self.config.rules_dir,
            inbox_dir=self.config.inbox_dir,
            public_key="",
            require_signature=True,
        )
        service = YaraRulePackService(config)
        with self.assertRaises(LsecError):
            service.install(str(path), activate=True)


class YaraOutputParsingTests(unittest.TestCase):
    def test_tags_and_targets_with_spaces(self) -> None:
        matches = parse_yara_output(
            "Rule_One [high,test] /scan/a file.bin\n"
            "Rule_Two /scan/plain.bin\n"
            "garbage\n"
        )
        self.assertEqual(
            matches,
            [
                ("Rule_One", ["high", "test"], "/scan/a file.bin"),
                ("Rule_Two", [], "/scan/plain.bin"),
            ],
        )

    def test_severity_precedence(self) -> None:
        self.assertEqual(severity_for_tags([]), "high")
        self.assertEqual(severity_for_tags(["test"]), "medium")
        self.assertEqual(severity_for_tags(["low", "critical"]), "critical")
        self.assertEqual(severity_for_tags(["info"]), "info")
        self.assertEqual(severity_for_tags(["bogus"]), "high")


class YaraAdapterTests(YaraPackTestBase):
    def _adapter(self) -> YaraAdapter:
        return YaraAdapter(
            self.config,
            ScanConfig(
                allowed_roots=(str(self.root / "scan"),),
                quick_scan_paths=(str(self.root / "scan"),),
                skip_paths=(),
                max_file_size_mb=10,
                max_parallel_tasks=1,
            ),
            self.service,
        )

    def _task(self, target: Path) -> tuple[dict, TaskContext]:
        progress: list[tuple] = []
        detections: list = []
        context = TaskContext(
            task_id="task-1",
            cancel_event=threading.Event(),
            progress=lambda *args: progress.append(args),
            on_detection=detections.append,
        )
        return {
            "task_id": "task-1",
            "task_type": "yara",
            "target_paths": [str(target)],
            "_progress": progress,
            "_detections": detections,
        }, context

    def test_probe_without_active_packs_is_not_ready(self) -> None:
        probe = self._adapter().probe()
        self.assertTrue(probe.installed)
        self.assertEqual(probe.error_code, "no_active_packs")
        self.assertNotEqual(probe.health_status, "ok")
        self.assertEqual(probe.details["active_count"], 0)

    def test_scan_finds_matches_and_ignores_symlinks(self) -> None:
        path, _ = self.make_pack()
        self.install(path)
        scan_dir = self.root / "scan"
        scan_dir.mkdir()
        eicar = scan_dir / "eicar.txt"
        eicar.write_text("test", encoding="utf-8")
        (scan_dir / "normal.txt").write_text("clean", encoding="utf-8")
        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (scan_dir / "link.txt").symlink_to(outside)

        adapter = self._adapter()
        self.assertEqual(adapter.probe().health_status, "ok")
        task, context = self._task(scan_dir)
        outcome = adapter.run_task(task, context)

        self.assertEqual(outcome.files_scanned, 2)
        self.assertEqual(outcome.detections, 1)
        self.assertEqual(len(task["_detections"]), 1)
        detection = task["_detections"][0]
        self.assertEqual(detection.path, str(eicar))
        self.assertEqual(detection.detection_name, "EICAR_Test_String")
        self.assertEqual(detection.details["severity"], "medium")
        self.assertEqual(detection.details["pack_id"], "local-test")
        self.assertEqual(detection.details["tags"], ["eicar", "test"])
        self.assertEqual(outcome.summary["skipped"]["symlink"], 1)
        self.assertTrue(task["_progress"])

    def test_out_of_scope_match_is_rejected(self) -> None:
        path, _ = self.make_pack()
        self.install(path)
        scan_dir = self.root / "scan"
        scan_dir.mkdir()
        (scan_dir / "out-of-scope.txt").write_text("x", encoding="utf-8")
        adapter = self._adapter()
        task, context = self._task(scan_dir)
        outcome = adapter.run_task(task, context)
        self.assertEqual(outcome.detections, 0)
        self.assertGreaterEqual(outcome.errors, 1)
        self.assertTrue(
            any("outside the scan scope" in item.get("error", "") for item in outcome.error_details)
        )
        self.assertEqual(task["_detections"], [])

    def test_batches_respect_count_and_argv_budget(self) -> None:
        adapter = self._adapter()
        paths = ["/" + ("a" * 300) + f"/{index}" for index in range(1000)]
        batches = list(adapter._batches(paths))
        self.assertEqual([item for batch in batches for item in batch], paths)
        self.assertTrue(all(len(batch) <= 200 for batch in batches))
        self.assertGreater(len(batches), 1)
        for batch in batches:
            self.assertLessEqual(
                sum(len(os.fsencode(item)) + 1 for item in batch), 128 * 1024
            )

    def test_scan_without_rules_raises_component_unavailable(self) -> None:
        scan_dir = self.root / "scan"
        scan_dir.mkdir()
        adapter = self._adapter()
        task, context = self._task(scan_dir)
        with self.assertRaises(LsecError) as caught:
            adapter.run_task(task, context)
        self.assertEqual(caught.exception.code.value, "component_unavailable")

    def test_all_pack_compile_failures_raise(self) -> None:
        path, _ = self.make_pack()
        self.install(path)
        failing = _write_exec(self.tools / "yarac-fail", FAKE_YARAC_FAIL)
        config = YaraConfig(
            binary=str(self.yara),
            yarac_binary=str(failing),
            enabled=True,
            rules_dir=self.config.rules_dir,
            inbox_dir=self.config.inbox_dir,
            public_key="",
            require_signature=False,
        )
        adapter = YaraAdapter(
            config,
            ScanConfig(allowed_roots=(str(self.root / "scan"),), skip_paths=()),
            YaraRulePackService(config),
        )
        scan_dir = self.root / "scan"
        scan_dir.mkdir()
        (scan_dir / "eicar.txt").write_text("x", encoding="utf-8")
        task, context = self._task(scan_dir)
        with self.assertRaises(LsecError) as caught:
            adapter.run_task(task, context)
        self.assertEqual(caught.exception.code.value, "component_unavailable")


if __name__ == "__main__":
    unittest.main()
