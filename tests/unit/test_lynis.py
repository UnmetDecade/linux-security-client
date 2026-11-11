"""Lynis report parsing and adapter invocation tests."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from lsec.adapters.lynis import (
    LynisAdapter,
    parse_report,
    warning_severity,
)

REPORT = """\
# Lynis Report
report_version_major=1
report_version_minor=0
lynis_version=3.0.8
lynis_tests_done=230
hardening_index=56
warning[]=LOGG-2138|No logging daemon found|-|-
warning[]=PKGS-7392|Vulnerable package installed|openssl|Run apt upgrade|
suggestion[]=BOOT-5122|Set a password on GRUB boot loader|grub|grub-mkconfig|
suggestion[]=SSH-7408|Consider hardening SSH configuration|sshd|Check SSH options|
"""


class LynisParsingTests(unittest.TestCase):
    def test_parses_stable_keys_and_entries(self) -> None:
        parsed = parse_report(REPORT)
        self.assertEqual(parsed["lynis_version"], "3.0.8")
        self.assertEqual(parsed["hardening_index"], 56)
        self.assertEqual(parsed["tests_done"], 230)
        self.assertEqual(len(parsed["warnings"]), 2)
        self.assertEqual(parsed["warnings"][0]["test_id"], "LOGG-2138")
        self.assertEqual(parsed["warnings"][0]["target"], "")
        self.assertEqual(parsed["warnings"][1]["target"], "openssl")
        self.assertEqual(
            parsed["warnings"][1]["remediation"], "Run apt upgrade"
        )
        self.assertEqual(len(parsed["suggestions"]), 2)
        self.assertEqual(parsed["suggestions"][0]["test_id"], "BOOT-5122")

    def test_missing_values_are_not_guessed(self) -> None:
        parsed = parse_report("# only a comment\n")
        self.assertIsNone(parsed["hardening_index"])
        self.assertIsNone(parsed["tests_done"])
        self.assertEqual(parsed["warnings"], [])

    def test_invalid_test_id_falls_back_to_lynis(self) -> None:
        parsed = parse_report("warning[]=not a test id|Some warning|||\n")
        self.assertEqual(parsed["warnings"][0]["test_id"], "LYNIS")

    def test_severity_is_deterministic(self) -> None:
        self.assertEqual(
            warning_severity("PKGS-7392", "Vulnerable package installed"), "high"
        )
        self.assertEqual(warning_severity("LOGG-2138", "No logging daemon"), "medium")
        self.assertIn(
            warning_severity("SSH-7408", "SSH password authentication"),
            {"medium", "high"},
        )


class LynisAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.script = self.root / "fake-lynis"
        self.script.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "--version" ]; then echo "3.0.8"; exit 0; fi\n'
            'report=""\n'
            'log=""\n'
            'prev=""\n'
            'for arg in "$@"; do\n'
            '  if [ "$prev" = "--report-file" ]; then report="$arg"; fi\n'
            '  if [ "$prev" = "--logfile" ]; then log="$arg"; fi\n'
            '  prev="$arg"\n'
            "done\n"
            'printf "%s\\n" "lynis_version=3.0.8" "lynis_tests_done=12" '
            '"hardening_index=71" "warning[]=SSH-7408|Weak SSH|sshd|Harden|" > "$report"\n'
            'echo "audit log" > "$log"\n'
            'echo "audit log"\n',
            encoding="utf-8",
        )
        os.chmod(self.script, 0o755)

    def test_probe_reports_real_binary(self) -> None:
        adapter = LynisAdapter(str(self.script))
        probe = adapter.probe()
        self.assertTrue(probe.installed)
        self.assertEqual(probe.version, "3.0.8")
        self.assertEqual(probe.capabilities, ["host_audit"])

    def test_disabled_probe_is_unavailable_and_builtin_only(self) -> None:
        adapter = LynisAdapter(str(self.script), enabled=False)
        probe = adapter.probe()
        self.assertFalse(probe.installed)
        self.assertEqual(probe.error_code, "disabled")

    def test_missing_binary_is_unavailable(self) -> None:
        adapter = LynisAdapter(str(self.root / "does-not-exist"))
        probe = adapter.probe()
        self.assertFalse(probe.installed)
        self.assertEqual(probe.error_code, "not_installed")
        outcome = adapter.run_audit(self.root / "work", timeout=5)
        self.assertFalse(outcome.available)
        self.assertIn("未检测到", outcome.error or "")

    def test_run_audit_parses_report_and_restricts_permissions(self) -> None:
        adapter = LynisAdapter(str(self.script))
        work = self.root / "work"
        outcome = adapter.run_audit(work, timeout=10)
        self.assertTrue(outcome.available)
        self.assertFalse(outcome.timed_out)
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(outcome.hardening_index, 71)
        self.assertEqual(outcome.tests_done, 12)
        self.assertEqual(len(outcome.warnings), 1)
        self.assertEqual(outcome.warnings[0]["test_id"], "SSH-7408")
        self.assertTrue(Path(outcome.report_path or "").is_file())
        self.assertTrue(Path(outcome.log_path or "").is_file())
        for path in (outcome.report_path, outcome.log_path):
            mode = stat.S_IMODE(os.stat(path or "").st_mode)
            self.assertEqual(mode, 0o600)

    def test_disabled_audit_does_not_execute(self) -> None:
        adapter = LynisAdapter(str(self.script), enabled=False)
        outcome = adapter.run_audit(self.root / "work", timeout=5)
        self.assertFalse(outcome.available)
        self.assertFalse((self.root / "work").exists())


if __name__ == "__main__":
    unittest.main()
