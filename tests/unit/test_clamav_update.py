"""ClamAV update signature verification tests (sigtool --info)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lsec.adapters.clamav import ClamAVAdapter
from lsec.common.config import ClamAVConfig, ScanConfig

FAKE_FRESHCLAM = "#!/bin/sh\necho 'Database test passed.'\nexit 0\n"

FAKE_SIGTOOL_OK = """#!/bin/sh
case "$1" in
  --info=*main.cvd) echo "Verification OK."; exit 0 ;;
  --info=*daily.cvd) echo "Verification OK."; exit 0 ;;
  --info=*bytecode.cvd) echo "Verification OK."; exit 0 ;;
esac
exit 1
"""

FAKE_SIGTOOL_BAD_DAILY = """#!/bin/sh
case "$1" in
  --info=*main.cvd) echo "Verification OK."; exit 0 ;;
  --info=*daily.cvd) echo "Verification FAILED."; exit 0 ;;
esac
exit 1
"""


def _write_exec(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


class SignatureVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.db_dir = root / "clamav-db"
        self.db_dir.mkdir()
        (self.db_dir / "main.cvd").write_bytes(b"fake-cvd-main")
        (self.db_dir / "daily.cvd").write_bytes(b"fake-cvd-daily")
        self.freshclam = _write_exec(root / "freshclam", FAKE_FRESHCLAM)
        self.ok_sigtool = _write_exec(root / "sigtool-ok", FAKE_SIGTOOL_OK)
        self.bad_sigtool = _write_exec(root / "sigtool-bad", FAKE_SIGTOOL_BAD_DAILY)

    def _adapter(self, **overrides: object) -> ClamAVAdapter:
        values = {
            "freshclam_bin": str(self.freshclam),
            "sigtool_bin": str(self.ok_sigtool),
            "database_dir": str(self.db_dir),
        }
        values.update(overrides)
        return ClamAVAdapter(
            ClamAVConfig(**values),  # type: ignore[arg-type]
            ScanConfig(),
            self.tmp.name,
        )

    def test_all_cvd_files_verified(self) -> None:
        result = self._adapter().verify_database_signatures()
        self.assertTrue(result["checked"])
        self.assertTrue(result["ok"])
        self.assertEqual(
            sorted(item["name"] for item in result["files"]),
            ["daily.cvd", "main.cvd"],
        )
        self.assertTrue(all(item["verified"] for item in result["files"]))

    def test_failed_verification_is_reported(self) -> None:
        result = self._adapter(sigtool_bin=str(self.bad_sigtool)).verify_database_signatures()
        self.assertTrue(result["checked"])
        self.assertFalse(result["ok"])
        states = {item["name"]: item["verified"] for item in result["files"]}
        self.assertTrue(states["main.cvd"])
        self.assertFalse(states["daily.cvd"])

    def test_missing_sigtool_is_not_treated_as_verified(self) -> None:
        result = self._adapter(sigtool_bin=str(Path(self.tmp.name) / "missing")).verify_database_signatures()
        self.assertFalse(result["checked"])
        self.assertIsNone(result["ok"])
        self.assertIn("sigtool", result["reason"])

    def test_cld_only_is_not_applicable(self) -> None:
        for name in ("main.cvd", "daily.cvd"):
            (self.db_dir / name).unlink()
        (self.db_dir / "main.cld").write_bytes(b"fake-cld")
        result = self._adapter().verify_database_signatures()
        self.assertFalse(result["checked"])
        self.assertIsNone(result["ok"])
        self.assertIn(".cld", result["reason"])

    def test_update_includes_verification(self) -> None:
        outcome = self._adapter().update()
        self.assertTrue(outcome["ok"])
        verification = outcome["signature_verification"]
        self.assertTrue(verification["checked"])
        self.assertTrue(verification["ok"])
        self.assertIn("output_tail", outcome)


if __name__ == "__main__":
    unittest.main()
