"""Path validation and containment tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from lsec.common.errors import LsecError
from lsec.common.paths import (
    ensure_within_roots,
    is_within,
    require_regular_file,
    validate_path_text,
)


class PathValidationTests(unittest.TestCase):
    def test_relative_and_control_paths_are_rejected(self) -> None:
        for value in ("relative/path", "", "/tmp/with\nnewline", "/tmp/nul\x00byte"):
            with self.assertRaises(LsecError):
                validate_path_text(value)

    def test_overlong_path_is_rejected(self) -> None:
        with self.assertRaises(LsecError):
            validate_path_text("/" + "a" * 5000)

    def test_allow_list_containment(self) -> None:
        self.assertTrue(is_within("/srv/scan/a", "/srv/scan"))
        self.assertFalse(is_within("/srv/scan-other/a", "/srv/scan"))
        with self.assertRaises(LsecError):
            ensure_within_roots("/etc/passwd", ("/srv/scan",))

    def test_symlink_is_rejected_for_destructive_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside.txt"
            outside.write_text("data", encoding="utf-8")
            link = Path(tmp) / "link.txt"
            link.symlink_to(outside)
            with self.assertRaises(LsecError):
                require_regular_file(str(link))
            # A normal regular file is accepted.
            self.assertTrue(require_regular_file(str(outside)).st_size == 4)

    def test_directory_is_not_a_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(LsecError):
                require_regular_file(tmp)


if __name__ == "__main__":
    unittest.main()
