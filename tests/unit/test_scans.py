"""Scan task state machine and restart recovery."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lsec.common.errors import LsecError
from lsec.storage import scans as scan_store
from lsec.storage.db import Database


class ScanStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "lsec.db")
        self.db.initialize()
        self.task = scan_store.create_task(
            self.db,
            task_type="custom",
            targets=["/scan"],
            engines=["clamav"],
            actor="test",
        )

    def test_cancel_queued_task(self) -> None:
        task = scan_store.request_cancel(self.db, self.task["task_id"])
        self.assertEqual(task["status"], "cancelled")
        with self.assertRaises(LsecError):
            scan_store.request_cancel(self.db, self.task["task_id"])

    def test_cannot_mark_cancelled_task_running(self) -> None:
        scan_store.request_cancel(self.db, self.task["task_id"])
        self.assertFalse(scan_store.mark_running(self.db, self.task["task_id"]))

    def test_running_to_cancel_requested(self) -> None:
        task_id = self.task["task_id"]
        self.assertTrue(scan_store.mark_running(self.db, task_id))
        task = scan_store.request_cancel(self.db, task_id)
        self.assertEqual(task["status"], "cancel_requested")
        finished = scan_store.finish(
            self.db,
            task_id,
            status="cancelled",
            summary={},
            errors=[],
            files_scanned=0,
            detections=0,
            error_count=0,
            progress=None,
        )
        self.assertEqual(finished["status"], "cancelled")

    def test_unsupported_task_type(self) -> None:
        with self.assertRaises(LsecError):
            scan_store.create_task(
                self.db,
                task_type="unsupported",
                targets=["/scan"],
                engines=["clamav"],
                actor="test",
            )

    def test_interrupted_tasks_are_marked_failed(self) -> None:
        task_id = self.task["task_id"]
        scan_store.mark_running(self.db, task_id)
        self.assertEqual(scan_store.recover_interrupted(self.db), 1)
        task = scan_store.get_task(self.db, task_id)
        self.assertEqual(task["status"], "failed")
        self.assertTrue(task["result_summary"].get("interrupted"))


if __name__ == "__main__":
    unittest.main()
