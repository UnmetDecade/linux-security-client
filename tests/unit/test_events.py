"""Event normalization, severity mapping and deduplication."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lsec.adapters.base import Detection
from lsec.core.events import EventService, severity_for_detection
from lsec.storage import events as event_store
from lsec.storage.db import Database


class SeverityTests(unittest.TestCase):
    def test_mapping(self) -> None:
        self.assertEqual(severity_for_detection("Eicar-Test-Signature"), "medium")
        self.assertEqual(severity_for_detection("Win.Trojan.Agent-123"), "critical")
        self.assertEqual(severity_for_detection("Adware.Toolbar"), "low")
        self.assertEqual(severity_for_detection("Some.Unknown.Signature"), "high")
        self.assertEqual(severity_for_detection(""), "high")


class DedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "lsec.db")
        self.db.initialize()
        self.service = EventService(
            self.db, host_provider=lambda: {"hostname": "test-host"}
        )

    def _ingest(self, task_id: str) -> dict:
        return self.service.ingest_clamav_detection(
            Detection(
                path="/scan/eicar.txt",
                detection_name="Eicar-Test-Signature",
                size=68,
                sha256="a" * 64,
            ),
            task_id=task_id,
            task_type="quick",
        )

    def test_repeated_detection_merges(self) -> None:
        first = self._ingest("task-1")
        second = self._ingest("task-2")
        self.assertEqual(first["event_id"], second["event_id"])
        event = self.service.get(first["event_id"])
        self.assertEqual(event["occurrences"], 2)
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["status"], "new")
        self.assertEqual(event["target"]["path"], "/scan/eicar.txt")
        self.assertEqual(event["evidence"]["detection_name"], "Eicar-Test-Signature")
        self.assertGreaterEqual(len(event["source_refs"]), 2)

    def test_open_counts(self) -> None:
        event = self._ingest("task-1")
        counts = self.service.counts()
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["total_open"], 1)
        self.service.update_status(event["event_id"], "resolved", actor="test")
        self.assertEqual(self.service.counts()["total_open"], 0)

    def test_status_transitions(self) -> None:
        event = self._ingest("task-1")
        event_id = event["event_id"]
        self.service.update_status(event_id, "acknowledged", actor="test")
        self.service.update_status(event_id, "resolved", actor="test")
        with self.assertRaises(Exception):
            self.service.update_status(event_id, "acknowledged", actor="test")

    def test_prune_only_terminal_old_events(self) -> None:
        event = self._ingest("task-1")
        self.assertEqual(event_store.prune_events(self.db, retention_days=90), 0)
        self.service.update_status(event["event_id"], "ignored", actor="test")
        # Event is recent, so it is still retained.
        self.assertEqual(event_store.prune_events(self.db, retention_days=90), 0)


if __name__ == "__main__":
    unittest.main()
