"""Schema migration tests, including upgrade from schema v1."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lsec.storage.db import Database


class MigrationTests(unittest.TestCase):
    def test_initialize_creates_schema_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "lsec.db")
            db.initialize()
            versions = {
                row["version"]
                for row in db.query("SELECT version FROM schema_migrations")
            }
            self.assertEqual(versions, {1, 2})
            self.assertIsNotNone(
                db.query_one(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_runs'"
                )
            )

    def test_upgrade_from_v1_preserves_existing_rows_and_backs_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.db"
            db = Database(path)
            db.initialize()
            with db.write() as conn:
                conn.execute(
                    "INSERT INTO components (component_id, display_name) VALUES ('clamav','ClamAV')"
                )
                # Simulate a v1 database that predates the audit_runs table.
                conn.execute("DROP TABLE audit_runs")
                conn.execute("DELETE FROM schema_migrations WHERE version = 2")
            db.initialize()
            self.assertIsNotNone(
                db.query_one("SELECT component_id FROM components WHERE component_id='clamav'")
            )
            self.assertIsNotNone(
                db.query_one(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_runs'"
                )
            )
            self.assertTrue((Path(tmp) / "lsec.db.pre-v2.bak").is_file())


if __name__ == "__main__":
    unittest.main()
