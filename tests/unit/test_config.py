"""Configuration loading and validation tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsec.common.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_defaults_are_safe(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            config = load_config(str(Path(tempfile.gettempdir()) / "missing-lsec.toml"))
        self.assertEqual(config.server.bind, "127.0.0.1")
        self.assertFalse(config.server.allow_insecure_remote)
        self.assertFalse(config.clamav.auto_start)
        self.assertFalse(config.response.auto_quarantine_enabled)
        self.assertEqual(config.response.default_mode, "suggest")
        self.assertFalse(config.config_loaded)

    def test_unknown_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text('[server]\nbind = "127.0.0.1"\ntypo = true\n', encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_config(str(path))
        self.assertIn("typo", str(ctx.exception))

    def test_unknown_section_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text("[unexpected]\nvalue = 1\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_type_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text("[server]\nport = \"8080\"\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_tls_pair_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text('[server]\ntls_cert = "/tmp/a.pem"\n', encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_paths_must_be_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text('[scan]\nallowed_roots = ["relative/path"]\n', encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_env_overrides(self) -> None:
        env = {
            "LSEC_DATA_DIR": "/tmp/lsec-data",
            "LSEC_BIND": "0.0.0.0",
            "LSEC_PORT": "9090",
            "LSEC_LOG_LEVEL": "debug",
            "LSEC_ALLOW_INSECURE_REMOTE": "1",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = load_config(str(Path(tempfile.gettempdir()) / "missing-lsec.toml"))
        self.assertEqual(str(config.data_dir), "/tmp/lsec-data")
        self.assertEqual(config.server.bind, "0.0.0.0")
        self.assertEqual(config.server.port, 9090)
        self.assertEqual(config.logging.level, "DEBUG")
        self.assertTrue(config.server.allow_insecure_remote)

    def test_audit_defaults_and_overrides(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            config = load_config(
                str(Path(tempfile.gettempdir()) / "missing-lsec.toml")
            )
        self.assertTrue(config.audit.lynis_enabled)
        self.assertEqual(config.audit.stale_after_hours, 168)
        self.assertEqual(config.audit.max_findings, 200)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text(
                "[audit]\nlynis_enabled = false\nlynis_timeout_seconds = 60\n"
                "stale_after_hours = 24\nmax_findings = 50\n",
                encoding="utf-8",
            )
            config = load_config(str(path))
        self.assertFalse(config.audit.lynis_enabled)
        self.assertEqual(config.audit.lynis_timeout_seconds, 60)
        self.assertEqual(config.audit.stale_after_hours, 24)
        self.assertEqual(config.audit.max_findings, 50)

    def test_audit_values_are_bounded_and_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text(
                "[audit]\nlynis_timeout_seconds = 99999\n", encoding="utf-8"
            )
            with self.assertRaises(ConfigError):
                load_config(str(path))
            path.write_text("[audit]\nlynis_enabled = \"yes\"\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_container_monitoring_defaults_and_validation(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            config = load_config(
                str(Path(tempfile.gettempdir()) / "missing-lsec.toml")
            )
        self.assertFalse(config.containers.enabled)
        self.assertFalse(config.falco.ingest_enabled)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text(
                "[containers]\nenabled = true\napi_url = \"http://docker-proxy:2375\"\n"
                "timeout_seconds = 5\nrefresh_seconds = 30\nmax_containers = 50\n"
                "[falco]\ningest_enabled = true\nmax_event_bytes = 16384\n",
                encoding="utf-8",
            )
            config = load_config(str(path))
            self.assertTrue(config.containers.enabled)
            self.assertEqual(config.containers.refresh_seconds, 30)
            self.assertTrue(config.falco.ingest_enabled)

            path.write_text(
                "[containers]\nenabled = true\napi_url = \"https://docker-proxy\"\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(str(path))
            path.write_text("[containers]\nrefresh_seconds = 1\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_container_and_falco_env_overrides(self) -> None:
        env = {
            "LSEC_CONTAINERS_ENABLED": "1",
            "LSEC_CONTAINERS_API_URL": "unix:///run/docker.sock",
            "LSEC_FALCO_INGEST_ENABLED": "true",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = load_config(
                str(Path(tempfile.gettempdir()) / "missing-lsec.toml")
            )
        self.assertTrue(config.containers.enabled)
        self.assertEqual(config.containers.api_url, "unix:///run/docker.sock")
        self.assertTrue(config.falco.ingest_enabled)

    def test_session_ttl_and_parallel_tasks_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lsec.toml"
            path.write_text("[scan]\nmax_parallel_tasks = 99\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))


if __name__ == "__main__":
    unittest.main()
