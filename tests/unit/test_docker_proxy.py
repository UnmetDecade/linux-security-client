"""GET-only Docker proxy allowlist tests.

These tests exercise the deployed proxy handler against a fake Docker Unix
socket so a regression that widens the allowlist or accepts mutations fails.
"""

from __future__ import annotations

import importlib.util
import json
import socketserver
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROXY_PATH = (
    Path(__file__).resolve().parents[2] / "packaging" / "docker_proxy.py"
)
spec = importlib.util.spec_from_file_location("lsec_docker_proxy", PROXY_PATH)
assert spec and spec.loader
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)

CID = "a" * 64


class _UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class FakeDockerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests: list[tuple[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(("GET", self.path))
        if self.path == "/version":
            body = json.dumps({"Version": "24.0.9"}).encode()
        elif self.path == "/info":
            body = json.dumps({"Architecture": "x86_64"}).encode()
        elif self.path.startswith("/containers/") and self.path.endswith("/json"):
            body = json.dumps({"Id": CID, "Name": "/demo"}).encode()
        elif self.path.startswith("/containers/json"):
            body = json.dumps([{"Id": CID}]).encode()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        pass


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        socket_path = str(Path(cls.tmp.name) / "docker.sock")
        cls.upstream = _UnixServer(socket_path, FakeDockerHandler)
        cls.upstream_thread = threading.Thread(
            target=cls.upstream.serve_forever, daemon=True
        )
        cls.upstream_thread.start()
        cls._old_socket = proxy.SOCKET_PATH
        proxy.SOCKET_PATH = socket_path

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), proxy.Handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.upstream.shutdown()
        cls.upstream.server_close()
        proxy.SOCKET_PATH = cls._old_socket
        cls.tmp.cleanup()

    def setUp(self) -> None:
        FakeDockerHandler.requests = []

    def get(self, path: str) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(self.base + path, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def request(self, method: str, path: str) -> int:
        request = urllib.request.Request(
            self.base + path, method=method, data=b"{}" if method != "GET" else None
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                response.read()
                return response.status
        except urllib.error.HTTPError as exc:
            exc.read()
            return exc.code

    def test_allowlisted_get_endpoints(self) -> None:
        status, body = self.get("/version")
        self.assertEqual(status, 200)
        self.assertEqual(body["Version"], "24.0.9")
        self.assertEqual(self.get(f"/containers/{CID}/json")[0], 200)
        self.assertEqual(self.get("/containers/json?all=1")[0], 200)
        self.assertEqual(self.get("/info")[0], 200)

    def test_mutations_and_unknown_paths_are_refused(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertEqual(self.request(method, "/containers/json"), 405)
        for path in (
            f"/containers/{CID}/start",
            f"/containers/{CID}/stop",
            "/containers/json?all=1&size=1",
            "/version?pretty=1",
            "/_ping",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 403)
        self.assertEqual(FakeDockerHandler.requests, [])

    def test_short_or_traversal_container_ids_are_refused(self) -> None:
        for path in (
            "/containers/abc/json",
            "/containers/../../etc/passwd/json",
            "/containers/" + "z" * 64 + "/json",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 403)
        self.assertEqual(FakeDockerHandler.requests, [])

    def test_health_checks_upstream_version(self) -> None:
        status, body = self.get("/__health")
        self.assertEqual(status, 200)
        self.assertEqual(body["Version"], "24.0.9")
        self.assertEqual(FakeDockerHandler.requests, [("GET", "/version")])


if __name__ == "__main__":
    unittest.main()
