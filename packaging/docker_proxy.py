#!/usr/bin/env python3
"""Read-only Docker Engine API proxy for lsec.

The proxy exists so the lsec Web/daemon process never mounts the Docker socket
itself. It forwards only an explicit allowlist of GET endpoints and refuses
every mutating method. A Docker socket is still effectively host root for the
proxy process, so run this container with no-new-privileges, a read-only root
filesystem, all capabilities dropped and an internal-only network.

Allowed upstream requests:
  GET /version
  GET /info
  GET /containers/json?all=0|1
  GET /containers/<12-64 hex chars>/json

Everything else returns 403 (unknown path) or 405 (non-GET).
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

SOCKET_PATH = os.environ.get("LSEC_DOCKER_SOCKET", "/var/run/docker.sock")
BIND = os.environ.get("LSEC_PROXY_BIND", "0.0.0.0")
PORT = int(os.environ.get("LSEC_PROXY_PORT", "2375"))
UPSTREAM_TIMEOUT = float(os.environ.get("LSEC_PROXY_UPSTREAM_TIMEOUT", "8"))
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PATH_CHARS = 300

CONTAINER_ID_RE = re.compile(r"^[0-9a-fA-F]{12,64}$")
CONTAINER_INSPECT_RE = re.compile(r"^/containers/([0-9a-fA-F]{12,64})/json$")


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.unix_path)
        except Exception:
            sock.close()
            raise
        self.sock = sock


def _allowed_target(raw_path: str) -> str | None:
    """Return the sanitized upstream path, or None when not allowlisted."""
    if not raw_path.startswith("/") or len(raw_path) > MAX_PATH_CHARS:
        return None
    parsed = urlsplit(raw_path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None
    path = parsed.path
    query = parsed.query

    if path in {"/version", "/info"}:
        return path if not query else None

    if path == "/containers/json":
        if query in {"", "all=0", "all=1"}:
            return path + (f"?{query}" if query else "")
        return None

    match = CONTAINER_INSPECT_RE.match(path)
    if match and not query:
        return f"/containers/{match.group(1)}/json"

    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "lsec-docker-proxy"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # Only GET is implemented; BaseHTTPRequestHandler answers the rest with 501,
    # so override them to make the read-only contract explicit.
    def do_POST(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_HEAD(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._send_json(405, {"message": "only GET is allowed"}, allow="GET")

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/__health":
            target = "/version"
        else:
            target = _allowed_target(self.path)
            if target is None:
                self._send_json(403, {"message": "path is not allowlisted"})
                return
        try:
            status, content_type, body = self._upstream(target)
        except FileNotFoundError:
            self._send_json(503, {"message": "docker socket is not available"})
            return
        except PermissionError:
            self._send_json(403, {"message": "permission denied by docker socket"})
            return
        except (socket.timeout, TimeoutError):
            self._send_json(504, {"message": "docker api timed out"})
            return
        except OSError as exc:
            self._send_json(
                503, {"message": f"docker api unavailable: {str(exc)[:120]}"}
            )
            return
        if len(body) > MAX_RESPONSE_BYTES:
            self._send_json(502, {"message": "docker api response too large"})
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _upstream(self, target: str) -> tuple[int, str, bytes]:
        connection = UnixHTTPConnection(SOCKET_PATH, UPSTREAM_TIMEOUT)
        try:
            connection.request(
                "GET",
                target,
                headers={"Accept": "application/json", "Host": "docker"},
            )
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BYTES + 1)
            content_type = response.getheader("Content-Type") or "application/json"
            return response.status, content_type, body
        finally:
            connection.close()

    def _send_json(
        self, status: int, payload: dict[str, Any], *, allow: str | None = None
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(
            "docker-proxy %s %s\n"
            % (self.address_string(), fmt % args)
        )


def main() -> None:
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.daemon_threads = True
    sys.stderr.write(
        f"lsec docker proxy listening on {BIND}:{PORT}, upstream {SOCKET_PATH}\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
