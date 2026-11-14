"""Minimal, read-only Docker Engine API client.

Only GET requests are implemented. Container monitoring never mutates the
runtime: there is no start/stop/restart/exec path in this module.

In production lsec connects to a dedicated GET-only proxy over an internal
network. A Unix socket URL is supported for local development, but mounting the
Docker socket into the Web process is strongly discouraged because the socket
is effectively host root.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
from typing import Any
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CONTAINER_ID_RE = re.compile(r"^[0-9a-fA-F]{12,64}$")


class DockerApiError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _UnixHTTPConnection(http.client.HTTPConnection):
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


class DockerApiClient:
    def __init__(self, api_url: str, timeout: float = 8) -> None:
        self.api_url = api_url
        self.timeout = timeout
        self._mode, self._target = self._parse_url(api_url)

    @staticmethod
    def _parse_url(api_url: str) -> tuple[str, Any]:
        if api_url.startswith("unix://"):
            path = api_url[len("unix://"):]
            if not path.startswith("/"):
                raise DockerApiError("invalid_config", "Unix socket path must be absolute")
            return "unix", path
        if api_url.startswith("http://"):
            parsed = urlsplit(api_url)
            if (
                not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise DockerApiError("invalid_config", "invalid Docker API address")
            return "tcp", (parsed.hostname, parsed.port or 80)
        raise DockerApiError("invalid_config", "only unix:// or http:// Docker API URLs are supported")

    def _connection(self) -> http.client.HTTPConnection:
        if self._mode == "unix":
            return _UnixHTTPConnection(self._target, self.timeout)
        host, port = self._target
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def _get(self, path: str) -> Any:
        connection = self._connection()
        try:
            try:
                connection.request(
                    "GET",
                    path,
                    headers={"Accept": "application/json", "Host": "docker"},
                )
                response = connection.getresponse()
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            except FileNotFoundError:
                raise DockerApiError("unavailable", "Docker API socket does not exist") from None
            except PermissionError:
                raise DockerApiError("permission_denied", "permission denied accessing the Docker API socket") from None
            except (socket.timeout, TimeoutError):
                raise DockerApiError("timeout", "Docker API request timed out") from None
            except ConnectionRefusedError:
                raise DockerApiError("unavailable", "Docker API connection refused") from None
            except OSError as exc:
                message = str(exc)
                if "permission denied" in message.lower():
                    raise DockerApiError("permission_denied", "permission denied accessing the Docker API") from None
                raise DockerApiError("unavailable", f"cannot connect to Docker API: {message[:200]}") from None
        finally:
            connection.close()

        if len(raw) > MAX_RESPONSE_BYTES:
            raise DockerApiError("protocol_error", "Docker API response too large")
        if response.status in {401, 403}:
            raise DockerApiError("permission_denied", "Docker API access denied (insufficient privileges)")
        if response.status == 404:
            raise DockerApiError("not_found", "Docker API resource not found")
        if response.status >= 400:
            detail = raw.decode("utf-8", errors="replace")[:300]
            raise DockerApiError(
                "protocol_error", f"Docker API returned HTTP {response.status}: {detail}"
            )
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise DockerApiError("protocol_error", "Docker API returned non-JSON data") from None

    def version(self) -> dict[str, Any]:
        data = self._get("/version")
        if not isinstance(data, dict):
            raise DockerApiError("protocol_error", "invalid Docker /version response format")
        return data

    def info(self) -> dict[str, Any]:
        data = self._get("/info")
        if not isinstance(data, dict):
            raise DockerApiError("protocol_error", "invalid Docker /info response format")
        return data

    def list_containers(self) -> list[dict[str, Any]]:
        data = self._get("/containers/json?all=1")
        if not isinstance(data, list):
            raise DockerApiError("protocol_error", "invalid Docker container list format")
        return [item for item in data if isinstance(item, dict)]

    def inspect_container(self, container_id: str) -> dict[str, Any]:
        if not CONTAINER_ID_RE.match(container_id):
            raise DockerApiError("invalid_argument", "invalid container ID format")
        data = self._get(f"/containers/{container_id}/json")
        if not isinstance(data, dict):
            raise DockerApiError("protocol_error", "invalid Docker container details format")
        return data
